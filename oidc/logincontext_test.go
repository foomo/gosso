package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/internal/fakeidp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransit_RoundTripLoginContext(t *testing.T) {
	t.Parallel()

	c := newTestCodec(time.Unix(1_700_000_000, 0))

	roundTrip := func(in transitData) transitData {
		rec := httptest.NewRecorder()
		require.NoError(t, c.write(rec, in))

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)
		for _, ck := range rec.Result().Cookies() {
			req.AddCookie(ck)
		}

		out, err := c.read(req)
		require.NoError(t, err)

		return out
	}

	out := roundTrip(transitData{State: "s", Context: LoginContext{"k": "v"}})
	assert.Equal(t, LoginContext{"k": "v"}, out.Context)

	// a cookie without a context keeps the old wire format
	out = roundTrip(transitData{State: "s"})
	assert.Nil(t, out.Context)
}

func TestTransit_RejectsOversizedCookie(t *testing.T) {
	t.Parallel()

	c := newTestCodec(time.Unix(1_700_000_000, 0))
	rec := httptest.NewRecorder()

	err := c.write(rec, transitData{State: "s", Context: LoginContext{"k": strings.Repeat("<", 1000)}})
	require.Error(t, err, "a cookie over the browser limit would be dropped silently")
	assert.Empty(t, rec.Result().Cookies())
}

func TestTransit_TamperedLoginContext(t *testing.T) {
	t.Parallel()

	c := newTestCodec(time.Unix(1_700_000_000, 0))
	rec := httptest.NewRecorder()
	require.NoError(t, c.write(rec, transitData{State: "s", Context: LoginContext{"k": "v"}}))

	parts := strings.SplitN(rec.Result().Cookies()[0].Value, ".", 2)
	require.Len(t, parts, 2)

	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var d transitData
	require.NoError(t, json.Unmarshal(body, &d))

	d.Context = LoginContext{"k": "evil"}
	body, err = json.Marshal(d)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)
	req.AddCookie(&http.Cookie{Name: c.name, Value: base64.RawURLEncoding.EncodeToString(body) + "." + parts[1]})

	_, err = c.read(req)
	require.Error(t, err)
}

// hookRecord captures what the callback hooks saw.
type hookRecord struct {
	mu            sync.Mutex
	authCtx       LoginContext
	authCtxOK     bool
	redirectCtx   LoginContext
	redirectCtxOK bool
	target        string
	authCalls     int
	refreshToken  string
	redirectCalls int

	loginErrorCalls int
	loginErrorCtx   LoginContext
	loginErrorStage string
	loginErrorQuery url.Values
}

// rpFixture is an RP against a fake IdP, mounted on its own server.
type rpFixture struct {
	idp    *fakeidp.IdP
	rp     *RP
	server *httptest.Server
	rec    *hookRecord
	client *http.Client
}

// newRPFixture starts a server whose mux mounts /login, /callback and
// /start (which calls rp.Login with the given options).
func newRPFixture(t *testing.T, loginErr OnLoginError, startOpts ...LoginOption) *rpFixture {
	t.Helper()

	f := &rpFixture{idp: fakeidp.New(t, "client", "secret"), rec: &hookRecord{}}

	mux := http.NewServeMux()
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	onAuth := func(ctx context.Context, _ http.ResponseWriter, _ *http.Request, sub sso.Subject[Payload]) error {
		f.rec.mu.Lock()
		defer f.rec.mu.Unlock()

		f.rec.authCalls++
		f.rec.refreshToken = sub.Raw.RefreshToken
		f.rec.authCtx, f.rec.authCtxOK = LoginContextFromContext(ctx)

		return nil
	}

	onRedirect := func(ctx context.Context, _ http.ResponseWriter, _ *http.Request, _ sso.Subject[Payload], target string) (string, error) {
		f.rec.mu.Lock()
		defer f.rec.mu.Unlock()

		f.rec.redirectCalls++
		f.rec.redirectCtx, f.rec.redirectCtxOK = LoginContextFromContext(ctx)
		f.rec.target = target

		return "", nil
	}

	opts := []Option{WithOnRedirect(onRedirect)}
	if loginErr != nil {
		opts = append(opts, WithOnLoginError(func(ctx context.Context, w http.ResponseWriter, r *http.Request, lc LoginContext, stage string, err error) string {
			f.rec.mu.Lock()
			f.rec.loginErrorCalls++
			f.rec.loginErrorCtx = lc
			f.rec.loginErrorStage = stage
			f.rec.loginErrorQuery = r.URL.Query()
			f.rec.mu.Unlock()

			return loginErr(ctx, w, r, lc, stage, err)
		}))
	}

	rp, err := New(t.Context(), f.idp.URL, "client", "secret", f.server.URL+"/callback",
		[]byte(strings.Repeat("k", 32)), onAuth, opts...)
	require.NoError(t, err)

	f.rp = rp

	h := rp.Handlers()
	mux.Handle("/login", h.Login)
	mux.Handle("/callback", h.Callback)
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		rp.Login(w, r, startOpts...)
	})

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	f.client = &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			// stop where the RP sends the browser back into the app
			if req.URL.Host != hostOf(f.server.URL) && req.URL.Host != hostOf(f.idp.URL) {
				return http.ErrUseLastResponse
			}

			if req.URL.Host == hostOf(f.server.URL) && req.URL.Path != "/callback" {
				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	return f
}

func hostOf(raw string) string {
	u, _ := url.Parse(raw)
	return u.Host
}

// response is a read and closed HTTP response.
type response struct {
	StatusCode int
	Header     http.Header
	Body       string
}

// get follows redirects through the IdP back to the RP callback and
// returns the callback's response.
func (f *rpFixture) get(t *testing.T, path string) response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+path, nil)
	require.NoError(t, err)

	resp, err := f.client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return response{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(body)}
}

func TestLogin_ContextReachesHooks(t *testing.T) {
	t.Parallel()

	f := newRPFixture(t, nil,
		WithLoginContext(LoginContext{"native": "1"}),
		WithLoginTarget("https://evil.example"),
	)

	resp := f.get(t, "/start")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/", resp.Header.Get("Location"))

	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()

	assert.True(t, f.rec.authCtxOK)
	assert.Equal(t, LoginContext{"native": "1"}, f.rec.authCtx)
	assert.True(t, f.rec.redirectCtxOK)
	assert.Equal(t, LoginContext{"native": "1"}, f.rec.redirectCtx)
	assert.Equal(t, "/", f.rec.target)
}

func TestLogin_WebUnchanged(t *testing.T) {
	t.Parallel()

	f := newRPFixture(t, nil)

	resp := f.get(t, "/login?target=/account")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/account", resp.Header.Get("Location"))

	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()

	assert.Equal(t, 1, f.rec.authCalls)
	assert.False(t, f.rec.authCtxOK)
	assert.Nil(t, f.rec.authCtx)
	assert.False(t, f.rec.redirectCtxOK)
	assert.Equal(t, "/account", f.rec.target)
}

func TestLogin_InitError(t *testing.T) {
	t.Parallel()

	oversized := WithLoginContext(LoginContext{"k": strings.Repeat("<", 1000)})

	t.Run("default 500", func(t *testing.T) {
		t.Parallel()

		f := newRPFixture(t, nil, oversized)

		resp := f.get(t, "/start")
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("custom response", func(t *testing.T) {
		t.Parallel()

		var gotErr error

		f := newRPFixture(t, nil, oversized, WithLoginInitError(func(w http.ResponseWriter, r *http.Request, err error) {
			gotErr = err

			http.Redirect(w, r, "/failed", http.StatusFound)
		}))

		resp := f.get(t, "/start")
		require.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, "/failed", resp.Header.Get("Location"))
		require.Error(t, gotErr)
		assert.Empty(t, resp.Header.Values("Set-Cookie"), "no transit cookie")
	})
}

func TestLoginContextFromContext_ReturnsClone(t *testing.T) {
	t.Parallel()

	lc := LoginContext{"k": "v"}
	ctx := withLoginContext(t.Context(), lc)

	got, ok := LoginContextFromContext(ctx)
	require.True(t, ok)

	got["k"] = "changed"

	again, _ := LoginContextFromContext(ctx)
	assert.Equal(t, "v", again["k"])
}

func TestCallback_OnLoginErrorRedirects(t *testing.T) {
	t.Parallel()

	f := newRPFixture(t,
		func(context.Context, http.ResponseWriter, *http.Request, LoginContext, string, error) string {
			return "com.example.app:/cb?error=x"
		},
		WithLoginContext(LoginContext{"native": "1"}),
	)
	f.idp.SetAuthorizeError("access_denied")

	resp := f.get(t, "/start")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "com.example.app:/cb?error=x", resp.Header.Get("Location"))

	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()

	assert.Equal(t, 1, f.rec.loginErrorCalls)
	assert.Equal(t, StageIDPError, f.rec.loginErrorStage)
	assert.Equal(t, LoginContext{"native": "1"}, f.rec.loginErrorCtx)
	assert.Equal(t, "access_denied", f.rec.loginErrorQuery.Get("error"))
}

func TestCallback_OnLoginErrorNotCalledBeforeState(t *testing.T) {
	t.Parallel()

	f := newRPFixture(t,
		func(context.Context, http.ResponseWriter, *http.Request, LoginContext, string, error) string {
			return "com.example.app:/cb?error=x"
		},
		WithLoginContext(LoginContext{"native": "1"}),
	)

	// start a login to get a valid transit cookie, then call back with a
	// state that does not match it
	client := *f.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/start", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusFound, resp.StatusCode)

	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/callback?state=tampered&error=access_denied", nil)
	require.NoError(t, err)
	resp, err = client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "state mismatch\n", string(body))

	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()

	assert.Zero(t, f.rec.loginErrorCalls)
}

func TestCallback_OnLoginErrorEmptyKeepsDefault(t *testing.T) {
	t.Parallel()

	f := newRPFixture(t,
		func(context.Context, http.ResponseWriter, *http.Request, LoginContext, string, error) string {
			return ""
		},
		WithLoginContext(LoginContext{"native": "1"}),
	)
	f.idp.SetAuthorizeError("access_denied")

	resp := f.get(t, "/start")
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Equal(t, "idp error\n", resp.Body)

	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()

	assert.Equal(t, 1, f.rec.loginErrorCalls)
}
