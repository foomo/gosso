package native

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/internal/fakeidp"
	"github.com/foomo/gosso/internal/mongotest"
	"github.com/foomo/gosso/oidc"
	"github.com/foomo/gosso/oidc/native/repository"
	"github.com/foomo/gosso/oidc/native/repository/store"
)

const (
	appRedirect      = "com.example.app:/oauth2redirect"
	loopbackRedirect = "http://127.0.0.1:8090/callback"
	clientIOS        = "app-ios"
	clientAndroid    = "app-android"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func testClients() []Client {
	return []Client{
		{ID: clientIOS, RedirectURIs: []string{appRedirect, loopbackRedirect}},
		{ID: clientAndroid, RedirectURIs: []string{appRedirect}},
	}
}

// testClock is a settable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// fixture is a broker attached to an RP against a fake IdP, all mounted
// on one server: /login, /callback (web RP) and /app/authorize,
// /app/token, /app/revoke (broker).
type fixture struct {
	idp      *fakeidp.IdP
	codes    *repository.BaseCode
	sessions *repository.BaseSession
	clock    *testClock
	broker   *Broker
	rp       *oidc.RP
	server   *httptest.Server
	client   *http.Client

	mu               sync.Mutex
	authenticateErr  error
	mintErr          error
	authenticated    []sso.Subject[oidc.Payload]
	webAuthCalls     int
	webRedirectCalls int
	mints            int
}

func newFixture(t *testing.T, opts ...Option) *fixture {
	t.Helper()

	return newFixtureWithSessions(t, nil, opts...)
}

// newRepositories returns MongoDB repositories on a fresh database.
func newRepositories(t *testing.T) (*repository.BaseCode, *repository.BaseSession) {
	t.Helper()

	p := mongotest.Persistor(t)

	codes, err := repository.NewDefaultCode(p)
	require.NoError(t, err)

	sessions, err := repository.NewDefaultSession(p)
	require.NoError(t, err)

	return codes, sessions
}

// newFixtureWithSessions is newFixture with the broker's session repository
// wrapped by wrap (nil = unwrapped), e.g. to inject failures.
func newFixtureWithSessions(t *testing.T, wrap func(repository.Session) repository.Session, opts ...Option) *fixture {
	t.Helper()

	f := &fixture{
		idp:   fakeidp.New(t, "rp-client", "rp-secret"),
		clock: newTestClock(),
	}

	f.codes, f.sessions = newRepositories(t)

	hooks := Hooks{
		Authenticate: func(_ context.Context, _ *http.Request, sub sso.Subject[oidc.Payload]) (store.Attributes, error) {
			f.mu.Lock()
			defer f.mu.Unlock()

			if f.authenticateErr != nil {
				return nil, f.authenticateErr
			}

			f.authenticated = append(f.authenticated, sub)

			return store.Attributes{"email": sub.Email, "logins": strings.Repeat("x", len(f.authenticated))}, nil
		},
		Mint: func(_ context.Context, s store.Session) (Tokens, error) {
			f.mu.Lock()
			defer f.mu.Unlock()

			f.mints++

			if f.mintErr != nil {
				return Tokens{}, f.mintErr
			}

			return Tokens{AccessToken: "at-" + s.ID, ExpiresIn: time.Hour}, nil
		},
	}

	var sessions repository.Session = f.sessions
	if wrap != nil {
		sessions = wrap(f.sessions)
	}

	b, err := New(f.codes, sessions, hooks, testClients(), testKey, append([]Option{WithClock(f.clock.Now)}, opts...)...)
	require.NoError(t, err)

	f.broker = b

	mux := http.NewServeMux()
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	webOnAuth := func(context.Context, http.ResponseWriter, *http.Request, sso.Subject[oidc.Payload]) error {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.webAuthCalls++

		return nil
	}

	webOnRedirect := func(_ context.Context, _ http.ResponseWriter, _ *http.Request, _ sso.Subject[oidc.Payload], _ string) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.webRedirectCalls++

		return "", nil
	}

	rp, err := oidc.New(t.Context(), f.idp.URL, "rp-client", "rp-secret", f.server.URL+"/callback",
		[]byte(strings.Repeat("t", 32)),
		b.OnAuthenticated(webOnAuth),
		oidc.WithExtraScopes("offline_access"),
		oidc.WithOnRedirect(b.OnRedirect(webOnRedirect)),
		oidc.WithOnLoginError(b.OnLoginError(nil)),
	)
	require.NoError(t, err)
	require.NoError(t, b.Attach(rp))

	f.rp = rp

	rh := rp.Handlers()
	bh := b.Handlers()

	mux.Handle("/login", rh.Login)
	mux.Handle("/callback", rh.Callback)
	mux.Handle("/app/authorize", bh.Authorize)
	mux.Handle("/app/token", bh.Token)
	mux.Handle("/app/revoke", bh.Revoke)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	serverHost := hostOf(f.server.URL)
	idpHost := hostOf(f.idp.URL)

	f.client = &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			// follow the browser through the IdP and back to /callback;
			// stop at app schemes and anything the callback sends us to
			switch {
			case req.URL.Scheme != "http" && req.URL.Scheme != "https":
				return http.ErrUseLastResponse
			case req.URL.Host == idpHost:
				return nil
			case req.URL.Host == serverHost && req.URL.Path == "/callback":
				return nil
			default:
				return http.ErrUseLastResponse
			}
		},
	}

	return f
}

func hostOf(raw string) string {
	u, _ := url.Parse(raw)
	return u.Host
}

func (f *fixture) setAuthenticateErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.authenticateErr = err
}

func (f *fixture) setMintErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.mintErr = err
}

// mintCount returns how often Hooks.Mint ran.
func (f *fixture) mintCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.mints
}

func (f *fixture) authenticatedSubjects() []sso.Subject[oidc.Payload] {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]sso.Subject[oidc.Payload](nil), f.authenticated...)
}

// browseResult is the last response of a browse, body discarded.
type browseResult struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie
}

// browse runs a browser GET through the server, following redirects as
// set up in newFixture, and returns the last response.
func (f *fixture) browse(t *testing.T, path string) browseResult {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+path, nil)
	require.NoError(t, err)

	resp, err := f.client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	return browseResult{StatusCode: resp.StatusCode, Header: resp.Header, Cookies: resp.Cookies()}
}

// authorizeQuery builds the authorize query for clientIOS / appRedirect.
func authorizeQuery(state, challenge string) url.Values {
	return url.Values{
		"client_id":             {clientIOS},
		"redirect_uri":          {appRedirect},
		"response_type":         {"code"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

// login runs the native authorization flow and returns the app redirect.
func (f *fixture) login(t *testing.T, state, challenge string) *url.URL {
	t.Helper()

	resp := f.browse(t, "/app/authorize?"+authorizeQuery(state, challenge).Encode())
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	return loc
}

// tokenResult is a decoded token or revoke response.
type tokenResult struct {
	status int
	header http.Header
	body   map[string]any
}

func (r tokenResult) str(key string) string {
	s, _ := r.body[key].(string)
	return s
}

// post sends a form POST to path.
func (f *fixture) post(t *testing.T, path string, form url.Values) tokenResult {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.server.URL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	res := tokenResult{status: resp.StatusCode, header: resp.Header, body: map[string]any{}}

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if len(raw) > 0 && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		require.NoError(t, json.Unmarshal(raw, &res.body))
	}

	return res
}

// fullLogin runs authorize + the authorization_code grant and returns the
// refresh token.
func (f *fixture) fullLogin(t *testing.T) string {
	t.Helper()

	verifier := strings.Repeat("v", 43)
	loc := f.login(t, "app-state", hashToken(verifier))

	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "app redirect %s", loc)

	res := f.post(t, "/app/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {appRedirect},
		"client_id":     {clientIOS},
		"code_verifier": {verifier},
	})
	require.Equal(t, http.StatusOK, res.status, "%v", res.body)

	return res.str("refresh_token")
}

func (f *fixture) refresh(t *testing.T, refreshToken string) tokenResult {
	t.Helper()

	return f.post(t, "/app/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientIOS},
	})
}

var errHook = errors.New("hook failed")
