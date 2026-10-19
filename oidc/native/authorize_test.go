package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/oidc"
)

func validHooks() Hooks {
	return Hooks{
		Authenticate: func(context.Context, *http.Request, sso.Subject[oidc.Payload]) (Attributes, error) {
			return nil, nil
		},
		Mint: func(context.Context, Session) (Tokens, error) { return Tokens{}, nil },
	}
}

func TestNew_Validation(t *testing.T) {
	t.Parallel()

	type args struct {
		store   Store
		hooks   Hooks
		clients []Client
		key     []byte
	}

	valid := func() args {
		return args{store: NewMemoryStore(), hooks: validHooks(), clients: testClients(), key: testKey}
	}

	cases := map[string]struct {
		mutate  func(a *args)
		wantErr string
	}{
		"valid":               {mutate: func(*args) {}},
		"nil store":           {mutate: func(a *args) { a.store = nil }, wantErr: "store"},
		"nil authenticate":    {mutate: func(a *args) { a.hooks.Authenticate = nil }, wantErr: "Authenticate"},
		"nil mint":            {mutate: func(a *args) { a.hooks.Mint = nil }, wantErr: "Mint"},
		"no clients":          {mutate: func(a *args) { a.clients = nil }, wantErr: "client"},
		"empty client id":     {mutate: func(a *args) { a.clients[0].ID = "" }, wantErr: "client id"},
		"duplicate client id": {mutate: func(a *args) { a.clients[1].ID = a.clients[0].ID }, wantErr: "duplicate"},
		"no redirect uris":    {mutate: func(a *args) { a.clients[0].RedirectURIs = nil }, wantErr: "redirect"},
		"unparsable redirect": {mutate: func(a *args) { a.clients[0].RedirectURIs = []string{"http://[::1"} }, wantErr: "redirect"},
		"no scheme":           {mutate: func(a *args) { a.clients[0].RedirectURIs = []string{"/relative"} }, wantErr: "scheme"},
		"fragment":            {mutate: func(a *args) { a.clients[0].RedirectURIs = []string{"com.example.app:/cb#frag"} }, wantErr: "fragment"},
		"short key":           {mutate: func(a *args) { a.key = testKey[:31] }, wantErr: "32 bytes"},
		"long key":            {mutate: func(a *args) { a.key = slices.Concat(testKey, []byte{'x'}) }, wantErr: "32 bytes"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := valid()
			tc.mutate(&a)

			_, err := New(a.store, a.hooks, a.clients, a.key)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestAttach_RequiresWrappers(t *testing.T) {
	t.Parallel()

	f := newFixture(t) // a real RP to attach

	newBroker := func() *Broker {
		b, err := New(NewMemoryStore(), validHooks(), testClients(), testKey)
		require.NoError(t, err)

		return b
	}

	b := newBroker()
	require.Error(t, b.Attach(f.rp), "no wrappers taken")

	b = newBroker()
	b.OnAuthenticated(nil)
	b.OnRedirect(nil)
	err := b.Attach(f.rp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OnLoginError")

	b = newBroker()
	b.OnAuthenticated(nil)
	b.OnRedirect(nil)
	b.OnLoginError(nil)
	require.Error(t, b.Attach(nil), "nil rp")
	require.NoError(t, b.Attach(f.rp))
}

func TestNativeRedirectURL(t *testing.T) {
	t.Parallel()

	params := url.Values{"code": {"c"}, "state": {"s"}}

	cases := map[string]struct{ in, want string }{
		"reverse-dns scheme": {"com.example.app:/oauth2redirect", "com.example.app:/oauth2redirect?code=c&state=s"},
		"scheme with host":   {"com.example.app://host/cb", "com.example.app://host/cb?code=c&state=s"},
		"loopback":           {"http://127.0.0.1:8090/callback", "http://127.0.0.1:8090/callback?code=c&state=s"},
		"existing query":     {"com.example.app:/cb?x=1", "com.example.app:/cb?code=c&state=s&x=1"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := nativeRedirectURL(tc.in, params)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func hasTransitCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gosso_oidc_transit" && c.MaxAge > 0 {
			return true
		}
	}

	return false
}

func TestAuthorize_Validation(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	challenge := hashToken(strings.Repeat("v", 43))

	cases := map[string]struct {
		mutate    func(q url.Values)
		method    string
		status    int
		wantError string // error= on the app redirect; "" = no app redirect
	}{
		"unknown client":    {mutate: func(q url.Values) { q.Set("client_id", "nope") }, status: http.StatusBadRequest},
		"wrong redirect":    {mutate: func(q url.Values) { q.Set("redirect_uri", "com.evil.app:/cb") }, status: http.StatusBadRequest},
		"other client uri":  {mutate: func(q url.Values) { q.Set("client_id", clientAndroid); q.Set("redirect_uri", loopbackRedirect) }, status: http.StatusBadRequest},
		"missing state":     {mutate: func(q url.Values) { q.Del("state") }, status: http.StatusFound, wantError: "invalid_request"},
		"state too long":    {mutate: func(q url.Values) { q.Set("state", strings.Repeat("s", 513)) }, status: http.StatusFound, wantError: "invalid_request"},
		"state escapes":     {mutate: func(q url.Values) { q.Set("state", strings.Repeat("<", 512)) }, status: http.StatusFound, wantError: "invalid_request"},
		"state control":     {mutate: func(q url.Values) { q.Set("state", "a\x01b") }, status: http.StatusFound, wantError: "invalid_request"},
		"short challenge":   {mutate: func(q url.Values) { q.Set("code_challenge", challenge[:42]) }, status: http.StatusFound, wantError: "invalid_request"},
		"missing challenge": {mutate: func(q url.Values) { q.Del("code_challenge") }, status: http.StatusFound, wantError: "invalid_request"},
		"plain method":      {mutate: func(q url.Values) { q.Set("code_challenge_method", "plain") }, status: http.StatusFound, wantError: "invalid_request"},
		"missing method":    {mutate: func(q url.Values) { q.Del("code_challenge_method") }, status: http.StatusFound, wantError: "invalid_request"},
		"token response":    {mutate: func(q url.Values) { q.Set("response_type", "token") }, status: http.StatusFound, wantError: "unsupported_response_type"},
		"post":              {mutate: func(url.Values) {}, method: http.MethodPost, status: http.StatusMethodNotAllowed},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			q := authorizeQuery("app-state", challenge)
			tc.mutate(q)

			method := tc.method
			if method == "" {
				method = http.MethodGet
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), method, "/app/authorize?"+q.Encode(), nil)
			f.broker.Handlers().Authorize.ServeHTTP(rec, req)

			assert.Equal(t, tc.status, rec.Code)
			assert.False(t, hasTransitCookie(rec), "no login started")

			if tc.wantError == "" {
				assert.Empty(t, rec.Header().Get("Location"))
				return
			}

			loc, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "com.example.app", loc.Scheme)
			assert.Equal(t, tc.wantError, loc.Query().Get("error"))

			if q.Get("state") == "app-state" {
				assert.Equal(t, "app-state", loc.Query().Get("state"))
			}
		})
	}

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app/authorize?"+authorizeQuery("app-state", challenge).Encode(), nil)
		f.broker.Handlers().Authorize.ServeHTTP(rec, req)

		require.Equal(t, http.StatusFound, rec.Code)
		assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), f.idp.URL+"/authorize?"), rec.Header().Get("Location"))
		assert.True(t, hasTransitCookie(rec))
	})

	t.Run("response type omitted", func(t *testing.T) {
		t.Parallel()

		q := authorizeQuery("app-state", challenge)
		q.Del("response_type")

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app/authorize?"+q.Encode(), nil)
		f.broker.Handlers().Authorize.ServeHTTP(rec, req)

		require.Equal(t, http.StatusFound, rec.Code)
		assert.True(t, hasTransitCookie(rec))
	})
}

func TestAuthorize_BeforeAttach(t *testing.T) {
	t.Parallel()

	b, err := New(NewMemoryStore(), validHooks(), testClients(), testKey)
	require.NoError(t, err)

	h := b.Handlers()
	for name, handler := range map[string]http.Handler{"authorize": h.Authorize, "token": h.Token, "revoke": h.Revoke} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil))
		assert.Equal(t, http.StatusInternalServerError, rec.Code, name)
	}
}
