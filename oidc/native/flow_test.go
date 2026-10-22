package native

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlow_LoginTokenRefreshRevoke(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	verifier := strings.Repeat("V", 64)
	state := "af0ifjsldkj"

	resp := f.browse(t, "/app/authorize?"+authorizeQuery(state, hashToken(verifier)).Encode())
	require.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	require.True(t, strings.HasPrefix(location, appRedirect+"?"), location)

	loc, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, state, loc.Query().Get("state"))
	require.NotEmpty(t, loc.Query().Get("code"))

	// the callback only clears the transit cookie: no web session
	for _, c := range resp.Cookies {
		assert.Equal(t, "gosso_oidc_transit", c.Name)
		assert.Negative(t, c.MaxAge)
	}

	f.mu.Lock()
	assert.Zero(t, f.webAuthCalls)
	assert.Zero(t, f.webRedirectCalls)
	f.mu.Unlock()

	res := f.post(t, "/app/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"redirect_uri":  {appRedirect},
		"client_id":     {clientIOS},
		"code_verifier": {verifier},
	})
	require.Equal(t, http.StatusOK, res.status, "%v", res.body)

	res = f.refresh(t, res.str("refresh_token"))
	require.Equal(t, http.StatusOK, res.status, "%v", res.body)

	latest := res.str("refresh_token")

	res = f.post(t, "/app/revoke", url.Values{"token": {latest}, "client_id": {clientIOS}})
	require.Equal(t, http.StatusOK, res.status)

	assertOAuthError(t, f.refresh(t, latest), http.StatusBadRequest, errInvalidGrant)
}

func TestFlow_UserCancels(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.idp.SetAuthorizeError("access_denied")

	loc := f.login(t, "st", hashToken(strings.Repeat("v", 43)))
	assert.Equal(t, appRedirect+"?error=access_denied&state=st", loc.String())
}

func TestFlow_UnknownIdPErrorBecomesServerError(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.idp.SetAuthorizeError("weird")

	loc := f.login(t, "st", hashToken(strings.Repeat("v", 43)))
	assert.Equal(t, appRedirect+"?error=server_error&state=st", loc.String())
}

// A failed login whose client or redirect URI was deregistered meanwhile
// is not redirected to the app.
func TestOnLoginError_Deregistered(t *testing.T) {
	t.Parallel()

	codes, sessions := newRepositories(t)
	b, err := New(codes, sessions, validHooks(), testClients(), testKey)
	require.NoError(t, err)

	onLoginError := b.OnLoginError(nil)

	tests := map[string]struct {
		clientID    string
		redirectURI string
		want        string
	}{
		"registered":       {clientID: clientIOS, redirectURI: appRedirect, want: appRedirect + "?error=server_error&state=st"},
		"unknown client":   {clientID: "gone", redirectURI: appRedirect},
		"unknown redirect": {clientID: clientIOS, redirectURI: "com.example.old:/cb"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			lc := nativeLogin{clientID: tt.clientID, redirectURI: tt.redirectURI, state: "st"}.loginContext()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)

			got := onLoginError(t.Context(), httptest.NewRecorder(), req, lc, "exchange", errHook)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFlow_NoIDPRefreshToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.idp.SetIssueRefreshToken(false)

	loc := f.login(t, "st", hashToken(strings.Repeat("v", 43)))
	assert.Equal(t, appRedirect+"?error=server_error&state=st", loc.String())

	n, err := f.codes.Collection().CountAll(t.Context())
	require.NoError(t, err)
	assert.Zero(t, n, "no code stored")
}

func TestFlow_AuthenticateFails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.setAuthenticateErr(errHook)

	loc := f.login(t, "st", hashToken(strings.Repeat("v", 43)))
	assert.Equal(t, appRedirect+"?error=server_error&state=st", loc.String())
}

func TestFlow_WebLoginUnaffected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	resp := f.browse(t, "/login?target=/account")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/account", resp.Header.Get("Location"))

	f.mu.Lock()
	defer f.mu.Unlock()

	assert.Equal(t, 1, f.webAuthCalls)
	assert.Equal(t, 1, f.webRedirectCalls)
	assert.Empty(t, f.authenticated, "Authenticate is native-only")
}
