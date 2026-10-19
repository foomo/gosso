package native

import (
	"net/http"
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

func TestFlow_NoIDPRefreshToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.idp.SetIssueRefreshToken(false)

	loc := f.login(t, "st", hashToken(strings.Repeat("v", 43)))
	assert.Equal(t, appRedirect+"?error=server_error&state=st", loc.String())

	f.store.mu.Lock()
	defer f.store.mu.Unlock()

	assert.Empty(t, f.store.codes)
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
