package native

import (
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/foomo/gosso/oidc/native/repository/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// seedCode stores a code for clientIOS / appRedirect with a real sealed
// IdP refresh token and returns the code.
func (f *fixture) seedCode(t *testing.T) string {
	t.Helper()

	code, err := randomToken(32)
	require.NoError(t, err)

	sealed, err := f.broker.sealer.seal("idp-rt", sealAAD("alice"))
	require.NoError(t, err)

	require.NoError(t, f.codes.Put(t.Context(), store.Code{
		Hash:            hashToken(code),
		ClientID:        clientIOS,
		RedirectURI:     appRedirect,
		CodeChallenge:   hashToken(testVerifier),
		Subject:         store.Subject{ExternalID: "alice", Email: "alice@example.com"},
		Attributes:      store.Attributes{"k": "v"},
		IDPRefreshToken: sealed,
		ExpiresAt:       f.clock.Now().Add(defaultCodeTTL),
	}))

	return code
}

func codeForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {appRedirect},
		"client_id":     {clientIOS},
		"code_verifier": {testVerifier},
	}
}

func assertOAuthError(t *testing.T, res tokenResult, status int, code string) {
	t.Helper()

	assert.Equal(t, status, res.status, "%v", res.body)
	assert.Equal(t, code, res.str("error"), "%v", res.body)
	assert.Equal(t, "no-store", res.header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", res.header.Get("Pragma"))
	assert.Equal(t, "application/json", res.header.Get("Content-Type"))
}

func TestToken_AuthorizationCode(t *testing.T) {
	t.Parallel()

	t.Run("happy", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		res := f.post(t, "/app/token", codeForm(f.seedCode(t)))

		require.Equal(t, http.StatusOK, res.status, "%v", res.body)
		assert.Equal(t, "Bearer", res.str("token_type"))
		assert.InDelta(t, 3600, res.body["expires_in"], 0)
		assert.Equal(t, "no-store", res.header.Get("Cache-Control"))
		assert.Equal(t, "no-cache", res.header.Get("Pragma"))

		rt := res.str("refresh_token")
		require.Equal(t, 1, strings.Count(rt, "."), rt)

		id, secret, _ := strings.Cut(rt, ".")
		assert.Equal(t, "at-"+id, res.str("access_token"))

		s, err := f.sessions.Get(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, hashToken(secret), s.RefreshHash)
		assert.Equal(t, clientIOS, s.ClientID)
		assert.Equal(t, "alice", s.Subject.ExternalID)
		assert.Equal(t, store.Attributes{"k": "v"}, s.Attributes)
		assert.True(t, s.ExpiresAt.Equal(f.clock.Now().Add(defaultSessionTTL)))
		assert.True(t, s.CreatedAt.Equal(f.clock.Now()))

		idpRT, err := f.broker.sealer.open(s.IDPRefreshToken, sealAAD("alice"))
		require.NoError(t, err)
		assert.Equal(t, "idp-rt", idpRT)
	})

	t.Run("replay", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		form := codeForm(f.seedCode(t))
		require.Equal(t, http.StatusOK, f.post(t, "/app/token", form).status)
		assertOAuthError(t, f.post(t, "/app/token", form), http.StatusBadRequest, errInvalidGrant)
	})

	t.Run("expired", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		form := codeForm(f.seedCode(t))
		f.clock.Advance(61 * time.Second)
		assertOAuthError(t, f.post(t, "/app/token", form), http.StatusBadRequest, errInvalidGrant)
	})

	t.Run("wrong verifier consumes the code", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		form := codeForm(f.seedCode(t))

		wrong := maps.Clone(form)
		wrong.Set("code_verifier", strings.Repeat("w", 43))
		assertOAuthError(t, f.post(t, "/app/token", wrong), http.StatusBadRequest, errInvalidGrant)
		assertOAuthError(t, f.post(t, "/app/token", form), http.StatusBadRequest, errInvalidGrant)
	})

	cases := map[string]struct {
		mutate func(url.Values)
		status int
		code   string
	}{
		"wrong redirect":       {mutate: func(v url.Values) { v.Set("redirect_uri", loopbackRedirect) }, status: http.StatusBadRequest, code: errInvalidGrant},
		"wrong client":         {mutate: func(v url.Values) { v.Set("client_id", clientAndroid) }, status: http.StatusBadRequest, code: errInvalidGrant},
		"unknown client":       {mutate: func(v url.Values) { v.Set("client_id", "nope") }, status: http.StatusBadRequest, code: errInvalidClient},
		"missing client":       {mutate: func(v url.Values) { v.Del("client_id") }, status: http.StatusBadRequest, code: errInvalidClient},
		"short verifier":       {mutate: func(v url.Values) { v.Set("code_verifier", strings.Repeat("v", 42)) }, status: http.StatusBadRequest, code: errInvalidRequest},
		"missing code":         {mutate: func(v url.Values) { v.Del("code") }, status: http.StatusBadRequest, code: errInvalidRequest},
		"missing redirect":     {mutate: func(v url.Values) { v.Del("redirect_uri") }, status: http.StatusBadRequest, code: errInvalidRequest},
		"password grant":       {mutate: func(v url.Values) { v.Set("grant_type", "password") }, status: http.StatusBadRequest, code: errUnsupportedGrantType},
		"missing grant":        {mutate: func(v url.Values) { v.Del("grant_type") }, status: http.StatusBadRequest, code: errUnsupportedGrantType},
		"unknown code ignored": {mutate: func(v url.Values) { v.Set("code", "nope") }, status: http.StatusBadRequest, code: errInvalidGrant},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			form := codeForm(f.seedCode(t))
			tc.mutate(form)
			assertOAuthError(t, f.post(t, "/app/token", form), tc.status, tc.code)
		})
	}

	t.Run("get", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/app/token", nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})

	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		form := codeForm(f.seedCode(t))
		form.Set("padding", strings.Repeat("p", 17*1024))
		assertOAuthError(t, f.post(t, "/app/token", form), http.StatusBadRequest, errInvalidRequest)
	})

	t.Run("mint error", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		f.setMintErr(errHook)
		assertOAuthError(t, f.post(t, "/app/token", codeForm(f.seedCode(t))), http.StatusInternalServerError, errServerError)

		n, err := f.sessions.Collection().CountAll(t.Context())
		require.NoError(t, err)
		assert.Zero(t, n, "no session left behind")
	})
}
