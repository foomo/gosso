package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sso "github.com/foomo/gosso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_DiscoveryBaseURL covers an IdP reachable for discovery only under
// another address than its issuer — an in-cluster server whose issuer names
// the public host. Discovery must go to the discovery base URL, while the
// issuer stays the one tokens are validated against.
func TestNew_DiscoveryBaseURL(t *testing.T) {
	t.Parallel()

	const issuer = "https://idp.public.example/realms/customer"

	var requested []string

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)

		if r.URL.Path != "/realms/customer/.well-known/openid-configuration" {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/protocol/openid-connect/auth",
			"token_endpoint":         issuer + "/protocol/openid-connect/token",
			"jwks_uri":               issuer + "/protocol/openid-connect/certs",
			"end_session_endpoint":   issuer + "/protocol/openid-connect/logout",
			"scopes_supported":       []string{"openid", "profile"},
		})
	}))
	t.Cleanup(idp.Close)

	onAuthenticated := func(context.Context, http.ResponseWriter, *http.Request, sso.Subject[Payload]) error { return nil }

	rp, err := New(
		t.Context(),
		issuer,
		"client",
		"secret",
		"http://app.cluster.internal/callback",
		[]byte(strings.Repeat("k", 32)),
		onAuthenticated,
		WithDiscoveryBaseURL(idp.URL+"/realms/customer"),
	)
	require.NoError(t, err)

	assert.Equal(t, []string{"/realms/customer/.well-known/openid-configuration"}, requested)
	assert.Equal(t, issuer+"/protocol/openid-connect/auth", rp.oauth2Cfg.Endpoint.AuthURL, "browser-facing endpoints come from the document")
	assert.Equal(t, issuer+"/protocol/openid-connect/logout", rp.endSession)
	assert.Equal(t, []string{"email"}, rp.UnsupportedScopes())
}
