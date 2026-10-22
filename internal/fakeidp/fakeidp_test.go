package fakeidp

import (
	"net/http"
	"net/url"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestFakeIDP_AuthCodeAndRefresh(t *testing.T) {
	t.Parallel()

	const (
		clientID     = "client"
		clientSecret = "secret"
		redirectURL  = "http://127.0.0.1:1/callback"
	)

	idp := New(t, clientID, clientSecret)
	ctx := t.Context()

	provider, err := gooidc.NewProvider(ctx, idp.URL)
	require.NoError(t, err)

	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{gooidc.ScopeOpenID, gooidc.ScopeOfflineAccess},
	}

	verifier := oauth2.GenerateVerifier()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	authURL := cfg.AuthCodeURL("st", oauth2.S256ChallengeOption(verifier), gooidc.Nonce("no"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "st", loc.Query().Get("state"))

	code := loc.Query().Get("code")
	require.NotEmpty(t, code)

	_, err = cfg.Exchange(ctx, code, oauth2.VerifierOption("wrong-verifier-wrong-verifier-wrong-verifier"))
	require.Error(t, err, "a wrong verifier is rejected")

	// the failed attempt above consumed the code; start over
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	loc, err = url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	tok, err := cfg.Exchange(ctx, loc.Query().Get("code"), oauth2.VerifierOption(verifier))
	require.NoError(t, err)

	rawIDToken, ok := tok.Extra("id_token").(string)
	require.True(t, ok)

	idToken, err := provider.Verifier(&gooidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
	require.NoError(t, err)
	assert.Equal(t, "alice", idToken.Subject)
	assert.Equal(t, "no", idToken.Nonce)
	require.NotEmpty(t, tok.RefreshToken)

	refresh := func(rt string) (*oauth2.Token, error) {
		return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: rt}).Token()
	}

	idp.SetRefreshBehaviour(RefreshRotate)

	rotated, err := refresh(tok.RefreshToken)
	require.NoError(t, err)
	assert.NotEqual(t, tok.RefreshToken, rotated.RefreshToken)
	assert.NotEmpty(t, rotated.Extra("id_token"))

	idp.SetRefreshBehaviour(RefreshReject)

	_, err = refresh(rotated.RefreshToken)

	var rerr *oauth2.RetrieveError
	require.ErrorAs(t, err, &rerr)
	assert.Equal(t, "invalid_grant", rerr.ErrorCode)

	_, err = refresh("rt-unknown")
	require.ErrorAs(t, err, &rerr)

	assert.Equal(t, 3, idp.RefreshCalls())
}

func TestFakeIDP_AuthorizeError(t *testing.T) {
	t.Parallel()

	idp := New(t, "client", "secret")
	idp.SetAuthorizeError("access_denied")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	u := idp.URL + "/authorize?" + url.Values{
		"client_id":    {"client"},
		"redirect_uri": {"http://127.0.0.1:1/callback"},
		"state":        {"st"},
	}.Encode()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "access_denied", loc.Query().Get("error"))
	assert.Equal(t, "st", loc.Query().Get("state"))
	assert.Empty(t, loc.Query().Get("code"))
}
