// Package fakeidp is an in-process OIDC identity provider for tests. It
// serves discovery, JWKS, authorize (auto-approving), token (authorization
// code with PKCE S256 and refresh) and UserInfo from an httptest server,
// and lets a test steer the refresh grant's behaviour.
package fakeidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// RefreshBehaviour selects how the token endpoint answers a refresh grant.
type RefreshBehaviour int

const (
	// RefreshRotate issues a new refresh token "rt-<n>" (the old one stops
	// working) and a new ID token.
	RefreshRotate RefreshBehaviour = iota
	// RefreshKeep omits refresh_token from the response; the client keeps
	// the old one.
	RefreshKeep
	// RefreshNoIDToken returns an access and a refresh token, no ID token.
	RefreshNoIDToken
	// RefreshOtherSubject returns an ID token for sub "someone-else".
	RefreshOtherSubject
	// RefreshReject answers 400 {"error":"invalid_grant"}.
	RefreshReject
	// RefreshServerError answers 500.
	RefreshServerError
)

// OtherSubject is the sub RefreshOtherSubject issues tokens for.
const OtherSubject = "someone-else"

const keyID = "fakeidp-1"

type pendingCode struct {
	clientID    string
	redirectURI string
	nonce       string
	challenge   string
}

// IdP is a running fake identity provider. URL is its issuer.
type IdP struct {
	URL string

	clientID     string
	clientSecret string
	signer       jose.Signer
	jwks         jose.JSONWebKeySet

	mu             sync.Mutex
	counter        int
	sub            string
	claims         map[string]any
	issueRefresh   bool
	authorizeError string
	userInfoError  bool
	behaviour      RefreshBehaviour
	refreshCalls   int
	refreshDelay   time.Duration
	codes          map[string]pendingCode
	refreshTokens  map[string]bool
	accessTokens   map[string]string // access token → sub
}

// New starts a fake IdP for the given confidential client. The server is
// closed when the test ends.
func New(t *testing.T, clientID, clientSecret string) *IdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("fakeidp: generate key: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
	)
	if err != nil {
		t.Fatalf("fakeidp: signer: %v", err)
	}

	i := &IdP{
		clientID:     clientID,
		clientSecret: clientSecret,
		signer:       signer,
		jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig",
		}}},
		sub:           "alice",
		claims:        defaultClaims(),
		issueRefresh:  true,
		codes:         map[string]pendingCode{},
		refreshTokens: map[string]bool{},
		accessTokens:  map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", i.handleDiscovery)
	mux.HandleFunc("/jwks", i.handleJWKS)
	mux.HandleFunc("/authorize", i.handleAuthorize)
	mux.HandleFunc("/token", i.handleToken)
	mux.HandleFunc("/userinfo", i.handleUserInfo)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	i.URL = srv.URL

	return i
}

func defaultClaims() map[string]any {
	return map[string]any{
		"email":       "alice@example.com",
		"given_name":  "Alice",
		"family_name": "Example",
	}
}

// SetUser replaces the logged-in user. claims are added to every ID
// token and UserInfo response.
func (i *IdP) SetUser(sub string, claims map[string]any) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.sub = sub
	i.claims = maps.Clone(claims)
}

// SetIssueRefreshToken controls whether the authorization-code grant
// returns a refresh token. Default true.
func (i *IdP) SetIssueRefreshToken(on bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.issueRefresh = on
}

// SetAuthorizeError makes /authorize redirect back with ?error=code
// instead of a code. "" restores auto-approval.
func (i *IdP) SetAuthorizeError(code string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.authorizeError = code
}

// SetUserInfoError makes /userinfo answer 500 while on.
func (i *IdP) SetUserInfoError(on bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.userInfoError = on
}

// SetRefreshBehaviour selects how the next refresh grants are answered.
func (i *IdP) SetRefreshBehaviour(b RefreshBehaviour) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.behaviour = b
}

// SetRefreshDelay delays every refresh grant response by d.
func (i *IdP) SetRefreshDelay(d time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.refreshDelay = d
}

// RefreshCalls returns the number of refresh grants received.
func (i *IdP) RefreshCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.refreshCalls
}

func (i *IdP) next(prefix string) string {
	i.counter++
	return fmt.Sprintf("%s-%d", prefix, i.counter)
}

func (i *IdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                i.URL,
		"authorization_endpoint":                i.URL + "/authorize",
		"token_endpoint":                        i.URL + "/token",
		"jwks_uri":                              i.URL + "/jwks",
		"userinfo_endpoint":                     i.URL + "/userinfo",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{string(jose.RS256)},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (i *IdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, i.jwks)
}

func (i *IdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != i.clientID {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}

	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Scheme == "" {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}

	i.mu.Lock()

	params := redirect.Query()
	params.Set("state", q.Get("state"))

	if i.authorizeError != "" {
		params.Set("error", i.authorizeError)
	} else {
		code := i.next("code")
		i.codes[code] = pendingCode{
			clientID:    q.Get("client_id"),
			redirectURI: q.Get("redirect_uri"),
			nonce:       q.Get("nonce"),
			challenge:   q.Get("code_challenge"),
		}
		params.Set("code", code)
	}
	i.mu.Unlock()

	redirect.RawQuery = params.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound) //nolint:gosec // test IdP: redirects wherever the test asks
}

func (i *IdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}

	if id != i.clientID || subtle.ConstantTimeCompare([]byte(secret), []byte(i.clientSecret)) != 1 {
		tokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		i.authCodeGrant(w, r)
	case "refresh_token":
		i.refreshGrant(w, r)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (i *IdP) authCodeGrant(w http.ResponseWriter, r *http.Request) {
	i.mu.Lock()
	defer i.mu.Unlock()

	code := r.PostForm.Get("code")

	pc, ok := i.codes[code]
	delete(i.codes, code)

	if !ok || pc.redirectURI != r.PostForm.Get("redirect_uri") {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	resp, err := i.tokenResponse(i.sub, pc.nonce, i.issueRefresh, true)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (i *IdP) refreshGrant(w http.ResponseWriter, r *http.Request) {
	i.mu.Lock()
	i.refreshCalls++
	delay := i.refreshDelay
	i.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	rt := r.PostForm.Get("refresh_token")

	switch i.behaviour {
	case RefreshReject:
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	case RefreshServerError:
		tokenError(w, http.StatusInternalServerError, "server_error")
		return
	default:
	}

	if !i.refreshTokens[rt] {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	sub := i.sub
	if i.behaviour == RefreshOtherSubject {
		sub = OtherSubject
	}

	rotate := i.behaviour != RefreshKeep
	if rotate {
		delete(i.refreshTokens, rt)
	}

	resp, err := i.tokenResponse(sub, "", rotate, i.behaviour != RefreshNoIDToken)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// tokenResponse builds a token response; the caller holds i.mu.
func (i *IdP) tokenResponse(sub, nonce string, withRefresh, withIDToken bool) (map[string]any, error) {
	at := i.next("at")
	i.accessTokens[at] = sub

	resp := map[string]any{
		"access_token": at,
		"token_type":   "Bearer",
		"expires_in":   300,
	}

	if withRefresh {
		rt := i.next("rt")
		i.refreshTokens[rt] = true
		resp["refresh_token"] = rt
	}

	if withIDToken {
		idToken, err := i.idToken(sub, nonce)
		if err != nil {
			return nil, err
		}

		resp["id_token"] = idToken
	}

	return resp, nil
}

func (i *IdP) idToken(sub, nonce string) (string, error) {
	now := time.Now()

	claims := maps.Clone(i.claims)
	if claims == nil {
		claims = map[string]any{}
	}

	claims["iss"] = i.URL
	claims["aud"] = i.clientID
	claims["sub"] = sub
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(5 * time.Minute).Unix()

	if nonce != "" {
		claims["nonce"] = nonce
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	sig, err := i.signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return sig.CompactSerialize()
}

func (i *IdP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	at, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")

	i.mu.Lock()
	defer i.mu.Unlock()

	if i.userInfoError {
		http.Error(w, "userinfo unavailable", http.StatusInternalServerError)
		return
	}

	sub, known := i.accessTokens[at]
	if !ok || !known {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	claims := maps.Clone(i.claims)
	if claims == nil {
		claims = map[string]any{}
	}

	claims["sub"] = sub

	writeJSON(w, http.StatusOK, claims)
}

func tokenError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
