package native

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
	"github.com/foomo/gosso/oidc"
	"github.com/foomo/gosso/oidc/native/repository"
	"github.com/foomo/gosso/oidc/native/repository/store"
)

// maxFormBytes bounds token and revoke request bodies.
const maxFormBytes = 16 << 10

const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
)

// tokenResponse is the RFC 6749 §5.1 success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// issue mints the consumer's tokens for s and formats the response; secret
// is the session's current refresh secret.
func (b *Broker) issue(ctx context.Context, s store.Session, secret string) (tokenResponse, error) {
	tokens, err := b.hooks.Mint(ctx, s)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("mint: %w", err)
	}

	return tokenResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(tokens.ExpiresIn / time.Second),
		RefreshToken: s.ID + "." + secret,
	}, nil
}

// parseForm reads a bounded url-encoded POST body.
func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	return r.ParseForm()
}

// cutToken splits a refresh token "<sessionID>.<secret>".
func cutToken(token string) (string, string, bool) {
	id, secret, ok := strings.Cut(token, ".")
	if !ok || id == "" || secret == "" || strings.Contains(secret, ".") {
		return "", "", false
	}

	return id, secret, true
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request, rp *oidc.RP) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.native.token",
		trace.WithAttributes(oidcProtocolAttr),
	)
	defer span.End()

	r = r.WithContext(ctx)

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if err := parseForm(w, r); err != nil {
		b.tokenFailed(ctx, r, "", "parse-form", nil)
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed request body")

		return
	}

	grantType := r.PostForm.Get("grant_type")
	if grantType != grantAuthorizationCode && grantType != grantRefreshToken {
		b.tokenFailed(ctx, r, "", "grant-type", nil)
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType, "grant_type must be authorization_code or refresh_token")

		return
	}

	client, ok := b.clients[r.PostForm.Get("client_id")]
	if !ok {
		b.tokenFailed(ctx, r, grantType, "client", nil)
		writeError(w, http.StatusBadRequest, errInvalidClient, "unknown client_id")

		return
	}

	if grantType == grantAuthorizationCode {
		b.authorizationCodeGrant(w, r, client)
		return
	}

	b.refreshTokenGrant(w, r, rp, client)
}

func (b *Broker) authorizationCodeGrant(w http.ResponseWriter, r *http.Request, client Client) {
	ctx := r.Context()

	fail := func(status int, code, stage, description string, err error) {
		b.tokenFailed(ctx, r, grantAuthorizationCode, stage, err)
		writeError(w, status, code, description)
	}

	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")

	if code == "" || redirectURI == "" || verifier == "" {
		fail(http.StatusBadRequest, errInvalidRequest, "missing-parameter", "code, redirect_uri and code_verifier are required", nil)
		return
	}

	if !validVerifier(verifier) {
		fail(http.StatusBadRequest, errInvalidRequest, "invalid-verifier", "malformed code_verifier", nil)
		return
	}

	// From here on the code is consumed, whatever the outcome.
	c, err := b.codes.Take(ctx, hashToken(code))
	if errors.Is(err, repository.ErrNotFound) {
		fail(http.StatusBadRequest, errInvalidGrant, "code-unknown", "code invalid", nil)
		return
	} else if err != nil {
		fail(http.StatusInternalServerError, errServerError, "store-take-code", "", err)
		return
	}

	now := b.now()

	switch {
	case now.After(c.ExpiresAt):
		fail(http.StatusBadRequest, errInvalidGrant, "code-expired", "code expired", nil)
		return
	case c.ClientID != client.ID:
		fail(http.StatusBadRequest, errInvalidGrant, "client-mismatch", "code was issued to another client", nil)
		return
	case c.RedirectURI != redirectURI:
		fail(http.StatusBadRequest, errInvalidGrant, "redirect-mismatch", "redirect_uri mismatch", nil)
		return
	case !verifyS256(verifier, c.CodeChallenge):
		fail(http.StatusBadRequest, errInvalidGrant, "verifier-mismatch", "code_verifier mismatch", nil)
		return
	}

	id, err := randomToken(16)
	if err != nil {
		fail(http.StatusInternalServerError, errServerError, "random", "", err)
		return
	}

	secret, err := randomToken(32)
	if err != nil {
		fail(http.StatusInternalServerError, errServerError, "random", "", err)
		return
	}

	s := store.Session{
		ID:              id,
		ClientID:        client.ID,
		RefreshHashes:   []string{hashToken(secret)},
		Subject:         c.Subject,
		Attributes:      c.Attributes,
		IDPRefreshToken: c.IDPRefreshToken,
		CreatedAt:       now,
		LastUsedAt:      now,
		ExpiresAt:       now.Add(b.sessionTTL),
	}

	if err := b.sessions.Create(ctx, s); err != nil {
		fail(http.StatusInternalServerError, errServerError, "store-create-session", "", err)
		return
	}

	resp, err := b.issue(ctx, s, secret)
	if err != nil {
		if derr := b.sessions.Delete(ctx, s.ID); derr != nil {
			b.logError(r, "native-token-store-delete-session", derr)
		}

		fail(http.StatusInternalServerError, errServerError, "mint", "", err)

		return
	}

	tokenSucceeded(ctx, grantAuthorizationCode)
	writeJSON(w, http.StatusOK, resp)
}
