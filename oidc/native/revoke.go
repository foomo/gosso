package native

import (
	"errors"
	"net/http"
	"slices"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
	"github.com/foomo/gosso/oidc"
	"github.com/foomo/gosso/oidc/native/repository"
	"github.com/foomo/gosso/oidc/native/repository/store"
)

// handleRevoke ends the refresh session a refresh token belongs to (RFC
// 7009). The client must identify itself with client_id (§2.1). For a
// known client the answer is 200 whether or not anything was revoked: a
// malformed, unknown or foreign token reveals nothing.
func (b *Broker) handleRevoke(w http.ResponseWriter, r *http.Request, _ *oidc.RP) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.native.revoke",
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
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed request body")
		return
	}

	token := r.PostForm.Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "token is required")
		return
	}

	client, ok := b.clients[r.PostForm.Get("client_id")]
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidClient, "unknown client_id")
		return
	}

	defer writeJSON(w, http.StatusOK, struct{}{})

	id, secret, ok := cutToken(token)
	if !ok {
		return
	}

	s, err := b.sessions.Get(ctx, id)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			b.logError(r, "native-revoke-get-session", err)
		}

		return
	}

	if s.ClientID != client.ID || !b.matchesSession(s, hashToken(secret)) {
		return
	}

	if err := b.sessions.Delete(ctx, s.ID); err != nil {
		b.logError(r, "native-revoke-delete-session", err)
	}
}

// matchesSession reports whether h is one of the session's current refresh
// hashes, or a previous one within the rotation grace window.
func (b *Broker) matchesSession(s store.Session, h string) bool {
	return slices.Contains(s.RefreshHashes, h) || b.inGrace(s, h)
}

// inGrace reports whether h is a previous refresh hash and the grace
// window after the rotation that retired it is still open.
func (b *Broker) inGrace(s store.Session, h string) bool {
	return slices.Contains(s.PreviousRefreshHashes, h) && !b.now().After(s.RotatedAt.Add(b.rotationGrace))
}
