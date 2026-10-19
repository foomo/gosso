package native

import (
	"errors"
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
	"github.com/foomo/gosso/oidc"
)

// handleRevoke ends the refresh session a refresh token belongs to (RFC
// 7009). The answer is 200 whether or not anything was revoked: a
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

	defer writeJSON(w, http.StatusOK, struct{}{})

	id, secret, ok := cutToken(token)
	if !ok {
		return
	}

	s, err := b.store.GetSession(ctx, id)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			b.logError(r, "native-revoke-get-session", err)
		}

		return
	}

	if s.ClientID != r.PostForm.Get("client_id") || !b.matchesSession(s, hashToken(secret)) {
		return
	}

	if err := b.store.DeleteSession(ctx, s.ID); err != nil {
		b.logError(r, "native-revoke-delete-session", err)
	}
}

// matchesSession reports whether h is the session's current refresh hash,
// or its previous one within the rotation grace window.
func (b *Broker) matchesSession(s Session, h string) bool {
	return h == s.RefreshHash || b.inGrace(s, h)
}

func (b *Broker) inGrace(s Session, h string) bool {
	return s.PreviousRefreshHash != "" && h == s.PreviousRefreshHash && !b.now().After(s.RotatedAt.Add(b.rotationGrace))
}
