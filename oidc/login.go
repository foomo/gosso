package oidc

import (
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
)

// handleLogin starts the flow through Login. The optional `?target=` query
// parameter selects the post-login destination (safe relative paths only).
func (rp *RP) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.login",
		trace.WithAttributes(oidcProtocolAttr),
	)
	defer span.End()

	loginStarted.Add(ctx, 1)

	rp.Login(w, r.WithContext(ctx), WithLoginTarget(r.URL.Query().Get("target")))
}
