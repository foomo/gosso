package saml

import (
	"net/http"
	"net/url"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/safepath"
	"github.com/foomo/gosso/internal/telemetry"
)

// handleLogin kicks off the SAML AuthnRequest round-trip. The optional
// `?target=` query parameter selects the post-login redirect; only
// safe relative paths are honoured (see internal/safepath).
func (sp *SP) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "saml.login",
		trace.WithAttributes(samlProtocolAttr),
	)
	defer span.End()

	loginStarted.Add(ctx, 1)

	target := safepath.Target(r.URL.Query().Get("target"))
	// Rewrite the request URL so the RequestTracker stores the target.
	// The samlsp middleware remembers this URL in its signed relay-state
	// cookie and redirects to it after the ACS flow completes. The target
	// carries its query, so it is split rather than written into Path.
	parsed, err := url.Parse(target)
	if err != nil {
		parsed = &url.URL{Path: "/"}
	}

	rewrite := *r.URL
	rewrite.Path = parsed.Path
	rewrite.RawPath = parsed.RawPath
	rewrite.RawQuery = parsed.RawQuery
	r2 := r.Clone(ctx)
	r2.URL = &rewrite
	sp.startAuthFlow(w, r2)
}
