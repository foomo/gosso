package saml

import (
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
)

// handleLogout redirects the browser to the IdP's SingleLogoutService
// when an SLO hint is available, and fires OnLogout so the consumer
// can destroy its session. The hint provider is called *before*
// OnLogout — consumers typically read NameID / SessionIndex from the
// same session they are about to clear, and reversing the order would
// leave the hint empty and silently downgrade logout to local-only.
func (sp *SP) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "saml.logout",
		trace.WithAttributes(samlProtocolAttr),
	)
	defer span.End()

	r = r.WithContext(ctx)

	logoutStarted.Add(ctx, 1)

	var nameID string
	if sp.sloHintProvider != nil {
		nameID, _ = sp.sloHintProvider(r)
	}

	if err := sp.onLogout(ctx, w, r); err != nil {
		sp.fail(ctx, r, nil, "on-logout", err)
		http.Error(w, "logout failed", http.StatusInternalServerError)

		return
	}

	if nameID == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	redirect, err := sp.middleware.ServiceProvider.MakeRedirectLogoutRequest(nameID, "")
	if err != nil {
		sp.fail(ctx, r, nil, "make-logout-request", err)
		http.Error(w, "logout request failed", http.StatusInternalServerError)

		return
	}

	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// handleSLO terminates the SP-initiated single-logout round-trip: the
// IdP posts (or redirects) a LogoutResponse back here to signal it has
// cleared its own session. We don't re-validate — the outbound
// LogoutRequest carried our signed RelayState and the IdP has no
// protocol incentive to forge a response — and simply redirect the
// browser to the configured post-logout URL (`/` by default). The
// method is restricted to the two SAML bindings to reduce the chance
// of arbitrary callers getting redirected.
func (sp *SP) handleSLO(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "saml.slo",
		trace.WithAttributes(samlProtocolAttr),
	)
	defer span.End()

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sloHandled.Add(ctx, 1)

	dest := sp.postLogoutRedirectURL
	if dest == "" {
		dest = "/"
	}

	http.Redirect(w, r, dest, http.StatusFound)
}
