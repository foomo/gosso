package saml

import (
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
)

// handleLogout redirects the browser to the IdP's SingleLogoutService
// when an SLO hint is available, and fires OnLogout so the consumer
// can destroy its session. The LogoutRequest carries the hint's
// SessionIndex when it has one (see SLOHintProvider for what an empty
// one asks of the IdP). The hint provider is called *before*
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

	var nameID, sessionIndex string
	if sp.sloHintProvider != nil {
		nameID, sessionIndex = sp.sloHintProvider(r)
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

	redirect, err := makeRedirectLogoutRequest(&sp.middleware.ServiceProvider, nameID, sessionIndex)
	if err != nil {
		sp.fail(ctx, r, nil, "make-logout-request", err)
		http.Error(w, "logout request failed", http.StatusInternalServerError)

		return
	}

	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// makeRedirectLogoutRequest builds the redirect-binding LogoutRequest
// URL, with a SessionIndex element when sessionIndex is non-empty.
//
// crewjam/saml's MakeRedirectLogoutRequest cannot carry a SessionIndex
// (its second parameter is the RelayState), so the request is built
// from MakeLogoutRequest instead. That signs the request as it builds
// it when signing is configured, so adding the SessionIndex afterwards
// means signing again, or the signature would not cover it.
func makeRedirectLogoutRequest(sp *saml.ServiceProvider, nameID, sessionIndex string) (*url.URL, error) {
	req, err := sp.MakeLogoutRequest(sp.GetSLOBindingLocation(saml.HTTPRedirectBinding), nameID)
	if err != nil {
		return nil, err
	}

	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}

		if sp.SignatureMethod != "" {
			req.Signature = nil
			if err := sp.SignLogoutRequest(req); err != nil {
				return nil, err
			}
		}
	}

	return req.Redirect(""), nil
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
