package oidc

import (
	"net/http"
	"net/url"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
)

// handleLogout redirects to the IdP's end-session endpoint when a
// LogoutHintProvider supplies an id_token_hint, and fires OnLogout so
// the consumer can destroy its session. The hint provider runs
// *before* OnLogout — consumers typically read the raw ID token from
// the same session they are about to clear, and reversing the order
// would leave the hint empty and silently downgrade logout to
// local-only (defeating Keycloak / other IdP's SSO cookie).
func (rp *RP) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.logout",
		trace.WithAttributes(oidcProtocolAttr),
	)
	defer span.End()

	r = r.WithContext(ctx)

	logoutStarted.Add(ctx, 1)

	var hint string
	if rp.logoutHintProvider != nil {
		hint = rp.logoutHintProvider(r)
	}

	if err := rp.onLogout(ctx, w, r); err != nil {
		rp.fail(ctx, r, nil, "on-logout", err)
		http.Error(w, "logout failed", http.StatusInternalServerError)

		return
	}

	if rp.endSession == "" || hint == "" {
		if rp.postLogoutRedirectURL != "" {
			http.Redirect(w, r, rp.postLogoutRedirectURL, http.StatusFound)
			return
		}

		w.WriteHeader(http.StatusOK)

		return
	}

	endpoint, err := url.Parse(rp.endSession)
	if err != nil {
		rp.fail(ctx, r, nil, "parse-end-session", err)
		http.Error(w, "end session parse failed", http.StatusInternalServerError)

		return
	}

	q := endpoint.Query()
	q.Set("id_token_hint", hint)

	if rp.postLogoutRedirectURL != "" {
		q.Set("post_logout_redirect_uri", rp.postLogoutRedirectURL)
	}

	endpoint.RawQuery = q.Encode()
	http.Redirect(w, r, endpoint.String(), http.StatusFound)
}
