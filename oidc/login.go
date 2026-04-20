package oidc

import (
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/safepath"
	"github.com/foomo/gosso/internal/telemetry"
)

// handleLogin generates fresh state/nonce/PKCE values, persists them in
// a signed transit cookie and redirects the browser to the IdP's
// authorization endpoint. The optional `?target=` query parameter
// selects the post-login destination (safe relative paths only).
func (rp *RP) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.login",
		trace.WithAttributes(oidcProtocolAttr),
	)
	defer span.End()

	loginStarted.Add(ctx, 1)

	target := safepath.Target(r.URL.Query().Get("target"))

	state, err := generateState()
	if err != nil {
		rp.fail(ctx, r, nil, "generate-state", err)
		http.Error(w, "login init failed", http.StatusInternalServerError)

		return
	}

	nonce, err := generateNonce()
	if err != nil {
		rp.fail(ctx, r, nil, "generate-nonce", err)
		http.Error(w, "login init failed", http.StatusInternalServerError)

		return
	}

	verifier, err := generateVerifier()
	if err != nil {
		rp.fail(ctx, r, nil, "generate-verifier", err)
		http.Error(w, "login init failed", http.StatusInternalServerError)

		return
	}

	if err := rp.transit.write(w, transitData{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		Target:       target,
	}); err != nil {
		rp.fail(ctx, r, nil, "transit-write", err)
		http.Error(w, "login init failed", http.StatusInternalServerError)

		return
	}

	http.Redirect(w, r, rp.authorizeURL(state, nonce, codeChallenge(verifier)), http.StatusFound)
}
