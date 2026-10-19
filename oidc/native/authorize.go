package native

import (
	"net/http"
	"net/url"

	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
	"github.com/foomo/gosso/oidc"
)

// maxStateLength bounds the app's state: it travels in the transit cookie,
// and a cookie over ~4 KB is dropped by the browser.
const maxStateLength = 512

// validState accepts 1–512 printable ASCII characters (RFC 6749 VSCHAR)
// except <, > and &, which JSON escapes to six bytes each and would push
// the transit cookie past the browser limit.
func validState(state string) bool {
	if state == "" || len(state) > maxStateLength {
		return false
	}

	for _, c := range []byte(state) {
		if c < 0x20 || c > 0x7e || c == '<' || c == '>' || c == '&' {
			return false
		}
	}

	return true
}

// handleAuthorize validates a native authorization request and starts the
// RP's login with the app's parameters in the login context. An unknown
// client or redirect URI is answered 400 without a redirect (RFC 6749
// §4.1.2.1); every later error redirects to the app.
func (b *Broker) handleAuthorize(w http.ResponseWriter, r *http.Request, rp *oidc.RP) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.native.authorize",
		trace.WithAttributes(oidcProtocolAttr),
	)
	defer span.End()

	r = r.WithContext(ctx)

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")

	_, known, allowed := b.client(q.Get("client_id"), redirectURI)
	if !known {
		http.Error(w, "invalid client", http.StatusBadRequest)
		return
	}

	if !allowed {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	state := q.Get("state")

	fail := func(code string) {
		params := url.Values{"error": {code}}
		if validState(state) {
			params.Set("state", state)
		}

		target, err := nativeRedirectURL(redirectURI, params)
		if err != nil {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}

		// redirectURI is one of the client's registered URIs (checked above)
		http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // exact match against the registered list
	}

	switch rt := q.Get("response_type"); {
	case rt != "" && rt != "code":
		fail(errUnsupportedResponseType)
		return
	case !validState(state),
		!validChallenge(q.Get("code_challenge")),
		q.Get("code_challenge_method") != "S256":
		fail(errInvalidRequest)
		return
	}

	rp.Login(w, r,
		oidc.WithLoginTarget("/"),
		oidc.WithLoginContext(nativeLogin{
			clientID:    q.Get("client_id"),
			redirectURI: redirectURI,
			state:       state,
			challenge:   q.Get("code_challenge"),
		}.loginContext()),
	)
}
