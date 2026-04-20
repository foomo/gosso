package saml

import (
	"net/http"
)

// Handlers groups the HTTP handlers the consumer mounts on its
// router. The ACS handler also serves the metadata document on the
// IdP-configured metadata path. SLO handles the LogoutResponse the IdP
// posts back after an SP-initiated single-logout round-trip and
// redirects the browser to the configured post-logout URL (or `/`).
type Handlers struct {
	ACS    http.Handler
	Login  http.Handler
	Logout http.Handler
	SLO    http.Handler
}

// Handlers returns the SP's HTTP handlers.
func (sp *SP) Handlers() Handlers {
	return Handlers{
		ACS:    sp.middleware,
		Login:  http.HandlerFunc(sp.handleLogin),
		Logout: http.HandlerFunc(sp.handleLogout),
		SLO:    http.HandlerFunc(sp.handleSLO),
	}
}

// Middleware exposes the underlying crewjam middleware for advanced
// use-cases (e.g. mounting RequireAccount on a subtree). Most consumers
// should not need this.
func (sp *SP) Middleware() *anyMiddleware {
	return &anyMiddleware{sp.middleware}
}

type anyMiddleware struct {
	inner http.Handler
}

func (m *anyMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.inner.ServeHTTP(w, r)
}
