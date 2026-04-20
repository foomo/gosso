package oidc

import "net/http"

// Handlers groups the three HTTP handlers the consumer mounts on its
// router: Login initiates the flow, Callback completes the code
// exchange, Logout fires OnLogout and (optionally) redirects to the
// IdP's end-session endpoint.
type Handlers struct {
	Login    http.Handler
	Callback http.Handler
	Logout   http.Handler
}

// Handlers returns the RP's HTTP handlers.
func (rp *RP) Handlers() Handlers {
	return Handlers{
		Login:    http.HandlerFunc(rp.handleLogin),
		Callback: http.HandlerFunc(rp.handleCallback),
		Logout:   http.HandlerFunc(rp.handleLogout),
	}
}
