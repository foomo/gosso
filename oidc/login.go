package oidc

import (
	"net/http"
)

// handleLogin starts the flow through Login. The optional `?target=` query
// parameter selects the post-login destination (safe relative paths only).
func (rp *RP) handleLogin(w http.ResponseWriter, r *http.Request) {
	rp.Login(w, r, WithLoginTarget(r.URL.Query().Get("target")))
}
