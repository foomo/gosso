// Package oidc implements a stateless OIDC 1.0 Relying Party running the
// Authorization Code flow with PKCE. On a successful callback the
// verified principal is handed to the consumer via a gosso.OnAuthenticated
// callback; this package never writes session cookies itself. A short
// lived, signed transit cookie is used purely to carry state, nonce and
// the PKCE verifier between /login and /callback.
package oidc
