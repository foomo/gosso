// Package oidc implements a stateless OIDC 1.0 Relying Party running the
// Authorization Code flow with PKCE. On a successful callback the
// verified principal is handed to the consumer via a gosso.OnAuthenticated
// callback; this package never writes session cookies itself. A short
// lived, signed transit cookie is used purely to carry state, nonce and
// the PKCE verifier between /login and /callback.
//
// The post-login redirect defaults to the ?target= carried through the
// transit cookie. WithOnRedirect lets the consumer compute the final
// destination — it sees the resolved target (which OnAuthenticated does
// not) and owns the ResponseWriter, so it can branch on where login was
// initiated and set additional cookies before the redirect.
package oidc
