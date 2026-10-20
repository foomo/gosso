// Package native is an opt-in broker that lets native (mobile, desktop,
// CLI) public clients log in through an oidc.RP using OAuth 2.0 for native
// apps: RFC 6749 authorization code + RFC 7636 PKCE (S256 only), RFC 8252
// redirect URIs and RFC 7009 revocation.
//
// The app never talks to the IdP. It opens the broker's authorize endpoint
// in a browser tab; the broker runs the RP's normal login and, on the
// callback, redirects back to the app with a one-time code. The app
// redeems that code (with its PKCE verifier) at the token endpoint for an
// access token minted by the consumer and a rotating refresh token. Each
// refresh redeems the IdP refresh token kept on the session, so the IdP
// still decides whether the session lives on.
//
// Unlike the rest of gosso this package is stateful: codes and refresh
// sessions are persisted through the repository.Code and repository.Session
// interfaces, implemented on MongoDB (keel's persistor) by the repository
// package. Refresh secrets and codes are stored hashed; the IdP refresh
// token is stored encrypted with AES-256-GCM.
//
// Wiring order: the RP needs the broker's wrapped hooks, and the broker
// needs the RP, so build the broker first and attach the RP last:
//
//	b, err := native.New(codes, sessions, hooks, clients, key)
//	rp, err := oidc.New(ctx, issuer, id, secret, callbackURL, transitKey,
//		b.OnAuthenticated(webOnAuth),
//		oidc.WithExtraScopes("offline_access"),
//		oidc.WithOnRedirect(b.OnRedirect(webOnRedirect)),
//		oidc.WithOnLoginError(b.OnLoginError(nil)))
//	err = b.Attach(rp)
//
// Then mount Handlers().Authorize, Token and Revoke next to the RP's own.
package native
