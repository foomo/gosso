# oidc/native

An opt-in broker that lets native public clients (mobile, desktop, CLI) log
in through a gosso `oidc.RP`, following OAuth 2.0 for native apps:

- RFC 6749 authorization code flow with RFC 7636 PKCE (S256 only)
- RFC 8252 redirect URIs (custom schemes, claimed HTTPS, loopback)
- RFC 7009 token revocation

The app never talks to the IdP. It opens the broker's authorize endpoint in
a browser tab, the broker runs the RP's normal login, and on the callback
redirects back to the app with a one-time code. The app redeems the code
with its PKCE verifier for an access token minted by your code and a
rotating refresh token. Every refresh also redeems the IdP refresh token
kept on the session, so the IdP still decides whether the session lives on.

## Stateful, unlike the rest of gosso

The broker owns one-time codes and refresh sessions. Everything about
persisting them lives in [`repository`](./repository):

| Path | Contents |
|---|---|
| `repository/interfaces.go` | `repository.Code` and `repository.Session`, the interfaces the broker uses |
| `repository/code.go`, `session.go` | `BaseCode` and `BaseSession`: MongoDB implementations on keel's persistor |
| `repository/store` | the entities: `Code`, `Session`, `Subject`, `Attributes`, `EncryptedToken` |

Refresh secrets and codes are stored hashed; the IdP refresh token is
stored encrypted with AES-256-GCM. Tests run against MongoDB in a
testcontainer, so they need Docker.

## Endpoints

| Handler | Method | Purpose |
|---|---|---|
| `Handlers().Authorize` | GET | starts a native login, redirects to the IdP |
| `Handlers().Token` | POST | `authorization_code` and `refresh_token` grants |
| `Handlers().Revoke` | POST | ends a refresh session (RFC 7009) |

## Wiring

The RP needs the broker's wrapped hooks and the broker needs the RP, so
build the broker first and attach the RP last:

```go
codes, err := repository.NewDefaultCode(persistor)
sessions, err := repository.NewDefaultSession(persistor)

b, err := native.New(codes, sessions, native.Hooks{
	Authenticate: authenticate, // map the subject to your user, return attributes
	Mint:         mint,         // mint the access token the app receives
}, []native.Client{
	{ID: "app-ios", RedirectURIs: []string{"com.example.app:/oauth2redirect"}},
}, encryptionKey) // exactly 32 bytes

rp, err := oidc.New(ctx, issuer, clientID, clientSecret, callbackURL, transitKey,
	b.OnAuthenticated(webOnAuth),
	oidc.WithExtraScopes("offline_access"),
	oidc.WithOnRedirect(b.OnRedirect(webOnRedirect)),
	oidc.WithOnLoginError(b.OnLoginError(nil)),
)

err = b.Attach(rp)

h := b.Handlers()
mux.Handle("/oidc/app/authorize", h.Authorize)
mux.Handle("/oidc/app/token", h.Token)
mux.Handle("/oidc/app/revoke", h.Revoke)
```

`Attach` fails unless all three wrappers were taken from the broker. It
cannot see whether they reached `oidc.New`, so make sure they do.

A login that outlives the RP's transit cookie (the user takes longer at
the IdP than its lifetime) ends with a plain `400` at the callback, never
with a redirect to the app: without the cookie there is no trusted
redirect URI. Raise `oidc.WithTransitTTL` (default 5 min) if your users
need longer, and let apps time out their own wait.

## Further reading

- [Native apps guide](https://foomo.github.io/gosso/guide/native): flow,
  options, error responses, security notes, known limitations
- [`examples/sandbox`](../../examples/sandbox) and
  [`examples/nativeapp`](../../examples/nativeapp): a runnable broker against
  Keycloak and a loopback CLI client
