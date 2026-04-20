# Getting started

`gosso` gives you two protocol adapters — SAML 2.0 and OIDC 1.0 — that
share a common `Subject[T]` contract. The library never stores a user
session; after a successful round-trip it calls your `OnAuthenticated`
callback and you decide what happens next.

## Install

```sh
go get github.com/foomo/gosso
```

The adapter you need lives under `saml` or `oidc`:

```go
import (
    sso "github.com/foomo/gosso"
    "github.com/foomo/gosso/saml"
    "github.com/foomo/gosso/oidc"
)
```

## Hello, `Subject`

The smallest possible OIDC consumer:

```go
rp, err := oidc.New(
    oidc.WithIssuerURL("https://login.example.com/realms/my-realm"),
    oidc.WithClientID("my-client"),
    oidc.WithClientSecret(os.Getenv("CLIENT_SECRET")),
    oidc.WithRedirectURL("https://my.app/oidc/callback"),
    oidc.WithTransitSigningKey([]byte(os.Getenv("TRANSIT_KEY"))),
    oidc.WithOnAuthenticated(func(ctx context.Context, w http.ResponseWriter, r *http.Request, s sso.Subject[oidc.Payload]) error {
        // YOU own the session — set a cookie, write a JWT, persist a row, whatever.
        log.Printf("logged in: %s (%s)", s.Email, s.ExternalID)
        return nil
    }),
)
if err != nil { log.Fatal(err) }

h := rp.Handlers()
http.Handle("/oidc/login", h.Login)
http.Handle("/oidc/callback", h.Callback)
http.Handle("/oidc/logout", h.Logout)
```

SAML follows the exact same shape — see [SAML](./saml) and
[OIDC](./oidc) for the per-protocol details.

## Where to go next

- [Architecture](./architecture) — the stateless-framework principle, `Subject[T]`, and the boundary between library and consumer.
- [Sandbox](./sandbox) — run a local Keycloak and log in through both protocols without touching your own infra.
- [Configuration reference](../reference/configuration) — every `With*` option in one place.
