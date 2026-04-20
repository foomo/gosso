[![Build Status](https://github.com/foomo/gosso/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/foomo/gosso/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/foomo/gosso)](https://goreportcard.com/report/github.com/foomo/gosso)
[![GoDoc](https://godoc.org/github.com/foomo/gosso?status.svg)](https://godoc.org/github.com/foomo/gosso)
[![Docs](https://img.shields.io/badge/docs-foomo.github.io%2Fgosso-blue)](https://foomo.github.io/gosso/)

# gosso

> Stateless SAML + OIDC adapters for Go. You own the session.

```go
import (
    sso "github.com/foomo/gosso"
    "github.com/foomo/gosso/oidc"
)

rp, err := oidc.New(
    "https://login.example.com/realms/my-realm",
    "my-client",
    os.Getenv("CLIENT_SECRET"),
    "https://app.example.com/oidc/callback",
    []byte(os.Getenv("TRANSIT_KEY")),
    func(ctx context.Context, w http.ResponseWriter, r *http.Request, s sso.Subject[oidc.Payload]) error {
        // You own the session. Do whatever you want with s here.
        return writeCookie(w, s)
    },
)
if err != nil { log.Fatal(err) }

h := rp.Handlers()
http.Handle("/oidc/login", h.Login)
http.Handle("/oidc/callback", h.Callback)
http.Handle("/oidc/logout", h.Logout)
```

SAML has the exact same shape. Both protocols produce an
`sso.Subject[T]` so your session-construction code can be shared.

## Full docs

<https://foomo.github.io/gosso/>

## Sandbox

```sh
make sandbox.up   # Keycloak on :8081 with realm preloaded
make sandbox.run  # demo app on :8080, both protocols mounted

# log in as alice / password (admins) or bob / password (users)
```

See [examples/sandbox/README.md](examples/sandbox/README.md).

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE).

_Made with ♥ [foomo](https://www.foomo.org) by [bestbytes](https://www.bestbytes.com)_
