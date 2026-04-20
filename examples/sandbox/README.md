# gosso sandbox

A minimal demo that mounts both the SAML and OIDC adapters against a
local Keycloak, so you can step through a real authentication round-trip
without standing up anything yourself.

## Run it

```sh
# 1. start Keycloak (port 8081, admin / admin)
make sandbox.up

# 2. start the demo app (port 8080)
make sandbox.run
```

Open <http://localhost:8080> and click *login via SAML* or *login via
OIDC*. Log in as one of the seeded users:

| user  | password | groups  |
| ----- | -------- | ------- |
| alice | password | admins  |
| bob   | password | users   |

## Endpoints

- `/`                 landing page, login buttons / session card
- `/whoami`           JSON dump of the current session
- `/protected`        401 unless logged in
- `/saml/login`       kicks off the SAML round-trip
- `/saml/acs`         SAML assertion consumer (Keycloak posts here)
- `/saml/metadata`    SP metadata document
- `/saml/logout`      fires OnLogout + SLO redirect
- `/oidc/login`       kicks off the OIDC auth-code flow (PKCE)
- `/oidc/callback`    OIDC callback
- `/oidc/logout`      fires OnLogout + RP-initiated end-session redirect

## Tear down

```sh
make sandbox.down
```

## Files

| File                     | Purpose                                                                  |
| ------------------------ | ------------------------------------------------------------------------ |
| `docker-compose.yaml`    | Keycloak container, imports the realm JSON on first boot.                |
| `realm-export.json`      | Pre-provisioned realm (users, groups, SAML + OIDC clients).              |
| `certs/sp.{crt,key}`     | Dev-only SP cert. Do **not** use outside this sandbox. Regenerate with `make sandbox.certs`. |
| `main.go`                | The demo app. ~300 LOC of in-memory session + both protocols mounted.    |

## How to break it (educational)

- Edit `realm-export.json`, e.g. disable the `groups` protocol mapper
  on the SAML client, and watch `sub.Groups` become empty on the
  `/whoami` endpoint.
- Swap `oidc.WithUserInfo(true)` in `main.go` on/off and see the effect
  on which claims populate `Subject`.
- Change the SAML attribute URIs in `saml.WithAttributeMap(...)` to
  something Keycloak isn't emitting, and watch `Subject` fields go
  blank.
