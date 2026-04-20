# Sandbox

The repo ships a runnable sandbox — one Go binary + one Keycloak
container — that lets you step through a real SAML and a real OIDC
round-trip without touching your own infrastructure.

## Run it

```sh
# 1. pre-provisioned Keycloak on :8081 (admin / admin)
make sandbox.up

# 2. demo app on :8080
make sandbox.run
```

Visit <http://localhost:8080> and pick one of the login buttons. Sign
in as:

| user  | password | groups  |
| ----- | -------- | ------- |
| alice | password | admins  |
| bob   | password | users   |

You'll be bounced back to the demo app with a session. The card shows
which protocol authenticated you, and `/whoami` dumps the raw
`Subject`.

## What's set up

### Keycloak realm

`examples/sandbox/realm-export.json` is imported on first boot. It
defines:

- Two users (alice, bob) with plaintext passwords seeded for
  convenience.
- Two groups: `admins` (alice) and `users` (bob).
- An OIDC client `gosso-oidc` with standard flow, PKCE, a `groups`
  claim mapper, and `offline_access` scope enabled.
- A SAML client whose entity ID is
  `http://localhost:8080/saml/metadata` and whose attribute mappers
  emit Azure-AD-style URIs. This means the library's default
  `AzureADAttributeMap` works unmodified against this realm.

### Demo app

`examples/sandbox/main.go` (~300 LOC). An in-memory session store
keyed by a signed random cookie. Two `OnAuthenticated` callbacks — one
per protocol — write into the same store; the root page renders the
stored subject. Note that it keeps only a normalised projection of
`Subject` (plus `RawIDToken` and `SessionIndex` for logout), because
the raw SAML assertion and OIDC ID token are not JSON-friendly.

### Certificates

A dev-only SP cert lives at `examples/sandbox/certs/sp.{crt,key}`.
**Do not use outside this sandbox.** Regenerate with `make
sandbox.certs`.

## Tear down

```sh
make sandbox.down    # stops Keycloak, removes volumes
```

## Things to try

- Log in via OIDC, hit `/oidc/logout` — watch Keycloak invalidate the
  session via `id_token_hint` and bounce you back to the landing page.
- Log in via SAML, then open a private tab to confirm the session is
  tied to the cookie, not to the IdP.
- Disable the `groups` protocol mapper on the SAML client
  (Keycloak admin UI on :8081) and see `Subject.Groups` become
  empty.
- Flip `oidc.WithUserInfo(true)` on and off in `main.go` and compare
  the `/whoami` output.
- Replace `AzureADAttributeMap` with one of your own URIs to
  reproduce a different IdP's shape.
