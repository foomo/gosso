# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`gosso` — Go Single Sign-On. A **stateless** SAML 2.0 and OIDC 1.0 adapter library. The library owns the protocol round-trip and hands the caller an `sso.Subject[T]`; the consumer owns the session, persistence, RBAC, and audit logging.

Consumed as `github.com/foomo/gosso` — the **root package is named `sso`** (the `go` prefix is repo-naming convention only; don't offer it as a package-name option). Subpackages `saml/` and `oidc/` are the two protocol adapters.

## Layout

```
github.com/foomo/gosso          # root package `sso`: Subject[T], callbacks, GroupMapper[R]
  doc.go                        # package doc
  subject.go
  callback.go                   # OnAuthenticated[T], OnLogout
  groupmapper.go + _test.go     # GroupMapper[R comparable]

github.com/foomo/gosso/saml     # SAML SP on crewjam/saml
  saml.go                       # SP + New(...Option)
  options.go                    # With* (foomo/go/options based)
  payload.go, attributemap.go, extract.go, extract_test.go
  session_provider.go           # stateless adapter returning ErrNoSession
  handlers.go, login.go + _test.go, logout.go

github.com/foomo/gosso/oidc     # OIDC RP: auth-code + PKCE, coreos/go-oidc/v3 + x/oauth2
  oidc.go, options.go, payload.go, claimmap.go
  transit.go + _test.go         # HMAC-signed transit cookie (state/nonce/PKCE verifier)
  pkce.go + _test.go            # RFC 7636 helpers
  extract.go + _test.go, token.go
  handlers.go, login.go, callback.go, logout.go

examples/                       # separate module (replace ../)
  sandbox/                      # runnable Keycloak + demo app
    docker-compose.yaml, realm-export.json, main.go, certs/sp.{crt,key}
```

## Load-bearing design principles

Violating these requires explicit discussion — they're why the library exists:

1. **Stateless framework.** No session storage. The SAML `sessionProvider` returns `ErrNoSession` from `GetSession` on purpose — "is the user logged in?" is answered entirely by consumer code.
2. **Consumer owns the session.** `OnAuthenticated[T]` hands over a `Subject[T]` plus the ResponseWriter; the consumer writes whatever cookie/JWT/server-side record it wants. Returning an error aborts login as HTTP 500.
3. **Shared `Subject[T]` across protocols.** SAML and OIDC both produce `sso.Subject[T]` with the same common fields (`ExternalID`, `Email`, `Firstname`, `Lastname`, `Groups`, `NameID`) and differ only in `Raw T` (`saml.Payload` vs `oidc.Payload`). Don't diverge the shared fields.
4. **Transit state ≠ session state.** The OIDC package uses a signed short-lived cookie `gosso_oidc_transit` to carry `state`/`nonce`/PKCE verifier between `/login` and `/callback`. Protocol plumbing, not a user session — carries no identity, deleted on first read.
5. **Functional options via `github.com/foomo/go/options`.** `Option = options.OptionE[*SP]` / `[*RP]`; validation lives in each `With*`; `options.ApplyE` centralises error wrapping.
6. **Open-redirect guard on `?target=`.** Both `/login` handlers accept a `target` query param; only relative URLs are honoured, others fall back to `/`.

## What is NOT in scope

Session cookies/JWTs, role-mapping enforcement, RBAC middleware, audit logging, E2E bypass handlers, token refresh orchestration, multi-tenant caches. `GroupMapper[R]` is a three-line helper — anything more lives in consumer code.

## Conventions inherited from foomo/keel

- **Branching:** lefthook enforces `feature/` or `fix/` prefixes.
- **Commits:** Conventional Commits (`type(scope?): subject`) enforced in commit-msg hook.
- **Tools pinned via mise:** lefthook, golangci-lint, bun. `make .mise` installs them.
- **Multi-module:** `examples/` has its own `go.mod` with `replace github.com/foomo/gosso => ../`. The Makefile iterates both via `GOMODS=$(find . -name go.mod -not -path './tmp/*')`.
- **Linter:** `default: all` minus a long disabled list in `.golangci.yaml`. `testpackage` is disabled so internal unit tests are allowed.
- **Docs:** vitepress under `docs/`, built with bun. GitHub Pages deploy via `.github/workflows/docs.yml` on push to `main` touching `docs/**`. Site lives at `foomo.github.io/gosso/`.

## Commands

```
make .mise            # install pinned tool versions
make lint             # golangci-lint run per module
make lint.fix         # auto-fix
make test             # go test across all modules (via go.work)
make check            # tidy + generate + lint + test + audit
make godocs           # serve pkg.go.dev-style godoc locally

make sandbox.up       # docker compose up keycloak at :8081
make sandbox.down     # docker compose down -v
make sandbox.run      # run demo app at :8080 (cwd=examples)
make sandbox.certs    # regenerate dev SP cert pair

make docs             # vitepress dev server (docs/)
make docs.build       # static build -> docs/.vitepress/dist
```

## Test approach

- **Root `sso`**: external `sso_test` package. `GroupMapper` table tests.
- **`saml/`**: internal `package saml` tests. `parseAssertion` tested with hand-constructed `*saml.Assertion`; `safeTarget` table test.
- **`oidc/`**: internal `package oidc` tests. Transit codec (round-trip + tamper + expiry + key rotation), PKCE helpers (RFC 7636 test vector), `stringSliceClaim`, `buildSubject` merge precedence.
- **No end-to-end Go integration test for the stub IdPs** yet — the sandbox is the practical integration path. If you add one for SAML, `crewjam/saml`'s test helpers (`testsaml/`) are the right starting point.

## Sandbox specifics

- Keycloak 26.0, `quay.io/keycloak/keycloak:26.0`, port 8081 on host.
- Realm `gosso-sandbox` pre-provisioned from `realm-export.json` on first boot (users: `alice` / `password` in admins, `bob` / `password` in users; OIDC client `gosso-oidc` with PKCE enabled; SAML client whose attribute mappers emit Azure-AD-style URIs so the library's `AzureADAttributeMap` works unmodified).
- Demo app keeps an in-memory session store keyed by a random HttpOnly cookie; it strips the raw SAML assertion / OIDC ID token down to a JSON-friendly projection plus `RawIDToken`/`SessionIndex` for logout.
- Dev SP cert at `examples/sandbox/certs/sp.{crt,key}` is committed. Not for production.
- Sandbox paths are relative to `examples/` (the Makefile target `cd`s into that directory).

## Dependencies

- `github.com/crewjam/saml` — SAML protocol machinery.
- `github.com/coreos/go-oidc/v3` — OIDC ID-token verification, discovery, JWKS.
- `golang.org/x/oauth2` — auth code + token exchange.
- `github.com/foomo/go/options` — functional options helpers (`OptionE[T]`, `ApplyE`).
- `github.com/stretchr/testify` — tests only.

## Open, non-blocking follow-ups

- **Stub-IdP integration tests** in Go (separate from the docker sandbox).
- **Migrations doc** — placeholder in `docs/guide/migrating.md`, populate on first breaking change.
- **govulncheck** in CI — currently only via `make audit`; could add a separate workflow.
