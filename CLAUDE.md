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
  transit.go + _test.go         # HMAC-signed transit cookie (state/nonce/PKCE verifier/login context)
  pkce.go + _test.go            # RFC 7636 helpers
  extract.go + _test.go, token.go
  handlers.go, login.go, callback.go, logout.go
  logincontext.go + _test.go    # LoginContext, RP.Login, LoginOption; OnLoginError tests
  refresh.go + _test.go         # RP.Refresh, ErrRefreshRejected

github.com/foomo/gosso/oidc/native            # opt-in, STATEFUL native-app broker
  README.md
  broker.go, options.go, hooks.go             # New, Attach, Handlers; web-hook wrappers
  authorize.go, token.go, refresh.go, revoke.go, oautherror.go
  types.go (Client, Tokens, Hooks), secret.go, telemetry.go

github.com/foomo/gosso/oidc/native/repository # commerce-style repository layer
  interfaces.go                               # Code, Session interfaces; ErrNotFound, ErrConflict
  code.go + codeindex.go, session.go + sessionindex.go, index.go, document.go  # keelmongo BaseCode/BaseSession
  store/                                      # entities: Code, Session, Subject, Attributes, EncryptedToken

internal/mongotest              # one mongo:7 testcontainer per test binary, fresh DB per persistor

internal/fakeidp                # httptest OIDC IdP (discovery, JWKS, authorize, token, userinfo)

examples/                       # separate module (replace ../)
  sandbox/                      # runnable Keycloak + demo app (+ native broker, /app/whoami)
    docker-compose.yaml, realm-export.json, main.go, certs/sp.{crt,key}
  nativeapp/                    # CLI native client (x/oauth2, loopback redirect)
```

## Load-bearing design principles

Violating these requires explicit discussion — they're why the library exists:

1. **Stateless framework — except the opt-in `oidc/native` broker, which owns codes and refresh sessions through `repository.Code` / `repository.Session` (MongoDB via keelmongo).** No session storage elsewhere. The SAML `sessionProvider` returns `ErrNoSession` from `GetSession` on purpose — "is the user logged in?" is answered entirely by consumer code.
2. **Consumer owns the session.** `OnAuthenticated[T]` hands over a `Subject[T]` plus the ResponseWriter; the consumer writes whatever cookie/JWT/server-side record it wants. Returning an error aborts login as HTTP 500.
3. **Shared `Subject[T]` across protocols.** SAML and OIDC both produce `sso.Subject[T]` with the same common fields (`ExternalID`, `Email`, `Firstname`, `Lastname`, `Groups`, `NameID`) and differ only in `Raw T` (`saml.Payload` vs `oidc.Payload`). Don't diverge the shared fields.
4. **Transit state ≠ session state.** The OIDC package uses a signed short-lived cookie `gosso_oidc_transit` to carry `state`/`nonce`/PKCE verifier between `/login` and `/callback`. Protocol plumbing, not a user session — carries no identity, deleted on first read.
5. **Functional options via `github.com/foomo/go/options`.** `Option = options.OptionE[*SP]` / `[*RP]`; validation lives in each `With*`; `options.ApplyE` centralises error wrapping.
6. **Open-redirect guard on `?target=`.** Both `/login` handlers accept a `target` query param; only relative URLs are honoured, others fall back to `/`.
7. **Redirect decision separate from auth (OIDC).** `oidc.WithOnRedirect(func(ctx, w, r, sub, target) (finalTarget, err))` runs after `OnAuthenticated` and computes the post-login destination. It exists because `OnAuthenticated` never sees `target` (so it can't branch on *where* login was initiated) yet the consumer often needs to — and because it owns the ResponseWriter, it can set extra cookies before the redirect. Return `""` to keep `target`; an error aborts the callback. The `?target=` guard still applies to `target`; the rewritten target is not sanitised — the consumer owns it (the native broker redirects to app schemes). `oidc.WithOnLoginError` is the error-path counterpart: it runs only for failures after the transit/state check and may return a (likewise unsanitised) redirect.
8. **Login context is signed, not encrypted.** `oidc.LoginContext` rides in the transit cookie from `RP.Login` to the callback hooks (`LoginContextFromContext`). No secrets in it; keep it small (cookie size). It reaches hooks only after the state check.

## What is NOT in scope

Session cookies/JWTs, role-mapping enforcement, RBAC middleware, audit logging, E2E bypass handlers, multi-tenant caches. Refresh orchestration is out of scope except the native broker (`oidc/native`), which rotates its own refresh sessions on top of `RP.Refresh`. `GroupMapper[R]` is a three-line helper — anything more lives in consumer code.

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

make sandbox.up       # keycloak :8081 + mongo :27017, waits until healthy
make sandbox.status   # container health; sandbox.logs ARGS=keycloak|mongo follows logs
make sandbox.down     # docker compose down -v
make sandbox.run      # run demo app at :8080 (cwd=examples)
make sandbox.app      # native client: login, refresh, revoke (PASS/FAIL); also .check .reuse .concurrent .outage .signout .restart
make sandbox.idp.stop / sandbox.idp.start / sandbox.idp.signout   # IdP outage / offline-session sign-out
make sandbox.mongo    # broker codes, sessions, indexes
make sandbox.certs    # regenerate dev SP cert pair

make docs             # vitepress dev server (docs/)
make docs.build       # static build -> docs/.vitepress/dist
```

## Test approach

- **Root `sso`**: external `sso_test` package. `GroupMapper` table tests.
- **`saml/`**: internal `package saml` tests. `parseAssertion` tested with hand-constructed `*saml.Assertion`; `safeTarget` table test.
- **`oidc/`**: internal `package oidc` tests. Transit codec (round-trip + tamper + expiry + key rotation + login context), PKCE helpers (RFC 7636 test vector), `stringSliceClaim`, `buildSubject` merge precedence; login context, `OnLoginError` and `RP.Refresh` end to end against `internal/fakeidp`.
- **`internal/fakeidp`**: httptest OIDC IdP with steerable refresh behaviour (rotate / keep / no ID token / other subject / reject / 5xx, delay, call count). Tests need local port binding.
- **Docker is required**: `oidc/native` and `oidc/native/repository` tests run against `mongo:7` via `internal/mongotest` (testcontainers). There is no in-memory repository on purpose — no parallel implementation to maintain.
- **`oidc/native`**: internal tests against fakeidp + a real RP + MongoDB repositories (`fixture_test.go`), settable clock; `sessionfaults_test.go` wraps `repository.Session` for failure injection.
- **`oidc/native/repository`**: repository semantics (take-once, CAS rotate, idempotent delete, copies) and index checks.
- No SAML stub-IdP integration test yet — `crewjam/saml`'s `testsaml/` helpers are the starting point.

## Sandbox specifics

- Keycloak 26.0, `quay.io/keycloak/keycloak:26.0`, port 8081 on host; MongoDB `mongo:7` on 27017 for the native broker (`mongodb://localhost:27017/gosso_sandbox`).
- Realm `gosso-sandbox` pre-provisioned from `realm-export.json` on first boot (users: `alice` / `password` in admins, `bob` / `password` in users; OIDC client `gosso-oidc` with PKCE enabled; SAML client whose attribute mappers emit Azure-AD-style URIs so the library's `AzureADAttributeMap` works unmodified).
- Demo app keeps an in-memory session store keyed by a random HttpOnly cookie; it strips the raw SAML assertion / OIDC ID token down to a JSON-friendly projection plus `RawIDToken`/`SessionIndex` for logout.
- Dev SP cert at `examples/sandbox/certs/sp.{crt,key}` is committed. Not for production.
- Sandbox paths are relative to `examples/` (the Makefile target `cd`s into that directory).

## Dependencies

- `github.com/crewjam/saml` — SAML protocol machinery.
- `github.com/coreos/go-oidc/v3` — OIDC ID-token verification, discovery, JWKS.
- `golang.org/x/oauth2` — auth code + token exchange.
- `github.com/foomo/go/options` — functional options helpers (`OptionE[T]`, `ApplyE`).
- `github.com/foomo/keel/persistence/mongo` (keelmongo) + `go.mongodb.org/mongo-driver/v2` — `oidc/native/repository`. Requires Go 1.27.
- `github.com/stretchr/testify`, `github.com/go-jose/go-jose/v4` (fakeidp signing), `github.com/testcontainers/testcontainers-go/modules/mongodb` — tests only (`internal/mongotest`).

## Open, non-blocking follow-ups

- **SAML stub-IdP integration test** in Go (OIDC is covered by `internal/fakeidp`).
- **Migrations doc** — placeholder in `docs/guide/migrating.md`, populate on first breaking change.
- **govulncheck** in CI — currently only via `make audit`; could add a separate workflow.
