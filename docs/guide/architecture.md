# Architecture

`gosso` is built around one load-bearing idea: **the library owns the
protocol, the consumer owns the session.**

## The seam

```
┌──────────────────┐            ┌────────────────────────────────┐            ┌──────────┐
│ your service     │            │ gosso                          │            │   IdP    │
│                  │            │                                │            │          │
│  ─ HTTP router   │ mounts ─▶  │  saml.SP  /  oidc.RP           │ ◀──────▶  │          │
│                  │            │                                │            │          │
│  ─ OnAuth cb ──── receives ── │  Subject[T]                    │            │          │
│    (write your   │            │                                │            │          │
│     own session) │            │  OnAuthenticated[T]            │            │          │
│                  │            │  OnLogout                      │            │          │
│  ─ OnLogout cb ── receives ── │  GroupMapper[R]                │            │          │
└──────────────────┘            └────────────────────────────────┘            └──────────┘
```

The library translates the SAML or OIDC round-trip into a typed
`Subject`. The consumer decides what that authentication event *means*:
what session to create, what roles to assign, what to audit-log, how
long the session lasts, how logout destroys it.

## `Subject[T]`

Every protocol produces the same struct, parameterised only by its
protocol-specific raw payload.

```go
type Subject[T any] struct {
    ExternalID string
    Email      string
    Firstname  string
    Lastname   string
    Groups     []string
    NameID     string // SAML only; empty for OIDC
    Raw        T      // saml.Payload or oidc.Payload
}
```

You can write one session-construction helper for both IdPs and only
reach into `Raw` for protocol-specific behaviour (e.g. stashing the
OIDC `RawIDToken` for RP-initiated logout, or the SAML `SessionIndex`
for SLO).

## Load-bearing design choices

### Stateless framework

Neither adapter ever reads or writes a session cookie on your behalf.
The SAML `SessionProvider` under the hood returns `ErrNoSession` from
`GetSession` every time on purpose — "is the user logged in?" is
answered entirely by consumer code. You cannot accidentally get into a
state where gosso thinks the user is logged in but your app doesn't.

### Consumer-owned session

`OnAuthenticated` receives the `http.ResponseWriter` and the request.
Set any cookies, issue any tokens, persist any rows you like. Return
`nil` to let the adapter perform its post-authentication redirect, or
a non-nil error to abort the login as HTTP 500.

### Transit state ≠ session state

The OIDC adapter does set a short-lived signed cookie
(`gosso_oidc_transit`, configurable) between `/login` and
`/callback` to carry `state`, `nonce` and the PKCE verifier. This is
protocol plumbing, not a user session — it carries no identity, exists
for ~60 seconds, is scoped to the callback URL, and is deleted on
first read.

### Functional options, validated up-front

`New(...Option)` returns an error if any required option is missing or
malformed. There is no zero-value `SP{}` or `RP{}` that silently works
with wrong defaults.

## What `gosso` does not do

- It does not store sessions.
- It does not enforce RBAC. `GroupMapper` is a tiny convenience helper
  for translating raw groups into your role type; anything more lives
  in your app.
- It does not audit-log authentication events. Log from inside
  `OnAuthenticated` or wrap the handler.
- It does not manage token refresh. If you enabled `offline_access`,
  the refresh token shows up in `Subject.Raw.RefreshToken` and is
  yours to use.
- It does not implement an E2E bypass handler. Write a consumer-side
  handler that invokes the same session-construction path and is
  gated behind basic auth or a build tag.
