# OIDC with a custom provider

Data-exchange runbook for pairing a `gosso/oidc` Relying Party with
any OIDC 1.0 provider that supports the Authorization Code flow plus
PKCE (S256) — Keycloak, Auth0, Okta, ForgeRock, Dex, Zitadel, an
in-house IdP, etc.

If you're on Entra ID multi-tenant, see the
[OIDC guide](../oidc#azure-entra-id-multi-tenant) for the issuer
validator pattern.

## What each side needs

| Direction | Artefact | Provided by / notes |
| --- | --- | --- |
| **Consumer → IdP** | Redirect URI (callback) | `WithRedirectURL`; exact string match at the IdP. `https://app.example.com/oidc/callback` |
| Consumer → IdP | Post-logout redirect URI | `WithPostLogoutRedirectURL`; pre-register on most IdPs |
| Consumer → IdP | Requested scopes | `openid profile email` unconditionally; `WithExtraScopes("offline_access", "groups", …)` for the rest |
| Consumer → IdP | Response type | `code` (fixed) |
| Consumer → IdP | Grant types | `authorization_code`, optionally `refresh_token` |
| Consumer → IdP | PKCE | `code_challenge_method=S256` (fixed) |
| Consumer → IdP | Token-endpoint auth method | `client_secret_basic` by default (driven by `golang.org/x/oauth2`) |
| **IdP → Consumer** | Issuer URL | `WithIssuerURL`; must serve `{issuer}/.well-known/openid-configuration` |
| IdP → Consumer | Client ID | `WithClientID` |
| IdP → Consumer | Client secret | `WithClientSecret` — confidential client |
| IdP → Consumer | JWKS | Advertised by `jwks_uri` in the discovery document; fetched automatically |
| IdP → Consumer | End-session endpoint | `end_session_endpoint` in discovery (only needed for RP-initiated logout) |
| IdP → Consumer | UserInfo endpoint | `userinfo_endpoint` in discovery (only needed when `WithUserInfo(true)`) |

`WithIssuerURL` and `WithRedirectURL` **must be HTTPS**. `localhost`,
`127.0.0.1`, `[::1]` are accepted over HTTP for local development.

## Discovery document

`gosso/oidc` loads the IdP configuration from
`{issuer}/.well-known/openid-configuration` during `oidc.New`. The
fields actually consulted:

| Field | Purpose |
| --- | --- |
| `issuer` | Must equal `WithIssuerURL` (strict string compare). For IdPs that emit a different issuer value (Entra's tenant-GUID pattern is the classic case), supply `WithIssuerValidator(fn)` and validate the expected pattern inside `fn`. A validator that returns nil unconditionally disables the check — [see the option's GoDoc](../oidc#azure-entra-id-multi-tenant) for a correct example. |
| `authorization_endpoint` | Redirect target for `/oidc/login`. |
| `token_endpoint` | Called during `/oidc/callback` for the code→token exchange. |
| `jwks_uri` | Fetched by `go-oidc` to verify the ID token signature. |
| `userinfo_endpoint` | Used only when `WithUserInfo(true)`. |
| `end_session_endpoint` | Used by `/oidc/logout` when a `LogoutHintProvider` returns a non-empty raw ID token. |
| `id_token_signing_alg_values_supported` | Must include `RS256` (the `go-oidc` default); other algorithms require verifier customisation that this library does not expose. |
| `code_challenge_methods_supported` | Must include `S256`. |

Sanity check from the service host:

```sh
curl -fsSL https://auth.example.com/.well-known/openid-configuration | jq '.issuer, .authorization_endpoint, .token_endpoint, .jwks_uri, .end_session_endpoint'
```

## Client registration at the IdP

Nomenclature varies by provider; the substance is the same everywhere:

| Field | Value |
| --- | --- |
| Client type / Access type | **Confidential** / `private` (never `public`) |
| Allowed grant types | `authorization_code` (+ `refresh_token` if you use `offline_access`) |
| Allowed response types | `code` |
| PKCE | **Required**, method `S256` |
| Redirect URIs | `https://app.example.com/oidc/callback` — **exact** match (trailing slashes count) |
| Post-logout redirect URIs | `https://app.example.com/` |
| Token-endpoint auth method | `client_secret_basic` (default) or `client_secret_post` |
| Issuance scopes | At least `openid profile email`; add `offline_access` for refresh tokens, add a `groups` scope / mapper if the IdP doesn't emit groups by default |
| Front-/back-channel logout | Not required; this library drives RP-initiated logout via the end-session endpoint |

## Claims

Default `ClaimMap`:

| Subject field | Default claim |
| --- | --- |
| `ExternalID` | `sub` |
| `Email` | `email` |
| `Firstname` | `given_name` |
| `Lastname` | `family_name` |
| `Groups` | `groups` |

Override with `oidc.WithClaimMap(...)`. Rules that `gosso/oidc`
enforces on your behalf:

- `sub` is **required**. `buildSubject` rejects an ID token with no
  `sub` rather than silently keying sessions off `""`.
- `sub` in UserInfo **must equal** `sub` in the ID token (OIDC
  Core §5.3.2). If UserInfo lies, the login is rejected.
- `groups` is **not a standard OIDC claim**. Most IdPs need an
  explicit mapper/protocol-mapper to emit it. The library accepts
  `[]string`, `[]any`, and single comma-separated strings (common
  mapper misconfiguration).
- When `WithUserInfo(true)` is set, UserInfo claims **override** ID
  token claims on conflict (except `sub`, which is checked for
  equality).

## Secrets

| Secret | Minimum | Rotation |
| --- | --- | --- |
| Client secret | Provider-defined (typically 32+ random bytes) | Rotate at the IdP, update the secret store, restart the service |
| Transit signing key | **≥ 32 bytes** (HMAC-SHA256 block size) | `WithTransitDeprecatedKeys(old)` accepts the old key for cookie-TTL (5 min default) while the primary rotates; drop once every node has the new key |

Both belong in a secret manager; neither is safe in source.

## `oidc.New` configuration

```go
rp, err := oidc.New(
    oidc.WithIssuerURL("https://auth.example.com/realms/my-realm"),
    oidc.WithClientID("my-app"),
    oidc.WithClientSecret(os.Getenv("OIDC_CLIENT_SECRET")),
    oidc.WithRedirectURL("https://app.example.com/oidc/callback"),
    oidc.WithTransitSigningKey([]byte(os.Getenv("OIDC_TRANSIT_KEY"))), // 32+ bytes
    oidc.WithExtraScopes("offline_access"),                             // optional
    oidc.WithUserInfo(true),                                            // when groups live in UserInfo
    oidc.WithOnAuthenticated(onAuthenticated),
    oidc.WithOnLogout(onLogout),
    oidc.WithLogoutHintProvider(readRawIDTokenFromSession),
    oidc.WithPostLogoutRedirectURL("https://app.example.com/"),
    oidc.WithErrorLogger(logError),
)
```

## Flow on the wire

```
browser                 gosso RP                  IdP
  |                        |                       |
  |  GET /oidc/login?target=/admin                 |
  |----------------------->|                       |
  |                        |  Set-Cookie: gosso_oidc_transit
  |                        |  HMAC-SHA256 over {state, nonce, pkce_verifier, target}
  |                        |                       |
  |  302 Location: {authorization_endpoint}?
  |                        |     response_type=code&
  |                        |     scope=openid+profile+email[+...]&
  |                        |     client_id=&redirect_uri=&
  |                        |     state=&nonce=&
  |                        |     code_challenge=&code_challenge_method=S256
  |<-----------------------|                       |
  |                                                |
  |  GET {authorization_endpoint}?...              |
  |----------------------------------------------->|
  |                                                | (user authenticates)
  |  302 Location: {redirect_uri}?code=&state=     |
  |<-----------------------------------------------|
  |                        |                       |
  |  GET /oidc/callback?code=&state=               |
  |----------------------->|                       |
  |                        |  read + delete gosso_oidc_transit
  |                        |  constant-time compare state
  |                        |  POST {token_endpoint}
  |                        |    grant_type=authorization_code&
  |                        |    code=&code_verifier=&
  |                        |    redirect_uri=&client_id=&client_secret=
  |                        |---------------------->|
  |                        |<----------------------| {id_token, access_token[, refresh_token]}
  |                        |  verify(id_token) — JWKS signature, aud, exp, nonce, issuer
  |                        |  (optional) GET {userinfo_endpoint}  → sub equality check
  |                        |  OnAuthenticated(ctx, w, r, Subject)
  |  302 Location: /admin  |                       |
  |<-----------------------|                       |
```

## Pre-flight checklist

- [ ] `{issuer}/.well-known/openid-configuration` reachable from the
      service host at startup.
- [ ] Discovery `issuer` matches `WithIssuerURL` exactly, or a
      validator accepts it.
- [ ] `jwks_uri` reachable; `id_token_signing_alg_values_supported`
      includes `RS256`.
- [ ] Client registered with PKCE `S256` **required**; gosso always
      sends `code_challenge`, but the IdP should enforce it too.
- [ ] Redirect URI registered with the **exact** string from
      `WithRedirectURL` (including trailing slash or lack thereof).
- [ ] Post-logout redirect URI pre-registered if you use RP-initiated
      logout.
- [ ] `groups` mapper / scope configured if the app uses
      `Subject.Groups`.
- [ ] Client secret and transit signing key (≥ 32 bytes) provisioned
      through a secret manager; neither appears in source or build
      artefacts.
- [ ] `WithIssuerURL` and `WithRedirectURL` are HTTPS in every
      environment except local dev (loopback-only exception).
- [ ] Transit cookie name (`gosso_oidc_transit` by default) isn't
      colliding with another cookie on the host.
