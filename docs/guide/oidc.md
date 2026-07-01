# OIDC

OpenID Connect 1.0 Relying Party implementing the Authorization Code
flow with PKCE. Built on
[`github.com/coreos/go-oidc/v3`](https://github.com/coreos/go-oidc) for
ID-token verification and `golang.org/x/oauth2` for the token
exchange.

## Quick example

```go
rp, err := oidc.New(
    "https://login.example.com/realms/my-realm",
    "my-client",
    os.Getenv("CLIENT_SECRET"),
    "https://app.example.com/oidc/callback",
    []byte(os.Getenv("TRANSIT_KEY")),
    func(ctx context.Context, w http.ResponseWriter, r *http.Request, s sso.Subject[oidc.Payload]) error {
        return writeSessionCookie(w, s)
    },
    oidc.WithExtraScopes("offline_access"), // for refresh tokens
    oidc.WithUserInfo(true),                // if groups live in UserInfo
    oidc.WithOnLogout(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
        return clearSessionCookie(w)
    }),
    oidc.WithLogoutHintProvider(func(r *http.Request) string {
        return readRawIDTokenFromSession(r)
    }),
    oidc.WithPostLogoutRedirectURL("https://app.example.com/"),
)
if err != nil { log.Fatal(err) }

h := rp.Handlers()
mux.Handle("/oidc/login", h.Login)
mux.Handle("/oidc/callback", h.Callback)
mux.Handle("/oidc/logout", h.Logout)
```

## How the flow runs

1. Browser hits `/oidc/login?target=/dashboard`.
2. The adapter generates `state`, `nonce`, and a PKCE `code_verifier`
   (32 random bytes each); computes
   `code_challenge = base64url(SHA256(code_verifier))`.
3. A signed transit cookie (`gosso_oidc_transit`, configurable)
   carries `{state, nonce, code_verifier, target, iat}`. Path-scoped to
   the callback URL; `HttpOnly`, `SameSite=Lax`, `Secure` when the
   redirect URL is HTTPS. TTL 5 min by default.
4. Browser is redirected to the IdP's `authorization_endpoint` with
   `response_type=code`, `code_challenge_method=S256`, the configured
   scopes, state and nonce.
5. On IdP callback, `/oidc/callback`:
   - reads + validates + deletes the transit cookie
   - checks `state` matches the query parameter
   - exchanges `code` + `code_verifier` at the token endpoint
   - verifies the ID token (JWKS signature, audience, expiry, nonce,
     issuer)
   - optionally fetches `/userinfo` and merges claims over the ID
     token
   - constructs a `Subject[Payload]` via the `ClaimMap`
   - invokes `OnAuthenticated`
   - invokes `OnRedirect` (if configured) to compute the final target
   - redirects to the (possibly rewritten) target

## Post-login redirect (`WithOnRedirect`)

By default the callback redirects the browser to the `target` carried in the
transit cookie (the `?target=` from `/login`, or `/` when absent). Supply
`oidc.WithOnRedirect` to compute the final destination yourself:

```go
oidc.WithOnRedirect(func(
    ctx context.Context,
    w http.ResponseWriter,
    r *http.Request,
    sub sso.Subject[oidc.Payload],
    target string,
) (string, error) {
    // Runs after OnAuthenticated succeeds. It receives the authenticated
    // subject and the resolved (safe) target. Return a non-empty string to
    // override the redirect destination; return "" to keep `target`.
    if strings.HasPrefix(target, "/checkout") {
        return target, nil // leave checkout logins untouched
    }
    return target + "?notice=cartMerged", nil
}),
```

Why a separate hook rather than doing this in `OnAuthenticated`?

- **It sees the `target`.** `OnAuthenticated` never receives the post-login
  destination, so it cannot branch on *where* login was initiated.
- **It owns the `ResponseWriter`.** A consumer can set additional cookies
  (e.g. rebinding a shopping cart on login) before the redirect happens.

Semantics:

- Runs only after `OnAuthenticated` returns successfully.
- Returning `""` keeps the default target; a non-empty string overrides it.
- Returning an error aborts the callback (HTTP 500) — the redirect is not sent.
- When the option is unset, behaviour is unchanged (redirect to `target`).

The open-redirect guard still applies: `target` is always a safe relative path.
It is your responsibility to keep any rewritten destination relative.

## Claims

Default `ClaimMap`:

| Subject field | Default claim |
| --- | --- |
| `ExternalID` | `sub` |
| `Email`      | `email` |
| `Firstname`  | `given_name` |
| `Lastname`   | `family_name` |
| `Groups`     | `groups` |

Override with `oidc.WithClaimMap(oidc.ClaimMap{...})`.

### UserInfo

Some IdPs omit `groups` (and other profile claims) from the ID token.
Set `oidc.WithUserInfo(true)` to trigger a UserInfo call after the
token exchange; claims from UserInfo override the ID token on
conflict.

## Transit cookie

The transit cookie is HMAC-SHA256 signed with the key passed as the
`transitSigningKey` argument to `oidc.New`. **This is protocol state,
not a user session** — it carries no identity, only the random values
the protocol needs to correlate `/login` and `/callback`.

To rotate the key, pass the new key positionally and the old key as
a deprecated-keys option:

```go
rp, err := oidc.New(
    issuerURL, clientID, clientSecret, redirectURL,
    []byte(newKey),
    onAuthenticated,
    oidc.WithTransitDeprecatedKeys([]byte(oldKey)),
)
```

The reader accepts signatures from the primary key or any deprecated
key; remove the deprecated entry once the TTL has elapsed
everywhere.

## RP-initiated logout

When the IdP advertises `end_session_endpoint` and you register a
`LogoutHintProvider` returning the raw ID token, `/oidc/logout`:

1. Calls the hint provider (reads from your session).
2. Fires `OnLogout`.
3. Redirects the browser to the end-session endpoint with
   `id_token_hint` and (if `WithPostLogoutRedirectURL` was supplied)
   `post_logout_redirect_uri`.

**The hint provider runs *before* `OnLogout`** — because consumers
typically read the raw ID token from the same session they are about
to clear. Reversing the order would leave the hint empty and silently
downgrade logout to local-only (defeating Keycloak / other IdPs' SSO
cookie).

Without the provider — or when the provider returns an empty string —
logout is local-only (HTTP 200, or redirect to
`PostLogoutRedirectURL` if set). Local-only logout does **not**
terminate the IdP-side session, so the next `/login` will
re-authenticate without prompting.

## Azure Entra ID multi-tenant

The default issuer validation requires strict equality with the
configured issuer URL. For tenant-GUID issuers, supply a custom
validator:

```go
oidc.WithIssuerValidator(func(iss string) error {
    if strings.HasPrefix(iss, "https://login.microsoftonline.com/") &&
        strings.HasSuffix(iss, "/v2.0") {
        return nil
    }
    return fmt.Errorf("unexpected issuer: %s", iss)
})
```

## Groups overage (Azure)

Users in >150 groups receive a "groups overage" indicator instead of
the full list. Resolving this requires a Microsoft Graph call with
extra permissions — out of scope for this library. If your tenant has
users in that situation, hit Graph from inside your
`OnAuthenticated` callback.
