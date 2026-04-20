# SAML

SAML 2.0 Service Provider built on top of
[`github.com/crewjam/saml`](https://github.com/crewjam/saml). The
crewjam middleware is used purely for protocol machinery — signing
AuthnRequests, parsing and validating Responses, constructing SLO
URLs. The session layer is replaced with a stateless adapter that
forwards every valid assertion to your callback.

## Quick example

```go
cert, key, err := saml.LoadKeyPair("/etc/gosso/sp.crt", "/etc/gosso/sp.key")
if err != nil { log.Fatal(err) }

sp, err := saml.New(
    "https://app.example.com/saml/metadata",
    "https://app.example.com",
    "https://login.example.com/realms/my-realm/protocol/saml/descriptor",
    cert,
    key,
    func(ctx context.Context, w http.ResponseWriter, r *http.Request, s sso.Subject[saml.Payload]) error {
        // Build your session here.
        return writeSessionCookie(w, s)
    },
    saml.WithOnLogout(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
        return clearSessionCookie(w)
    }),
    saml.WithSLOHintProvider(func(r *http.Request) (nameID, sessionIndex string) {
        // Pull from your session. Returning empty NameID turns logout local-only.
        return readNameIDFromSession(r), readSessionIndexFromSession(r)
    }),
)
if err != nil { log.Fatal(err) }

h := sp.Handlers()
mux.Handle("/saml/", h.ACS)          // /saml/metadata and /saml/acs
mux.Handle("/saml/login", h.Login)
mux.Handle("/saml/logout", h.Logout)
mux.Handle("/saml/slo", h.SLO)       // receives the IdP's LogoutResponse
```

## How the flow runs

1. Browser hits `/saml/login?target=/dashboard`.
2. The login handler sanitises `target` (relative URLs only —
   absolute URLs, scheme-relative URLs, and `javascript:` all fall back
   to `/`), rewrites the request URL, and calls the crewjam
   `HandleStartAuthFlow`.
3. A signed relay-state cookie is issued, carrying the original target
   URL. The browser is redirected to the IdP's SSO endpoint.
4. After the user authenticates at the IdP, the browser POSTs the
   SAML Response to `/saml/acs`.
5. crewjam verifies signatures, audience, expiry. On success it calls
   our `SessionProvider.CreateSession` which:
   - parses the assertion via the configured `AttributeMap`
   - constructs a `Subject[Payload]`
   - invokes `OnAuthenticated`
6. The browser is redirected to the target URL from the relay-state
   cookie (or `/` if none).

## Attributes

The assertion is read out using `AttributeMap`. Defaults are
Azure-AD-shaped URIs:

| Subject field | Default URI |
| --- | --- |
| `ExternalID` | `http://schemas.microsoft.com/identity/claims/objectidentifier` |
| `Email`      | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| `Firstname`  | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` |
| `Lastname`   | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` |
| `Groups`     | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |

Override any subset with `saml.WithAttributeMap(...)`.

## Single Logout

Optional. Register a `SLOHintProvider` to enable it:

```go
saml.WithSLOHintProvider(func(r *http.Request) (nameID, sessionIndex string) {
    // Extract from your own session representation.
    return sess.NameID, sess.SessionIndex
})
```

When configured and returning a non-empty `nameID`, `/saml/logout`:

1. Calls the hint provider (reads from your session).
2. Fires `OnLogout` so you can destroy your session.
3. Builds a SAML `LogoutRequest` redirect via
   `ServiceProvider.MakeRedirectLogoutRequest(nameID, "")`.
4. Redirects the browser to the IdP's SLO endpoint.

**The hint provider runs *before* `OnLogout`** — because consumers
typically read `NameID`/`SessionIndex` from the same session they are
about to clear. Reversing the order would leave the hint empty and
silently downgrade logout to local-only.

Without the provider, `/saml/logout` is local-only: `OnLogout` fires
and the response is HTTP 200. Note that local-only logout leaves the
IdP's SSO cookie alive, so the next `/login` will re-authenticate
without prompting.

## Certificates

`saml.LoadKeyPair(certPath, keyPath)` loads a PEM x509 certificate
plus RSA private key from disk. Use `saml.ParseKeyPair([]byte, []byte)`
when secrets come from a vault or environment. Both return the
`*x509.Certificate` and `*rsa.PrivateKey` that `saml.New` expects.

The cert is used to sign the SP metadata and (if
`WithSignRequest` is ever added) the AuthnRequest itself. Keep the
key rotated on whatever schedule matches your operational posture;
rotation is not automated by the library.
