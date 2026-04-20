# SAML with Microsoft Entra ID (Azure AD)

Data-exchange runbook for pairing a `gosso/saml` Service Provider with
an Entra ID tenant's Enterprise Application. If you use a different IdP
(ADFS, Okta, PingFederate, Keycloak), the same artefacts are exchanged
under different UI labels — this page concentrates on what Entra emits
and what it needs back.

## What each side needs

| Direction | Artefact | Provided by / notes |
| --- | --- | --- |
| **Consumer → IdP** | Entity ID (SP) | `WithEntityID`; typically `https://app.example.com/saml/metadata` |
| Consumer → IdP | Reply URL (ACS) | Derived from `WithRootURL` → `https://app.example.com/saml/acs` |
| Consumer → IdP | Sign-on URL (optional) | `https://app.example.com/saml/login`, for bookmarkable SP-initiated login |
| Consumer → IdP | Logout URL | `https://app.example.com/saml/slo` |
| Consumer → IdP | SP metadata XML | Served automatically at `{RootURL}/saml/metadata` |
| Consumer → IdP | SP signing certificate | Public half of the RSA pair loaded by `WithCertificate` / `WithCertificatePEM` |
| **IdP → Consumer** | IdP Entity ID / issuer | Entra emits `https://sts.windows.net/{tenant-id}/` |
| IdP → Consumer | Federation metadata URL | `https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml?appid={application-id}` — passed to `WithIDPMetadataURL` |
| IdP → Consumer | Signing certificate | Embedded in the federation metadata XML (rotated by Microsoft) |
| IdP → Consumer | SSO / SLO endpoints | Discoverable in metadata; `https://login.microsoftonline.com/{tenant-id}/saml2` |
| IdP → Consumer | Assertion attributes | See **Attribute claims** below |

The IdP-side federation metadata URL is the only value you strictly
need to configure at runtime; everything else (endpoints, certs) is
resolved from that document.

## Portal setup (Entra ID)

1. **Microsoft Entra admin center → Enterprise applications → New
   application → Create your own application**. Pick *Integrate any
   other application you don't find in the gallery* (non-gallery).
2. On the application's **Single sign-on** pane, choose **SAML**.
3. Section 1 ("Basic SAML Configuration") — either upload the SP
   metadata fetched from `{RootURL}/saml/metadata`, or enter manually:
   - **Identifier (Entity ID)**: `https://app.example.com/saml/metadata`
   - **Reply URL (ACS URL)**: `https://app.example.com/saml/acs`
   - **Sign on URL** *(optional)*: `https://app.example.com/saml/login`
   - **Logout URL**: `https://app.example.com/saml/slo`
4. Section 3 ("SAML Certificates") — copy the **App Federation Metadata
   Url**. This is your `WithIDPMetadataURL` value.
5. **Users and groups** — assign the users/groups who may log in.
6. **(Optional)** Section 2 ("Attributes & Claims") — add a **group
   claim** if the app needs `Subject.Groups`.

## Attribute claims

Entra ID emits this set by default, and `saml.AzureADAttributeMap`
(the gosso default) maps them straight across — no `WithAttributeMap`
override needed.

| Subject field | SAML attribute URI | Entra ID source |
| --- | --- | --- |
| `ExternalID` | `http://schemas.microsoft.com/identity/claims/objectidentifier` | `user.objectid` (the stable directory object GUID — **this** is your principal key) |
| `Email` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `user.mail` |
| `Firstname` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | `user.givenname` |
| `Lastname` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | `user.surname` |
| `Groups` | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` | Configured group claim (see below) |

NameID defaults to the `emailAddress` format with the user's UPN —
exposed on `Subject.NameID` and needed for SLO.

### Group claims are opt-in

Under the application's **Single sign-on → Attributes & Claims → Add a
group claim**:

- **Which groups**: *All groups* / *Groups assigned to the application*
  / *Security groups* — pick one.
- **Source attribute**: *Group ID* (GUID) is safest. Use
  *sAMAccountName* or *Cloud-only group display names* only if those
  are unique in your tenant — Entra emits them without scoping.

Users in **> 150 groups** hit
[groups overage](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference#groups-overage-claim):
Entra emits a `hasgroups` placeholder instead of the list. Resolving
this requires a Microsoft Graph call from inside `OnAuthenticated`
using the signed-in user's access token — out of scope for this
library.

## `saml.New` configuration

```go
sp, err := saml.New(
    saml.WithEntityID("https://app.example.com/saml/metadata"),
    saml.WithRootURL("https://app.example.com"),
    saml.WithIDPMetadataURL(
        "https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml?appid={app-id}",
    ),
    saml.WithCertificate("/etc/gosso/sp.crt", "/etc/gosso/sp.key"),
    // AzureADAttributeMap is the default — no WithAttributeMap needed.
    saml.WithOnAuthenticated(onAuthenticated),
    saml.WithOnLogout(onLogout),
    saml.WithSLOHintProvider(readNameIDAndSessionIndex),
    saml.WithPostLogoutRedirectURL("https://app.example.com/"),
    saml.WithErrorLogger(logError),
)
```

## SP certificate lifecycle

`WithCertificate` / `WithCertificatePEM` load an x509 cert + RSA
private key. The cert is published in SP metadata and used to sign
AuthnRequests (via crewjam/saml) so Entra can verify the SP.

Rotation is manual: generate a new cert/key pair, deploy it, re-upload
the refreshed SP metadata to Entra (or let Entra re-fetch via URL if
you expose one). Keep the overlap on both sides long enough for
in-flight sessions to drain.

## Single Logout

When `WithSLOHintProvider` is configured and your session yields a
non-empty `NameID`, `/saml/logout`:

1. Pulls `(NameID, SessionIndex)` from your session via the provider.
2. Fires `OnLogout` so you can destroy your session.
3. Builds a `LogoutRequest` via `crewjam/saml`'s
   `MakeRedirectLogoutRequest` and redirects the browser to Entra's
   `SingleLogoutService`.
4. Entra terminates its SSO session and POSTs a `LogoutResponse` to
   `/saml/slo`.
5. `/saml/slo` redirects to `WithPostLogoutRedirectURL` (`/` by
   default). The library does not re-validate the response — see the
   security review for rationale.

Without the provider, `/saml/logout` is **local-only** — Entra's SSO
cookie survives, and the next `/saml/login` re-authenticates silently.

## Pre-flight checklist

- [ ] SP cert/key deployed (via file paths or PEM bytes in a secret).
- [ ] `{RootURL}/saml/metadata` reachable from the internet; uploaded
      or registered at Entra.
- [ ] Entra federation metadata URL reachable from the service host at
      startup. `gosso/saml` fetches it during `saml.New` with a 30 s
      default timeout (`WithBootstrapTimeout`).
- [ ] Users/groups assigned to the Enterprise Application.
- [ ] Group claim configured if `Subject.Groups` is used.
- [ ] `OnAuthenticated` treats `ExternalID` (Entra object ID) as the
      stable principal key — **not** `Email`, which can change when a
      user renames their UPN.
- [ ] Logout works end-to-end: verify the `NameID` your session stores
      matches what Entra expects (UPN by default).
- [ ] HTTPS on `WithRootURL`. Entra rejects HTTP Reply URLs outside of
      `localhost`.
