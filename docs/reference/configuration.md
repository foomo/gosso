# Configuration reference

Every `With*` option for both adapters, one table each. Mandatory
options are marked **required**; everything else has a default listed
in the right column.

## `saml.New(opts ...Option)`

| Option | Required | Default | Purpose |
| --- | --- | --- | --- |
| `WithEntityID(string)` | ✓ | | SP entity ID advertised in metadata. |
| `WithRootURL(string)` | ✓ | | Externally reachable base URL. `/saml/metadata`, `/saml/acs`, `/saml/slo` are resolved relative to it. |
| `WithIDPMetadataURL(string)` | ✓ | | IdP metadata endpoint. Fetched synchronously during `New`. |
| `WithCertificate(certPath, keyPath)` | ✓ | | SP x509 cert + RSA key loaded from disk. |
| `WithCertificatePEM(cert, key)` | | | Same as above but from in-memory PEM bytes. |
| `WithAttributeMap(AttributeMap)` | | `AzureADAttributeMap` | SAML attribute URIs mapped into `Subject` fields. |
| `WithOnAuthenticated(fn)` | ✓ | | Invoked after a successful assertion. |
| `WithOnLogout(fn)` | | no-op | Invoked when `/saml/logout` is hit. |
| `WithSLOHintProvider(fn)` | | | Returns `(nameID, sessionIndex)` for SP-initiated SLO. Called *before* `OnLogout`. Without it, logout is local-only. |
| `WithPostLogoutRedirectURL(url)` | | `/` | Where the `SLO` handler redirects after the IdP's LogoutResponse. |
| `WithHTTPClient(*http.Client)` | | `http.DefaultClient` | Used for IdP metadata fetch. |
| `WithAllowIDPInitiated(bool)` | | `false` | Allow unsolicited IdP-initiated SSO. Leave disabled unless required. |

## `oidc.New(opts ...Option)`

| Option | Required | Default | Purpose |
| --- | --- | --- | --- |
| `WithIssuerURL(string)` | ✓ | | OIDC issuer. Triggers discovery. |
| `WithClientID(string)` | ✓ | | Registered client ID. |
| `WithClientSecret(string)` | ✓ | | Registered client secret. |
| `WithRedirectURL(string)` | ✓ | | Must match the IdP-registered `redirect_uri`. |
| `WithExtraScopes(...string)` | | | Added to `{openid, profile, email}`. Use `offline_access` for refresh tokens. |
| `WithClaimMap(ClaimMap)` | | `StandardClaimMap` | Claim-name → `Subject` field mapping. |
| `WithUserInfo(bool)` | | `false` | Fetch `/userinfo` after token exchange; claims override ID token. |
| `WithIssuerValidator(fn)` | | strict eq | Custom issuer check (e.g. for Entra ID multi-tenant). |
| `WithTransitSigningKey([]byte)` | ✓ | | HMAC key for the transit cookie. |
| `WithTransitDeprecatedKeys(...[]byte)` | | | Rotated keys still accepted on read. |
| `WithTransitCookieName(string)` | | `gosso_oidc_transit` | Transit cookie name. |
| `WithTransitTTL(duration)` | | `5m` | Transit cookie lifetime. |
| `WithOnAuthenticated(fn)` | ✓ | | Invoked after token + ID-token validation. |
| `WithOnLogout(fn)` | | no-op | Invoked when `/oidc/logout` is hit. |
| `WithLogoutHintProvider(fn)` | | | Returns the raw ID token for `id_token_hint` on RP-initiated logout. Called *before* `OnLogout`. |
| `WithPostLogoutRedirectURL(string)` | | | Sent as `post_logout_redirect_uri`. |
| `WithHTTPClient(*http.Client)` | | `http.DefaultClient` | Used for discovery, token, and UserInfo calls. |
