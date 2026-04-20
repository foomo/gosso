# Configuration reference

Mandatory inputs are positional arguments to `New`; everything else is
an `Option` (functional option). Defaults are listed in the right
column.

## `saml.New(entityID, rootURL, idpMetadataURL, cert, key, onAuthenticated, opts ...Option)`

### Required parameters

| Parameter | Type | Purpose |
| --- | --- | --- |
| `entityID` | `string` | SP entity ID advertised in metadata. |
| `rootURL` | `string` | Externally reachable base URL. `/saml/metadata`, `/saml/acs`, `/saml/slo` are resolved relative to it. |
| `idpMetadataURL` | `string` | IdP metadata endpoint. Fetched synchronously during `New`. |
| `cert` | `*x509.Certificate` | SP x509 certificate. Use `saml.LoadKeyPair(certPath, keyPath)` or `saml.ParseKeyPair(certPEM, keyPEM)` to obtain it. |
| `key` | `*rsa.PrivateKey` | SP private key (paired with `cert`). |
| `onAuthenticated` | `sso.OnAuthenticated[Payload]` | Invoked after a successful assertion. |

### Options

| Option | Default | Purpose |
| --- | --- | --- |
| `WithAttributeMap(AttributeMap)` | `AzureADAttributeMap` | SAML attribute URIs mapped into `Subject` fields. |
| `WithOnLogout(fn)` | no-op | Invoked when `/saml/logout` is hit. |
| `WithErrorLogger(fn)` | silent | Routes runtime errors from the SAML handlers to the supplied logger. |
| `WithSLOHintProvider(fn)` | | Returns `(nameID, sessionIndex)` for SP-initiated SLO. Called *before* `OnLogout`. Without it, logout is local-only. |
| `WithPostLogoutRedirectURL(url)` | `/` | Where the `SLO` handler redirects after the IdP's LogoutResponse. |
| `WithHTTPClient(*http.Client)` | instrumented, 15s timeout | Used for IdP metadata fetch. |
| `WithBootstrapTimeout(duration)` | `30s` | Bounds the time `New` will spend fetching IdP metadata. |
| `WithAllowIDPInitiated(bool)` | `false` | Allow unsolicited IdP-initiated SSO. Leave disabled unless required. |

## `oidc.New(issuerURL, clientID, clientSecret, redirectURL, transitSigningKey, onAuthenticated, opts ...Option)`

### Required parameters

| Parameter | Type | Purpose |
| --- | --- | --- |
| `issuerURL` | `string` | OIDC issuer. Triggers discovery. HTTPS required (loopback exception applies). |
| `clientID` | `string` | Registered client ID. |
| `clientSecret` | `string` | Registered client secret. |
| `redirectURL` | `string` | Must match the IdP-registered `redirect_uri`. HTTPS required (loopback exception applies). |
| `transitSigningKey` | `[]byte` | HMAC-SHA256 key for the transit cookie. Minimum 32 bytes. |
| `onAuthenticated` | `sso.OnAuthenticated[Payload]` | Invoked after token + ID-token validation. |

### Options

| Option | Default | Purpose |
| --- | --- | --- |
| `WithExtraScopes(...string)` | | Added to `{openid, profile, email}`. Use `offline_access` for refresh tokens. |
| `WithClaimMap(ClaimMap)` | `StandardClaimMap` | Claim-name → `Subject` field mapping. |
| `WithUserInfo(bool)` | `false` | Fetch `/userinfo` after token exchange; claims override ID token. |
| `WithIssuerValidator(fn)` | strict eq | Custom issuer check (e.g. for Entra ID multi-tenant). |
| `WithTransitDeprecatedKeys(...[]byte)` | | Rotated keys still accepted on read. |
| `WithTransitCookieName(string)` | `gosso_oidc_transit` | Transit cookie name. |
| `WithTransitTTL(duration)` | `5m` | Transit cookie lifetime. |
| `WithOnLogout(fn)` | no-op | Invoked when `/oidc/logout` is hit. |
| `WithErrorLogger(fn)` | silent | Routes runtime errors from the OIDC handlers to the supplied logger. |
| `WithLogoutHintProvider(fn)` | | Returns the raw ID token for `id_token_hint` on RP-initiated logout. Called *before* `OnLogout`. |
| `WithPostLogoutRedirectURL(string)` | | Sent as `post_logout_redirect_uri`. |
| `WithHTTPClient(*http.Client)` | instrumented, 15s timeout | Used for discovery, token, and UserInfo calls. |
| `WithBootstrapTimeout(duration)` | `30s` | Bounds the time `New` will spend on OIDC discovery. |
