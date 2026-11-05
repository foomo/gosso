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
| `WithSLOHintProvider(fn)` | | Returns `(nameID, sessionIndex)` for SP-initiated SLO. Called *before* `OnLogout`. An empty `sessionIndex` asks the IdP to end all of the principal's sessions, a set one only that session. Without it, logout is local-only. |
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
| `WithScopes(...string)` | `{openid, profile, email}` | Replaces the default scope set; `openid` is always kept. For IdPs that reject a scope they do not offer, e.g. `email`. |
| `WithExtraScopes(...string)` | | Added to the scope set. Use `offline_access` for refresh tokens. |
| `WithClaimMap(ClaimMap)` | `StandardClaimMap` | Claim-name → `Subject` field mapping. |
| `WithUserInfo(bool)` | `false` | Fetch `/userinfo` after token exchange; claims override ID token. |
| `WithIssuerValidator(fn)` | strict eq | Custom issuer check (e.g. for Entra ID multi-tenant). |
| `WithTransitDeprecatedKeys(...[]byte)` | | Rotated keys still accepted on read. |
| `WithTransitCookieName(string)` | `gosso_oidc_transit` | Transit cookie name. |
| `WithTransitTTL(duration)` | `5m` | Transit cookie lifetime. |
| `WithOnLogout(fn)` | no-op | Invoked when `/oidc/logout` is hit. |
| `WithErrorLogger(fn)` | silent | Routes runtime errors from the OIDC handlers to the supplied logger. |
| `WithLogoutHintProvider(fn)` | | Returns the raw ID token for `id_token_hint` on RP-initiated logout. Called *before* `OnLogout`. |
| `WithOnRedirect(fn)` | redirect to `target` | Computes the post-login destination. The returned URL is not sanitised. |
| `WithOnLoginError(fn)` | plain HTTP error | Runs on callback failures after the `state` check; a non-empty return is a 302 target (not sanitised). |
| `WithPostLogoutRedirectURL(string)` | | Sent as `post_logout_redirect_uri`. |
| `WithHTTPClient(*http.Client)` | instrumented, 15s timeout | Used for discovery, token, and UserInfo calls. |
| `WithBootstrapTimeout(duration)` | `30s` | Bounds the time `New` will spend on OIDC discovery. |

### `RP.Login` options

Per-login options for `rp.Login(w, r, opts ...LoginOption)`; `Handlers().Login`
is `Login` with `WithLoginTarget(r.URL.Query().Get("target"))`.

| Option | Default | Purpose |
| --- | --- | --- |
| `WithLoginTarget(string)` | `/` | Post-login target, sanitised like `?target=` (app-local paths only, over 1024 bytes the query is dropped). |
| `WithLoginContext(LoginContext)` | | Signed (not encrypted) data handed to `OnAuthenticated`, `OnRedirect` and `OnLoginError` on the callback. |
| `WithLoginScopes(...string)` | | Scopes requested for this login on top of the RP's own. |
| `WithLoginInitError(fn)` | `500` | Replaces the response when the login cannot start (transit cookie too large). |

## `native.New(codes, sessions, hooks, clients, encryptionKey, opts ...Option)`

See [Native apps](../guide/native).

### Required parameters

| Parameter | Type | Purpose |
| --- | --- | --- |
| `codes` | `repository.Code` | Pending one-time codes. `repository.NewDefaultCode(persistor)` on MongoDB. |
| `sessions` | `repository.Session` | Refresh sessions. `repository.NewDefaultSession(persistor)` on MongoDB. |
| `hooks` | `native.Hooks` | `Authenticate` (login and every refresh) and `Mint` (access tokens). Both required. |
| `clients` | `[]native.Client` | Registered apps: unique `ID`, at least one exact `RedirectURIs` entry (scheme required, no fragment). |
| `encryptionKey` | `[]byte` | AES-256-GCM key for stored IdP refresh tokens. Exactly 32 bytes. |

### Options

| Option | Default | Purpose |
| --- | --- | --- |
| `WithCodeTTL(duration)` | `60s` | Lifetime of a one-time code. |
| `WithSessionTTL(duration)` | `90 days` | Absolute lifetime of a refresh session. |
| `WithRotationGrace(duration)` | `10s` | How long the previous refresh token keeps working after a rotation. `0` disables. |
| `WithDeprecatedEncryptionKeys(...[]byte)` | | Previous 32-byte keys that still decrypt. Empty entries are skipped. |
| `WithLoginScopes(...string)` | `offline_access` | Scopes native logins request on top of the RP's. No arguments: none. |
| `WithErrorLogger(fn)` | silent | Routes runtime errors to the supplied logger. |
| `WithClock(func() time.Time)` | `time.Now` | For tests. |

## `oidc/native/repository`

| Constructor | Purpose |
| --- | --- |
| `NewDefaultCode(*keelmongo.Persistor)` | Codes in `gosso_native_codes` (`DefaultCodeName`), indexes `DefaultCodeIndices`. |
| `NewDefaultSession(*keelmongo.Persistor)` | Sessions in `gosso_native_sessions` (`DefaultSessionName`), indexes `DefaultSessionIndices`. |
| `NewCode(*keelmongo.Collection)` | Codes in a collection you opened yourself; it must carry `DefaultCodeIndices` or equivalents. |
| `NewSession(*keelmongo.Collection)` | Sessions likewise, with `DefaultSessionIndices`. |

Both index sets are a unique index on `id` and a TTL index on `expiresAt`
(`expireAfterSeconds: 0`). The TTL index only collects garbage: the broker
checks expiry itself.
