package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/foomo/go/options"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/internal/telemetry"
)

const (
	defaultTransitCookieName = "gosso_oidc_transit"
	defaultTransitTTL        = 5 * time.Minute
	defaultHTTPClientTimeout = 15 * time.Second
	defaultBootstrapTimeout  = 30 * time.Second
)

// RP is a constructed OIDC Relying Party. Obtain one from New and mount
// the values returned by Handlers onto the consumer's router.
type RP struct {
	// configuration
	issuerURL             string
	clientID              string
	clientSecret          string
	redirectURL           string
	extraScopes           []string
	claimMap              ClaimMap
	fetchUserInfo         bool
	issuerValidator       func(iss string) error
	transitSigningKey     []byte
	transitDeprecatedKeys [][]byte
	transitCookieName     string
	transitTTL            time.Duration
	postLogoutRedirectURL string
	httpClient            *http.Client
	bootstrapTimeout      time.Duration
	onAuthenticated       sso.OnAuthenticated[Payload]
	onRedirect            OnRedirect
	onLogout              sso.OnLogout
	errorLogger           sso.ErrorLogger
	logoutHintProvider    LogoutHintProvider
	discoveryBaseURL      string

	// runtime
	provider   *gooidc.Provider
	verifier   *gooidc.IDTokenVerifier
	oauth2Cfg  *oauth2.Config
	transit    *transitCodec
	endSession string
}

// New constructs an OIDC Relying Party. It performs OIDC discovery
// synchronously; a slow or unreachable IdP surfaces as an error here
// (bounded by the bootstrap timeout).
//
// The mandatory parameters are:
//   - ctx: context of the calling service
//   - issuerURL: OIDC issuer; all endpoints are populated from
//     `<issuer>/.well-known/openid-configuration` unless overridden.
//     Must be HTTPS; loopback hosts are allowed over HTTP for local
//     development.
//   - clientID, clientSecret: confidential-client credentials.
//   - redirectURL: callback URL matching the redirect_uri registered at
//     the IdP. HTTPS required (loopback exception applies).
//   - transitSigningKey: HMAC-SHA256 key used to sign the short-lived
//     transit cookie carrying state, nonce and PKCE verifier. Minimum
//     32 bytes.
//   - onAuthenticated: callback invoked after a successful code
//     exchange + ID token verification.
func New(
	ctx context.Context,
	issuerURL string,
	clientID string,
	clientSecret string,
	redirectURL string,
	transitSigningKey []byte,
	onAuthenticated sso.OnAuthenticated[Payload],
	opts ...Option,
) (*RP, error) {
	if issuerURL == "" {
		return nil, fmt.Errorf("issuer url must not be empty")
	}

	issuerParsed, err := url.Parse(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("parse issuer url: %w", err)
	}

	if clientID == "" {
		return nil, fmt.Errorf("client id must not be empty")
	}

	if clientSecret == "" {
		return nil, fmt.Errorf("client secret must not be empty")
	}

	redirectParsed, err := url.Parse(redirectURL)
	if err != nil {
		return nil, fmt.Errorf("parse redirect url: %w", err)
	}

	if redirectParsed.Scheme == "" || redirectParsed.Host == "" {
		return nil, fmt.Errorf("redirect url must be absolute: %s", redirectURL)
	}

	if len(transitSigningKey) < minTransitSigningKeyBytes {
		return nil, fmt.Errorf("transit signing key must be at least %d bytes, got %d", minTransitSigningKeyBytes, len(transitSigningKey))
	}

	if onAuthenticated == nil {
		return nil, fmt.Errorf("onAuthenticated must not be nil")
	}

	rp := &RP{
		issuerURL:         issuerURL,
		clientID:          clientID,
		clientSecret:      clientSecret,
		redirectURL:       redirectURL,
		transitSigningKey: append([]byte(nil), transitSigningKey...),
		onAuthenticated:   onAuthenticated,
		claimMap:          StandardClaimMap,
		transitCookieName: defaultTransitCookieName,
		transitTTL:        defaultTransitTTL,
		httpClient:        newInstrumentedHTTPClient(defaultHTTPClientTimeout),
		bootstrapTimeout:  defaultBootstrapTimeout,
		onLogout:          noopOnLogout,
	}
	if err := options.ApplyE(rp, opts...); err != nil {
		return nil, err
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, rp.bootstrapTimeout)
	defer cancel()

	if len(rp.discoveryBaseURL) == 0 {
		if err := requireSecureURL(issuerParsed, "issuer url"); err != nil {
			return nil, err
		}

		if err := requireSecureURL(redirectParsed, "redirect url"); err != nil {
			return nil, err
		}

		if err = rp.bootstrap(ctxTimeout, redirectParsed, rp.issuerURL); err != nil {
			return nil, err
		}
	} else {
		// Provider will be discovered with the discoveryBaseURL, but use issuerURL
		// for future issuer validation.
		ctxInsecure := gooidc.InsecureIssuerURLContext(ctxTimeout, rp.issuerURL)

		// Provider will be discovered with the discoveryBaseURL, but use issuerURL
		// for future issuer validation.
		if err = rp.bootstrap(ctxInsecure, redirectParsed, rp.discoveryBaseURL); err != nil {
			return nil, err
		}
	}

	return rp, nil
}

func (rp *RP) bootstrap(ctx context.Context, redirectParsed *url.URL, issuerURL string) error {
	ctx = gooidc.ClientContext(ctx, rp.httpClient)

	discoverCtx, discoverSpan := telemetry.Tracer().Start(ctx, "oidc.discover",
		trace.WithAttributes(oidcProtocolAttr),
	)

	provider, err := gooidc.NewProvider(discoverCtx, rp.issuerURL)
	if err != nil {
		discoverSpan.RecordError(err)
		discoverSpan.End()

		return fmt.Errorf("oidc discovery: %w", err)
	}

	discoverSpan.End()

	rp.provider = provider

	verifierCfg := &gooidc.Config{
		ClientID: rp.clientID,
	}
	if rp.issuerValidator != nil {
		verifierCfg.SkipIssuerCheck = true
	}

	rp.verifier = provider.Verifier(verifierCfg)

	rp.oauth2Cfg = &oauth2.Config{
		ClientID:     rp.clientID,
		ClientSecret: rp.clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  rp.redirectURL,
		Scopes:       rp.scopes(),
	}

	// The transit cookie is scoped to the callback path: it is read only
	// at /callback and the login handler still gets to set it (browsers
	// store Set-Cookie headers regardless of the setting request's path).
	rp.transit = &transitCodec{
		name:           rp.transitCookieName,
		ttl:            rp.transitTTL,
		path:           redirectParsed.Path,
		signingKey:     rp.transitSigningKey,
		deprecatedKeys: rp.transitDeprecatedKeys,
		secure:         redirectParsed.Scheme == "https",
	}

	// Resolve end_session_endpoint from the provider discovery document.
	var claims struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&claims); err == nil {
		rp.endSession = claims.EndSession
	}

	return nil
}

func (rp *RP) scopes() []string {
	base := []string{gooidc.ScopeOpenID, "profile", "email"}
	if len(rp.extraScopes) == 0 {
		return base
	}

	seen := make(map[string]struct{}, len(base)+len(rp.extraScopes))

	out := make([]string, 0, len(base)+len(rp.extraScopes))
	for _, s := range append(base, rp.extraScopes...) {
		if s == "" {
			continue
		}

		if _, dup := seen[s]; dup {
			continue
		}

		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}

// authorizeURL builds the /authorize URL with all OIDC + PKCE params.
func (rp *RP) authorizeURL(state, nonce, challenge string) string {
	return rp.oauth2Cfg.AuthCodeURL(
		state,
		gooidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// newInstrumentedHTTPClient builds the default HTTP client used by this
// package for discovery, token exchange and UserInfo. The transport is
// wrapped with otelhttp so consumers with an OTel TracerProvider see
// automatic client spans around every outbound call; without a
// provider, otelhttp is a no-op.
func newInstrumentedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}

func noopOnLogout(_ context.Context, _ http.ResponseWriter, _ *http.Request) error { return nil }
