package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/foomo/go/options"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/internal/telemetry"
)

const (
	defaultHTTPClientTimeout = 15 * time.Second
	defaultBootstrapTimeout  = 30 * time.Second
)

// SP is a constructed SAML Service Provider. Obtain one from New and
// mount the values returned by Handlers onto the consumer's router.
type SP struct {
	// configuration (set by New + options, read-only after New returns)
	entityID              string
	rootURL               *url.URL
	idpMetadataURL        *url.URL
	cert                  *x509.Certificate
	key                   *rsa.PrivateKey
	attributeMap          AttributeMap
	httpClient            *http.Client
	bootstrapTimeout      time.Duration
	allowIDPInitiated     bool
	onAuthenticated       sso.OnAuthenticated[Payload]
	onLogout              sso.OnLogout
	errorLogger           sso.ErrorLogger
	sloHintProvider       SLOHintProvider
	postLogoutRedirectURL string

	// runtime
	middleware    *samlsp.Middleware
	startAuthFlow func(http.ResponseWriter, *http.Request)
}

// New constructs a SAML Service Provider. It fetches the IdP metadata
// synchronously, so a slow or unreachable IdP endpoint will surface as
// an error here (bounded by the bootstrap timeout).
//
// The mandatory parameters are:
//   - entityID: the SAML Entity ID advertised in SP metadata.
//   - rootURL: externally reachable base URL of the consuming service
//     (e.g. `https://app.example.com`); metadata, ACS and logout URLs
//     are derived from it.
//   - idpMetadataURL: the IdP metadata endpoint, fetched during New.
//   - cert, key: the SP's x509 cert / RSA key pair. Use LoadKeyPair or
//     ParseKeyPair to obtain them.
//   - onAuthenticated: the callback that receives the parsed Subject
//     after a successful assertion.
func New(
	entityID string,
	rootURL string,
	idpMetadataURL string,
	cert *x509.Certificate,
	key *rsa.PrivateKey,
	onAuthenticated sso.OnAuthenticated[Payload],
	opts ...Option,
) (*SP, error) {
	if entityID == "" {
		return nil, fmt.Errorf("entity id must not be empty")
	}

	rootParsed, err := url.Parse(rootURL)
	if err != nil {
		return nil, fmt.Errorf("parse root url: %w", err)
	}

	if rootParsed.Scheme == "" || rootParsed.Host == "" {
		return nil, fmt.Errorf("root url must be absolute: %s", rootURL)
	}

	idpParsed, err := url.Parse(idpMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("parse idp metadata url: %w", err)
	}

	if cert == nil || key == nil {
		return nil, fmt.Errorf("cert and key must not be nil")
	}

	if onAuthenticated == nil {
		return nil, fmt.Errorf("onAuthenticated must not be nil")
	}

	sp := &SP{
		entityID:         entityID,
		rootURL:          rootParsed,
		idpMetadataURL:   idpParsed,
		cert:             cert,
		key:              key,
		onAuthenticated:  onAuthenticated,
		attributeMap:     AzureADAttributeMap,
		httpClient:       newInstrumentedHTTPClient(defaultHTTPClientTimeout),
		bootstrapTimeout: defaultBootstrapTimeout,
		onLogout:         noopOnLogout,
	}
	if err := options.ApplyE(sp, opts...); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), sp.bootstrapTimeout)
	defer cancel()

	mw, err := sp.buildMiddleware(ctx)
	if err != nil {
		return nil, err
	}

	sp.middleware = mw
	// Replace the default cookie-based session provider with our
	// stateless adapter that invokes OnAuthenticated.
	sp.middleware.Session = &sessionProvider{sp: sp}
	sp.startAuthFlow = sp.middleware.HandleStartAuthFlow

	return sp, nil
}

func (sp *SP) buildMiddleware(ctx context.Context) (*samlsp.Middleware, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "saml.fetch_metadata",
		trace.WithAttributes(samlProtocolAttr),
	)

	idpMeta, err := samlsp.FetchMetadata(ctx, sp.httpClient, *sp.idpMetadataURL)
	if err != nil {
		span.RecordError(err)
		span.End()

		return nil, fmt.Errorf("fetch idp metadata: %w", err)
	}

	span.End()

	return samlsp.New(samlsp.Options{
		EntityID:          sp.entityID,
		URL:               *sp.rootURL,
		Key:               sp.key,
		Certificate:       sp.cert,
		IDPMetadata:       idpMeta,
		HTTPClient:        sp.httpClient,
		AllowIDPInitiated: sp.allowIDPInitiated,
	})
}

// newInstrumentedHTTPClient builds the default HTTP client used for IdP
// metadata fetches. The transport is wrapped with otelhttp so consumers
// with an OTel TracerProvider see automatic client spans; without a
// provider, otelhttp is a no-op.
func newInstrumentedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}

func noopOnLogout(_ context.Context, _ http.ResponseWriter, _ *http.Request) error { return nil }
