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
	// configuration (set by options, read-only after New returns)
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
func New(opts ...Option) (*SP, error) {
	sp := &SP{
		attributeMap:     AzureADAttributeMap,
		httpClient:       newInstrumentedHTTPClient(defaultHTTPClientTimeout),
		bootstrapTimeout: defaultBootstrapTimeout,
		onLogout:         noopOnLogout,
	}
	if err := options.ApplyE(sp, opts...); err != nil {
		return nil, err
	}

	if err := sp.validate(); err != nil {
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

func (sp *SP) validate() error {
	if sp.entityID == "" {
		return fmt.Errorf("WithEntityID is required")
	}

	if sp.rootURL == nil {
		return fmt.Errorf("WithRootURL is required")
	}

	if sp.idpMetadataURL == nil {
		return fmt.Errorf("WithIDPMetadataURL is required")
	}

	if sp.cert == nil || sp.key == nil {
		return fmt.Errorf("WithCertificate (or WithCertificatePEM) is required")
	}

	if sp.onAuthenticated == nil {
		return fmt.Errorf("WithOnAuthenticated is required")
	}

	return nil
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
