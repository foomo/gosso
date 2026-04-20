package saml

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/foomo/go/options"
	sso "github.com/foomo/gosso"
)

// Option configures an SP.
type Option = options.OptionE[*SP]

// WithEntityID sets the SAML Entity ID advertised in SP metadata.
// Required.
func WithEntityID(id string) Option {
	return func(sp *SP) error {
		if id == "" {
			return fmt.Errorf("entity id must not be empty")
		}

		sp.entityID = id

		return nil
	}
}

// WithRootURL is the externally reachable base URL of the consuming
// service (e.g. `https://app.example.com`). Metadata, ACS and logout
// URLs are derived from it. Required.
func WithRootURL(rawURL string) Option {
	return func(sp *SP) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return fmt.Errorf("parse root url: %w", err)
		}

		if u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("root url must be absolute: %s", rawURL)
		}

		sp.rootURL = u

		return nil
	}
}

// WithIDPMetadataURL configures the IdP metadata endpoint. It is fetched
// during New. Required (unless WithIDPMetadata is used).
func WithIDPMetadataURL(rawURL string) Option {
	return func(sp *SP) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return fmt.Errorf("parse idp metadata url: %w", err)
		}

		sp.idpMetadataURL = u

		return nil
	}
}

// WithCertificate loads the SP's x509 cert / RSA key pair from disk.
// Required.
func WithCertificate(certPath, keyPath string) Option {
	return func(sp *SP) error {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return fmt.Errorf("load x509 key pair: %w", err)
		}

		return applyKeyPair(sp, pair, certPath)
	}
}

// WithCertificatePEM loads the SP cert / key from in-memory PEM bytes.
// Useful for tests or when secrets are injected from a vault.
func WithCertificatePEM(certPEM, keyPEM []byte) Option {
	return func(sp *SP) error {
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("x509 key pair: %w", err)
		}

		return applyKeyPair(sp, pair, "PEM input")
	}
}

func applyKeyPair(sp *SP, pair tls.Certificate, source string) error {
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("no certificate in %s", source)
	}

	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("certificate key must be RSA")
	}

	sp.cert = cert
	sp.key = key

	return nil
}

// WithAttributeMap overrides the default Azure-AD attribute URIs used
// when parsing an assertion.
func WithAttributeMap(m AttributeMap) Option {
	return func(sp *SP) error {
		sp.attributeMap = m
		return nil
	}
}

// WithOnAuthenticated registers the callback that receives the parsed
// Subject after a successful assertion. Required.
func WithOnAuthenticated(fn sso.OnAuthenticated[Payload]) Option {
	return func(sp *SP) error {
		if fn == nil {
			return fmt.Errorf("OnAuthenticated must not be nil")
		}

		sp.onAuthenticated = fn

		return nil
	}
}

// WithOnLogout registers a callback invoked when the logout handler
// fires. If not supplied, logout is a no-op before the SLO redirect.
func WithOnLogout(fn sso.OnLogout) Option {
	return func(sp *SP) error {
		sp.onLogout = fn
		return nil
	}
}

// WithErrorLogger routes runtime errors encountered by the SAML handlers
// to the supplied logger. HTTP responses stay generic regardless; the
// logger sees the underlying cause (e.g. IdP SLO construction failure,
// OnAuthenticated callback errors).
func WithErrorLogger(fn sso.ErrorLogger) Option {
	return func(sp *SP) error {
		sp.errorLogger = fn
		return nil
	}
}

// SLOHintProvider returns the NameID and SessionIndex required to build
// a SAML LogoutRequest. Typically the consumer extracts them from its
// own session. Returning an empty NameID skips the IdP-side SLO.
type SLOHintProvider func(*http.Request) (nameID, sessionIndex string)

// WithSLOHintProvider registers the callback used by the logout handler
// to build the IdP-side single-logout request. Without it, /logout is
// local-only: OnLogout fires and the response is HTTP 200.
func WithSLOHintProvider(fn SLOHintProvider) Option {
	return func(sp *SP) error {
		sp.sloHintProvider = fn
		return nil
	}
}

// WithPostLogoutRedirectURL sets the URL the SLO handler redirects to
// after the IdP signals it has cleared its session. Defaults to `/`.
func WithPostLogoutRedirectURL(u string) Option {
	return func(sp *SP) error {
		sp.postLogoutRedirectURL = u
		return nil
	}
}

// WithHTTPClient overrides the client used to fetch IdP metadata. The
// default client has a 15 second Timeout; a client supplied here is
// used as-is — set your own Timeout if you want one.
func WithHTTPClient(c *http.Client) Option {
	return func(sp *SP) error {
		if c == nil {
			return fmt.Errorf("http client must not be nil")
		}

		sp.httpClient = c

		return nil
	}
}

// WithBootstrapTimeout bounds the time `New` will spend fetching IdP
// metadata. Defaults to 30s. Values ≤ 0 are rejected.
func WithBootstrapTimeout(d time.Duration) Option {
	return func(sp *SP) error {
		if d <= 0 {
			return fmt.Errorf("bootstrap timeout must be > 0")
		}

		sp.bootstrapTimeout = d

		return nil
	}
}

// WithAllowIDPInitiated permits IdP-initiated login. Disabled by
// default; enable only if the IdP is trusted and the consumer does not
// rely on the request tracker to carry a target URL.
func WithAllowIDPInitiated(allow bool) Option {
	return func(sp *SP) error {
		sp.allowIDPInitiated = allow
		return nil
	}
}
