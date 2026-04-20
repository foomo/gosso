package saml

import (
	"net/http"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
)

// sessionProvider is the adapter through which crewjam/saml hands off a
// validated assertion. We do not maintain a session ourselves:
//
//   - CreateSession parses the assertion and invokes OnAuthenticated.
//   - GetSession always returns ErrNoSession so the middleware
//     re-initiates the SAML round-trip on every RequireAccount call.
//   - DeleteSession is a no-op; the consumer already cleared its session
//     in OnLogout.
type sessionProvider struct {
	sp *SP
}

var _ samlsp.SessionProvider = (*sessionProvider)(nil)

func (s *sessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	ctx, span := telemetry.Tracer().Start(r.Context(), "saml.acs",
		trace.WithAttributes(samlProtocolAttr),
	)
	defer span.End()

	r = r.WithContext(ctx)
	start := time.Now()

	defer func() {
		acsDuration.Record(ctx, time.Since(start).Milliseconds())
	}()

	sub := parseAssertion(assertion, s.sp.attributeMap)

	if err := s.sp.onAuthenticated(ctx, w, r, sub); err != nil {
		s.sp.fail(ctx, r, acsCompleted, "on-authenticated", err)
		return err
	}

	acsCompleted.Add(ctx, 1, metric.WithAttributes(
		attribute.String(telemetry.AttrOutcome, "success"),
	))

	return nil
}

func (s *sessionProvider) DeleteSession(_ http.ResponseWriter, _ *http.Request) error {
	return nil
}

func (s *sessionProvider) GetSession(_ *http.Request) (samlsp.Session, error) {
	return nil, samlsp.ErrNoSession
}
