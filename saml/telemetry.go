package saml

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
)

var (
	loginStarted  metric.Int64Counter
	acsDuration   metric.Int64Histogram
	acsCompleted  metric.Int64Counter
	logoutStarted metric.Int64Counter
	sloHandled    metric.Int64Counter
)

func init() {
	m := telemetry.Meter()

	loginStarted, _ = m.Int64Counter(
		"gosso.saml.login.started",
		metric.WithDescription("Number of SAML login flows initiated"),
	)
	acsDuration, _ = m.Int64Histogram(
		"gosso.saml.acs.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Wall-clock duration of SAML assertion processing (parse + OnAuthenticated)"),
	)
	acsCompleted, _ = m.Int64Counter(
		"gosso.saml.acs.completed",
		metric.WithDescription("Number of SAML assertion flows completed, tagged by outcome and (on failure) stage"),
	)
	logoutStarted, _ = m.Int64Counter(
		"gosso.saml.logout.started",
		metric.WithDescription("Number of SAML logout flows initiated"),
	)
	sloHandled, _ = m.Int64Counter(
		"gosso.saml.slo.handled",
		metric.WithDescription("Number of SAML single-logout responses received"),
	)
}

// samlProtocolAttr is the protocol tag applied to every span created in
// this package.
var samlProtocolAttr = attribute.String(telemetry.AttrProtocol, "saml")

// fail routes a handler-level failure to the three sinks that matter:
// the active span, the consumer's ErrorLogger and (when non-nil) a
// completed-counter failure point with the stage attribute. See the
// matching helper on oidc.RP — they are intentionally parallel.
func (sp *SP) fail(ctx context.Context, r *http.Request, resultCounter metric.Int64Counter, stage string, err error) {
	span := trace.SpanFromContext(ctx)
	span.RecordError(err, trace.WithAttributes(attribute.String(telemetry.AttrStage, stage)))
	span.SetStatus(codes.Error, stage)

	if resultCounter != nil {
		resultCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String(telemetry.AttrOutcome, "failure"),
			attribute.String(telemetry.AttrStage, stage),
		))
	}

	if sp.errorLogger != nil {
		sp.errorLogger(r, stage, err)
	}
}
