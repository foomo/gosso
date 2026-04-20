package oidc

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
)

// Metric names are stable: consumers build dashboards and alerts against
// them. `completed` counters use (outcome, stage) attributes; `duration`
// histograms are plain milliseconds so rate/percentile queries work
// without attribute filtering.
var (
	loginStarted          metric.Int64Counter
	callbackStarted       metric.Int64Counter
	callbackCompleted     metric.Int64Counter
	callbackDuration      metric.Int64Histogram
	tokenExchangeDuration metric.Int64Histogram
	userinfoDuration      metric.Int64Histogram
	logoutStarted         metric.Int64Counter
)

func init() {
	m := telemetry.Meter()

	loginStarted, _ = m.Int64Counter(
		"gosso.oidc.login.started",
		metric.WithDescription("Number of OIDC login flows initiated"),
	)
	callbackStarted, _ = m.Int64Counter(
		"gosso.oidc.callback.started",
		metric.WithDescription("Number of OIDC callback flows entered"),
	)
	callbackCompleted, _ = m.Int64Counter(
		"gosso.oidc.callback.completed",
		metric.WithDescription("Number of OIDC callback flows completed, tagged by outcome and (on failure) stage"),
	)
	callbackDuration, _ = m.Int64Histogram(
		"gosso.oidc.callback.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Wall-clock duration of OIDC callback processing"),
	)
	tokenExchangeDuration, _ = m.Int64Histogram(
		"gosso.oidc.token_exchange.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Duration of the OIDC authorization-code → token exchange"),
	)
	userinfoDuration, _ = m.Int64Histogram(
		"gosso.oidc.userinfo.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Duration of the OIDC UserInfo call"),
	)
	logoutStarted, _ = m.Int64Counter(
		"gosso.oidc.logout.started",
		metric.WithDescription("Number of OIDC logout flows initiated"),
	)
}

// oidcProtocolAttr is the protocol tag applied to every span created in
// this package.
var oidcProtocolAttr = attribute.String(telemetry.AttrProtocol, "oidc")

// fail routes a handler-level failure to the three sinks that matter:
// the active span (error + status), the consumer's ErrorLogger, and —
// when the caller passes a non-nil counter — a `completed{outcome=
// failure, stage=...}` data point on that counter.
//
// The counter is optional because login/logout failures are rare and
// don't warrant their own result counters; the span and ErrorLogger
// still fire in those cases.
func (rp *RP) fail(ctx context.Context, r *http.Request, resultCounter metric.Int64Counter, stage string, err error) {
	span := trace.SpanFromContext(ctx)
	span.RecordError(err, trace.WithAttributes(attribute.String(telemetry.AttrStage, stage)))
	span.SetStatus(codes.Error, stage)

	if resultCounter != nil {
		resultCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String(telemetry.AttrOutcome, "failure"),
			attribute.String(telemetry.AttrStage, stage),
		))
	}

	if rp.errorLogger != nil {
		rp.errorLogger(r, stage, err)
	}
}
