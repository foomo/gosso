package native

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/telemetry"
)

// attrGrantType tags token metrics with the grant type.
const attrGrantType = "grant_type"

var tokenCompleted metric.Int64Counter

func init() {
	tokenCompleted, _ = telemetry.Meter().Int64Counter(
		"gosso.oidc.native.token.completed",
		metric.WithDescription("Number of native token requests completed, tagged by grant type, outcome and (on failure) stage"),
	)
}

var oidcProtocolAttr = attribute.String(telemetry.AttrProtocol, "oidc")

// tokenSucceeded counts a successful token request.
func tokenSucceeded(ctx context.Context, grantType string) {
	tokenCompleted.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrGrantType, grantType),
		attribute.String(telemetry.AttrOutcome, "success"),
	))
}

// tokenFailed records a failed token request on the span and the counter;
// err, when set, also goes to the error logger.
func (b *Broker) tokenFailed(ctx context.Context, r *http.Request, grantType, stage string, err error) {
	span := trace.SpanFromContext(ctx)
	span.SetStatus(codes.Error, stage)

	if err != nil {
		span.RecordError(err, trace.WithAttributes(attribute.String(telemetry.AttrStage, stage)))
		b.logError(r, "native-token-"+stage, err)
	}

	tokenCompleted.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrGrantType, grantType),
		attribute.String(telemetry.AttrOutcome, "failure"),
		attribute.String(telemetry.AttrStage, stage),
	))
}
