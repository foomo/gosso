// Package telemetry exposes the OpenTelemetry instrumentation scope used
// by the gosso adapters. Callers obtain the gosso-scoped Tracer/Meter
// through this package so every span and metric carries the same
// instrumentation name and is filterable in a backend.
//
// When no global TracerProvider or MeterProvider is configured, the
// returned tracer and meter are no-ops: gosso can therefore be imported
// safely by consumers with no telemetry stack, and lights up
// automatically once they wire one.
package telemetry

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// InstrumentationName is the instrumentation scope reported on every
// span and metric emitted by gosso.
const InstrumentationName = "github.com/foomo/gosso"

// Attribute keys used across both adapters. Kept as a small, stable set
// so backend dashboards can standardise on them.
const (
	AttrProtocol = "gosso.protocol"
	AttrStage    = "gosso.stage"
	AttrOutcome  = "outcome"
)

// Tracer returns the gosso-scoped Tracer.
func Tracer() trace.Tracer { return otel.Tracer(InstrumentationName) }

// Meter returns the gosso-scoped Meter.
func Meter() metric.Meter { return otel.Meter(InstrumentationName) }
