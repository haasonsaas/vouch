package telemetry

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type loggingExporter struct {
	logger zerolog.Logger
}

func newLoggingExporter() sdktrace.SpanExporter {
	return &loggingExporter{logger: log.With().Str("component", "otel").Logger()}
}

func newLoggingExporterWithLogger(logger zerolog.Logger) sdktrace.SpanExporter {
	return &loggingExporter{logger: logger}
}

func (l *loggingExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	for _, span := range spans {
		sc := span.SpanContext()
		event := l.logger.Info()
		if sc.TraceID().IsValid() {
			event = event.Str("trace_id", sc.TraceID().String())
		}
		if sc.SpanID().IsValid() {
			event = event.Str("span_id", sc.SpanID().String())
		}
		parent := span.Parent()
		if parent.IsValid() {
			event = event.Str("parent_span_id", parent.SpanID().String())
		}
		event = event.Str("span_name", span.Name())
		event = event.Str("span_kind", span.SpanKind().String())
		event = event.Time("start_time", span.StartTime())
		event = event.Dur("duration", span.EndTime().Sub(span.StartTime()))
		attrs := span.Attributes()
		fields := make(map[string]any, len(attrs))
		for _, attr := range attrs {
			fields[string(attr.Key)] = attr.Value.Emit()
		}
		if len(fields) > 0 {
			event = event.Fields(fields)
		}
		event.Msg("otel span completed")
	}
	return nil
}

func (l *loggingExporter) Shutdown(context.Context) error {
	return nil
}

func (l *loggingExporter) ForceFlush(context.Context) error {
	return nil
}

var _ sdktrace.SpanExporter = (*loggingExporter)(nil)
