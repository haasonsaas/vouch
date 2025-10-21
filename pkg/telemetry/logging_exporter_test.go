package telemetry

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type captureWriter struct {
	entries []string
}

func (c *captureWriter) Write(p []byte) (int, error) {
	c.entries = append(c.entries, string(p))
	return len(p), nil
}

func TestLoggingExporterEmitsSpan(t *testing.T) {
	writer := &captureWriter{}
	logger := zerolog.New(writer)
	exporter := newLoggingExporterWithLogger(logger)
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)),
	)
	ctx := context.Background()
	tracer := provider.Tracer("test")
	_, span := tracer.Start(ctx, "test-span")
	span.SetAttributes(attribute.String("key", "value"))
	span.End()
	if err := provider.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
	if len(writer.entries) == 0 {
		t.Fatal("expected log entry")
	}
}
