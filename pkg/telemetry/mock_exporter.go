package telemetry

import (
	"context"
	"sync"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type SpanRecorder struct {
	mu    sync.Mutex
	spans []sdktrace.ReadOnlySpan
}

func NewSpanRecorder() *SpanRecorder {
	return &SpanRecorder{}
}

func (r *SpanRecorder) OnStart(_ context.Context, _ sdktrace.ReadWriteSpan) {}

func (r *SpanRecorder) OnEnd(span sdktrace.ReadOnlySpan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans = append(r.spans, span)
}

func (r *SpanRecorder) Shutdown(context.Context) error { return nil }

func (r *SpanRecorder) ForceFlush(context.Context) error { return nil }

func (r *SpanRecorder) Completed() []sdktrace.ReadOnlySpan {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]sdktrace.ReadOnlySpan, len(r.spans))
	copy(out, r.spans)
	return out
}

func (r *SpanRecorder) FirstSpanNamed(name string) sdktrace.ReadOnlySpan {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, span := range r.spans {
		if span.Name() == name {
			return span
		}
	}
	return nil
}

var _ sdktrace.SpanProcessor = (*SpanRecorder)(nil)
