package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/haasonsaas/vouch/pkg/telemetry"
)

func TestWithRequestContextSetsID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	baseLogger := zerolog.Nop()
	r := gin.New()
	r.Use(withRequestContext(baseLogger))
	r.GET("/ping", func(c *gin.Context) {
		if requestID(c) == "" {
			t.Error("request ID not set")
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	if resp.Header().Get(requestIDHeader) == "" {
		t.Fatal("expected request ID header")
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
}

func TestRespondErrorIncludesRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	baseLogger := zerolog.Nop()
	r := gin.New()
	r.Use(withRequestContext(baseLogger))
	r.GET("/fail", func(c *gin.Context) {
		respondError(c, http.StatusBadRequest, "boom", baseLogger)
	})

	req := httptest.NewRequest(http.MethodGet, "/fail", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
	if resp.Header().Get(requestIDHeader) == "" {
		t.Fatal("missing request ID header")
	}
}

func TestWithRequestContextPropagatesTraceparent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	spanRecorder := telemetry.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	originalProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	originalPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(originalProvider)
		otel.SetTextMapPropagator(originalPropagator)
	})

	baseLogger := zerolog.Nop()
	r := gin.New()
	r.Use(withRequestContext(baseLogger))
	r.GET("/ping", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	parentCtx, parentSpan := otel.Tracer("test").Start(context.Background(), "parent")
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	otel.GetTextMapPropagator().Inject(parentCtx, propagation.HeaderCarrier(req.Header))
	parentSpan.End()

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.Code)
	}

	serverSpan := spanRecorder.FirstSpanNamed("GET /ping")
	if serverSpan == nil {
		t.Fatal("expected server span to be recorded")
	}
	if got, want := serverSpan.Parent().SpanID(), parentSpan.SpanContext().SpanID(); got != want {
		t.Fatalf("unexpected parent span id: got %s want %s", got, want)
	}
}
