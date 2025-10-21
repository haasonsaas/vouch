package main

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	requestIDContextKey     = "request_id"
	requestLoggerContextKey = "request_logger"
	requestIDHeader         = "X-Request-ID"
)

const tracerName = "github.com/haasonsaas/vouch/server"

func withRequestContext(base zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := c.GetHeader(requestIDHeader)
		if reqID == "" {
			reqID = xid.New().String()
		}
		c.Set(requestIDContextKey, reqID)
		c.Writer.Header().Set(requestIDHeader, reqID)

		logger := base.With().Str("request_id", reqID).Str("method", c.Request.Method).Str("path", c.FullPath()).Logger()
		c.Set(requestLoggerContextKey, logger)

		propagator := otel.GetTextMapPropagator()
		ctx := propagator.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))
		tracer := otel.Tracer(tracerName)
		spanName := c.Request.Method + " " + c.FullPath()
		ctx, span := tracer.Start(ctx, spanName, trace.WithSpanKind(trace.SpanKindServer))
		span.SetAttributes(attribute.String("http.method", c.Request.Method))
		span.SetAttributes(attribute.String("http.route", c.FullPath()))
		span.SetAttributes(attribute.String("http.target", c.Request.URL.RequestURI()))
		if reqID != "" {
			span.SetAttributes(attribute.String("request.id", reqID))
		}

		c.Request = c.Request.WithContext(ctx)
		c.Set("otel_span", span)

		c.Next()

		status := c.Writer.Status()
		span.SetAttributes(attribute.Int("http.status_code", status))
		if status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(status))
		}
		span.End()
	}
}

func requestLogger(c *gin.Context, fallback zerolog.Logger) zerolog.Logger {
	if value, ok := c.Get(requestLoggerContextKey); ok {
		if logger, ok := value.(zerolog.Logger); ok {
			return logger
		}
	}
	return fallback
}

func requestID(c *gin.Context) string {
	if value, ok := c.Get(requestIDContextKey); ok {
		if id, ok := value.(string); ok {
			return id
		}
	}
	return ""
}

func respondError(c *gin.Context, status int, message string, fallback zerolog.Logger) {
	logger := requestLogger(c, fallback)
	entry := logger.Warn()
	if status >= http.StatusInternalServerError {
		entry = logger.Error()
	}
	entry.Int("status", status).Msg(message)
	if span := trace.SpanFromContext(c.Request.Context()); span.IsRecording() {
		span.AddEvent("http.error", trace.WithAttributes(
			attribute.Int("http.status_code", status),
			attribute.String("error.message", message),
		))
		if status >= http.StatusInternalServerError {
			span.RecordError(errors.New(message))
		}
	}

	c.AbortWithStatusJSON(status, gin.H{
		"error":      message,
		"request_id": requestID(c),
	})
}
