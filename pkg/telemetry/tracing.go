package telemetry

import (
	"context"
	"errors"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// SetupTracing configures an OpenTelemetry tracer provider with optional OTLP exporter
// and installs global propagators. Returns the provider so callers can shut it down.
func SetupTracing(ctx context.Context, serviceName, serviceVersion, endpoint string, insecure bool, sampleRatio float64) (*sdktrace.TracerProvider, error) {
	if sampleRatio <= 0 || sampleRatio > 1 {
		sampleRatio = 1
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRatio))
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(serviceVersion),
	)

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
	}

	if endpoint != "" {
		clientOpts := []otlptracehttp.Option{}
		// The OTLP HTTP exporter expects an endpoint without scheme by default. If a scheme is provided,
		// strip it and mark the exporter as insecure when using HTTP.
		ep := endpoint
		if strings.HasPrefix(endpoint, "https://") {
			ep = strings.TrimPrefix(endpoint, "https://")
		} else if strings.HasPrefix(endpoint, "http://") {
			ep = strings.TrimPrefix(endpoint, "http://")
			insecure = true
		}
		if ep == "" {
			return nil, errors.New("invalid OTLP endpoint")
		}
		clientOpts = append(clientOpts, otlptracehttp.WithEndpoint(ep))
		if insecure {
			clientOpts = append(clientOpts, otlptracehttp.WithInsecure())
		}

		exporter, err := otlptracehttp.New(ctx, clientOpts...)
		if err != nil {
			return nil, err
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	provider := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	return provider, nil
}
