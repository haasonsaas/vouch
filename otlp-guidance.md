# OTLP Tracing Deployment Guidance

## Overview
Vouch services emit OpenTelemetry traces. To collect them, deploy an OTLP-compatible backend (OpenTelemetry Collector, Jaeger, Tempo, etc.) and point both the server and agents at the collector endpoint via config or environment variables.

## Minimal OpenTelemetry Collector
Example `docker-compose` snippet for a collector listening on OTLP HTTP:

```yaml
services:
  otel-collector:
    image: otel/opentelemetry-collector:0.99.0
    command: ["--config=/etc/otel-config.yaml"]
    volumes:
      - ./otel-config.yaml:/etc/otel-config.yaml:ro
    ports:
      - "4318:4318"  # OTLP HTTP ingest
```

`otel-config.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  logging:
    loglevel: info
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: []
      exporters: [logging, jaeger]
```

## Configuring Vouch
Both server and agent read tracing settings from config and environment variables.

### Environment Variables
- `VOUCH_TRACE_ENDPOINT` / `VOUCH_AGENT_TRACE_ENDPOINT`: host:port for OTLP HTTP (without scheme). Example: `collector:4318`.
- `VOUCH_TRACE_INSECURE` / `VOUCH_AGENT_TRACE_INSECURE`: `true` to allow plaintext HTTP.
- `VOUCH_TRACE_SAMPLE_RATIO` / `VOUCH_AGENT_TRACE_SAMPLE_RATIO`: sampling ratio (0-1].
- `VOUCH_TRACE_LOG_SPANS` / `VOUCH_AGENT_TRACE_LOG_SPANS`: `true` to enable logging exporter fallback (spans logged via zerolog).

### Config File
Under `tracing`:
```yaml
tracing:
  endpoint: collector:4318
  insecure: true
  sample_ratio: 1.0
  log_spans: false
```

Restart services after updating environment variables or config.

## TLS Considerations
- For HTTPS collectors, keep `insecure: false` and provide `https://` in the endpoint. The tracer strips the scheme; ensure certificates validate.
- For local testing with self-signed certificates, set `insecure: true`.

## Observability
- When OTLP is unreachable, enable `log_spans` to log completed spans for diagnostic purposes.
- Monitor collector logs for dropped spans; consider adding batch processors or exporters as needed.

