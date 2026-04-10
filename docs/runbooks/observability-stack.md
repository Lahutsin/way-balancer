# Observability Stack

## Purpose

This runbook defines the operator-facing telemetry contract for the runtime observability stack.

## Structured Logs And Events

- Structured logs mirror bounded telemetry events emitted through `lb_runtime::RuntimeTelemetry`.
- Event codes are stable and sourced from `lb_observability::TelemetryEventCode`.
- Log labels are bounded and sanitized through `lb_observability::TelemetryLabel` and `TelemetryLabelKey`.
- Correlation fields use normalized `correlation_id`, `trace_id`, and `span_id` values.

## Metrics Contract

The runtime exports Prometheus text via `RuntimeTelemetry::export_metrics()`.

Stable metric families currently include:

- `runtime_listener_active_connections`
- `runtime_listener_accepted_connections`
- `runtime_listener_rejected_connections`
- `runtime_listener_events_total`
- `runtime_breaker_events_total`
- `runtime_overload_state`
- `runtime_shed_requests_total`
- `runtime_overload_active_signals`
- `runtime_overload_rate_limited`
- `runtime_overload_concurrency_limited`
- `runtime_overload_breaker_open`
- `runtime_overload_retry_budget_exhausted`
- `runtime_overload_brownout_features`
- `runtime_tracing_enabled`
- `runtime_trace_hooks_total`
- `runtime_invalid_tracing_metadata_total`
- `runtime_request_latency_samples_total`
- `runtime_http_cache_entries`
- `runtime_http_cache_bytes`
- `runtime_http_cache_max_object_bytes`
- `runtime_http_cache_requests_total`
- `runtime_http_cache_revalidations_total`
- `runtime_http_cache_purge_requests_total`
- `runtime_http_cache_purged_entries_total`

## Label Contract

Stable labels currently include:

- `listener`
- `state`
- `scope`
- `event_code`
- `result`
- `reason`
- `phase`
- `bucket`
- `component`
- `correlation_id`
- `trace_id`
- `span_id`

All label values are normalized to lowercase bounded identifiers. Values that look unsafe or high-entropy are redacted before emission.

## Latency Buckets

`runtime_request_latency_samples_total` exports bounded latency buckets for critical request-flow phases. The current buckets are:

- `le_1ms`
- `le_5ms`
- `le_10ms`
- `le_25ms`
- `le_50ms`
- `le_100ms`
- `le_250ms`
- `le_500ms`
- `le_1000ms`
- `gt_1000ms`

These counters are intended for dashboard heatmaps, SLO burn-rate approximations, and alert thresholds on slow-path growth.

## Tracing Semantics

- Incoming tracing metadata is accepted only if it passes normalization.
- Invalid incoming correlation or trace fields are counted in `runtime_invalid_tracing_metadata_total`.
- Trace hook emission is controlled by `TracingPolicy` and reflected by `runtime_tracing_enabled`.

## Validation

Focused contract coverage currently lives in:

- `cargo test -p lb-runtime --test telemetry`
- `cargo test -p lb-runtime --test tracing`

These tests lock in metric names, label contracts, correlation handling, and trace-hook export behavior.