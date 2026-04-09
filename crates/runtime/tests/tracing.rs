use lb_observability::{IncomingTraceContext, TraceHookPhase, TracingPolicy};
use lb_runtime::RuntimeTelemetry;

#[test]
fn preserves_valid_incoming_correlation_context() -> Result<(), Box<dyn std::error::Error>> {
    let telemetry = RuntimeTelemetry::new()?;
    let context = telemetry.establish_trace_context(
        "http1/request",
        IncomingTraceContext {
            correlation_id: Some(String::from("REQ-1234_abcd")),
            trace_id: Some(String::from("0123456789abcdef0123456789abcdef")),
            parent_span_id: Some(String::from("abcdef0123456789")),
        },
    )?;
    telemetry.record_trace_hook(
        "http1/request",
        &context,
        TraceHookPhase::RequestReceived,
        "request received",
    )?;
    telemetry.record_trace_hook(
        "http1/request",
        &context,
        TraceHookPhase::ResponseCompleted,
        "response completed",
    )?;

    assert_eq!(context.correlation_id.as_str(), "req-1234_abcd");
    assert_eq!(context.trace_id.as_str(), "0123456789abcdef0123456789abcdef");
    assert_eq!(context.parent_span_id.as_ref().map(|span| span.as_str()), Some("abcdef0123456789"));

    let metrics = telemetry.export_metrics();
    assert!(metrics.contains("runtime_trace_hooks_total{phase=\"request_received\"} 1"));
    assert!(metrics.contains("runtime_trace_hooks_total{phase=\"response_completed\"} 1"));
    let snapshot = telemetry.snapshot();
    assert!(snapshot.events.iter().any(|event| event.code.as_str() == "trace.context.accepted"));
    assert!(snapshot.events.iter().any(|event| event.code.as_str() == "trace.hook.emitted"));
    assert!(snapshot.logs.iter().any(|record| {
        record
            .labels
            .iter()
            .any(|label| label.key.as_str() == "correlation_id" && label.value == "req-1234_abcd")
    }));
    Ok(())
}

#[test]
fn invalid_incoming_trace_metadata_is_rejected_and_regenerated(
) -> Result<(), Box<dyn std::error::Error>> {
    let telemetry = RuntimeTelemetry::new()?;
    let context = telemetry.establish_trace_context(
        "http2/stream",
        IncomingTraceContext {
            correlation_id: Some(String::from("user@example.com?token=abc")),
            trace_id: Some(String::from("bad trace")),
            parent_span_id: Some(String::from("span???")),
        },
    )?;

    assert!(context.correlation_id.as_str().starts_with("corr-"));
    assert_eq!(context.parent_span_id, None);

    let metrics = telemetry.export_metrics();
    assert!(metrics.contains("runtime_invalid_tracing_metadata_total{reason=\"correlation_id\"} 1"));
    assert!(metrics.contains("runtime_invalid_tracing_metadata_total{reason=\"trace_id\"} 1"));
    assert!(metrics.contains("runtime_invalid_tracing_metadata_total{reason=\"parent_span_id\"} 1"));
    let snapshot = telemetry.snapshot();
    assert!(snapshot.events.iter().any(|event| event.code.as_str() == "trace.context.rejected"));
    Ok(())
}

#[test]
fn disabled_tracing_suppresses_hook_emission_but_exposes_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let telemetry = RuntimeTelemetry::with_tracing_policy(TracingPolicy { enabled: false })?;
    let context =
        telemetry.establish_trace_context("grpc/unary", IncomingTraceContext::default())?;
    telemetry.record_trace_hook(
        "grpc/unary",
        &context,
        TraceHookPhase::RequestReceived,
        "request received",
    )?;

    let metrics = telemetry.export_metrics();
    assert!(metrics.contains("runtime_tracing_enabled{component=\"runtime\"} 0"));
    assert!(!metrics.contains("runtime_trace_hooks_total{phase=\"request_received\"}"));
    let snapshot = telemetry.snapshot();
    assert!(snapshot.events.iter().any(|event| event.code.as_str() == "trace.context.generated"));
    assert!(!snapshot.events.iter().any(|event| event.code.as_str() == "trace.hook.emitted"));
    Ok(())
}
