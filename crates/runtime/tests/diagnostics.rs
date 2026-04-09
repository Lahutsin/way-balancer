use lb_observability::{
    DiagnosticsLimits, RedactionEngine, StructuredLogRecord, SupportBundleBuilder,
    TelemetryEventCode, TelemetryLabel, TelemetryLabelKey, TelemetrySeverity,
};
use lb_runtime::{HttpCacheStore, HttpCacheStoreConfig, RuntimeTelemetry};

#[test]
fn runtime_diagnostics_are_bounded_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let telemetry = RuntimeTelemetry::new()?;
    telemetry.push_log(StructuredLogRecord {
        severity: TelemetrySeverity::Warn,
        code: TelemetryEventCode::TraceContextRejected,
        message: String::from("authorization: bearer top-secret"),
        labels: vec![TelemetryLabel::new(TelemetryLabelKey::Reason, "token")],
    });
    let builder = SupportBundleBuilder::new(RedactionEngine);
    let store = HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 4,
        max_bytes: 1024,
        max_object_bytes: 512,
    })?;
    let diagnostics = telemetry.collect_runtime_diagnostics(
        DiagnosticsLimits {
            max_metrics_bytes: 128,
            max_log_records: 1,
            max_event_records: 4,
            max_artifact_bytes: 256,
        },
        &builder,
    );

    assert_eq!(diagnostics.logs.len(), 1);
    assert_eq!(diagnostics.logs[0].message, "[REDACTED]");
    assert!(diagnostics.redaction_hit_count >= 1);

    let diagnostics_with_cache = telemetry.collect_runtime_diagnostics_with_cache(
        DiagnosticsLimits::default(),
        &builder,
        Some(("public-http", &store.snapshot())),
    );
    assert!(diagnostics_with_cache.cache_diagnostics_text.contains("scope=public-http"));
    Ok(())
}
