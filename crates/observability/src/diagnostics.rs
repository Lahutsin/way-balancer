use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{StructuredLogRecord, TelemetryEvent, TelemetryLabel};

const REDACTED_VALUE: &str = "[REDACTED]";
const SECRET_MARKERS: [&str; 8] =
    ["authorization", "password", "secret", "token", "api_key", "apikey", "cookie", "set-cookie"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticsLimits {
    pub max_metrics_bytes: usize,
    pub max_log_records: usize,
    pub max_event_records: usize,
    pub max_artifact_bytes: usize,
}

impl Default for DiagnosticsLimits {
    fn default() -> Self {
        Self {
            max_metrics_bytes: 16 * 1024,
            max_log_records: 64,
            max_event_records: 64,
            max_artifact_bytes: 32 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticsSection {
    Metrics,
    Logs,
    Events,
    Bundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsWarning {
    pub section: DiagnosticsSection,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDiagnosticsInput {
    pub metrics_text: Option<String>,
    pub logs: Option<Vec<StructuredLogRecord>>,
    pub events: Option<Vec<TelemetryEvent>>,
    pub cache_diagnostics_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDiagnostics {
    pub metrics_text: String,
    pub logs: Vec<StructuredLogRecord>,
    pub events: Vec<TelemetryEvent>,
    pub cache_diagnostics_text: String,
    pub warnings: Vec<DiagnosticsWarning>,
    pub redaction_hit_count: u64,
    pub truncation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleArtifact {
    pub name: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundle {
    pub bundle_name: String,
    pub artifacts: Vec<SupportBundleArtifact>,
    pub warnings: Vec<DiagnosticsWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SupportBundleMetrics {
    pub success_count: u64,
    pub failure_count: u64,
    pub redaction_hit_count: u64,
    pub truncation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticsError {
    EmptyBundleName,
}

impl fmt::Display for DiagnosticsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBundleName => formatter.write_str("support bundle name must not be empty"),
        }
    }
}

impl std::error::Error for DiagnosticsError {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedactionEngine;

impl RedactionEngine {
    #[must_use]
    pub fn redact_text(&self, input: &str) -> (String, bool) {
        let lowered = input.to_ascii_lowercase();
        if SECRET_MARKERS.iter().any(|marker| lowered.contains(marker)) {
            return (String::from(REDACTED_VALUE), true);
        }
        (input.to_string(), false)
    }
}

#[derive(Debug, Default)]
pub struct SupportBundleBuilder {
    redactor: RedactionEngine,
    success_count: AtomicU64,
    failure_count: AtomicU64,
    redaction_hit_count: AtomicU64,
    truncation_count: AtomicU64,
}

impl SupportBundleBuilder {
    #[must_use]
    pub fn new(redactor: RedactionEngine) -> Self {
        Self {
            redactor,
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
            redaction_hit_count: AtomicU64::new(0),
            truncation_count: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn collect_runtime_diagnostics(
        &self,
        limits: DiagnosticsLimits,
        input: RuntimeDiagnosticsInput,
    ) -> RuntimeDiagnostics {
        let mut warnings = Vec::new();
        let mut redaction_hit_count = 0_u64;
        let mut truncation_count = 0_u64;

        let metrics_text = match input.metrics_text {
            Some(metrics) => {
                let (redacted, redacted_hit) = self.redact_and_truncate_text(
                    &metrics,
                    limits.max_metrics_bytes,
                    DiagnosticsSection::Metrics,
                    &mut warnings,
                );
                if redacted_hit > 0 {
                    redaction_hit_count += redacted_hit;
                }
                redacted.0
            }
            None => {
                warnings.push(DiagnosticsWarning {
                    section: DiagnosticsSection::Metrics,
                    detail: String::from(
                        "metrics section unavailable during diagnostics collection",
                    ),
                });
                String::new()
            }
        };

        let logs = match input.logs {
            Some(logs) => {
                let (logs, redactions, truncated) =
                    self.redact_logs(logs, limits.max_log_records, &mut warnings);
                redaction_hit_count += redactions;
                if truncated {
                    truncation_count += 1;
                }
                logs
            }
            None => {
                warnings.push(DiagnosticsWarning {
                    section: DiagnosticsSection::Logs,
                    detail: String::from("logs section unavailable during diagnostics collection"),
                });
                Vec::new()
            }
        };

        let events = match input.events {
            Some(events) => {
                let (events, redactions, truncated) =
                    self.redact_events(events, limits.max_event_records, &mut warnings);
                redaction_hit_count += redactions;
                if truncated {
                    truncation_count += 1;
                }
                events
            }
            None => {
                warnings.push(DiagnosticsWarning {
                    section: DiagnosticsSection::Events,
                    detail: String::from(
                        "events section unavailable during diagnostics collection",
                    ),
                });
                Vec::new()
            }
        };

        let cache_diagnostics_text = match input.cache_diagnostics_text {
            Some(cache_text) => {
                let (redacted, redacted_hit) = self.redact_and_truncate_text(
                    &cache_text,
                    limits.max_artifact_bytes,
                    DiagnosticsSection::Bundle,
                    &mut warnings,
                );
                if redacted_hit > 0 {
                    redaction_hit_count += redacted_hit;
                }
                redacted.0
            }
            None => String::new(),
        };

        let warning_truncations =
            warnings.iter().filter(|warning| warning.detail.contains("truncated")).count() as u64;
        truncation_count += warning_truncations;
        self.redaction_hit_count.fetch_add(redaction_hit_count, Ordering::SeqCst);
        self.truncation_count.fetch_add(truncation_count, Ordering::SeqCst);

        RuntimeDiagnostics {
            metrics_text,
            logs,
            events,
            cache_diagnostics_text,
            warnings,
            redaction_hit_count,
            truncation_count,
        }
    }

    pub fn build_bundle(
        &self,
        bundle_name: &str,
        diagnostics: &RuntimeDiagnostics,
        limits: DiagnosticsLimits,
    ) -> Result<SupportBundle, DiagnosticsError> {
        if bundle_name.trim().is_empty() {
            self.failure_count.fetch_add(1, Ordering::SeqCst);
            return Err(DiagnosticsError::EmptyBundleName);
        }

        let mut warnings = diagnostics.warnings.clone();
        let metrics_artifact = self.build_artifact(
            "metrics.txt",
            diagnostics.metrics_text.clone(),
            limits.max_artifact_bytes,
            &mut warnings,
        );
        let logs_artifact = self.build_artifact(
            "logs.txt",
            render_logs(&diagnostics.logs),
            limits.max_artifact_bytes,
            &mut warnings,
        );
        let cache_artifact = (!diagnostics.cache_diagnostics_text.is_empty()).then(|| {
            self.build_artifact(
                "cache.txt",
                diagnostics.cache_diagnostics_text.clone(),
                limits.max_artifact_bytes,
                &mut warnings,
            )
        });
        let events_artifact = self.build_artifact(
            "events.txt",
            render_events(&diagnostics.events),
            limits.max_artifact_bytes,
            &mut warnings,
        );
        let summary_artifact = self.build_artifact(
            "summary.txt",
            render_summary(bundle_name, diagnostics, &warnings),
            limits.max_artifact_bytes,
            &mut warnings,
        );

        let mut artifacts =
            vec![summary_artifact, metrics_artifact, logs_artifact, events_artifact];
        if let Some(cache_artifact) = cache_artifact {
            artifacts.push(cache_artifact);
        }

        self.success_count.fetch_add(1, Ordering::SeqCst);
        Ok(SupportBundle { bundle_name: bundle_name.trim().to_string(), artifacts, warnings })
    }

    #[must_use]
    pub fn metrics(&self) -> SupportBundleMetrics {
        SupportBundleMetrics {
            success_count: self.success_count.load(Ordering::SeqCst),
            failure_count: self.failure_count.load(Ordering::SeqCst),
            redaction_hit_count: self.redaction_hit_count.load(Ordering::SeqCst),
            truncation_count: self.truncation_count.load(Ordering::SeqCst),
        }
    }

    fn redact_logs(
        &self,
        logs: Vec<StructuredLogRecord>,
        max_log_records: usize,
        warnings: &mut Vec<DiagnosticsWarning>,
    ) -> (Vec<StructuredLogRecord>, u64, bool) {
        let truncated = logs.len() > max_log_records;
        let mut redaction_hits = 0_u64;
        let mut bounded_logs = Vec::new();
        for log in logs.into_iter().take(max_log_records) {
            let (message, redacted) = self.redactor.redact_text(&log.message);
            redaction_hits += u64::from(redacted);
            let mut labels = Vec::new();
            for label in log.labels {
                let (value, redacted) = self.redactor.redact_text(&label.value);
                redaction_hits += u64::from(redacted);
                labels.push(TelemetryLabel { key: label.key, value });
            }
            bounded_logs.push(StructuredLogRecord {
                severity: log.severity,
                code: log.code,
                message,
                labels,
            });
        }
        if truncated {
            warnings.push(DiagnosticsWarning {
                section: DiagnosticsSection::Logs,
                detail: format!("logs section truncated to {max_log_records} records"),
            });
        }
        (bounded_logs, redaction_hits, truncated)
    }

    fn redact_events(
        &self,
        events: Vec<TelemetryEvent>,
        max_event_records: usize,
        warnings: &mut Vec<DiagnosticsWarning>,
    ) -> (Vec<TelemetryEvent>, u64, bool) {
        let truncated = events.len() > max_event_records;
        let mut redaction_hits = 0_u64;
        let mut bounded_events = Vec::new();
        for event in events.into_iter().take(max_event_records) {
            let (detail, redacted_detail) = self.redactor.redact_text(&event.detail);
            let (scope, redacted_scope) = self.redactor.redact_text(&event.scope);
            redaction_hits += u64::from(redacted_detail) + u64::from(redacted_scope);
            let mut labels = Vec::new();
            for label in event.labels {
                let (value, redacted) = self.redactor.redact_text(&label.value);
                redaction_hits += u64::from(redacted);
                labels.push(TelemetryLabel { key: label.key, value });
            }
            bounded_events.push(TelemetryEvent {
                code: event.code,
                category: event.category,
                severity: event.severity,
                scope,
                detail,
                labels,
            });
        }
        if truncated {
            warnings.push(DiagnosticsWarning {
                section: DiagnosticsSection::Events,
                detail: format!("events section truncated to {max_event_records} records"),
            });
        }
        (bounded_events, redaction_hits, truncated)
    }

    fn redact_and_truncate_text(
        &self,
        input: &str,
        max_bytes: usize,
        section: DiagnosticsSection,
        warnings: &mut Vec<DiagnosticsWarning>,
    ) -> ((String, bool), u64) {
        let mut redaction_hits = 0_u64;
        let mut lines = Vec::new();
        for line in input.lines() {
            let (redacted, hit) = self.redactor.redact_text(line);
            redaction_hits += u64::from(hit);
            lines.push(redacted);
        }
        let redacted = lines.join("\n");
        let (truncated, truncated_flag) = truncate_text(&redacted, max_bytes);
        if truncated_flag {
            warnings.push(DiagnosticsWarning {
                section,
                detail: format!("{:?} section truncated to {} bytes", section, max_bytes),
            });
        }
        ((truncated, truncated_flag), redaction_hits)
    }

    fn build_artifact(
        &self,
        name: &str,
        content: String,
        max_bytes: usize,
        warnings: &mut Vec<DiagnosticsWarning>,
    ) -> SupportBundleArtifact {
        let (content, truncated) = truncate_text(&content, max_bytes);
        if truncated {
            self.truncation_count.fetch_add(1, Ordering::SeqCst);
            warnings.push(DiagnosticsWarning {
                section: DiagnosticsSection::Bundle,
                detail: format!("bundle artifact {name} truncated to {max_bytes} bytes"),
            });
        }
        SupportBundleArtifact { name: name.to_string(), content, truncated }
    }
}

fn truncate_text(input: &str, max_bytes: usize) -> (String, bool) {
    if input.len() <= max_bytes {
        return (input.to_string(), false);
    }
    let mut truncated = input[..max_bytes].to_string();
    truncated.push_str("\n[TRUNCATED]");
    (truncated, true)
}

fn render_labels(labels: &[TelemetryLabel]) -> String {
    labels
        .iter()
        .map(|label| format!("{}={}", label.key.as_str(), label.value))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_logs(logs: &[StructuredLogRecord]) -> String {
    logs.iter()
        .map(|log| {
            format!(
                "severity={:?} code={} labels={} message={}",
                log.severity,
                log.code.as_str(),
                render_labels(&log.labels),
                log.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_events(events: &[TelemetryEvent]) -> String {
    events
        .iter()
        .map(|event| {
            format!(
                "severity={:?} code={} scope={} labels={} detail={}",
                event.severity,
                event.code.as_str(),
                event.scope,
                render_labels(&event.labels),
                event.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_summary(
    bundle_name: &str,
    diagnostics: &RuntimeDiagnostics,
    warnings: &[DiagnosticsWarning],
) -> String {
    let warning_lines = warnings
        .iter()
        .map(|warning| format!("{:?}: {}", warning.section, warning.detail))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "bundle={}\nlogs={}\nevents={}\nredaction_hits={}\ntruncation_count={}\nwarnings=\n{}",
        bundle_name,
        diagnostics.logs.len(),
        diagnostics.events.len(),
        diagnostics.redaction_hit_count,
        diagnostics.truncation_count,
        warning_lines
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        StructuredLogRecord, TelemetryEvent, TelemetryEventCategory, TelemetryEventCode,
        TelemetryLabel, TelemetryLabelKey, TelemetrySeverity,
    };

    use super::{
        DiagnosticsLimits, DiagnosticsSection, RedactionEngine, RuntimeDiagnosticsInput,
        SupportBundleBuilder,
    };

    #[test]
    fn redaction_engine_redacts_secret_inputs() {
        let redactor = RedactionEngine;
        let (text, redacted) = redactor.redact_text("authorization: bearer super-secret-token");
        assert_eq!(text, "[REDACTED]");
        assert!(redacted);
    }

    #[test]
    fn diagnostics_collection_is_bounded() {
        let builder = SupportBundleBuilder::new(RedactionEngine);
        let diagnostics = builder.collect_runtime_diagnostics(
            DiagnosticsLimits {
                max_metrics_bytes: 24,
                max_log_records: 1,
                max_event_records: 1,
                max_artifact_bytes: 32,
            },
            RuntimeDiagnosticsInput {
                metrics_text: Some(String::from("metric_a 1\nmetric_b 2\nmetric_c 3")),
                logs: Some(vec![
                    StructuredLogRecord {
                        severity: TelemetrySeverity::Info,
                        code: TelemetryEventCode::RuntimeListenerStarted,
                        message: String::from("first"),
                        labels: Vec::new(),
                    },
                    StructuredLogRecord {
                        severity: TelemetrySeverity::Info,
                        code: TelemetryEventCode::RuntimeListenerStopped,
                        message: String::from("second"),
                        labels: Vec::new(),
                    },
                ]),
                events: Some(vec![
                    TelemetryEvent {
                        code: TelemetryEventCode::OverloadStateChanged,
                        category: TelemetryEventCategory::Overload,
                        severity: TelemetrySeverity::Warn,
                        scope: String::from("dataplane"),
                        detail: String::from("first"),
                        labels: Vec::new(),
                    },
                    TelemetryEvent {
                        code: TelemetryEventCode::OverloadRequestShed,
                        category: TelemetryEventCategory::Overload,
                        severity: TelemetrySeverity::Warn,
                        scope: String::from("dataplane"),
                        detail: String::from("second"),
                        labels: Vec::new(),
                    },
                ]),
                cache_diagnostics_text: None,
            },
        );

        assert_eq!(diagnostics.logs.len(), 1);
        assert_eq!(diagnostics.events.len(), 1);
        assert!(diagnostics.metrics_text.contains("[TRUNCATED]"));
        assert!(diagnostics
            .warnings
            .iter()
            .any(|warning| warning.section == DiagnosticsSection::Logs));
    }

    #[test]
    fn support_bundle_generation_tolerates_partial_failures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let builder = SupportBundleBuilder::new(RedactionEngine);
        let diagnostics = builder.collect_runtime_diagnostics(
            DiagnosticsLimits::default(),
            RuntimeDiagnosticsInput {
                metrics_text: Some(String::from("runtime_metric 1")),
                logs: None,
                events: Some(Vec::new()),
                cache_diagnostics_text: None,
            },
        );

        let bundle =
            builder.build_bundle("incident-001", &diagnostics, DiagnosticsLimits::default())?;
        assert_eq!(bundle.artifacts.len(), 4);
        assert!(bundle
            .warnings
            .iter()
            .any(|warning| warning.detail.contains("logs section unavailable")));
        assert_eq!(builder.metrics().success_count, 1);
        Ok(())
    }

    #[test]
    fn secret_containing_logs_are_redacted_in_bundle() -> Result<(), Box<dyn std::error::Error>> {
        let builder = SupportBundleBuilder::new(RedactionEngine);
        let diagnostics = builder.collect_runtime_diagnostics(
            DiagnosticsLimits::default(),
            RuntimeDiagnosticsInput {
                metrics_text: Some(String::from("safe_metric 1")),
                logs: Some(vec![StructuredLogRecord {
                    severity: TelemetrySeverity::Warn,
                    code: TelemetryEventCode::TraceContextRejected,
                    message: String::from("authorization: bearer super-secret-token"),
                    labels: vec![TelemetryLabel::new(TelemetryLabelKey::Reason, "token")],
                }]),
                events: Some(vec![TelemetryEvent {
                    code: TelemetryEventCode::TraceContextRejected,
                    category: TelemetryEventCategory::Tracing,
                    severity: TelemetrySeverity::Warn,
                    scope: String::from("password-reset"),
                    detail: String::from("api_key=top-secret"),
                    labels: Vec::new(),
                }]),
                cache_diagnostics_text: None,
            },
        );
        let bundle =
            builder.build_bundle("incident-002", &diagnostics, DiagnosticsLimits::default())?;
        let logs_artifact = bundle.artifacts.iter().find(|artifact| artifact.name == "logs.txt");
        let events_artifact =
            bundle.artifacts.iter().find(|artifact| artifact.name == "events.txt");
        assert!(logs_artifact.is_some_and(|artifact| artifact.content.contains("[REDACTED]")));
        assert!(events_artifact.is_some_and(|artifact| artifact.content.contains("[REDACTED]")));
        assert!(diagnostics.redaction_hit_count >= 2);
        Ok(())
    }

    #[test]
    fn support_bundle_includes_optional_cache_diagnostics_artifact(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let builder = SupportBundleBuilder::new(RedactionEngine);
        let diagnostics = builder.collect_runtime_diagnostics(
            DiagnosticsLimits::default(),
            RuntimeDiagnosticsInput {
                metrics_text: Some(String::from("runtime_metric 1")),
                logs: Some(Vec::new()),
                events: Some(Vec::new()),
                cache_diagnostics_text: Some(String::from("scope=public-http\nentries=2")),
            },
        );

        let bundle =
            builder.build_bundle("incident-cache", &diagnostics, DiagnosticsLimits::default())?;
        assert!(bundle.artifacts.iter().any(|artifact| artifact.name == "cache.txt"));
        Ok(())
    }
}
