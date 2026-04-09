#![forbid(unsafe_code)]

mod diagnostics;

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub use diagnostics::{
    DiagnosticsError, DiagnosticsLimits, DiagnosticsSection, DiagnosticsWarning, RedactionEngine,
    RuntimeDiagnostics, RuntimeDiagnosticsInput, SupportBundle, SupportBundleArtifact,
    SupportBundleBuilder, SupportBundleMetrics,
};

/// Default service name shared across workspace foundations.
pub const SERVICE_NAME: &str = "way-balancer";
const MAX_LABEL_VALUE_LEN: usize = 64;

/// Event kinds emitted by upstream health management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamHealthEventKind {
    /// Endpoint entered degraded mode.
    Degraded,
    /// Endpoint became unhealthy.
    Unhealthy,
    /// Endpoint was ejected due to repeated failures.
    Ejected,
    /// Endpoint began warm-up after admission or recovery.
    WarmupStarted,
    /// Endpoint completed warm-up and reached full traffic weight.
    WarmupCompleted,
    /// Endpoint ejection expired and recovery probing may resume.
    RecoveryStarted,
    /// Endpoint fully recovered.
    Recovered,
}

/// Bounded health event payload for diagnostics and telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHealthEvent {
    /// Event category.
    pub kind: UpstreamHealthEventKind,
    /// Affected upstream cluster.
    pub cluster_name: String,
    /// Affected endpoint identifier.
    pub endpoint_id: String,
    /// Short human-readable explanation.
    pub detail: String,
}

/// Event kinds emitted by retry budgets, timeouts and circuit breakers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureManagementEventKind {
    /// Circuit breaker opened.
    BreakerOpened,
    /// Circuit breaker moved to half-open.
    BreakerHalfOpened,
    /// Circuit breaker closed after recovery.
    BreakerClosed,
}

/// Bounded failure-management event payload for diagnostics and telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureManagementEvent {
    /// Event category.
    pub kind: FailureManagementEventKind,
    /// Affected logical scope.
    pub scope: String,
    /// Short human-readable explanation.
    pub detail: String,
}

/// Event kinds emitted by overload response handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadEventKind {
    /// Overload state changed.
    StateChanged,
    /// A request was explicitly shed.
    RequestShed,
    /// Brownout-disabled feature set changed.
    BrownoutFeaturesChanged,
}

/// Bounded overload event payload for diagnostics and telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverloadEvent {
    /// Event category.
    pub kind: OverloadEventKind,
    /// Affected logical scope.
    pub scope: String,
    /// Short human-readable explanation.
    pub detail: String,
}

/// Minimal structured logging policy placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoggingPolicy {
    /// Whether structured logging is enabled.
    pub structured: bool,
}

impl Default for LoggingPolicy {
    fn default() -> Self {
        Self { structured: true }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TracingPolicy {
    pub enabled: bool,
}

impl Default for TracingPolicy {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceHookPhase {
    RequestReceived,
    UpstreamSelected,
    UpstreamConnected,
    ResponseStarted,
    ResponseCompleted,
}

impl TraceHookPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestReceived => "request_received",
            Self::UpstreamSelected => "upstream_selected",
            Self::UpstreamConnected => "upstream_connected",
            Self::ResponseStarted => "response_started",
            Self::ResponseCompleted => "response_completed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceContextError {
    InvalidCorrelationId,
    InvalidTraceId,
    InvalidParentSpanId,
}

impl fmt::Display for TraceContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCorrelationId => formatter.write_str("incoming correlation ID is invalid"),
            Self::InvalidTraceId => formatter.write_str("incoming trace ID is invalid"),
            Self::InvalidParentSpanId => formatter.write_str("incoming parent span ID is invalid"),
        }
    }
}

impl std::error::Error for TraceContextError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationId(String);

impl CorrelationId {
    pub fn normalize(value: &str) -> Result<Self, TraceContextError> {
        normalize_trace_identifier(value, 8, 64)
            .map(Self)
            .map_err(|_| TraceContextError::InvalidCorrelationId)
    }

    #[must_use]
    pub fn generated(sequence: u64) -> Self {
        Self(format!("corr-{sequence:016x}"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceId(String);

impl TraceId {
    pub fn normalize(value: &str) -> Result<Self, TraceContextError> {
        normalize_trace_identifier(value, 16, 64)
            .map(Self)
            .map_err(|_| TraceContextError::InvalidTraceId)
    }

    #[must_use]
    pub fn generated(sequence: u64) -> Self {
        Self(format!("{sequence:016x}{:016x}", sequence.rotate_left(7)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanId(String);

impl SpanId {
    pub fn normalize_parent(value: &str) -> Result<Self, TraceContextError> {
        normalize_trace_identifier(value, 16, 64)
            .map(Self)
            .map_err(|_| TraceContextError::InvalidParentSpanId)
    }

    #[must_use]
    pub fn generated(sequence: u64) -> Self {
        Self(format!("{sequence:016x}"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IncomingTraceContext {
    pub correlation_id: Option<String>,
    pub trace_id: Option<String>,
    pub parent_span_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub correlation_id: CorrelationId,
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetrySeverity {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryEventCategory {
    Runtime,
    Health,
    Failure,
    Tracing,
    Overload,
    Cache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryEventCode {
    RuntimeListenerStarted,
    RuntimeListenerAccepted,
    RuntimeListenerRejected,
    RuntimeListenerShutdownRequested,
    RuntimeListenerDraining,
    RuntimeListenerStopped,
    RuntimeListenerAcceptError,
    HealthEndpointDegraded,
    HealthEndpointUnhealthy,
    HealthEndpointEjected,
    HealthWarmupStarted,
    HealthWarmupCompleted,
    HealthRecoveryStarted,
    HealthRecovered,
    FailureBreakerOpened,
    FailureBreakerHalfOpened,
    FailureBreakerClosed,
    TraceContextAccepted,
    TraceContextGenerated,
    TraceContextRejected,
    TraceHookEmitted,
    OverloadStateChanged,
    OverloadRequestShed,
    OverloadBrownoutFeaturesChanged,
    CacheHit,
    CacheMiss,
    CacheStaleHit,
    CacheFill,
    CacheBypass,
    CachePurged,
    CacheRevalidated,
}

impl TelemetryEventCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeListenerStarted => "runtime.listener.started",
            Self::RuntimeListenerAccepted => "runtime.listener.accepted",
            Self::RuntimeListenerRejected => "runtime.listener.rejected",
            Self::RuntimeListenerShutdownRequested => "runtime.listener.shutdown_requested",
            Self::RuntimeListenerDraining => "runtime.listener.draining",
            Self::RuntimeListenerStopped => "runtime.listener.stopped",
            Self::RuntimeListenerAcceptError => "runtime.listener.accept_error",
            Self::HealthEndpointDegraded => "health.endpoint.degraded",
            Self::HealthEndpointUnhealthy => "health.endpoint.unhealthy",
            Self::HealthEndpointEjected => "health.endpoint.ejected",
            Self::HealthWarmupStarted => "health.warmup.started",
            Self::HealthWarmupCompleted => "health.warmup.completed",
            Self::HealthRecoveryStarted => "health.recovery.started",
            Self::HealthRecovered => "health.recovered",
            Self::FailureBreakerOpened => "failure.breaker.opened",
            Self::FailureBreakerHalfOpened => "failure.breaker.half_opened",
            Self::FailureBreakerClosed => "failure.breaker.closed",
            Self::TraceContextAccepted => "trace.context.accepted",
            Self::TraceContextGenerated => "trace.context.generated",
            Self::TraceContextRejected => "trace.context.rejected",
            Self::TraceHookEmitted => "trace.hook.emitted",
            Self::OverloadStateChanged => "overload.state.changed",
            Self::OverloadRequestShed => "overload.request.shed",
            Self::OverloadBrownoutFeaturesChanged => "overload.brownout.features_changed",
            Self::CacheHit => "cache.hit",
            Self::CacheMiss => "cache.miss",
            Self::CacheStaleHit => "cache.stale_hit",
            Self::CacheFill => "cache.fill",
            Self::CacheBypass => "cache.bypass",
            Self::CachePurged => "cache.purged",
            Self::CacheRevalidated => "cache.revalidated",
        }
    }

    #[must_use]
    pub const fn category(self) -> TelemetryEventCategory {
        match self {
            Self::RuntimeListenerStarted
            | Self::RuntimeListenerAccepted
            | Self::RuntimeListenerRejected
            | Self::RuntimeListenerShutdownRequested
            | Self::RuntimeListenerDraining
            | Self::RuntimeListenerStopped
            | Self::RuntimeListenerAcceptError => TelemetryEventCategory::Runtime,
            Self::HealthEndpointDegraded
            | Self::HealthEndpointUnhealthy
            | Self::HealthEndpointEjected
            | Self::HealthWarmupStarted
            | Self::HealthWarmupCompleted
            | Self::HealthRecoveryStarted
            | Self::HealthRecovered => TelemetryEventCategory::Health,
            Self::FailureBreakerOpened
            | Self::FailureBreakerHalfOpened
            | Self::FailureBreakerClosed => TelemetryEventCategory::Failure,
            Self::TraceContextAccepted
            | Self::TraceContextGenerated
            | Self::TraceContextRejected
            | Self::TraceHookEmitted => TelemetryEventCategory::Tracing,
            Self::OverloadStateChanged
            | Self::OverloadRequestShed
            | Self::OverloadBrownoutFeaturesChanged => TelemetryEventCategory::Overload,
            Self::CacheHit
            | Self::CacheMiss
            | Self::CacheStaleHit
            | Self::CacheFill
            | Self::CacheBypass
            | Self::CachePurged
            | Self::CacheRevalidated => TelemetryEventCategory::Cache,
        }
    }

    #[must_use]
    pub const fn severity(self) -> TelemetrySeverity {
        match self {
            Self::RuntimeListenerAcceptError => TelemetrySeverity::Error,
            Self::RuntimeListenerRejected
            | Self::HealthEndpointUnhealthy
            | Self::HealthEndpointEjected
            | Self::FailureBreakerOpened
            | Self::TraceContextRejected
            | Self::OverloadStateChanged
            | Self::OverloadRequestShed
            | Self::OverloadBrownoutFeaturesChanged
            | Self::CacheMiss
            | Self::CacheBypass => TelemetrySeverity::Warn,
            Self::RuntimeListenerStarted
            | Self::RuntimeListenerAccepted
            | Self::RuntimeListenerShutdownRequested
            | Self::RuntimeListenerDraining
            | Self::RuntimeListenerStopped
            | Self::HealthEndpointDegraded
            | Self::HealthWarmupStarted
            | Self::HealthWarmupCompleted
            | Self::HealthRecoveryStarted
            | Self::HealthRecovered
            | Self::FailureBreakerHalfOpened
            | Self::FailureBreakerClosed
            | Self::TraceContextAccepted
            | Self::TraceContextGenerated
            | Self::TraceHookEmitted
            | Self::CacheHit
            | Self::CacheStaleHit
            | Self::CacheFill
            | Self::CachePurged
            | Self::CacheRevalidated => TelemetrySeverity::Info,
        }
    }

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::RuntimeListenerStarted,
            Self::RuntimeListenerAccepted,
            Self::RuntimeListenerRejected,
            Self::RuntimeListenerShutdownRequested,
            Self::RuntimeListenerDraining,
            Self::RuntimeListenerStopped,
            Self::RuntimeListenerAcceptError,
            Self::HealthEndpointDegraded,
            Self::HealthEndpointUnhealthy,
            Self::HealthEndpointEjected,
            Self::HealthWarmupStarted,
            Self::HealthWarmupCompleted,
            Self::HealthRecoveryStarted,
            Self::HealthRecovered,
            Self::FailureBreakerOpened,
            Self::FailureBreakerHalfOpened,
            Self::FailureBreakerClosed,
            Self::TraceContextAccepted,
            Self::TraceContextGenerated,
            Self::TraceContextRejected,
            Self::TraceHookEmitted,
            Self::OverloadStateChanged,
            Self::OverloadRequestShed,
            Self::OverloadBrownoutFeaturesChanged,
            Self::CacheHit,
            Self::CacheMiss,
            Self::CacheStaleHit,
            Self::CacheFill,
            Self::CacheBypass,
            Self::CachePurged,
            Self::CacheRevalidated,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TelemetryLabelKey {
    Component,
    Listener,
    ListenerClass,
    State,
    Scope,
    Feature,
    TrafficClass,
    Result,
    Reason,
    Cluster,
    Endpoint,
    EventCode,
    CorrelationId,
    TraceId,
    SpanId,
    Phase,
}

impl TelemetryLabelKey {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Component => "component",
            Self::Listener => "listener",
            Self::ListenerClass => "listener_class",
            Self::State => "state",
            Self::Scope => "scope",
            Self::Feature => "feature",
            Self::TrafficClass => "traffic_class",
            Self::Result => "result",
            Self::Reason => "reason",
            Self::Cluster => "cluster",
            Self::Endpoint => "endpoint",
            Self::EventCode => "event_code",
            Self::CorrelationId => "correlation_id",
            Self::TraceId => "trace_id",
            Self::SpanId => "span_id",
            Self::Phase => "phase",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TelemetryLabel {
    pub key: TelemetryLabelKey,
    pub value: String,
}

impl TelemetryLabel {
    #[must_use]
    pub fn new(key: TelemetryLabelKey, value: &str) -> Self {
        Self { key, value: sanitize_label_value(value) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryEvent {
    pub code: TelemetryEventCode,
    pub category: TelemetryEventCategory,
    pub severity: TelemetrySeverity,
    pub scope: String,
    pub detail: String,
    pub labels: Vec<TelemetryLabel>,
}

impl TelemetryEvent {
    #[must_use]
    pub fn new(
        code: TelemetryEventCode,
        scope: impl Into<String>,
        detail: impl Into<String>,
        mut labels: Vec<TelemetryLabel>,
    ) -> Self {
        labels.sort();
        Self {
            code,
            category: code.category(),
            severity: code.severity(),
            scope: sanitize_label_value(&scope.into()),
            detail: detail.into(),
            labels,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredLogRecord {
    pub severity: TelemetrySeverity,
    pub code: TelemetryEventCode,
    pub message: String,
    pub labels: Vec<TelemetryLabel>,
}

impl StructuredLogRecord {
    #[must_use]
    pub fn from_event(event: &TelemetryEvent) -> Self {
        Self {
            severity: event.severity,
            code: event.code,
            message: event.detail.clone(),
            labels: event.labels.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryBufferSnapshot {
    pub logs: Vec<StructuredLogRecord>,
    pub events: Vec<TelemetryEvent>,
    pub dropped_log_count: u64,
    pub dropped_event_count: u64,
}

#[derive(Debug)]
pub struct TelemetryCollector {
    policy: LoggingPolicy,
    max_logs: usize,
    max_events: usize,
    logs: Mutex<VecDeque<StructuredLogRecord>>,
    events: Mutex<VecDeque<TelemetryEvent>>,
    dropped_log_count: AtomicU64,
    dropped_event_count: AtomicU64,
}

impl TelemetryCollector {
    #[must_use]
    pub fn new(policy: LoggingPolicy, max_logs: usize, max_events: usize) -> Self {
        Self {
            policy,
            max_logs,
            max_events,
            logs: Mutex::new(VecDeque::with_capacity(max_logs)),
            events: Mutex::new(VecDeque::with_capacity(max_events)),
            dropped_log_count: AtomicU64::new(0),
            dropped_event_count: AtomicU64::new(0),
        }
    }

    pub fn push_event(&self, event: TelemetryEvent) {
        let mut events = self.events.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.max_events == 0 {
            self.dropped_event_count.fetch_add(1, Ordering::SeqCst);
        } else {
            if events.len() == self.max_events {
                let _ = events.pop_front();
                self.dropped_event_count.fetch_add(1, Ordering::SeqCst);
            }
            events.push_back(event.clone());
        }
        drop(events);

        if self.policy.structured {
            self.push_log(StructuredLogRecord::from_event(&event));
        }
    }

    pub fn push_log(&self, record: StructuredLogRecord) {
        let mut logs = self.logs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.max_logs == 0 {
            self.dropped_log_count.fetch_add(1, Ordering::SeqCst);
            return;
        }
        if logs.len() == self.max_logs {
            let _ = logs.pop_front();
            self.dropped_log_count.fetch_add(1, Ordering::SeqCst);
        }
        logs.push_back(record);
    }

    #[must_use]
    pub fn snapshot(&self) -> TelemetryBufferSnapshot {
        TelemetryBufferSnapshot {
            logs: self
                .logs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .cloned()
                .collect(),
            events: self
                .events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .cloned()
                .collect(),
            dropped_log_count: self.dropped_log_count.load(Ordering::SeqCst),
            dropped_event_count: self.dropped_event_count.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Gauge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricDescriptor {
    pub name: String,
    pub kind: MetricKind,
    pub help: String,
    pub allowed_labels: Vec<TelemetryLabelKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryError {
    EmptyMetricName,
    DuplicateMetricName,
    UnknownMetric,
    InvalidMetricOperation,
    InvalidMetricLabels,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMetricName => formatter.write_str("metric name must not be empty"),
            Self::DuplicateMetricName => formatter.write_str("metric names must be unique"),
            Self::UnknownMetric => formatter.write_str("metric is not registered"),
            Self::InvalidMetricOperation => {
                formatter.write_str("metric operation does not match descriptor kind")
            }
            Self::InvalidMetricLabels => {
                formatter.write_str("metric labels do not match the descriptor label policy")
            }
        }
    }
}

impl std::error::Error for TelemetryError {}

#[derive(Debug)]
pub struct MetricRegistry {
    descriptors: BTreeMap<String, MetricDescriptor>,
    series: Mutex<BTreeMap<String, BTreeMap<Vec<TelemetryLabel>, f64>>>,
    dropped_sample_count: AtomicU64,
}

impl MetricRegistry {
    pub fn new(descriptors: Vec<MetricDescriptor>) -> Result<Self, TelemetryError> {
        let mut descriptor_map = BTreeMap::new();
        for descriptor in descriptors {
            if descriptor.name.trim().is_empty() {
                return Err(TelemetryError::EmptyMetricName);
            }
            if descriptor_map.insert(descriptor.name.clone(), descriptor).is_some() {
                return Err(TelemetryError::DuplicateMetricName);
            }
        }

        Ok(Self {
            descriptors: descriptor_map,
            series: Mutex::new(BTreeMap::new()),
            dropped_sample_count: AtomicU64::new(0),
        })
    }

    pub fn increment_counter(
        &self,
        name: &str,
        labels: Vec<TelemetryLabel>,
        delta: u64,
    ) -> Result<(), TelemetryError> {
        self.update_metric(name, labels, delta as f64, true)
    }

    pub fn set_gauge(
        &self,
        name: &str,
        labels: Vec<TelemetryLabel>,
        value: f64,
    ) -> Result<(), TelemetryError> {
        self.update_metric(name, labels, value, false)
    }

    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();
        let series = self.series.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for (name, descriptor) in &self.descriptors {
            output.push_str(&format!("# HELP {name} {}\n", descriptor.help));
            output.push_str(&format!(
                "# TYPE {name} {}\n",
                match descriptor.kind {
                    MetricKind::Counter => "counter",
                    MetricKind::Gauge => "gauge",
                }
            ));
            if let Some(metric_series) = series.get(name) {
                for (labels, value) in metric_series {
                    output.push_str(name);
                    output.push_str(&render_labels(labels));
                    output.push(' ');
                    output.push_str(&format_metric_value(*value));
                    output.push('\n');
                }
            }
        }

        output.push_str(
            "# HELP telemetry_dropped_metric_samples_total Count of dropped metric samples\n",
        );
        output.push_str("# TYPE telemetry_dropped_metric_samples_total counter\n");
        output.push_str(&format!(
            "telemetry_dropped_metric_samples_total {}\n",
            self.dropped_sample_count.load(Ordering::SeqCst)
        ));
        output
    }

    #[must_use]
    pub fn dropped_sample_count(&self) -> u64 {
        self.dropped_sample_count.load(Ordering::SeqCst)
    }

    fn update_metric(
        &self,
        name: &str,
        mut labels: Vec<TelemetryLabel>,
        value: f64,
        increment: bool,
    ) -> Result<(), TelemetryError> {
        let Some(descriptor) = self.descriptors.get(name) else {
            self.dropped_sample_count.fetch_add(1, Ordering::SeqCst);
            return Err(TelemetryError::UnknownMetric);
        };
        if increment && !matches!(descriptor.kind, MetricKind::Counter)
            || !increment && !matches!(descriptor.kind, MetricKind::Gauge)
        {
            self.dropped_sample_count.fetch_add(1, Ordering::SeqCst);
            return Err(TelemetryError::InvalidMetricOperation);
        }

        labels.sort();
        let actual: Vec<TelemetryLabelKey> = labels.iter().map(|label| label.key).collect();
        let mut expected = descriptor.allowed_labels.clone();
        expected.sort();
        if actual != expected {
            self.dropped_sample_count.fetch_add(1, Ordering::SeqCst);
            return Err(TelemetryError::InvalidMetricLabels);
        }

        let mut series = self.series.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let metric_series = series.entry(String::from(name)).or_default();
        if increment {
            *metric_series.entry(labels).or_insert(0.0) += value;
        } else {
            metric_series.insert(labels, value);
        }
        Ok(())
    }
}

#[must_use]
pub fn sanitize_label_value(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.contains('@') || normalized.contains('?') || normalized.contains('=') {
        return String::from("redacted");
    }
    let mut invalid_count = 0usize;
    let mut collapsed = String::new();
    let mut previous_was_separator = false;
    for character in normalized.chars() {
        let mapped = if character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '_' | '-' | '.')
        {
            character
        } else {
            invalid_count += 1;
            '_'
        };

        if mapped == '_' {
            if previous_was_separator {
                continue;
            }
            previous_was_separator = true;
        } else {
            previous_was_separator = false;
        }

        if collapsed.len() == MAX_LABEL_VALUE_LEN {
            break;
        }
        collapsed.push(mapped);
    }

    let sanitized = collapsed.trim_matches('_').to_string();
    if sanitized.is_empty() {
        return String::from("unknown");
    }
    if invalid_count > normalized.len().saturating_div(3) {
        return String::from("redacted");
    }
    sanitized
}

fn normalize_trace_identifier(value: &str, min_len: usize, max_len: usize) -> Result<String, ()> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() < min_len || normalized.len() > max_len {
        return Err(());
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_')
    }) {
        return Err(());
    }
    Ok(normalized)
}

fn render_labels(labels: &[TelemetryLabel]) -> String {
    if labels.is_empty() {
        return String::new();
    }

    let parts: Vec<String> =
        labels.iter().map(|label| format!("{}=\"{}\"", label.key.as_str(), label.value)).collect();
    format!("{{{}}}", parts.join(","))
}

fn format_metric_value(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CorrelationId, LoggingPolicy, MetricDescriptor, MetricKind, MetricRegistry, SpanId,
        StructuredLogRecord, TelemetryCollector, TelemetryError, TelemetryEvent,
        TelemetryEventCode, TelemetryLabel, TelemetryLabelKey, TraceId,
    };

    #[test]
    fn trace_identifiers_validate_and_normalize() -> Result<(), Box<dyn std::error::Error>> {
        let correlation = CorrelationId::normalize("REQ-1234_abcd")?;
        let trace_id = TraceId::normalize("0123456789ABCDEF0123456789ABCDEF")?;
        let span_id = SpanId::normalize_parent("ABCDEF0123456789")?;

        assert_eq!(correlation.as_str(), "req-1234_abcd");
        assert_eq!(trace_id.as_str(), "0123456789abcdef0123456789abcdef");
        assert_eq!(span_id.as_str(), "abcdef0123456789");
        assert!(CorrelationId::normalize("bad@email").is_err());
        Ok(())
    }

    #[test]
    fn label_policy_redacts_high_entropy_values() {
        let label =
            TelemetryLabel::new(TelemetryLabelKey::Listener, "User@example.com?token=abc123456789");
        assert_eq!(label.value, "redacted");
    }

    #[test]
    fn metric_registry_exports_structured_samples() -> Result<(), Box<dyn std::error::Error>> {
        let registry = MetricRegistry::new(vec![
            MetricDescriptor {
                name: String::from("runtime_listener_active_connections"),
                kind: MetricKind::Gauge,
                help: String::from("Current active listener connections"),
                allowed_labels: vec![TelemetryLabelKey::Listener, TelemetryLabelKey::State],
            },
            MetricDescriptor {
                name: String::from("runtime_listener_events_total"),
                kind: MetricKind::Counter,
                help: String::from("Listener event counter"),
                allowed_labels: vec![TelemetryLabelKey::EventCode, TelemetryLabelKey::Listener],
            },
        ])?;

        registry.set_gauge(
            "runtime_listener_active_connections",
            vec![
                TelemetryLabel::new(TelemetryLabelKey::Listener, "Ingress TCP"),
                TelemetryLabel::new(TelemetryLabelKey::State, "Running"),
            ],
            7.0,
        )?;
        registry.increment_counter(
            "runtime_listener_events_total",
            vec![
                TelemetryLabel::new(TelemetryLabelKey::EventCode, "runtime.listener.accepted"),
                TelemetryLabel::new(TelemetryLabelKey::Listener, "Ingress TCP"),
            ],
            2,
        )?;
        let rendered = registry.export_prometheus();
        assert!(rendered.contains(
            "runtime_listener_active_connections{listener=\"ingress_tcp\",state=\"running\"} 7"
        ));
        assert!(rendered.contains("runtime_listener_events_total{listener=\"ingress_tcp\",event_code=\"runtime.listener.accepted\"} 2"));
        Ok(())
    }

    #[test]
    fn metric_registry_rejects_unapproved_labels() -> Result<(), Box<dyn std::error::Error>> {
        let registry = MetricRegistry::new(vec![MetricDescriptor {
            name: String::from("runtime_listener_active_connections"),
            kind: MetricKind::Gauge,
            help: String::from("Current active listener connections"),
            allowed_labels: vec![TelemetryLabelKey::Listener],
        }])?;

        let error = registry
            .set_gauge(
                "runtime_listener_active_connections",
                vec![TelemetryLabel::new(TelemetryLabelKey::State, "running")],
                1.0,
            )
            .err();
        assert_eq!(error, Some(TelemetryError::InvalidMetricLabels));
        assert_eq!(registry.dropped_sample_count(), 1);
        Ok(())
    }

    #[test]
    fn structured_log_schema_is_bounded_and_structured() {
        let collector = TelemetryCollector::new(LoggingPolicy::default(), 1, 1);
        collector.push_event(TelemetryEvent::new(
            TelemetryEventCode::RuntimeListenerStarted,
            "listener/ingress",
            "listener started",
            vec![TelemetryLabel::new(TelemetryLabelKey::Listener, "ingress")],
        ));
        collector.push_log(StructuredLogRecord {
            severity: TelemetryEventCode::RuntimeListenerAcceptError.severity(),
            code: TelemetryEventCode::RuntimeListenerAcceptError,
            message: String::from("accept failed"),
            labels: vec![TelemetryLabel::new(TelemetryLabelKey::Listener, "ingress")],
        });

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.logs.len(), 1);
        assert_eq!(snapshot.events.len(), 1);
        assert_eq!(snapshot.logs[0].code.as_str(), "runtime.listener.accept_error");
        assert_eq!(snapshot.events[0].scope, "listener_ingress");
        assert_eq!(snapshot.dropped_log_count, 1);
    }

    #[test]
    fn event_code_catalog_is_stable() {
        let codes: Vec<&'static str> =
            TelemetryEventCode::all().iter().map(|code| code.as_str()).collect();
        assert_eq!(
            codes,
            vec![
                "runtime.listener.started",
                "runtime.listener.accepted",
                "runtime.listener.rejected",
                "runtime.listener.shutdown_requested",
                "runtime.listener.draining",
                "runtime.listener.stopped",
                "runtime.listener.accept_error",
                "health.endpoint.degraded",
                "health.endpoint.unhealthy",
                "health.endpoint.ejected",
                "health.warmup.started",
                "health.warmup.completed",
                "health.recovery.started",
                "health.recovered",
                "failure.breaker.opened",
                "failure.breaker.half_opened",
                "failure.breaker.closed",
                "trace.context.accepted",
                "trace.context.generated",
                "trace.context.rejected",
                "trace.hook.emitted",
                "overload.state.changed",
                "overload.request.shed",
                "overload.brownout.features_changed",
                "cache.hit",
                "cache.miss",
                "cache.stale_hit",
                "cache.fill",
                "cache.bypass",
                "cache.purged",
                "cache.revalidated",
            ]
        );
    }
}
