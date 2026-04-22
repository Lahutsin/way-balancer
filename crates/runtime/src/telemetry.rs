use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use lb_observability::{
    CorrelationId, DiagnosticsLimits, IncomingTraceContext, LoggingPolicy, MetricDescriptor,
    MetricKind, MetricRegistry, RuntimeDiagnostics, RuntimeDiagnosticsInput, SpanId,
    StructuredLogRecord, SupportBundleBuilder, TelemetryBufferSnapshot, TelemetryCollector,
    TelemetryError, TelemetryEvent, TelemetryEventCode, TelemetryLabel, TelemetryLabelKey,
    TraceContext, TraceContextError, TraceHookPhase, TraceId, TracingPolicy,
};

use crate::{
    AbuseRejectionReason,
    HttpCacheStoreMetrics, HttpCacheStoreSnapshot, ListenerEvent, ListenerEventKind,
    ListenerAbuseProtectionSnapshot, ListenerSnapshot, OverloadSnapshot, OverloadState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpCacheRequestOutcome {
    Hit,
    Miss,
    StaleHit,
    Fill,
    Bypass,
}

impl HttpCacheRequestOutcome {
    const fn metric_result(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::StaleHit => "stale_hit",
            Self::Fill => "fill",
            Self::Bypass => "bypass",
        }
    }

    const fn event_code(self) -> TelemetryEventCode {
        match self {
            Self::Hit => TelemetryEventCode::CacheHit,
            Self::Miss => TelemetryEventCode::CacheMiss,
            Self::StaleHit => TelemetryEventCode::CacheStaleHit,
            Self::Fill => TelemetryEventCode::CacheFill,
            Self::Bypass => TelemetryEventCode::CacheBypass,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpCacheRevalidationResult {
    NotModified,
    Replaced,
    Failed,
}

impl HttpCacheRevalidationResult {
    const fn metric_result(self) -> &'static str {
        match self {
            Self::NotModified => "not_modified",
            Self::Replaced => "replaced",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpUpgradeResult {
    Accepted,
    Rejected,
    Failed,
}

impl HttpUpgradeResult {
    const fn metric_result(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }

    const fn event_code(self) -> TelemetryEventCode {
        match self {
            Self::Accepted => TelemetryEventCode::RuntimeHttpUpgradeAccepted,
            Self::Rejected => TelemetryEventCode::RuntimeHttpUpgradeRejected,
            Self::Failed => TelemetryEventCode::RuntimeHttpUpgradeFailed,
        }
    }
}

#[derive(Debug)]
pub struct RuntimeTelemetry {
    collector: TelemetryCollector,
    metrics: MetricRegistry,
    tracing_policy: TracingPolicy,
    sequence: AtomicU64,
}

impl RuntimeTelemetry {
    pub fn new() -> Result<Self, TelemetryError> {
        Self::with_tracing_policy(TracingPolicy::default())
    }

    pub fn with_tracing_policy(tracing_policy: TracingPolicy) -> Result<Self, TelemetryError> {
        let telemetry = Self {
            collector: TelemetryCollector::new(LoggingPolicy::default(), 128, 128),
            metrics: MetricRegistry::new(vec![
                MetricDescriptor {
                    name: String::from("runtime_listener_active_connections"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current active listener connections"),
                    allowed_labels: vec![TelemetryLabelKey::Listener, TelemetryLabelKey::State],
                },
                MetricDescriptor {
                    name: String::from("runtime_listener_events_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total listener events"),
                    allowed_labels: vec![TelemetryLabelKey::EventCode, TelemetryLabelKey::Listener],
                },
                MetricDescriptor {
                    name: String::from("runtime_listener_accepted_connections"),
                    kind: MetricKind::Gauge,
                    help: String::from("Total accepted listener connections observed in the latest snapshot"),
                    allowed_labels: vec![TelemetryLabelKey::Listener],
                },
                MetricDescriptor {
                    name: String::from("runtime_listener_rejected_connections"),
                    kind: MetricKind::Gauge,
                    help: String::from("Total rejected listener connections observed in the latest snapshot"),
                    allowed_labels: vec![TelemetryLabelKey::Listener],
                },
                MetricDescriptor {
                    name: String::from("runtime_listener_abuse_rejections_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total hostile-edge listener rejections by reason code"),
                    allowed_labels: vec![TelemetryLabelKey::Listener, TelemetryLabelKey::Reason],
                },
                MetricDescriptor {
                    name: String::from("runtime_listener_abuse_tracked_sources"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current number of tracked hostile-edge source buckets"),
                    allowed_labels: vec![TelemetryLabelKey::Listener],
                },
                MetricDescriptor {
                    name: String::from("runtime_listener_abuse_active_handshakes"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current number of in-flight guarded handshakes"),
                    allowed_labels: vec![TelemetryLabelKey::Listener],
                },
                MetricDescriptor {
                    name: String::from("runtime_breaker_events_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total failure-management breaker events"),
                    allowed_labels: vec![TelemetryLabelKey::EventCode, TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_overload_state"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current overload state value"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_shed_requests_total"),
                    kind: MetricKind::Gauge,
                    help: String::from("Total shed requests observed by overload management"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_overload_active_signals"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current active overload signal count"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_overload_rate_limited"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current rate-limit saturation indicator count"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_overload_concurrency_limited"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current concurrency-limit saturation indicator count"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_overload_breaker_open"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current open breaker saturation indicator count"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_overload_retry_budget_exhausted"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current exhausted retry-budget saturation indicator count"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_overload_brownout_features"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current number of brownout-disabled features"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_tracing_enabled"),
                    kind: MetricKind::Gauge,
                    help: String::from("Whether runtime tracing hooks are enabled"),
                    allowed_labels: vec![TelemetryLabelKey::Component],
                },
                MetricDescriptor {
                    name: String::from("runtime_request_latency_samples_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Latency bucket samples for critical request-flow phases"),
                    allowed_labels: vec![
                        TelemetryLabelKey::Bucket,
                        TelemetryLabelKey::Phase,
                        TelemetryLabelKey::Scope,
                    ],
                },
                MetricDescriptor {
                    name: String::from("runtime_trace_hooks_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total emitted trace hooks"),
                    allowed_labels: vec![TelemetryLabelKey::Phase],
                },
                MetricDescriptor {
                    name: String::from("runtime_invalid_tracing_metadata_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total invalid incoming tracing metadata values"),
                    allowed_labels: vec![TelemetryLabelKey::Reason],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_cache_entries"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current number of cached HTTP objects"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_cache_bytes"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current bytes stored in the HTTP cache"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_cache_max_object_bytes"),
                    kind: MetricKind::Gauge,
                    help: String::from("Current largest cached object footprint"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_cache_requests_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total HTTP cache request outcomes by result and reason"),
                    allowed_labels: vec![
                        TelemetryLabelKey::Scope,
                        TelemetryLabelKey::Result,
                        TelemetryLabelKey::Reason,
                    ],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_cache_revalidations_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total HTTP cache revalidation outcomes"),
                    allowed_labels: vec![TelemetryLabelKey::Scope, TelemetryLabelKey::Result],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_cache_purge_requests_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total HTTP cache purge requests by result"),
                    allowed_labels: vec![TelemetryLabelKey::Scope, TelemetryLabelKey::Result],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_cache_purged_entries_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total HTTP cache entries removed by purge actions"),
                    allowed_labels: vec![TelemetryLabelKey::Scope],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_cache_invalidation_peer_deliveries_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total peer delivery outcomes for distributed HTTP cache invalidation by transport"),
                    allowed_labels: vec![
                        TelemetryLabelKey::Scope,
                        TelemetryLabelKey::Result,
                        TelemetryLabelKey::Reason,
                    ],
                },
                MetricDescriptor {
                    name: String::from("runtime_http_upgrades_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total HTTP upgrade attempts by outcome and reason"),
                    allowed_labels: vec![
                        TelemetryLabelKey::Scope,
                        TelemetryLabelKey::Result,
                        TelemetryLabelKey::Reason,
                    ],
                },
                MetricDescriptor {
                    name: String::from("runtime_http3_requests_total"),
                    kind: MetricKind::Counter,
                    help: String::from("Total downstream HTTP/3 request outcomes by result and reason"),
                    allowed_labels: vec![
                        TelemetryLabelKey::Scope,
                        TelemetryLabelKey::Result,
                        TelemetryLabelKey::Reason,
                    ],
                },
            ])?,
            tracing_policy,
            sequence: AtomicU64::new(1),
        };
        telemetry.metrics.set_gauge(
            "runtime_tracing_enabled",
            vec![TelemetryLabel::new(TelemetryLabelKey::Component, "runtime")],
            if tracing_policy.enabled { 1.0 } else { 0.0 },
        )?;
        Ok(telemetry)
    }

    pub fn record_listener_event(
        &self,
        listener_name: &str,
        event: &ListenerEvent,
    ) -> Result<(), TelemetryError> {
        let code = match event.kind {
            ListenerEventKind::Started => TelemetryEventCode::RuntimeListenerStarted,
            ListenerEventKind::Accepted => TelemetryEventCode::RuntimeListenerAccepted,
            ListenerEventKind::Rejected => TelemetryEventCode::RuntimeListenerRejected,
            ListenerEventKind::ShutdownRequested => {
                TelemetryEventCode::RuntimeListenerShutdownRequested
            }
            ListenerEventKind::Draining => TelemetryEventCode::RuntimeListenerDraining,
            ListenerEventKind::Stopped => TelemetryEventCode::RuntimeListenerStopped,
            ListenerEventKind::AcceptError => TelemetryEventCode::RuntimeListenerAcceptError,
        };
        let labels = vec![
            TelemetryLabel::new(TelemetryLabelKey::EventCode, code.as_str()),
            TelemetryLabel::new(TelemetryLabelKey::Listener, listener_name),
        ];
        self.metrics.increment_counter("runtime_listener_events_total", labels.clone(), 1)?;
        self.collector.push_event(TelemetryEvent::new(code, listener_name, &event.detail, labels));
        Ok(())
    }

    pub fn record_listener_snapshot(
        &self,
        snapshot: &ListenerSnapshot,
    ) -> Result<(), TelemetryError> {
        self.metrics.set_gauge(
            "runtime_listener_active_connections",
            vec![
                TelemetryLabel::new(TelemetryLabelKey::Listener, &snapshot.name),
                TelemetryLabel::new(TelemetryLabelKey::State, &format!("{:?}", snapshot.state)),
            ],
            snapshot.active_connections as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_listener_accepted_connections",
            vec![TelemetryLabel::new(TelemetryLabelKey::Listener, &snapshot.name)],
            snapshot.accepted_connections as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_listener_rejected_connections",
            vec![TelemetryLabel::new(TelemetryLabelKey::Listener, &snapshot.name)],
            snapshot.rejected_connections as f64,
        )
    }

    pub fn record_listener_abuse_rejection(
        &self,
        listener_name: &str,
        reason: AbuseRejectionReason,
        detail: &str,
    ) -> Result<(), TelemetryError> {
        let labels = vec![
            TelemetryLabel::new(TelemetryLabelKey::Listener, listener_name),
            TelemetryLabel::new(TelemetryLabelKey::Reason, reason.code()),
        ];
        self.metrics.increment_counter(
            "runtime_listener_abuse_rejections_total",
            labels.clone(),
            1,
        )?;
        self.collector.push_event(TelemetryEvent::new(
            TelemetryEventCode::RuntimeListenerRejected,
            listener_name,
            detail,
            labels,
        ));
        Ok(())
    }

    pub fn record_listener_abuse_snapshot(
        &self,
        listener_name: &str,
        snapshot: &ListenerAbuseProtectionSnapshot,
    ) -> Result<(), TelemetryError> {
        self.metrics.set_gauge(
            "runtime_listener_abuse_tracked_sources",
            vec![TelemetryLabel::new(TelemetryLabelKey::Listener, listener_name)],
            snapshot.tracked_sources as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_listener_abuse_active_handshakes",
            vec![TelemetryLabel::new(TelemetryLabelKey::Listener, listener_name)],
            snapshot.active_handshakes as f64,
        )
    }

    pub fn record_failure_event(
        &self,
        scope: &str,
        kind: lb_observability::FailureManagementEventKind,
        detail: &str,
    ) -> Result<(), TelemetryError> {
        let code = match kind {
            lb_observability::FailureManagementEventKind::BreakerOpened => {
                TelemetryEventCode::FailureBreakerOpened
            }
            lb_observability::FailureManagementEventKind::BreakerHalfOpened => {
                TelemetryEventCode::FailureBreakerHalfOpened
            }
            lb_observability::FailureManagementEventKind::BreakerClosed => {
                TelemetryEventCode::FailureBreakerClosed
            }
        };
        let labels = vec![
            TelemetryLabel::new(TelemetryLabelKey::EventCode, code.as_str()),
            TelemetryLabel::new(TelemetryLabelKey::Scope, scope),
        ];
        self.metrics.increment_counter("runtime_breaker_events_total", labels.clone(), 1)?;
        self.collector.push_event(TelemetryEvent::new(code, scope, detail, labels));
        Ok(())
    }

    pub fn record_overload_event(
        &self,
        event: &lb_observability::OverloadEvent,
    ) -> Result<(), TelemetryError> {
        let code = match event.kind {
            lb_observability::OverloadEventKind::StateChanged => {
                TelemetryEventCode::OverloadStateChanged
            }
            lb_observability::OverloadEventKind::RequestShed => {
                TelemetryEventCode::OverloadRequestShed
            }
            lb_observability::OverloadEventKind::BrownoutFeaturesChanged => {
                TelemetryEventCode::OverloadBrownoutFeaturesChanged
            }
        };
        self.collector.push_event(TelemetryEvent::new(
            code,
            &event.scope,
            &event.detail,
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, &event.scope)],
        ));
        Ok(())
    }

    pub fn record_overload_snapshot(
        &self,
        scope: &str,
        snapshot: &OverloadSnapshot,
    ) -> Result<(), TelemetryError> {
        self.metrics.set_gauge(
            "runtime_overload_state",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            match snapshot.state {
                OverloadState::Normal => 0.0,
                OverloadState::Constrained => 1.0,
                OverloadState::Shedding => 2.0,
                OverloadState::Brownout => 3.0,
            },
        )?;
        self.metrics.set_gauge(
            "runtime_shed_requests_total",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            snapshot.shed_request_count as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_overload_active_signals",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            snapshot.active_signal_count as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_overload_rate_limited",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            snapshot.rate_limited_count as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_overload_concurrency_limited",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            snapshot.concurrency_limited_count as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_overload_breaker_open",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            snapshot.breaker_open_count as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_overload_retry_budget_exhausted",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            snapshot.retry_budget_exhausted_count as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_overload_brownout_features",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            snapshot.brownout_feature_count as f64,
        )
    }

    pub fn record_request_latency(
        &self,
        scope: &str,
        phase: TraceHookPhase,
        latency: Duration,
    ) -> Result<(), TelemetryError> {
        self.metrics.increment_counter(
            "runtime_request_latency_samples_total",
            vec![
                TelemetryLabel::new(TelemetryLabelKey::Bucket, latency_bucket_label(latency)),
                TelemetryLabel::new(TelemetryLabelKey::Phase, phase.as_str()),
                TelemetryLabel::new(TelemetryLabelKey::Scope, scope),
            ],
            1,
        )
    }

    pub fn record_http_cache_metrics(
        &self,
        scope: &str,
        metrics: &HttpCacheStoreMetrics,
    ) -> Result<(), TelemetryError> {
        self.metrics.set_gauge(
            "runtime_http_cache_entries",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            metrics.entry_count as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_http_cache_bytes",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            metrics.total_bytes as f64,
        )?;
        self.metrics.set_gauge(
            "runtime_http_cache_max_object_bytes",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            metrics.max_object_bytes as f64,
        )
    }

    pub fn record_http_cache_request(
        &self,
        scope: &str,
        outcome: HttpCacheRequestOutcome,
        reason: &str,
        detail: &str,
    ) -> Result<(), TelemetryError> {
        let labels = vec![
            TelemetryLabel::new(TelemetryLabelKey::Scope, scope),
            TelemetryLabel::new(TelemetryLabelKey::Result, outcome.metric_result()),
            TelemetryLabel::new(TelemetryLabelKey::Reason, reason),
        ];
        self.metrics.increment_counter("runtime_http_cache_requests_total", labels.clone(), 1)?;
        self.collector.push_event(TelemetryEvent::new(outcome.event_code(), scope, detail, labels));
        Ok(())
    }

    pub fn record_http_cache_revalidation(
        &self,
        scope: &str,
        result: HttpCacheRevalidationResult,
        detail: &str,
    ) -> Result<(), TelemetryError> {
        let labels = vec![
            TelemetryLabel::new(TelemetryLabelKey::Scope, scope),
            TelemetryLabel::new(TelemetryLabelKey::Result, result.metric_result()),
        ];
        self.metrics.increment_counter(
            "runtime_http_cache_revalidations_total",
            labels.clone(),
            1,
        )?;
        self.collector.push_event(TelemetryEvent::new(
            TelemetryEventCode::CacheRevalidated,
            scope,
            detail,
            labels,
        ));
        Ok(())
    }

    pub fn record_http_cache_purge(
        &self,
        scope: &str,
        result: &str,
        purged_entries: usize,
    ) -> Result<(), TelemetryError> {
        let labels = vec![
            TelemetryLabel::new(TelemetryLabelKey::Scope, scope),
            TelemetryLabel::new(TelemetryLabelKey::Result, result),
        ];
        self.metrics.increment_counter(
            "runtime_http_cache_purge_requests_total",
            labels.clone(),
            1,
        )?;
        self.metrics.increment_counter(
            "runtime_http_cache_purged_entries_total",
            vec![TelemetryLabel::new(TelemetryLabelKey::Scope, scope)],
            purged_entries as u64,
        )?;
        self.collector.push_event(TelemetryEvent::new(
            TelemetryEventCode::CachePurged,
            scope,
            format!("purged {purged_entries} cache entries"),
            labels,
        ));
        Ok(())
    }

    pub fn record_http_cache_invalidation_delivery(
        &self,
        scope: &str,
        transport: &str,
        result: &str,
        peer_count: usize,
    ) -> Result<(), TelemetryError> {
        self.metrics.increment_counter(
            "runtime_http_cache_invalidation_peer_deliveries_total",
            vec![
                TelemetryLabel::new(TelemetryLabelKey::Scope, scope),
                TelemetryLabel::new(TelemetryLabelKey::Result, result),
                TelemetryLabel::new(TelemetryLabelKey::Reason, transport),
            ],
            peer_count as u64,
        )
    }

    pub fn record_http_upgrade(
        &self,
        scope: &str,
        result: HttpUpgradeResult,
        reason: &str,
        detail: &str,
    ) -> Result<(), TelemetryError> {
        let labels = vec![
            TelemetryLabel::new(TelemetryLabelKey::Scope, scope),
            TelemetryLabel::new(TelemetryLabelKey::Result, result.metric_result()),
            TelemetryLabel::new(TelemetryLabelKey::Reason, reason),
        ];
        self.metrics.increment_counter("runtime_http_upgrades_total", labels.clone(), 1)?;
        self.collector
            .push_event(TelemetryEvent::new(result.event_code(), scope, detail, labels));
        Ok(())
    }

    pub fn record_http3_request(
        &self,
        scope: &str,
        result: &str,
        reason: &str,
    ) -> Result<(), TelemetryError> {
        self.metrics.increment_counter(
            "runtime_http3_requests_total",
            vec![
                TelemetryLabel::new(TelemetryLabelKey::Scope, scope),
                TelemetryLabel::new(TelemetryLabelKey::Result, result),
                TelemetryLabel::new(TelemetryLabelKey::Reason, reason),
            ],
            1,
        )
    }

    #[must_use]
    pub fn export_metrics(&self) -> String {
        self.metrics.export_prometheus()
    }

    #[must_use]
    pub fn snapshot(&self) -> TelemetryBufferSnapshot {
        self.collector.snapshot()
    }

    pub fn push_log(&self, record: StructuredLogRecord) {
        self.collector.push_log(record);
    }

    #[must_use]
    pub fn collect_runtime_diagnostics(
        &self,
        limits: DiagnosticsLimits,
        builder: &SupportBundleBuilder,
    ) -> RuntimeDiagnostics {
        self.collect_runtime_diagnostics_with_cache(limits, builder, None)
    }

    #[must_use]
    pub fn collect_runtime_diagnostics_with_cache(
        &self,
        limits: DiagnosticsLimits,
        builder: &SupportBundleBuilder,
        cache_snapshot: Option<(&str, &HttpCacheStoreSnapshot)>,
    ) -> RuntimeDiagnostics {
        builder.collect_runtime_diagnostics(
            limits,
            RuntimeDiagnosticsInput {
                metrics_text: Some(self.export_metrics()),
                logs: Some(self.snapshot().logs),
                events: Some(self.snapshot().events),
                cache_diagnostics_text: cache_snapshot
                    .map(|(scope, snapshot)| snapshot.render_diagnostics(scope, 16)),
            },
        )
    }

    pub fn establish_trace_context(
        &self,
        scope: &str,
        incoming: IncomingTraceContext,
    ) -> Result<TraceContext, TelemetryError> {
        let had_incoming = incoming.correlation_id.is_some()
            || incoming.trace_id.is_some()
            || incoming.parent_span_id.is_some();
        let correlation_valid =
            incoming.correlation_id.as_deref().map(CorrelationId::normalize).transpose();
        let trace_valid = incoming.trace_id.as_deref().map(TraceId::normalize).transpose();
        let parent_valid =
            incoming.parent_span_id.as_deref().map(SpanId::normalize_parent).transpose();
        let rejected = correlation_valid.is_err() || trace_valid.is_err() || parent_valid.is_err();

        let correlation_id = match correlation_valid {
            Ok(Some(correlation_id)) => correlation_id,
            Ok(None) => CorrelationId::generated(self.next_sequence()),
            Err(error) => {
                self.record_invalid_trace_metadata(&error)?;
                CorrelationId::generated(self.next_sequence())
            }
        };
        let trace_id = match trace_valid {
            Ok(Some(trace_id)) => trace_id,
            Ok(None) => TraceId::generated(self.next_sequence()),
            Err(error) => {
                self.record_invalid_trace_metadata(&error)?;
                TraceId::generated(self.next_sequence())
            }
        };
        let parent_span_id = match parent_valid {
            Ok(parent_span_id) => parent_span_id,
            Err(error) => {
                self.record_invalid_trace_metadata(&error)?;
                None
            }
        };
        let context = TraceContext {
            correlation_id,
            trace_id,
            span_id: SpanId::generated(self.next_sequence()),
            parent_span_id,
        };

        self.collector.push_event(TelemetryEvent::new(
            if rejected {
                TelemetryEventCode::TraceContextRejected
            } else if had_incoming {
                TelemetryEventCode::TraceContextAccepted
            } else {
                TelemetryEventCode::TraceContextGenerated
            },
            scope,
            "trace context established",
            trace_labels(&context, None),
        ));
        Ok(context)
    }

    pub fn record_trace_hook(
        &self,
        scope: &str,
        context: &TraceContext,
        phase: TraceHookPhase,
        detail: &str,
    ) -> Result<(), TelemetryError> {
        if !self.tracing_policy.enabled {
            return Ok(());
        }
        self.metrics.increment_counter(
            "runtime_trace_hooks_total",
            vec![TelemetryLabel::new(TelemetryLabelKey::Phase, phase.as_str())],
            1,
        )?;
        self.collector.push_event(TelemetryEvent::new(
            TelemetryEventCode::TraceHookEmitted,
            scope,
            detail,
            trace_labels(context, Some(phase)),
        ));
        Ok(())
    }

    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    fn record_invalid_trace_metadata(
        &self,
        error: &TraceContextError,
    ) -> Result<(), TelemetryError> {
        self.metrics.increment_counter(
            "runtime_invalid_tracing_metadata_total",
            vec![TelemetryLabel::new(
                TelemetryLabelKey::Reason,
                match error {
                    TraceContextError::InvalidCorrelationId => "correlation_id",
                    TraceContextError::InvalidTraceId => "trace_id",
                    TraceContextError::InvalidParentSpanId => "parent_span_id",
                },
            )],
            1,
        )
    }
}

fn trace_labels(context: &TraceContext, phase: Option<TraceHookPhase>) -> Vec<TelemetryLabel> {
    let mut labels = vec![
        TelemetryLabel::new(TelemetryLabelKey::CorrelationId, context.correlation_id.as_str()),
        TelemetryLabel::new(TelemetryLabelKey::TraceId, context.trace_id.as_str()),
        TelemetryLabel::new(TelemetryLabelKey::SpanId, context.span_id.as_str()),
    ];
    if let Some(phase) = phase {
        labels.push(TelemetryLabel::new(TelemetryLabelKey::Phase, phase.as_str()));
    }
    labels
}

fn latency_bucket_label(latency: Duration) -> &'static str {
    let millis = latency.as_millis();
    if millis <= 1 {
        "le_1ms"
    } else if millis <= 5 {
        "le_5ms"
    } else if millis <= 10 {
        "le_10ms"
    } else if millis <= 25 {
        "le_25ms"
    } else if millis <= 50 {
        "le_50ms"
    } else if millis <= 100 {
        "le_100ms"
    } else if millis <= 250 {
        "le_250ms"
    } else if millis <= 500 {
        "le_500ms"
    } else if millis <= 1000 {
        "le_1000ms"
    } else {
        "gt_1000ms"
    }
}
