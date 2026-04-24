#![forbid(unsafe_code)]

mod abuse_control;
mod auth;
mod cache;
mod cache_transport;
mod control;
mod fleet;
mod fleet_gate;
mod fleet_status;
mod fleet_staged;
mod listener_canary;
mod mtls;
mod promotion;
mod rollout;

use serde::{Deserialize, Serialize};

pub use abuse_control::{
    AbuseControlActionKind, AbuseControlError, AbuseControlHistoryEntry, AbuseControlMetrics,
    AbuseControlResultKind, AbuseForensicsExportRequest, AbuseProtectionAdminService,
    EmergencyModeAdminRequest, EmergencyModeAdminResponse, InvalidAbuseControlRequest,
};
pub use auth::{
    AdminAuthError, AdminAuthMetrics, AdminAuthService, AdminCredential, AdminOperationError,
    AdminPermission, AdminRole, AuthAuditEvent, AuthAuditEventKind, AuthenticatedAdminIdentity,
    InvalidAdminCredential,
};
pub use cache::{
    HttpCacheAdminMetrics, HttpCacheAdminService, HttpCachePurgeActionKind, HttpCachePurgeError,
    HttpCachePurgeHistoryEntry, HttpCachePurgeRequest, HttpCachePurgeResponse,
    HttpCachePurgeResultKind, HttpCachePurgeTarget, InvalidHttpCachePurgeRequest,
};
pub use cache_transport::{
    sign_http_cache_peer_request, HttpCacheInvalidationDeliveryMode, HttpCachePeerConfig,
    HttpCachePeerDeliveryRecord, HttpCachePeerDeliveryResult, HttpCachePeerFanoutReport,
    HttpCachePeerInvalidationResponse, HttpCachePeerInvalidationResult,
    HttpCachePeerRetryPolicy, HttpCachePeerTransport, InvalidHttpCachePeerConfig,
};
pub use control::{
    InvalidPublishRequest, PublishConflict, PublishEvent, PublishEventKind, PublishResponse,
    PublishResponseKind, PublishedSnapshotRecord, PublishedSnapshotSummary, SnapshotBackupBundle,
    SnapshotBackupError, SnapshotControlService, SnapshotDiffPreview, SnapshotDiffPreviewError,
    SnapshotImpactAnalysis, SnapshotImpactSeverity, SnapshotLookupError,
    SnapshotPublicationError, SnapshotPublishRequest, SnapshotRegistryDurableEnvelope,
    SnapshotRegistryDurableState, SnapshotRegistryMetrics, SnapshotRegistryRetentionPolicy,
    SnapshotRegistryStateError, SnapshotResourceImpactSummary, SnapshotRestoreError,
};
pub use fleet::{
    FleetAbortReason, FleetAbortRollbackDecision, FleetAutoRollbackMode,
    FleetAutoRollbackOutcome, FleetConsistencyMode, FleetConvergenceReport,
    FleetConvergenceState,
    FleetNodeActionOutcome, FleetNodeActionResult, FleetNodeBackend, FleetNodeBackendError,
    FleetNodeConvergenceState, FleetNodeRuntimeStatus, FleetNodeStatus,
    FleetRecommendedAction, FleetRollbackPolicyConfig, FleetRollbackRequest,
    FleetRolloutCoordinator,
    FleetRolloutError, FleetRolloutHistoryEntry, FleetRolloutMetrics, FleetRolloutRequest,
    FleetRolloutResponse, FleetRolloutStrategy, InvalidFleetRequest,
};
pub use fleet_gate::{
    collect_wave_health_signals, evaluate_wave_gate, evaluate_wave_gate_with_policy,
    FleetNodeHealthSignal, FleetWaveGateEvaluation, FleetWaveGateVerdict,
};
pub use fleet_status::{
    render_staged_status_surface, FleetNodeStatusSurface, FleetStagedRolloutState,
    FleetStagedStatusSurface, FleetWaveStatusState, FleetWaveStatusSurface,
};
pub use fleet_staged::{
    plan_staged_rollout, FleetHealthGateMode, FleetHealthGatePolicy,
    FleetRolloutWaveDefinition, FleetStagedRolloutPlan, FleetStagedRolloutRequest,
    InvalidFleetStagedRolloutRequest,
};
pub use listener_canary::{
    ListenerCanaryApplyRequest, ListenerCanaryApplyResponse, ListenerCanaryCoordinator,
    ListenerCanaryError, ListenerCanaryMetrics,
};
pub use mtls::{
    PrivilegedChannelAuthenticator, PrivilegedChannelIdentity, PrivilegedChannelMtlsConfig,
    PrivilegedChannelMtlsError, PrivilegedMtlsMetrics,
};
pub use promotion::{
    PromotionApplyRequest, PromotionApplyResponse, PromotionCoordinator, PromotionError,
    PromotionExecutionStrategy, PromotionMetrics, PromotionPreviewRequest,
    PromotionPreviewResponse,
};
pub use rollout::{
    InvalidRolloutRequest, RollbackRequest, RolloutActionKind, RolloutCoordinator, RolloutError,
    RolloutHistoryEntry, RolloutMetrics, RolloutRequest, RolloutResponse, RolloutResultKind,
};

/// Returns the crate identifier for admin API surfaces.
pub const CRATE_ID: &str = "lb-admin-api";

/// Stable machine-readable HTTP admin API version.
pub const STABLE_ADMIN_API_VERSION: &str = "v1";

/// Stable machine-readable error codes for the versioned admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminApiErrorCode {
    Unauthorized,
    Forbidden,
    ReplayRejected,
    RateLimited,
    ValidationFailed,
    ReloadFailed,
    UnsupportedMutation,
    Internal,
    NotFound,
    UnsupportedApiVersion,
    Misconfigured,
}

/// Versioned admin API success envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedAdminApiSuccessEnvelope<T> {
    pub api_version: String,
    pub request_id: String,
    pub status: String,
    pub data: T,
}

impl<T> VersionedAdminApiSuccessEnvelope<T> {
    #[must_use]
    pub fn new(request_id: impl Into<String>, data: T) -> Self {
        Self {
            api_version: String::from(STABLE_ADMIN_API_VERSION),
            request_id: request_id.into(),
            status: String::from("ok"),
            data,
        }
    }
}

/// Stable machine-readable admin API error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedAdminApiError {
    pub code: AdminApiErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl VersionedAdminApiError {
    #[must_use]
    pub fn new(code: AdminApiErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self { code, message: message.into(), retryable }
    }
}

/// Versioned admin API error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedAdminApiErrorEnvelope {
    pub api_version: String,
    pub request_id: String,
    pub status: String,
    pub error: VersionedAdminApiError,
}

impl VersionedAdminApiErrorEnvelope {
    #[must_use]
    pub fn new(request_id: impl Into<String>, error: VersionedAdminApiError) -> Self {
        Self {
            api_version: String::from(STABLE_ADMIN_API_VERSION),
            request_id: request_id.into(),
            status: String::from("error"),
            error,
        }
    }
}

/// Returns the canonical versioned target path for a stable admin endpoint.
#[must_use]
pub fn versioned_admin_target(target: &str) -> String {
    if target.is_empty() {
        return String::from("/v1");
    }
    if target == "/" {
        return String::from("/v1/");
    }
    if target.starts_with('/') {
        return format!("/v1{target}");
    }
    format!("/v1/{target}")
}

/// Minimal admin API status view placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminStatus {
    /// Workspace-level configuration summary.
    pub config_name: String,
}

impl From<lb_config_model::WorkspaceConfig> for AdminStatus {
    fn from(value: lb_config_model::WorkspaceConfig) -> Self {
        Self { config_name: value.name }
    }
}

/// Thin admin facade for bounded support-bundle generation.
#[derive(Debug, Default)]
pub struct SupportBundleService {
    builder: lb_observability::SupportBundleBuilder,
}

impl SupportBundleService {
    /// Creates a support-bundle service with conservative redaction defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            builder: lb_observability::SupportBundleBuilder::new(lb_observability::RedactionEngine),
        }
    }

    /// Builds a support bundle for the current admin-visible status and diagnostics dump.
    pub fn generate(
        &self,
        bundle_name: &str,
        diagnostics: &lb_observability::RuntimeDiagnostics,
        limits: lb_observability::DiagnosticsLimits,
        status: &AdminStatus,
    ) -> Result<AdminSupportBundle, lb_observability::DiagnosticsError> {
        let bundle = self.builder.build_bundle(bundle_name, diagnostics, limits)?;
        Ok(AdminSupportBundle { config_name: status.config_name.clone(), bundle })
    }

    #[must_use]
    pub fn metrics(&self) -> lb_observability::SupportBundleMetrics {
        self.builder.metrics()
    }
}

/// Admin-visible bundle envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSupportBundle {
    pub config_name: String,
    pub bundle: lb_observability::SupportBundle,
}

/// Admin-exported decision-trace event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminDecisionTraceEvent {
    pub event_code: String,
    pub scope: String,
    pub result: String,
    pub reason: String,
    pub route: String,
    pub destination: String,
    pub policy: String,
    pub discovery: String,
    pub detail: String,
}

/// Machine-readable dashboard summary for route/policy decision diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminDecisionDiagnosticsDashboard {
    pub total_decision_events: usize,
    pub by_event_code: Vec<AdminDecisionBreakdownEntry>,
    pub by_route: Vec<AdminDecisionBreakdownEntry>,
    pub by_policy: Vec<AdminDecisionBreakdownEntry>,
    pub by_result: Vec<AdminDecisionBreakdownEntry>,
    pub failure_reasons: Vec<AdminDecisionBreakdownEntry>,
    pub recent_failures: Vec<AdminDecisionFailureSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminDecisionBreakdownEntry {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminDecisionFailureSample {
    pub event_code: String,
    pub route: String,
    pub policy: String,
    pub result: String,
    pub reason: String,
    pub detail: String,
}

/// Exports runtime decision-trace events for admin surfaces.
#[must_use]
pub fn export_decision_trace_events(
    diagnostics: &lb_observability::RuntimeDiagnostics,
) -> Vec<AdminDecisionTraceEvent> {
    diagnostics
        .events
        .iter()
        .filter(|event| {
            matches!(
                event.code,
                lb_observability::TelemetryEventCode::DecisionRouteSelected
                    | lb_observability::TelemetryEventCode::DecisionRetryEvaluated
                    | lb_observability::TelemetryEventCode::DecisionHealthEjection
                    | lb_observability::TelemetryEventCode::DecisionPolicyEnforced
                    | lb_observability::TelemetryEventCode::DecisionDiscoveryUpdated
                    | lb_observability::TelemetryEventCode::DecisionRolloutUpdated
            )
        })
        .map(|event| {
            let label_value = |key: lb_observability::TelemetryLabelKey| {
                event
                    .labels
                    .iter()
                    .find(|label| label.key == key)
                    .map_or_else(|| String::from("none"), |label| label.value.clone())
            };

            AdminDecisionTraceEvent {
                event_code: event.code.as_str().to_string(),
                scope: event.scope.clone(),
                result: label_value(lb_observability::TelemetryLabelKey::Result),
                reason: label_value(lb_observability::TelemetryLabelKey::Reason),
                route: label_value(lb_observability::TelemetryLabelKey::Route),
                destination: label_value(lb_observability::TelemetryLabelKey::Destination),
                policy: label_value(lb_observability::TelemetryLabelKey::Policy),
                discovery: label_value(lb_observability::TelemetryLabelKey::Discovery),
                detail: event.detail.clone(),
            }
        })
        .collect()
}

/// Renders machine-readable dashboard aggregates for operator-facing decision diagnostics.
#[must_use]
pub fn render_decision_diagnostics_dashboard(
    diagnostics: &lb_observability::RuntimeDiagnostics,
) -> AdminDecisionDiagnosticsDashboard {
    let decision_events = export_decision_trace_events(diagnostics);

    let mut by_event_code = std::collections::BTreeMap::<String, u64>::new();
    let mut by_route = std::collections::BTreeMap::<String, u64>::new();
    let mut by_policy = std::collections::BTreeMap::<String, u64>::new();
    let mut by_result = std::collections::BTreeMap::<String, u64>::new();
    let mut failure_reasons = std::collections::BTreeMap::<String, u64>::new();
    let mut recent_failures = Vec::new();

    for event in &decision_events {
        increment_bucket(&mut by_event_code, &event.event_code);
        increment_bucket(&mut by_route, &event.route);
        increment_bucket(&mut by_policy, &event.policy);
        increment_bucket(&mut by_result, &event.result);

        if is_decision_failure(&event.result) {
            let reason_key = if event.reason == "none" {
                String::from("unspecified")
            } else {
                event.reason.clone()
            };
            increment_bucket(&mut failure_reasons, &reason_key);
            if recent_failures.len() < 10 {
                recent_failures.push(AdminDecisionFailureSample {
                    event_code: event.event_code.clone(),
                    route: event.route.clone(),
                    policy: event.policy.clone(),
                    result: event.result.clone(),
                    reason: reason_key,
                    detail: event.detail.clone(),
                });
            }
        }
    }

    AdminDecisionDiagnosticsDashboard {
        total_decision_events: decision_events.len(),
        by_event_code: map_to_breakdown(by_event_code),
        by_route: map_to_breakdown(by_route),
        by_policy: map_to_breakdown(by_policy),
        by_result: map_to_breakdown(by_result),
        failure_reasons: map_to_breakdown(failure_reasons),
        recent_failures,
    }
}

fn increment_bucket(map: &mut std::collections::BTreeMap<String, u64>, key: &str) {
    let entry = map.entry(key.to_string()).or_insert(0);
    *entry = entry.saturating_add(1);
}

fn map_to_breakdown(
    map: std::collections::BTreeMap<String, u64>,
) -> Vec<AdminDecisionBreakdownEntry> {
    map.into_iter()
        .map(|(key, count)| AdminDecisionBreakdownEntry { key, count })
        .collect()
}

fn is_decision_failure(result: &str) -> bool {
    matches!(
        result,
        "failed" | "rejected" | "denied" | "blocked" | "timeout" | "error"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        export_decision_trace_events, render_decision_diagnostics_dashboard,
        versioned_admin_target, AdminApiErrorCode, AdminStatus,
        SupportBundleService,
        VersionedAdminApiError, VersionedAdminApiErrorEnvelope,
        VersionedAdminApiSuccessEnvelope,
    };

    #[test]
    fn support_bundle_generation_is_bounded_and_partial_failure_tolerant(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let service = SupportBundleService::new();
        let diagnostics =
            lb_observability::SupportBundleBuilder::new(lb_observability::RedactionEngine)
                .collect_runtime_diagnostics(
                    lb_observability::DiagnosticsLimits::default(),
                    lb_observability::RuntimeDiagnosticsInput {
                        metrics_text: Some(String::from("runtime_metric 1")),
                        logs: None,
                        events: Some(Vec::new()),
                        cache_diagnostics_text: None,
                    },
                );
        let bundle = service.generate(
            "incident-003",
            &diagnostics,
            lb_observability::DiagnosticsLimits::default(),
            &AdminStatus { config_name: String::from("way-balancer") },
        )?;

        assert_eq!(bundle.config_name, "way-balancer");
        assert!(bundle.bundle.artifacts.iter().any(|artifact| artifact.name == "summary.txt"));
        assert!(bundle
            .bundle
            .warnings
            .iter()
            .any(|warning| warning.detail.contains("logs section unavailable")));
        assert_eq!(service.metrics().success_count, 1);
        Ok(())
    }

    #[test]
    fn versioned_admin_target_normalizes_paths() {
        assert_eq!(versioned_admin_target("/status"), "/v1/status");
        assert_eq!(versioned_admin_target("reload"), "/v1/reload");
        assert_eq!(versioned_admin_target(""), "/v1");
    }

    #[test]
    fn versioned_success_envelope_serializes_stably() -> Result<(), Box<dyn std::error::Error>> {
        let body = serde_json::to_value(VersionedAdminApiSuccessEnvelope::new(
            "req-1",
            serde_json::json!({"ready": true}),
        ))?;

        assert_eq!(body["api_version"], "v1");
        assert_eq!(body["request_id"], "req-1");
        assert_eq!(body["status"], "ok");
        assert_eq!(body["data"]["ready"], true);
        Ok(())
    }

    #[test]
    fn versioned_error_envelope_serializes_stably() -> Result<(), Box<dyn std::error::Error>> {
        let body = serde_json::to_value(VersionedAdminApiErrorEnvelope::new(
            "req-2",
            VersionedAdminApiError::new(
                AdminApiErrorCode::UnsupportedApiVersion,
                "unsupported admin api version",
                false,
            ),
        ))?;

        assert_eq!(body["api_version"], "v1");
        assert_eq!(body["request_id"], "req-2");
        assert_eq!(body["status"], "error");
        assert_eq!(body["error"]["code"], "unsupported_api_version");
        assert_eq!(body["error"]["retryable"], false);
        Ok(())
    }

    #[test]
    fn exports_decision_trace_events_from_runtime_diagnostics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let decision_events = vec![
            lb_observability::TelemetryEvent::new(
                lb_observability::TelemetryEventCode::DecisionRouteSelected,
                "http1-proxy",
                "route selected",
                vec![
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Result,
                        "selected",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Route,
                        "route.api",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Destination,
                        "cluster.api",
                    ),
                ],
            ),
            lb_observability::TelemetryEvent::new(
                lb_observability::TelemetryEventCode::DecisionRetryEvaluated,
                "http1-proxy",
                "retry rejected",
                vec![
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Result,
                        "rejected",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Route,
                        "route.api",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Destination,
                        "cluster.api",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Policy,
                        "retry_budget",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Reason,
                        "budget_exhausted",
                    ),
                ],
            ),
        ];

        let diagnostics = lb_observability::SupportBundleBuilder::new(lb_observability::RedactionEngine)
            .collect_runtime_diagnostics(
                lb_observability::DiagnosticsLimits::default(),
                lb_observability::RuntimeDiagnosticsInput {
                    metrics_text: Some(String::new()),
                    logs: Some(Vec::new()),
                    events: Some(decision_events),
                    cache_diagnostics_text: Some(String::new()),
                },
            );

        let decision_events = export_decision_trace_events(&diagnostics);
        assert_eq!(decision_events.len(), 2);
        assert_eq!(decision_events[0].event_code, "decision.route.selected");
        assert_eq!(decision_events[0].route, "route.api");
        assert_eq!(decision_events[1].event_code, "decision.retry.evaluated");
        assert_eq!(decision_events[1].reason, "budget_exhausted");
        assert_eq!(decision_events[1].policy, "retry_budget");
        Ok(())
    }

    #[test]
    fn renders_machine_readable_decision_dashboard_summary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let decision_events = vec![
            lb_observability::TelemetryEvent::new(
                lb_observability::TelemetryEventCode::DecisionRouteSelected,
                "http1-proxy",
                "route selected",
                vec![
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Result,
                        "selected",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Route,
                        "route.api",
                    ),
                ],
            ),
            lb_observability::TelemetryEvent::new(
                lb_observability::TelemetryEventCode::DecisionPolicyEnforced,
                "http1-proxy",
                "policy rejected",
                vec![
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Result,
                        "rejected",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Route,
                        "route.api",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Policy,
                        "authz",
                    ),
                    lb_observability::TelemetryLabel::new(
                        lb_observability::TelemetryLabelKey::Reason,
                        "policy_denied",
                    ),
                ],
            ),
        ];

        let diagnostics = lb_observability::SupportBundleBuilder::new(lb_observability::RedactionEngine)
            .collect_runtime_diagnostics(
                lb_observability::DiagnosticsLimits::default(),
                lb_observability::RuntimeDiagnosticsInput {
                    metrics_text: Some(String::new()),
                    logs: Some(Vec::new()),
                    events: Some(decision_events),
                    cache_diagnostics_text: Some(String::new()),
                },
            );

        let dashboard = render_decision_diagnostics_dashboard(&diagnostics);
        assert_eq!(dashboard.total_decision_events, 2);
        assert!(dashboard
            .failure_reasons
            .iter()
            .any(|entry| entry.key == "policy_denied" && entry.count == 1));
        assert_eq!(dashboard.recent_failures.len(), 1);
        assert_eq!(dashboard.recent_failures[0].policy, "authz");
        Ok(())
    }
}
