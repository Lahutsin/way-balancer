#![forbid(unsafe_code)]

mod abuse_control;
mod auth;
mod cache;
mod cache_transport;
mod control;
mod fleet;
mod mtls;
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
    SnapshotBackupError, SnapshotControlService, SnapshotLookupError, SnapshotPublicationError,
    SnapshotPublishRequest, SnapshotRegistryDurableEnvelope, SnapshotRegistryDurableState,
    SnapshotRegistryMetrics, SnapshotRegistryRetentionPolicy, SnapshotRegistryStateError,
    SnapshotRestoreError,
};
pub use fleet::{
    FleetConsistencyMode, FleetConvergenceReport, FleetConvergenceState,
    FleetNodeActionOutcome, FleetNodeActionResult, FleetNodeBackend, FleetNodeBackendError,
    FleetNodeConvergenceState, FleetNodeRuntimeStatus, FleetNodeStatus,
    FleetRecommendedAction, FleetRollbackRequest, FleetRolloutCoordinator,
    FleetRolloutError, FleetRolloutHistoryEntry, FleetRolloutMetrics, FleetRolloutRequest,
    FleetRolloutResponse, FleetRolloutStrategy, InvalidFleetRequest,
};
pub use mtls::{
    PrivilegedChannelAuthenticator, PrivilegedChannelIdentity, PrivilegedChannelMtlsConfig,
    PrivilegedChannelMtlsError, PrivilegedMtlsMetrics,
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

#[cfg(test)]
mod tests {
    use super::{
        versioned_admin_target, AdminApiErrorCode, AdminStatus, SupportBundleService,
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
}
