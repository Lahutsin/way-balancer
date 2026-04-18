#![forbid(unsafe_code)]

mod abuse_control;
mod auth;
mod cache;
mod cache_transport;
mod control;
mod mtls;
mod rollout;

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
    HttpCachePeerInvalidationResponse, HttpCachePeerInvalidationResult, HttpCachePeerTransport,
    InvalidHttpCachePeerConfig,
};
pub use control::{
    InvalidPublishRequest, PublishConflict, PublishEvent, PublishEventKind, PublishResponse,
    PublishResponseKind, PublishedSnapshotRecord, PublishedSnapshotSummary, SnapshotBackupBundle,
    SnapshotBackupError, SnapshotControlService, SnapshotLookupError, SnapshotPublicationError,
    SnapshotPublishRequest, SnapshotRegistryMetrics, SnapshotRestoreError,
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
    use super::{AdminStatus, SupportBundleService};

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
}
