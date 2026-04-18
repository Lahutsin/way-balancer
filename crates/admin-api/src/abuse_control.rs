use std::time::{SystemTime, UNIX_EPOCH};

use crate::{AdminStatus, AdminSupportBundle, SupportBundleService};

const MAX_ACTOR_LEN: usize = 128;
const MAX_REASON_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyModeAdminRequest {
    pub mode: lb_runtime::EmergencyProtectionMode,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
    pub allow_relaxation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseForensicsExportRequest {
    pub bundle_name: String,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
    pub limits: lb_observability::DiagnosticsLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseControlActionKind {
    SwitchMode,
    ExportForensics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseControlResultKind {
    Applied,
    Unchanged,
    Exported,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseControlHistoryEntry {
    pub action: AbuseControlActionKind,
    pub result: AbuseControlResultKind,
    pub previous_mode: lb_runtime::EmergencyProtectionMode,
    pub active_mode: lb_runtime::EmergencyProtectionMode,
    pub actor: Option<String>,
    pub reason: Option<String>,
    pub occurred_at_unix_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AbuseControlMetrics {
    pub successful_mode_switch_count: u64,
    pub rejected_mode_switch_count: u64,
    pub forensic_export_success_count: u64,
    pub forensic_export_failure_count: u64,
    pub audit_event_count: u64,
    pub history_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyModeAdminResponse {
    pub result: AbuseControlResultKind,
    pub previous_mode: lb_runtime::EmergencyProtectionMode,
    pub active_mode: lb_runtime::EmergencyProtectionMode,
    pub active_profile: lb_runtime::EmergencyProtectionProfile,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidAbuseControlRequest {
    EmptyRequestedBy,
    RequestedByTooLong,
    EmptyReason,
    ReasonTooLong,
    EmptyBundleName,
}

impl std::fmt::Display for InvalidAbuseControlRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRequestedBy => formatter.write_str("requested_by must not be empty"),
            Self::RequestedByTooLong => formatter.write_str("requested_by exceeds max length"),
            Self::EmptyReason => formatter.write_str("reason must not be empty"),
            Self::ReasonTooLong => formatter.write_str("reason exceeds max length"),
            Self::EmptyBundleName => formatter.write_str("bundle_name must not be empty"),
        }
    }
}

impl std::error::Error for InvalidAbuseControlRequest {}

#[derive(Debug)]
pub enum AbuseControlError {
    InvalidRequest(InvalidAbuseControlRequest),
    ModeSwitch(lb_runtime::EmergencyModeSwitchError),
    Forensics(lb_runtime::AbuseForensicsError),
    SupportBundle(lb_observability::DiagnosticsError),
    Internal(SystemTimeError),
}

impl std::fmt::Display for AbuseControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(error) => {
                write!(formatter, "invalid abuse-control request: {error}")
            }
            Self::ModeSwitch(error) => write!(formatter, "emergency mode switch failed: {error}"),
            Self::Forensics(error) => write!(formatter, "abuse forensics export failed: {error}"),
            Self::SupportBundle(error) => {
                write!(formatter, "support bundle generation failed: {error}")
            }
            Self::Internal(error) => {
                write!(formatter, "abuse-control operation failed internally: {error}")
            }
        }
    }
}

impl std::error::Error for AbuseControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRequest(error) => Some(error),
            Self::ModeSwitch(error) => Some(error),
            Self::Forensics(error) => Some(error),
            Self::SupportBundle(error) => Some(error),
            Self::Internal(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub struct SystemTimeError(std::time::SystemTimeError);

impl std::fmt::Display for SystemTimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "failed to read system time: {}", self.0)
    }
}

impl std::error::Error for SystemTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug, Default)]
pub struct AbuseProtectionAdminService {
    support_bundle: SupportBundleService,
    history: Vec<AbuseControlHistoryEntry>,
    metrics: AbuseControlMetrics,
}

impl AbuseProtectionAdminService {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn switch_mode(
        &mut self,
        controller: &mut lb_runtime::EmergencyProtectionController,
        request: EmergencyModeAdminRequest,
    ) -> Result<EmergencyModeAdminResponse, AbuseControlError> {
        validate_actor_reason(request.requested_by.as_deref(), request.reason.as_deref())
            .map_err(AbuseControlError::InvalidRequest)?;
        let occurred_at_unix_ms = current_unix_ms().map_err(AbuseControlError::Internal)?;
        let previous_mode = controller.active_mode();

        match controller.switch_mode_at(
            lb_runtime::EmergencyModeSwitchRequest {
                target_mode: request.mode,
                allow_relaxation: request.allow_relaxation,
            },
            occurred_at_unix_ms,
        ) {
            Ok(response) => {
                let result = match response.result {
                    lb_runtime::EmergencyModeSwitchResult::Applied => {
                        self.metrics.successful_mode_switch_count =
                            self.metrics.successful_mode_switch_count.saturating_add(1);
                        AbuseControlResultKind::Applied
                    }
                    lb_runtime::EmergencyModeSwitchResult::Unchanged => {
                        AbuseControlResultKind::Unchanged
                    }
                };
                self.push_history(AbuseControlHistoryEntry {
                    action: AbuseControlActionKind::SwitchMode,
                    result,
                    previous_mode,
                    active_mode: response.active_mode,
                    actor: request.requested_by,
                    reason: request.reason,
                    occurred_at_unix_ms,
                    detail: format!("emergency protection mode is now {}", response.active_mode),
                });
                Ok(EmergencyModeAdminResponse {
                    result,
                    previous_mode: response.previous_mode,
                    active_mode: response.active_mode,
                    active_profile: response.active_profile,
                    occurred_at_unix_ms: response.occurred_at_unix_ms,
                })
            }
            Err(error) => {
                self.metrics.rejected_mode_switch_count =
                    self.metrics.rejected_mode_switch_count.saturating_add(1);
                self.push_history(AbuseControlHistoryEntry {
                    action: AbuseControlActionKind::SwitchMode,
                    result: AbuseControlResultKind::Rejected,
                    previous_mode,
                    active_mode: previous_mode,
                    actor: request.requested_by,
                    reason: request.reason,
                    occurred_at_unix_ms,
                    detail: error.to_string(),
                });
                Err(AbuseControlError::ModeSwitch(error))
            }
        }
    }

    pub fn export_forensics(
        &mut self,
        controller: &mut lb_runtime::EmergencyProtectionController,
        request: AbuseForensicsExportRequest,
        diagnostics: &lb_observability::RuntimeDiagnostics,
        status: &AdminStatus,
    ) -> Result<AdminSupportBundle, AbuseControlError> {
        validate_actor_reason(request.requested_by.as_deref(), request.reason.as_deref())
            .map_err(AbuseControlError::InvalidRequest)?;
        if request.bundle_name.trim().is_empty() {
            return Err(AbuseControlError::InvalidRequest(
                InvalidAbuseControlRequest::EmptyBundleName,
            ));
        }

        let occurred_at_unix_ms = current_unix_ms().map_err(AbuseControlError::Internal)?;
        let forensic =
            match controller.export_forensics(request.limits, &lb_observability::RedactionEngine) {
                Ok(forensic) => forensic,
                Err(error) => {
                    self.metrics.forensic_export_failure_count =
                        self.metrics.forensic_export_failure_count.saturating_add(1);
                    self.push_history(AbuseControlHistoryEntry {
                        action: AbuseControlActionKind::ExportForensics,
                        result: AbuseControlResultKind::Rejected,
                        previous_mode: controller.active_mode(),
                        active_mode: controller.active_mode(),
                        actor: request.requested_by,
                        reason: request.reason,
                        occurred_at_unix_ms,
                        detail: error.to_string(),
                    });
                    return Err(AbuseControlError::Forensics(error));
                }
            };

        let mut bundle = self
            .support_bundle
            .generate(&request.bundle_name, diagnostics, request.limits, status)
            .map_err(AbuseControlError::SupportBundle)?;
        bundle.bundle.artifacts.push(lb_observability::SupportBundleArtifact {
            name: String::from("abuse-forensics.txt"),
            content: forensic.content,
            truncated: forensic.truncated,
        });

        self.metrics.forensic_export_success_count =
            self.metrics.forensic_export_success_count.saturating_add(1);
        self.push_history(AbuseControlHistoryEntry {
            action: AbuseControlActionKind::ExportForensics,
            result: AbuseControlResultKind::Exported,
            previous_mode: controller.active_mode(),
            active_mode: controller.active_mode(),
            actor: request.requested_by,
            reason: request.reason,
            occurred_at_unix_ms,
            detail: format!("abuse forensics exported for mode {}", controller.active_mode()),
        });

        Ok(bundle)
    }

    #[must_use]
    pub fn history(&self) -> &[AbuseControlHistoryEntry] {
        &self.history
    }

    #[must_use]
    pub fn metrics(&self) -> AbuseControlMetrics {
        self.metrics
    }

    fn push_history(&mut self, entry: AbuseControlHistoryEntry) {
        self.history.push(entry);
        self.metrics.audit_event_count = self.metrics.audit_event_count.saturating_add(1);
        self.metrics.history_size = self.history.len();
    }
}

fn validate_actor_reason(
    requested_by: Option<&str>,
    reason: Option<&str>,
) -> Result<(), InvalidAbuseControlRequest> {
    if let Some(requested_by) = requested_by {
        if requested_by.trim().is_empty() {
            return Err(InvalidAbuseControlRequest::EmptyRequestedBy);
        }
        if requested_by.len() > MAX_ACTOR_LEN {
            return Err(InvalidAbuseControlRequest::RequestedByTooLong);
        }
    }
    if let Some(reason) = reason {
        if reason.trim().is_empty() {
            return Err(InvalidAbuseControlRequest::EmptyReason);
        }
        if reason.len() > MAX_REASON_LEN {
            return Err(InvalidAbuseControlRequest::ReasonTooLong);
        }
    }
    Ok(())
}

fn current_unix_ms() -> Result<u64, SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(SystemTimeError)?.as_millis() as u64)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{
        AbuseForensicsExportRequest, AbuseProtectionAdminService, EmergencyModeAdminRequest,
        InvalidAbuseControlRequest,
    };
    use crate::AdminStatus;

    #[test]
    fn admin_mode_switch_and_forensics_export_are_audited() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut controller = lb_runtime::EmergencyProtectionController::new();
        controller.record_abuse_event_at(
            lb_runtime::AbuseEventInput {
                category: lb_runtime::AbuseEventCategory::ProtocolAnomaly(
                    lb_runtime::ProtocolAnomalyCategory::MalformedMessage,
                ),
                detail: String::from("authorization: bearer top-secret"),
                labels: Vec::new(),
            },
            1,
        );

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

        let mut service = AbuseProtectionAdminService::new();
        let response = service.switch_mode(
            &mut controller,
            EmergencyModeAdminRequest {
                mode: lb_runtime::EmergencyProtectionMode::Elevated,
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("traffic spike")),
                allow_relaxation: false,
            },
        )?;
        let bundle = service.export_forensics(
            &mut controller,
            AbuseForensicsExportRequest {
                bundle_name: String::from("abuse-incident-01"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("capture evidence")),
                limits: lb_observability::DiagnosticsLimits::default(),
            },
            &diagnostics,
            &AdminStatus { config_name: String::from("way-balancer") },
        )?;

        assert_eq!(response.active_mode, lb_runtime::EmergencyProtectionMode::Elevated);
        assert!(bundle
            .bundle
            .artifacts
            .iter()
            .any(|artifact| artifact.name == "abuse-forensics.txt"));
        let forensic_artifact = bundle
            .bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "abuse-forensics.txt")
            .ok_or_else(|| std::io::Error::other("forensic artifact should exist"))?;
        assert!(forensic_artifact.content.contains("[REDACTED]"));
        assert_eq!(service.history().len(), 2);
        assert_eq!(service.metrics().audit_event_count, 2);
        Ok(())
    }

    #[test]
    fn empty_actor_is_rejected() {
        let mut controller = lb_runtime::EmergencyProtectionController::new();
        let mut service = AbuseProtectionAdminService::new();

        let result = service.switch_mode(
            &mut controller,
            EmergencyModeAdminRequest {
                mode: lb_runtime::EmergencyProtectionMode::Elevated,
                requested_by: Some(String::new()),
                reason: None,
                allow_relaxation: false,
            },
        );

        assert!(matches!(
            result,
            Err(super::AbuseControlError::InvalidRequest(
                InvalidAbuseControlRequest::EmptyRequestedBy
            ))
        ));
    }

    #[test]
    fn invalid_bundle_name_and_error_sources_are_explicit() -> Result<(), Box<dyn std::error::Error>>
    {
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
        let mut controller = lb_runtime::EmergencyProtectionController::new();
        let mut service = AbuseProtectionAdminService::new();

        let error = service
            .export_forensics(
                &mut controller,
                AbuseForensicsExportRequest {
                    bundle_name: String::new(),
                    requested_by: Some(String::from("operator-a")),
                    reason: Some(String::from("capture evidence")),
                    limits: lb_observability::DiagnosticsLimits::default(),
                },
                &diagnostics,
                &AdminStatus { config_name: String::from("way-balancer") },
            )
            .expect_err("empty bundle names should be rejected");

        assert!(matches!(
            error,
            super::AbuseControlError::InvalidRequest(InvalidAbuseControlRequest::EmptyBundleName)
        ));
        assert!(std::error::Error::source(&error).is_some());
        Ok(())
    }

    #[test]
    fn switch_mode_tracks_unchanged_and_rejected_paths() -> Result<(), Box<dyn std::error::Error>> {
        let mut controller = lb_runtime::EmergencyProtectionController::new();
        let mut service = AbuseProtectionAdminService::new();

        let unchanged = service.switch_mode(
            &mut controller,
            EmergencyModeAdminRequest {
                mode: lb_runtime::EmergencyProtectionMode::Baseline,
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("already baseline")),
                allow_relaxation: false,
            },
        )?;

        let _ = service.switch_mode(
            &mut controller,
            EmergencyModeAdminRequest {
                mode: lb_runtime::EmergencyProtectionMode::Elevated,
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("raise mode")),
                allow_relaxation: false,
            },
        )?;

        let rejected = service
            .switch_mode(
                &mut controller,
                EmergencyModeAdminRequest {
                    mode: lb_runtime::EmergencyProtectionMode::Baseline,
                    requested_by: Some(String::from("operator-a")),
                    reason: Some(String::from("lower without override")),
                    allow_relaxation: false,
                },
            )
            .expect_err("relaxation without override should be rejected");

        assert_eq!(unchanged.result, super::AbuseControlResultKind::Unchanged);
        assert!(matches!(rejected, super::AbuseControlError::ModeSwitch(_)));
        assert_eq!(service.metrics().rejected_mode_switch_count, 1);
        assert_eq!(
            service.history().last().map(|entry| entry.result),
            Some(super::AbuseControlResultKind::Rejected)
        );
        Ok(())
    }

    #[test]
    fn forensics_failure_and_request_validation_are_counted(
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        let mut controller = lb_runtime::EmergencyProtectionController::new();
        let mut service = AbuseProtectionAdminService::new();

        let invalid_actor = super::validate_actor_reason(Some(&"a".repeat(129)), None);
        let invalid_reason = super::validate_actor_reason(None, Some(&"r".repeat(257)));
        let forensics = service
            .export_forensics(
                &mut controller,
                AbuseForensicsExportRequest {
                    bundle_name: String::from("bundle"),
                    requested_by: Some(String::from("operator-a")),
                    reason: Some(String::from("capture evidence")),
                    limits: lb_observability::DiagnosticsLimits {
                        max_metrics_bytes: 1,
                        max_log_records: 1,
                        max_event_records: 1,
                        max_artifact_bytes: 0,
                    },
                },
                &diagnostics,
                &AdminStatus { config_name: String::from("way-balancer") },
            )
            .expect_err("zero artifact limit should fail forensics export");

        assert_eq!(invalid_actor, Err(InvalidAbuseControlRequest::RequestedByTooLong));
        assert_eq!(invalid_reason, Err(InvalidAbuseControlRequest::ReasonTooLong));
        assert!(matches!(forensics, super::AbuseControlError::Forensics(_)));
        assert_eq!(service.metrics().forensic_export_failure_count, 1);
        Ok(())
    }
}
