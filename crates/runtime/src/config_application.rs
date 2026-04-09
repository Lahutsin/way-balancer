use std::time::{SystemTime, UNIX_EPOCH};

use lb_config_model::{
    verify_snapshot_artifact_integrity, ArtifactAttestation, ArtifactIntegrityError,
    WorkspaceSnapshot,
};

const SHA256_HEX_LEN: usize = 64;
const MAX_VERSION_LEN: usize = 128;
const MAX_ACTOR_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotApplyRequest {
    pub version: String,
    pub snapshot: WorkspaceSnapshot,
    pub artifact_attestation: Option<ArtifactAttestation>,
    pub expected_digest_sha256: String,
    pub acknowledged_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedSnapshotRecord {
    pub version: String,
    pub workspace_name: String,
    pub digest_sha256: String,
    pub applied_at_unix_ms: u64,
    pub acknowledged_by: Option<String>,
    pub snapshot: WorkspaceSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedSnapshotSummary {
    pub version: String,
    pub workspace_name: String,
    pub digest_sha256: String,
    pub applied_at_unix_ms: u64,
    pub acknowledged_by: Option<String>,
}

impl From<&AppliedSnapshotRecord> for AppliedSnapshotSummary {
    fn from(value: &AppliedSnapshotRecord) -> Self {
        Self {
            version: value.version.clone(),
            workspace_name: value.workspace_name.clone(),
            digest_sha256: value.digest_sha256.clone(),
            applied_at_unix_ms: value.applied_at_unix_ms,
            acknowledged_by: value.acknowledged_by.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotApplyOutcome {
    Applied,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotApplyAck {
    pub outcome: SnapshotApplyOutcome,
    pub active: AppliedSnapshotSummary,
    pub last_known_good: AppliedSnapshotSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotApplyFailureCategory {
    Integrity,
    Activation,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotApplyFailure {
    pub category: SnapshotApplyFailureCategory,
    pub version: String,
    pub digest_sha256: String,
    pub failed_at_unix_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotApplyLifecycle {
    Idle,
    Applying { version: String, digest_sha256: String },
    Active { version: String, digest_sha256: String },
    ApplyFailed { version: String, digest_sha256: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneSnapshotStatus {
    pub lifecycle: SnapshotApplyLifecycle,
    pub active: Option<AppliedSnapshotSummary>,
    pub last_known_good: Option<AppliedSnapshotSummary>,
    pub last_apply_failure: Option<SnapshotApplyFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SnapshotApplyMetrics {
    pub apply_success_count: u64,
    pub apply_noop_count: u64,
    pub apply_integrity_failure_count: u64,
    pub apply_activation_failure_count: u64,
    pub apply_internal_failure_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidApplyRequest {
    EmptyVersion,
    InvalidVersionFormat,
    VersionTooLong,
    InvalidSnapshotDigest,
    InvalidExpectedDigestFormat,
    DigestMismatch,
    EmptyAcknowledgedBy,
    AcknowledgedByTooLong,
}

impl std::fmt::Display for InvalidApplyRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyVersion => write!(formatter, "snapshot version must not be empty"),
            Self::InvalidVersionFormat => {
                write!(formatter, "snapshot version contains unsupported characters")
            }
            Self::VersionTooLong => write!(formatter, "snapshot version exceeds max length"),
            Self::InvalidSnapshotDigest => {
                write!(formatter, "snapshot digest must be a lowercase sha256 hex string")
            }
            Self::InvalidExpectedDigestFormat => {
                write!(formatter, "expected digest must be a lowercase sha256 hex string")
            }
            Self::DigestMismatch => {
                write!(formatter, "expected digest does not match snapshot digest")
            }
            Self::EmptyAcknowledgedBy => {
                write!(formatter, "acknowledged_by must not be empty")
            }
            Self::AcknowledgedByTooLong => {
                write!(formatter, "acknowledged_by exceeds max length")
            }
        }
    }
}

impl std::error::Error for InvalidApplyRequest {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotActivationError {
    Rejected(String),
}

impl std::fmt::Display for SnapshotActivationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(detail) => write!(formatter, "snapshot activation rejected: {detail}"),
        }
    }
}

impl std::error::Error for SnapshotActivationError {}

pub trait SnapshotActivationHook: Send + Sync {
    fn validate(&self, snapshot: &WorkspaceSnapshot) -> Result<(), SnapshotActivationError>;
    fn activate(&self, snapshot: &WorkspaceSnapshot) -> Result<(), SnapshotActivationError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSnapshotActivationHook;

impl SnapshotActivationHook for NoopSnapshotActivationHook {
    fn validate(&self, _snapshot: &WorkspaceSnapshot) -> Result<(), SnapshotActivationError> {
        Ok(())
    }

    fn activate(&self, _snapshot: &WorkspaceSnapshot) -> Result<(), SnapshotActivationError> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum SnapshotApplyError {
    InvalidRequest(InvalidApplyRequest),
    Integrity(ArtifactIntegrityError),
    Activation(SnapshotActivationError),
    Internal(SystemTimeError),
}

impl std::fmt::Display for SnapshotApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(error) => {
                write!(formatter, "invalid snapshot apply request: {error}")
            }
            Self::Integrity(error) => {
                write!(formatter, "snapshot integrity verification failed: {error}")
            }
            Self::Activation(error) => write!(formatter, "snapshot apply failed: {error}"),
            Self::Internal(error) => write!(formatter, "snapshot apply failed internally: {error}"),
        }
    }
}

impl std::error::Error for SnapshotApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRequest(error) => Some(error),
            Self::Integrity(error) => Some(error),
            Self::Activation(error) => Some(error),
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

pub struct DataplaneSnapshotManager {
    hook: Box<dyn SnapshotActivationHook>,
    lifecycle: SnapshotApplyLifecycle,
    active: Option<AppliedSnapshotRecord>,
    last_known_good: Option<AppliedSnapshotRecord>,
    last_apply_failure: Option<SnapshotApplyFailure>,
    metrics: SnapshotApplyMetrics,
}

impl Default for DataplaneSnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DataplaneSnapshotManager {
    #[must_use]
    pub fn new() -> Self {
        Self::with_hook(NoopSnapshotActivationHook)
    }

    #[must_use]
    pub fn with_hook<H>(hook: H) -> Self
    where
        H: SnapshotActivationHook + 'static,
    {
        Self {
            hook: Box::new(hook),
            lifecycle: SnapshotApplyLifecycle::Idle,
            active: None,
            last_known_good: None,
            last_apply_failure: None,
            metrics: SnapshotApplyMetrics::default(),
        }
    }

    pub fn apply(
        &mut self,
        request: SnapshotApplyRequest,
    ) -> Result<SnapshotApplyAck, SnapshotApplyError> {
        let applied_at_unix_ms = current_unix_ms().map_err(|error| {
            self.metrics.apply_internal_failure_count =
                self.metrics.apply_internal_failure_count.saturating_add(1);
            SnapshotApplyError::Internal(error)
        })?;
        self.apply_at(request, applied_at_unix_ms)
    }

    pub fn apply_at(
        &mut self,
        request: SnapshotApplyRequest,
        applied_at_unix_ms: u64,
    ) -> Result<SnapshotApplyAck, SnapshotApplyError> {
        if let Err(error) = validate_apply_request(&request) {
            let digest_sha256 = request.snapshot.metadata().digest_sha256().to_owned();
            self.record_failure(
                SnapshotApplyFailureCategory::Integrity,
                request.version,
                digest_sha256,
                applied_at_unix_ms,
                error.to_string(),
            );
            return Err(SnapshotApplyError::InvalidRequest(error));
        }

        let digest_sha256 = request.snapshot.metadata().digest_sha256().to_owned();
        if let Err(error) = verify_snapshot_artifact_integrity(
            &request.snapshot,
            request.artifact_attestation.as_ref(),
        ) {
            self.record_failure(
                SnapshotApplyFailureCategory::Integrity,
                request.version,
                digest_sha256,
                applied_at_unix_ms,
                error.to_string(),
            );
            return Err(SnapshotApplyError::Integrity(error));
        }

        let digest_sha256 = request.snapshot.metadata().digest_sha256().to_owned();
        self.lifecycle = SnapshotApplyLifecycle::Applying {
            version: request.version.clone(),
            digest_sha256: digest_sha256.clone(),
        };

        if let Some(active) = &self.active {
            if active.version == request.version && active.digest_sha256 == digest_sha256 {
                self.metrics.apply_noop_count = self.metrics.apply_noop_count.saturating_add(1);
                self.lifecycle = SnapshotApplyLifecycle::Active {
                    version: active.version.clone(),
                    digest_sha256: active.digest_sha256.clone(),
                };
                return Ok(SnapshotApplyAck {
                    outcome: SnapshotApplyOutcome::Unchanged,
                    active: AppliedSnapshotSummary::from(active),
                    last_known_good: AppliedSnapshotSummary::from(
                        self.last_known_good.as_ref().unwrap_or(active),
                    ),
                });
            }
        }

        if let Err(error) = self.hook.validate(&request.snapshot) {
            self.record_failure(
                SnapshotApplyFailureCategory::Activation,
                request.version,
                digest_sha256,
                applied_at_unix_ms,
                error.to_string(),
            );
            return Err(SnapshotApplyError::Activation(error));
        }

        if let Err(error) = self.hook.activate(&request.snapshot) {
            self.record_failure(
                SnapshotApplyFailureCategory::Activation,
                request.version,
                digest_sha256,
                applied_at_unix_ms,
                error.to_string(),
            );
            return Err(SnapshotApplyError::Activation(error));
        }

        let record = AppliedSnapshotRecord {
            version: request.version.clone(),
            workspace_name: request.snapshot.workspace_name().to_owned(),
            digest_sha256: digest_sha256.clone(),
            applied_at_unix_ms,
            acknowledged_by: request.acknowledged_by,
            snapshot: request.snapshot,
        };
        let summary = AppliedSnapshotSummary::from(&record);

        self.active = Some(record.clone());
        self.last_known_good = Some(record);
        self.last_apply_failure = None;
        self.metrics.apply_success_count = self.metrics.apply_success_count.saturating_add(1);
        self.lifecycle = SnapshotApplyLifecycle::Active { version: request.version, digest_sha256 };

        Ok(SnapshotApplyAck {
            outcome: SnapshotApplyOutcome::Applied,
            active: summary.clone(),
            last_known_good: summary,
        })
    }

    #[must_use]
    pub fn status(&self) -> DataplaneSnapshotStatus {
        DataplaneSnapshotStatus {
            lifecycle: self.lifecycle.clone(),
            active: self.active.as_ref().map(AppliedSnapshotSummary::from),
            last_known_good: self.last_known_good.as_ref().map(AppliedSnapshotSummary::from),
            last_apply_failure: self.last_apply_failure.clone(),
        }
    }

    #[must_use]
    pub fn active_record(&self) -> Option<&AppliedSnapshotRecord> {
        self.active.as_ref()
    }

    #[must_use]
    pub fn last_known_good_record(&self) -> Option<&AppliedSnapshotRecord> {
        self.last_known_good.as_ref()
    }

    #[must_use]
    pub const fn metrics(&self) -> SnapshotApplyMetrics {
        self.metrics
    }

    fn record_failure(
        &mut self,
        category: SnapshotApplyFailureCategory,
        version: String,
        digest_sha256: String,
        failed_at_unix_ms: u64,
        detail: String,
    ) {
        match category {
            SnapshotApplyFailureCategory::Integrity => {
                self.metrics.apply_integrity_failure_count =
                    self.metrics.apply_integrity_failure_count.saturating_add(1);
            }
            SnapshotApplyFailureCategory::Activation => {
                self.metrics.apply_activation_failure_count =
                    self.metrics.apply_activation_failure_count.saturating_add(1);
            }
            SnapshotApplyFailureCategory::Internal => {
                self.metrics.apply_internal_failure_count =
                    self.metrics.apply_internal_failure_count.saturating_add(1);
            }
        }

        self.last_apply_failure = Some(SnapshotApplyFailure {
            category,
            version: version.clone(),
            digest_sha256: digest_sha256.clone(),
            failed_at_unix_ms,
            detail,
        });
        self.lifecycle = SnapshotApplyLifecycle::ApplyFailed { version, digest_sha256 };
    }
}

fn validate_apply_request(request: &SnapshotApplyRequest) -> Result<(), InvalidApplyRequest> {
    let version = request.version.trim();
    if version.is_empty() {
        return Err(InvalidApplyRequest::EmptyVersion);
    }
    if version.len() > MAX_VERSION_LEN {
        return Err(InvalidApplyRequest::VersionTooLong);
    }
    if !version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(InvalidApplyRequest::InvalidVersionFormat);
    }

    let digest_sha256 = request.snapshot.metadata().digest_sha256();
    if !is_lower_hex_digest(digest_sha256) {
        return Err(InvalidApplyRequest::InvalidSnapshotDigest);
    }
    if !is_lower_hex_digest(&request.expected_digest_sha256) {
        return Err(InvalidApplyRequest::InvalidExpectedDigestFormat);
    }
    if request.expected_digest_sha256 != digest_sha256 {
        return Err(InvalidApplyRequest::DigestMismatch);
    }

    if let Some(acknowledged_by) = &request.acknowledged_by {
        let acknowledged_by = acknowledged_by.trim();
        if acknowledged_by.is_empty() {
            return Err(InvalidApplyRequest::EmptyAcknowledgedBy);
        }
        if acknowledged_by.len() > MAX_ACTOR_LEN {
            return Err(InvalidApplyRequest::AcknowledgedByTooLong);
        }
    }

    Ok(())
}

fn current_unix_ms() -> Result<u64, SystemTimeError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(SystemTimeError)?;
    let millis = duration.as_millis();
    Ok(u64::try_from(millis).unwrap_or(u64::MAX))
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use lb_config_model::WorkspaceConfig;
    use lb_test_support::{configure_test_trusted_signers, test_artifact_attestation};

    use super::{
        DataplaneSnapshotManager, InvalidApplyRequest, SnapshotActivationError,
        SnapshotActivationHook, SnapshotApplyFailureCategory, SnapshotApplyLifecycle,
        SnapshotApplyOutcome, SnapshotApplyRequest,
    };

    fn foundation_snapshot() -> Result<lb_config_model::WorkspaceSnapshot, Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        configure_test_trusted_signers(&mut config)?;
        Ok(config.compile_snapshot()?)
    }

    #[derive(Debug, Clone, Copy)]
    struct RejectingActivationHook {
        reject_validate_workspace: Option<&'static str>,
        reject_activate_workspace: Option<&'static str>,
    }

    impl SnapshotActivationHook for RejectingActivationHook {
        fn validate(
            &self,
            _snapshot: &lb_config_model::WorkspaceSnapshot,
        ) -> Result<(), SnapshotActivationError> {
            if self.reject_validate_workspace == Some(_snapshot.workspace_name()) {
                return Err(SnapshotActivationError::Rejected(String::from(
                    "pre-activation validation rejected snapshot",
                )));
            }
            Ok(())
        }

        fn activate(
            &self,
            _snapshot: &lb_config_model::WorkspaceSnapshot,
        ) -> Result<(), SnapshotActivationError> {
            if self.reject_activate_workspace == Some(_snapshot.workspace_name()) {
                return Err(SnapshotActivationError::Rejected(String::from(
                    "runtime activation failed after validation",
                )));
            }
            Ok(())
        }
    }

    #[test]
    fn apply_success_switches_active_and_last_known_good() -> Result<(), Box<dyn std::error::Error>>
    {
        let snapshot = foundation_snapshot()?;
        let digest = snapshot.metadata().digest_sha256().to_owned();
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let mut manager = DataplaneSnapshotManager::new();

        let ack = manager.apply_at(
            SnapshotApplyRequest {
                version: String::from("stable-2026-04-09"),
                snapshot,
                artifact_attestation: Some(artifact_attestation),
                expected_digest_sha256: digest.clone(),
                acknowledged_by: Some(String::from("node-a")),
            },
            100,
        )?;

        assert_eq!(ack.outcome, SnapshotApplyOutcome::Applied);
        assert_eq!(ack.active.version, "stable-2026-04-09");
        assert_eq!(ack.last_known_good.version, "stable-2026-04-09");
        assert_eq!(ack.active.digest_sha256, digest);
        assert!(matches!(manager.status().lifecycle, SnapshotApplyLifecycle::Active { .. }));
        assert_eq!(manager.metrics().apply_success_count, 1);
        Ok(())
    }

    #[test]
    fn digest_mismatch_is_rejected_before_activation() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = foundation_snapshot()?;
        let mut manager = DataplaneSnapshotManager::new();

        let error = manager.apply_at(
            SnapshotApplyRequest {
                version: String::from("stable-2026-04-09"),
                snapshot,
                artifact_attestation: None,
                expected_digest_sha256: String::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                acknowledged_by: Some(String::from("node-a")),
            },
            100,
        );

        assert!(matches!(
            error,
            Err(super::SnapshotApplyError::InvalidRequest(InvalidApplyRequest::DigestMismatch))
        ));
        let status = manager.status();
        assert!(matches!(
            status.last_apply_failure,
            Some(super::SnapshotApplyFailure {
                category: SnapshotApplyFailureCategory::Integrity,
                ..
            })
        ));
        assert!(status.active.is_none());
        assert_eq!(manager.metrics().apply_integrity_failure_count, 1);
        Ok(())
    }

    #[test]
    fn failed_apply_retains_previous_last_known_good() -> Result<(), Box<dyn std::error::Error>> {
        let stable_snapshot = foundation_snapshot()?;
        let stable_digest = stable_snapshot.metadata().digest_sha256().to_owned();

        let mut canary_config = WorkspaceConfig::foundation();
        canary_config.name = String::from("canary");
        configure_test_trusted_signers(&mut canary_config)?;
        let canary_snapshot = canary_config.compile_snapshot()?;
        let canary_digest = canary_snapshot.metadata().digest_sha256().to_owned();
        let stable_attestation = test_artifact_attestation(&stable_snapshot)?;
        let canary_attestation = test_artifact_attestation(&canary_snapshot)?;

        let mut manager = DataplaneSnapshotManager::with_hook(RejectingActivationHook {
            reject_validate_workspace: None,
            reject_activate_workspace: Some("canary"),
        });
        let _ = manager.apply_at(
            SnapshotApplyRequest {
                version: String::from("stable-2026-04-09"),
                snapshot: stable_snapshot,
                artifact_attestation: Some(stable_attestation),
                expected_digest_sha256: stable_digest,
                acknowledged_by: Some(String::from("node-a")),
            },
            100,
        )?;

        let error = manager.apply_at(
            SnapshotApplyRequest {
                version: String::from("canary-2026-04-09"),
                snapshot: canary_snapshot,
                artifact_attestation: Some(canary_attestation),
                expected_digest_sha256: canary_digest,
                acknowledged_by: Some(String::from("node-a")),
            },
            200,
        );

        assert!(matches!(
            error,
            Err(super::SnapshotApplyError::Activation(SnapshotActivationError::Rejected(_)))
        ));
        let status = manager.status();
        assert_eq!(
            status.active.as_ref().map(|record| record.version.as_str()),
            Some("stable-2026-04-09")
        );
        assert_eq!(
            status.last_known_good.as_ref().map(|record| record.version.as_str()),
            Some("stable-2026-04-09")
        );
        assert!(matches!(status.lifecycle, SnapshotApplyLifecycle::ApplyFailed { .. }));
        assert_eq!(manager.metrics().apply_activation_failure_count, 1);
        Ok(())
    }

    #[test]
    fn repeated_apply_of_same_version_and_digest_is_unchanged(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = foundation_snapshot()?;
        let digest = snapshot.metadata().digest_sha256().to_owned();
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let mut manager = DataplaneSnapshotManager::new();

        let first = manager.apply_at(
            SnapshotApplyRequest {
                version: String::from("stable-2026-04-09"),
                snapshot: snapshot.clone(),
                artifact_attestation: Some(artifact_attestation.clone()),
                expected_digest_sha256: digest.clone(),
                acknowledged_by: None,
            },
            100,
        )?;
        let second = manager.apply_at(
            SnapshotApplyRequest {
                version: String::from("stable-2026-04-09"),
                snapshot,
                artifact_attestation: Some(artifact_attestation),
                expected_digest_sha256: digest,
                acknowledged_by: None,
            },
            200,
        )?;

        assert_eq!(first.outcome, SnapshotApplyOutcome::Applied);
        assert_eq!(second.outcome, SnapshotApplyOutcome::Unchanged);
        assert_eq!(manager.metrics().apply_success_count, 1);
        assert_eq!(manager.metrics().apply_noop_count, 1);
        Ok(())
    }

    #[test]
    fn missing_attestation_is_rejected_before_activation() -> Result<(), Box<dyn std::error::Error>>
    {
        let snapshot = foundation_snapshot()?;
        let digest = snapshot.metadata().digest_sha256().to_owned();
        let mut manager = DataplaneSnapshotManager::new();

        let error = manager.apply_at(
            SnapshotApplyRequest {
                version: String::from("stable-2026-04-09"),
                snapshot,
                artifact_attestation: None,
                expected_digest_sha256: digest,
                acknowledged_by: Some(String::from("node-a")),
            },
            300,
        );

        assert!(matches!(
            error,
            Err(super::SnapshotApplyError::Integrity(
                lb_config_model::ArtifactIntegrityError::MissingAttestation
            ))
        ));
        assert_eq!(manager.metrics().apply_integrity_failure_count, 1);
        Ok(())
    }
}
