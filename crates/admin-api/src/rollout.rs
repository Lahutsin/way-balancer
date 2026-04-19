use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{PublishedSnapshotRecord, SnapshotControlService, SnapshotLookupError};

const MAX_VERSION_LEN: usize = 128;
const MAX_ACTOR_LEN: usize = 128;
const MAX_REASON_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutRequest {
    pub version: String,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackRequest {
    pub target_version: Option<String>,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutActionKind {
    Rollout,
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolloutResultKind {
    Applied,
    Unchanged,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutHistoryEntry {
    pub action: RolloutActionKind,
    pub result: RolloutResultKind,
    pub target_version: String,
    pub effective_version: Option<String>,
    pub previous_active_version: Option<String>,
    pub digest_sha256: Option<String>,
    pub actor: Option<String>,
    pub reason: Option<String>,
    pub occurred_at_unix_ms: u64,
    pub duration_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutResponse {
    pub action: RolloutActionKind,
    pub result: RolloutResultKind,
    pub active_version: String,
    pub active_digest_sha256: String,
    pub last_known_good_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RolloutMetrics {
    pub successful_rollout_count: u64,
    pub idempotent_rollout_count: u64,
    pub failed_rollout_count: u64,
    pub rollback_count: u64,
    pub audit_event_count: u64,
    pub total_rollout_duration_ms: u64,
    pub history_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidRolloutRequest {
    EmptyVersion,
    InvalidVersionFormat,
    VersionTooLong,
    EmptyRequestedBy,
    RequestedByTooLong,
    EmptyReason,
    ReasonTooLong,
}

impl std::fmt::Display for InvalidRolloutRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyVersion => write!(formatter, "snapshot version must not be empty"),
            Self::InvalidVersionFormat => {
                write!(formatter, "snapshot version contains unsupported characters")
            }
            Self::VersionTooLong => write!(formatter, "snapshot version exceeds max length"),
            Self::EmptyRequestedBy => write!(formatter, "requested_by must not be empty"),
            Self::RequestedByTooLong => write!(formatter, "requested_by exceeds max length"),
            Self::EmptyReason => write!(formatter, "rollout reason must not be empty"),
            Self::ReasonTooLong => write!(formatter, "rollout reason exceeds max length"),
        }
    }
}

impl std::error::Error for InvalidRolloutRequest {}

#[derive(Debug)]
pub enum RolloutError {
    InvalidRequest(InvalidRolloutRequest),
    UnknownPublishedVersion(String),
    NoRollbackCandidate,
    RollbackTargetNotKnownGood(String),
    Apply(lb_runtime::SnapshotApplyError),
    Internal(SystemTimeError),
}

impl std::fmt::Display for RolloutError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(error) => write!(formatter, "invalid rollout request: {error}"),
            Self::UnknownPublishedVersion(version) => {
                write!(formatter, "published snapshot version '{version}' was not found")
            }
            Self::NoRollbackCandidate => {
                write!(formatter, "no prior known-good rollback target exists")
            }
            Self::RollbackTargetNotKnownGood(version) => write!(
                formatter,
                "rollback target '{version}' is not a previously known-good version"
            ),
            Self::Apply(error) => write!(formatter, "rollout apply failed: {error}"),
            Self::Internal(error) => write!(formatter, "rollout failed internally: {error}"),
        }
    }
}

impl std::error::Error for RolloutError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRequest(error) => Some(error),
            Self::Apply(error) => Some(error),
            Self::Internal(error) => Some(error),
            Self::UnknownPublishedVersion(_)
            | Self::NoRollbackCandidate
            | Self::RollbackTargetNotKnownGood(_) => None,
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
pub struct RolloutCoordinator {
    history: Vec<RolloutHistoryEntry>,
    successful_versions: Vec<String>,
    metrics: RolloutMetrics,
}

impl RolloutCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rollout(
        &mut self,
        control: &SnapshotControlService,
        dataplane: &mut lb_runtime::DataplaneSnapshotManager,
        request: RolloutRequest,
    ) -> Result<RolloutResponse, RolloutError> {
        let now = current_unix_ms().map_err(RolloutError::Internal)?;
        self.rollout_at(control, dataplane, request, now)
    }

    pub fn rollout_at(
        &mut self,
        control: &SnapshotControlService,
        dataplane: &mut lb_runtime::DataplaneSnapshotManager,
        request: RolloutRequest,
        occurred_at_unix_ms: u64,
    ) -> Result<RolloutResponse, RolloutError> {
        if let Err(error) =
            validate_rollout_request(&request.version, &request.requested_by, &request.reason)
        {
            self.push_history(RolloutHistoryEntry {
                action: RolloutActionKind::Rollout,
                result: RolloutResultKind::Rejected,
                target_version: request.version,
                effective_version: None,
                previous_active_version: dataplane
                    .active_record()
                    .map(|record| record.version.clone()),
                digest_sha256: None,
                actor: request.requested_by,
                reason: request.reason,
                occurred_at_unix_ms,
                duration_ms: 0,
                detail: error.to_string(),
            });
            self.metrics.failed_rollout_count = self.metrics.failed_rollout_count.saturating_add(1);
            return Err(RolloutError::InvalidRequest(error));
        }

        let published = match control.get_version(&request.version) {
            Ok(record) => record,
            Err(SnapshotLookupError::VersionNotFound(version)) => {
                let detail = format!("published snapshot version '{version}' was not found");
                self.push_history(RolloutHistoryEntry {
                    action: RolloutActionKind::Rollout,
                    result: RolloutResultKind::Rejected,
                    target_version: version.clone(),
                    effective_version: None,
                    previous_active_version: dataplane
                        .active_record()
                        .map(|record| record.version.clone()),
                    digest_sha256: None,
                    actor: request.requested_by,
                    reason: request.reason,
                    occurred_at_unix_ms,
                    duration_ms: 0,
                    detail,
                });
                self.metrics.failed_rollout_count =
                    self.metrics.failed_rollout_count.saturating_add(1);
                return Err(RolloutError::UnknownPublishedVersion(version));
            }
            Err(SnapshotLookupError::DigestNotFound(_)) => {
                self.metrics.failed_rollout_count =
                    self.metrics.failed_rollout_count.saturating_add(1);
                return Err(RolloutError::UnknownPublishedVersion(request.version));
            }
        };

        self.execute_action(
            RolloutActionKind::Rollout,
            published,
            request.requested_by,
            request.reason,
            dataplane,
            occurred_at_unix_ms,
        )
    }

    pub fn rollback(
        &mut self,
        control: &SnapshotControlService,
        dataplane: &mut lb_runtime::DataplaneSnapshotManager,
        request: RollbackRequest,
    ) -> Result<RolloutResponse, RolloutError> {
        let now = current_unix_ms().map_err(RolloutError::Internal)?;
        self.rollback_at(control, dataplane, request, now)
    }

    pub fn rollback_at(
        &mut self,
        control: &SnapshotControlService,
        dataplane: &mut lb_runtime::DataplaneSnapshotManager,
        request: RollbackRequest,
        occurred_at_unix_ms: u64,
    ) -> Result<RolloutResponse, RolloutError> {
        let target_version = match request.target_version.clone() {
            Some(version) => {
                validate_rollout_request(&version, &request.requested_by, &request.reason)
                    .map_err(RolloutError::InvalidRequest)?;
                if !self.successful_versions.iter().any(|known| known == &version) {
                    let detail = format!(
                        "rollback target '{version}' is not a previously known-good version"
                    );
                    self.push_history(RolloutHistoryEntry {
                        action: RolloutActionKind::Rollback,
                        result: RolloutResultKind::Rejected,
                        target_version: version.clone(),
                        effective_version: None,
                        previous_active_version: dataplane
                            .active_record()
                            .map(|record| record.version.clone()),
                        digest_sha256: None,
                        actor: request.requested_by,
                        reason: request.reason,
                        occurred_at_unix_ms,
                        duration_ms: 0,
                        detail,
                    });
                    self.metrics.failed_rollout_count =
                        self.metrics.failed_rollout_count.saturating_add(1);
                    return Err(RolloutError::RollbackTargetNotKnownGood(version));
                }
                version
            }
            None => {
                let active_version =
                    dataplane.active_record().map(|record| record.version.as_str());
                let candidate = self
                    .successful_versions
                    .iter()
                    .rev()
                    .find(|version| Some(version.as_str()) != active_version)
                    .cloned();
                let Some(version) = candidate else {
                    self.push_history(RolloutHistoryEntry {
                        action: RolloutActionKind::Rollback,
                        result: RolloutResultKind::Rejected,
                        target_version: String::from("<previous-known-good>"),
                        effective_version: None,
                        previous_active_version: dataplane
                            .active_record()
                            .map(|record| record.version.clone()),
                        digest_sha256: None,
                        actor: request.requested_by,
                        reason: request.reason,
                        occurred_at_unix_ms,
                        duration_ms: 0,
                        detail: String::from("no prior known-good rollback target exists"),
                    });
                    self.metrics.failed_rollout_count =
                        self.metrics.failed_rollout_count.saturating_add(1);
                    return Err(RolloutError::NoRollbackCandidate);
                };
                version
            }
        };

        let published = match control.get_version(&target_version) {
            Ok(record) => record,
            Err(_) => {
                let detail = format!("published snapshot version '{target_version}' was not found");
                self.push_history(RolloutHistoryEntry {
                    action: RolloutActionKind::Rollback,
                    result: RolloutResultKind::Rejected,
                    target_version: target_version.clone(),
                    effective_version: None,
                    previous_active_version: dataplane
                        .active_record()
                        .map(|record| record.version.clone()),
                    digest_sha256: None,
                    actor: request.requested_by,
                    reason: request.reason,
                    occurred_at_unix_ms,
                    duration_ms: 0,
                    detail,
                });
                self.metrics.failed_rollout_count =
                    self.metrics.failed_rollout_count.saturating_add(1);
                return Err(RolloutError::UnknownPublishedVersion(target_version));
            }
        };

        self.execute_action(
            RolloutActionKind::Rollback,
            published,
            request.requested_by,
            request.reason,
            dataplane,
            occurred_at_unix_ms,
        )
    }

    #[must_use]
    pub fn history(&self) -> &[RolloutHistoryEntry] {
        &self.history
    }

    #[must_use]
    pub fn recent_history(&self, limit: usize) -> Vec<RolloutHistoryEntry> {
        self.history.iter().rev().take(limit).cloned().collect()
    }

    #[must_use]
    pub const fn metrics(&self) -> RolloutMetrics {
        self.metrics
    }

    fn execute_action(
        &mut self,
        action: RolloutActionKind,
        published: &PublishedSnapshotRecord,
        actor: Option<String>,
        reason: Option<String>,
        dataplane: &mut lb_runtime::DataplaneSnapshotManager,
        occurred_at_unix_ms: u64,
    ) -> Result<RolloutResponse, RolloutError> {
        let previous_active_version =
            dataplane.active_record().map(|record| record.version.clone());
        let result = dataplane.apply_at(
            lb_runtime::SnapshotApplyRequest {
                version: published.version.clone(),
                snapshot: published.snapshot.clone(),
                artifact_attestation: published.artifact_attestation.clone(),
                expected_digest_sha256: published.digest_sha256.clone(),
                acknowledged_by: actor.clone(),
            },
            occurred_at_unix_ms,
        );

        match result {
            Ok(ack) => {
                let result_kind = match ack.outcome {
                    lb_runtime::SnapshotApplyOutcome::Applied => RolloutResultKind::Applied,
                    lb_runtime::SnapshotApplyOutcome::Unchanged => RolloutResultKind::Unchanged,
                };
                if action == RolloutActionKind::Rollback {
                    self.metrics.rollback_count = self.metrics.rollback_count.saturating_add(1);
                }
                match result_kind {
                    RolloutResultKind::Applied => {
                        self.metrics.successful_rollout_count =
                            self.metrics.successful_rollout_count.saturating_add(1);
                        if self.successful_versions.last() != Some(&ack.active.version) {
                            self.successful_versions.push(ack.active.version.clone());
                        }
                    }
                    RolloutResultKind::Unchanged => {
                        self.metrics.idempotent_rollout_count =
                            self.metrics.idempotent_rollout_count.saturating_add(1);
                    }
                    RolloutResultKind::Rejected => {}
                }

                self.push_history(RolloutHistoryEntry {
                    action,
                    result: result_kind,
                    target_version: published.version.clone(),
                    effective_version: Some(ack.active.version.clone()),
                    previous_active_version,
                    digest_sha256: Some(ack.active.digest_sha256.clone()),
                    actor,
                    reason,
                    occurred_at_unix_ms,
                    duration_ms: 0,
                    detail: match action {
                        RolloutActionKind::Rollout => String::from("rollout applied to dataplane"),
                        RolloutActionKind::Rollback => {
                            String::from("rollback applied to dataplane")
                        }
                    },
                });

                Ok(RolloutResponse {
                    action,
                    result: result_kind,
                    active_version: ack.active.version,
                    active_digest_sha256: ack.active.digest_sha256,
                    last_known_good_version: ack.last_known_good.version,
                })
            }
            Err(error) => {
                self.metrics.failed_rollout_count =
                    self.metrics.failed_rollout_count.saturating_add(1);
                self.push_history(RolloutHistoryEntry {
                    action,
                    result: RolloutResultKind::Rejected,
                    target_version: published.version.clone(),
                    effective_version: dataplane
                        .active_record()
                        .map(|record| record.version.clone()),
                    previous_active_version,
                    digest_sha256: Some(published.digest_sha256.clone()),
                    actor,
                    reason,
                    occurred_at_unix_ms,
                    duration_ms: 0,
                    detail: error.to_string(),
                });
                Err(RolloutError::Apply(error))
            }
        }
    }

    fn push_history(&mut self, entry: RolloutHistoryEntry) {
        self.history.push(entry);
        self.metrics.audit_event_count = self.metrics.audit_event_count.saturating_add(1);
        self.metrics.history_size = self.history.len();
    }
}

pub(crate) fn validate_rollout_request(
    version: &str,
    requested_by: &Option<String>,
    reason: &Option<String>,
) -> Result<(), InvalidRolloutRequest> {
    let version = version.trim();
    if version.is_empty() {
        return Err(InvalidRolloutRequest::EmptyVersion);
    }
    if version.len() > MAX_VERSION_LEN {
        return Err(InvalidRolloutRequest::VersionTooLong);
    }
    if !version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(InvalidRolloutRequest::InvalidVersionFormat);
    }
    if let Some(requested_by) = requested_by {
        let requested_by = requested_by.trim();
        if requested_by.is_empty() {
            return Err(InvalidRolloutRequest::EmptyRequestedBy);
        }
        if requested_by.len() > MAX_ACTOR_LEN {
            return Err(InvalidRolloutRequest::RequestedByTooLong);
        }
    }
    if let Some(reason) = reason {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(InvalidRolloutRequest::EmptyReason);
        }
        if reason.len() > MAX_REASON_LEN {
            return Err(InvalidRolloutRequest::ReasonTooLong);
        }
    }
    Ok(())
}

fn current_unix_ms() -> Result<u64, SystemTimeError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(SystemTimeError)?;
    let millis = duration.as_millis();
    Ok(u64::try_from(millis).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use lb_config_model::WorkspaceConfig;
    use lb_test_support::{configure_test_trusted_signers, test_artifact_attestation};

    use super::{
        RollbackRequest, RolloutActionKind, RolloutCoordinator, RolloutError, RolloutRequest,
        RolloutResultKind,
    };

    fn publish_snapshot(
        control: &mut crate::SnapshotControlService,
        version: &str,
        workspace_name: &str,
        published_at_unix_ms: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        config.name = String::from(workspace_name);
        configure_test_trusted_signers(&mut config)?;
        let snapshot = config.compile_snapshot()?;
        let digest = snapshot.metadata().digest_sha256().to_owned();
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let _ = control.publish_at(
            crate::SnapshotPublishRequest {
                version: String::from(version),
                snapshot,
                artifact_attestation: Some(artifact_attestation),
                expected_digest_sha256: Some(digest),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("test publish")),
            },
            published_at_unix_ms,
        )?;
        Ok(())
    }

    #[test]
    fn rollout_success_switches_to_published_version() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-1", "stable", 10)?;
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
        let mut coordinator = RolloutCoordinator::new();

        let response = coordinator.rollout_at(
            &control,
            &mut dataplane,
            RolloutRequest {
                version: String::from("stable-1"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("initial rollout")),
            },
            20,
        )?;

        assert_eq!(response.action, RolloutActionKind::Rollout);
        assert_eq!(response.result, RolloutResultKind::Applied);
        assert_eq!(response.active_version, "stable-1");
        assert_eq!(coordinator.history().len(), 1);
        assert_eq!(coordinator.metrics().successful_rollout_count, 1);
        Ok(())
    }

    #[test]
    fn rollback_returns_to_previous_known_good_version() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-1", "stable", 10)?;
        publish_snapshot(&mut control, "canary-2", "canary", 20)?;
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
        let mut coordinator = RolloutCoordinator::new();

        let _ = coordinator.rollout_at(
            &control,
            &mut dataplane,
            RolloutRequest {
                version: String::from("stable-1"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("stable baseline")),
            },
            30,
        )?;
        let _ = coordinator.rollout_at(
            &control,
            &mut dataplane,
            RolloutRequest {
                version: String::from("canary-2"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("canary verification")),
            },
            40,
        )?;

        let response = coordinator.rollback_at(
            &control,
            &mut dataplane,
            RollbackRequest {
                target_version: None,
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("rollback after canary")),
            },
            50,
        )?;

        assert_eq!(response.action, RolloutActionKind::Rollback);
        assert_eq!(response.result, RolloutResultKind::Applied);
        assert_eq!(response.active_version, "stable-1");
        assert_eq!(coordinator.metrics().rollback_count, 1);
        Ok(())
    }

    #[test]
    fn rollback_rejects_target_that_is_not_known_good() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-1", "stable", 10)?;
        publish_snapshot(&mut control, "canary-2", "canary", 20)?;
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
        let mut coordinator = RolloutCoordinator::new();

        let _ = coordinator.rollout_at(
            &control,
            &mut dataplane,
            RolloutRequest {
                version: String::from("stable-1"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("baseline")),
            },
            30,
        )?;

        let error = coordinator.rollback_at(
            &control,
            &mut dataplane,
            RollbackRequest {
                target_version: Some(String::from("canary-2")),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("unsafe rollback")),
            },
            40,
        );

        assert!(matches!(
            error,
            Err(RolloutError::RollbackTargetNotKnownGood(version)) if version == "canary-2"
        ));
        assert_eq!(coordinator.history().len(), 2);
        assert_eq!(coordinator.history()[1].result, RolloutResultKind::Rejected);
        Ok(())
    }

    #[test]
    fn audit_history_tracks_rollout_and_rollback_actions() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-1", "stable", 10)?;
        publish_snapshot(&mut control, "canary-2", "canary", 20)?;
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
        let mut coordinator = RolloutCoordinator::new();

        let _ = coordinator.rollout_at(
            &control,
            &mut dataplane,
            RolloutRequest {
                version: String::from("stable-1"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("baseline")),
            },
            30,
        )?;
        let _ = coordinator.rollout_at(
            &control,
            &mut dataplane,
            RolloutRequest {
                version: String::from("canary-2"),
                requested_by: Some(String::from("operator-b")),
                reason: Some(String::from("promote canary")),
            },
            40,
        )?;
        let _ = coordinator.rollback_at(
            &control,
            &mut dataplane,
            RollbackRequest {
                target_version: Some(String::from("stable-1")),
                requested_by: Some(String::from("operator-b")),
                reason: Some(String::from("undo canary")),
            },
            50,
        )?;

        let history = coordinator.recent_history(3);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].action, RolloutActionKind::Rollback);
        assert_eq!(history[1].action, RolloutActionKind::Rollout);
        assert_eq!(history[2].actor.as_deref(), Some("operator-a"));
        assert_eq!(coordinator.metrics().audit_event_count, 3);
        Ok(())
    }

    #[test]
    fn repeated_rollout_of_active_version_is_idempotent() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-1", "stable", 10)?;
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
        let mut coordinator = RolloutCoordinator::new();

        let first = coordinator.rollout_at(
            &control,
            &mut dataplane,
            RolloutRequest {
                version: String::from("stable-1"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("baseline")),
            },
            20,
        )?;
        let second = coordinator.rollout_at(
            &control,
            &mut dataplane,
            RolloutRequest {
                version: String::from("stable-1"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("repeat baseline")),
            },
            30,
        )?;

        assert_eq!(first.result, RolloutResultKind::Applied);
        assert_eq!(second.result, RolloutResultKind::Unchanged);
        assert_eq!(coordinator.metrics().idempotent_rollout_count, 1);
        Ok(())
    }

    #[test]
    fn invalid_rollout_requests_are_rejected_and_counted() -> Result<(), Box<dyn std::error::Error>>
    {
        let control = crate::SnapshotControlService::new();
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
        let mut coordinator = RolloutCoordinator::new();

        let error = coordinator
            .rollout_at(
                &control,
                &mut dataplane,
                RolloutRequest {
                    version: String::new(),
                    requested_by: Some(String::from("operator-a")),
                    reason: Some(String::from("invalid")),
                },
                10,
            )
            .expect_err("empty rollout version should be rejected");

        assert!(matches!(
            error,
            RolloutError::InvalidRequest(super::InvalidRolloutRequest::EmptyVersion)
        ));
        assert_eq!(coordinator.metrics().failed_rollout_count, 1);
        assert_eq!(coordinator.history()[0].result, RolloutResultKind::Rejected);
        Ok(())
    }

    #[test]
    fn unknown_rollback_candidate_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let control = crate::SnapshotControlService::new();
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
        let mut coordinator = RolloutCoordinator::new();

        let error = coordinator
            .rollback_at(
                &control,
                &mut dataplane,
                RollbackRequest {
                    target_version: None,
                    requested_by: Some(String::from("operator-a")),
                    reason: Some(String::from("nothing deployed yet")),
                },
                10,
            )
            .expect_err("rollback should fail when there is no known-good target");

        assert!(matches!(error, RolloutError::NoRollbackCandidate));
        Ok(())
    }
}
