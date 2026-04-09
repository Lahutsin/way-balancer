use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use lb_config_model::{
    verify_snapshot_artifact_integrity, ArtifactAttestation, ArtifactIntegrityError,
    WorkspaceSnapshot,
};

const SHA256_HEX_LEN: usize = 64;
const MAX_VERSION_LEN: usize = 128;
const MAX_ACTOR_LEN: usize = 128;
const MAX_REASON_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPublishRequest {
    pub version: String,
    pub snapshot: WorkspaceSnapshot,
    pub artifact_attestation: Option<ArtifactAttestation>,
    pub expected_digest_sha256: Option<String>,
    pub published_by: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedSnapshotRecord {
    pub version: String,
    pub workspace_name: String,
    pub digest_sha256: String,
    pub artifact_attestation: Option<ArtifactAttestation>,
    pub published_at_unix_ms: u64,
    pub published_by: Option<String>,
    pub reason: Option<String>,
    pub snapshot: WorkspaceSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedSnapshotSummary {
    pub version: String,
    pub workspace_name: String,
    pub digest_sha256: String,
    pub published_at_unix_ms: u64,
    pub published_by: Option<String>,
}

impl From<&PublishedSnapshotRecord> for PublishedSnapshotSummary {
    fn from(value: &PublishedSnapshotRecord) -> Self {
        Self {
            version: value.version.clone(),
            workspace_name: value.workspace_name.clone(),
            digest_sha256: value.digest_sha256.clone(),
            published_at_unix_ms: value.published_at_unix_ms,
            published_by: value.published_by.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishResponseKind {
    Published,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishResponse {
    pub kind: PublishResponseKind,
    pub record: PublishedSnapshotRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishEventKind {
    Published,
    Unchanged,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishEvent {
    pub kind: PublishEventKind,
    pub version: String,
    pub digest_sha256: Option<String>,
    pub occurred_at_unix_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SnapshotRegistryMetrics {
    pub published_versions_count: u64,
    pub idempotent_publish_count: u64,
    pub publish_invalid_count: u64,
    pub publish_conflict_count: u64,
    pub publish_internal_failure_count: u64,
    pub backup_export_count: u64,
    pub restore_success_count: u64,
    pub restore_failure_count: u64,
    pub active_registry_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBackupBundle {
    pub exported_at_unix_ms: u64,
    pub records: Vec<PublishedSnapshotRecord>,
}

#[derive(Debug)]
pub enum SnapshotBackupError {
    Internal(SystemTimeError),
}

impl std::fmt::Display for SnapshotBackupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(error) => {
                write!(formatter, "snapshot backup failed internally: {error}")
            }
        }
    }
}

impl std::error::Error for SnapshotBackupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub enum SnapshotRestoreError {
    Publication(SnapshotPublicationError),
}

impl std::fmt::Display for SnapshotRestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Publication(error) => write!(formatter, "snapshot restore failed: {error}"),
        }
    }
}

impl std::error::Error for SnapshotRestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Publication(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPublishRequest {
    EmptyVersion,
    InvalidVersionFormat,
    VersionTooLong,
    InvalidSnapshotDigest,
    InvalidExpectedDigestFormat,
    DigestMismatch,
    ArtifactIntegrity(ArtifactIntegrityError),
    EmptyPublishedBy,
    PublishedByTooLong,
    EmptyReason,
    ReasonTooLong,
}

impl std::fmt::Display for InvalidPublishRequest {
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
            Self::ArtifactIntegrity(error) => write!(formatter, "{error}"),
            Self::EmptyPublishedBy => write!(formatter, "published_by must not be empty"),
            Self::PublishedByTooLong => write!(formatter, "published_by exceeds max length"),
            Self::EmptyReason => write!(formatter, "publish reason must not be empty"),
            Self::ReasonTooLong => write!(formatter, "publish reason exceeds max length"),
        }
    }
}

impl std::error::Error for InvalidPublishRequest {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishConflict {
    VersionAlreadyExists { version: String, existing_digest_sha256: String },
    DigestAlreadyPublished { digest_sha256: String, existing_version: String },
}

impl std::fmt::Display for PublishConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionAlreadyExists { version, existing_digest_sha256 } => write!(
                formatter,
                "snapshot version '{version}' already exists with digest {existing_digest_sha256}"
            ),
            Self::DigestAlreadyPublished { digest_sha256, existing_version } => write!(
                formatter,
                "snapshot digest {digest_sha256} is already published as version '{existing_version}'"
            ),
        }
    }
}

impl std::error::Error for PublishConflict {}

#[derive(Debug)]
pub enum SnapshotPublicationError {
    InvalidRequest(InvalidPublishRequest),
    Conflict(PublishConflict),
    Internal(SystemTimeError),
}

impl std::fmt::Display for SnapshotPublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(error) => {
                write!(formatter, "invalid snapshot publication: {error}")
            }
            Self::Conflict(error) => write!(formatter, "snapshot publication conflict: {error}"),
            Self::Internal(error) => {
                write!(formatter, "snapshot publication failed internally: {error}")
            }
        }
    }
}

impl std::error::Error for SnapshotPublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRequest(error) => Some(error),
            Self::Conflict(error) => Some(error),
            Self::Internal(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotLookupError {
    VersionNotFound(String),
    DigestNotFound(String),
}

impl std::fmt::Display for SnapshotLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionNotFound(version) => {
                write!(formatter, "snapshot version '{version}' was not found")
            }
            Self::DigestNotFound(digest_sha256) => {
                write!(formatter, "snapshot digest {digest_sha256} was not found")
            }
        }
    }
}

impl std::error::Error for SnapshotLookupError {}

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
pub struct SnapshotControlService {
    records_by_version: BTreeMap<String, PublishedSnapshotRecord>,
    version_by_digest: BTreeMap<String, String>,
    history: Vec<String>,
    audit_events: Vec<PublishEvent>,
    metrics: SnapshotRegistryMetrics,
}

impl SnapshotControlService {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(
        &mut self,
        request: SnapshotPublishRequest,
    ) -> Result<PublishResponse, SnapshotPublicationError> {
        let published_at_unix_ms = current_unix_ms().map_err(SnapshotPublicationError::Internal)?;
        self.publish_at(request, published_at_unix_ms)
    }

    pub fn publish_at(
        &mut self,
        request: SnapshotPublishRequest,
        published_at_unix_ms: u64,
    ) -> Result<PublishResponse, SnapshotPublicationError> {
        if let Err(error) = validate_publish_request(&request) {
            self.metrics.publish_invalid_count =
                self.metrics.publish_invalid_count.saturating_add(1);
            self.push_event(
                PublishEventKind::Rejected,
                request.version,
                Some(request.snapshot.metadata().digest_sha256().to_owned()),
                published_at_unix_ms,
                error.to_string(),
            );
            return Err(SnapshotPublicationError::InvalidRequest(error));
        }

        let digest_sha256 = request.snapshot.metadata().digest_sha256().to_owned();
        if let Some(existing) = self.records_by_version.get(&request.version) {
            if existing.digest_sha256 == digest_sha256 {
                let record = existing.clone();
                self.metrics.idempotent_publish_count =
                    self.metrics.idempotent_publish_count.saturating_add(1);
                self.push_event(
                    PublishEventKind::Unchanged,
                    request.version,
                    Some(digest_sha256),
                    published_at_unix_ms,
                    String::from("idempotent duplicate publish ignored"),
                );
                return Ok(PublishResponse { kind: PublishResponseKind::Unchanged, record });
            }

            let error = PublishConflict::VersionAlreadyExists {
                version: existing.version.clone(),
                existing_digest_sha256: existing.digest_sha256.clone(),
            };
            self.metrics.publish_conflict_count =
                self.metrics.publish_conflict_count.saturating_add(1);
            self.push_event(
                PublishEventKind::Rejected,
                request.version,
                Some(digest_sha256),
                published_at_unix_ms,
                error.to_string(),
            );
            return Err(SnapshotPublicationError::Conflict(error));
        }

        if let Some(existing_version) = self.version_by_digest.get(&digest_sha256) {
            let error = PublishConflict::DigestAlreadyPublished {
                digest_sha256: digest_sha256.clone(),
                existing_version: existing_version.clone(),
            };
            self.metrics.publish_conflict_count =
                self.metrics.publish_conflict_count.saturating_add(1);
            self.push_event(
                PublishEventKind::Rejected,
                request.version,
                Some(digest_sha256),
                published_at_unix_ms,
                error.to_string(),
            );
            return Err(SnapshotPublicationError::Conflict(error));
        }

        let record = PublishedSnapshotRecord {
            version: request.version.clone(),
            workspace_name: request.snapshot.workspace_name().to_owned(),
            digest_sha256: digest_sha256.clone(),
            artifact_attestation: request.artifact_attestation,
            published_at_unix_ms,
            published_by: request.published_by,
            reason: request.reason,
            snapshot: request.snapshot,
        };

        self.version_by_digest.insert(digest_sha256.clone(), request.version.clone());
        self.history.push(request.version.clone());
        self.records_by_version.insert(request.version.clone(), record.clone());
        self.metrics.published_versions_count =
            self.metrics.published_versions_count.saturating_add(1);
        self.metrics.active_registry_size = self.records_by_version.len();
        self.push_event(
            PublishEventKind::Published,
            request.version,
            Some(digest_sha256),
            published_at_unix_ms,
            String::from("snapshot version published"),
        );

        Ok(PublishResponse { kind: PublishResponseKind::Published, record })
    }

    pub fn export_backup(&mut self) -> Result<SnapshotBackupBundle, SnapshotBackupError> {
        let exported_at_unix_ms = current_unix_ms().map_err(SnapshotBackupError::Internal)?;
        Ok(self.export_backup_at(exported_at_unix_ms))
    }

    #[must_use]
    pub fn export_backup_at(&mut self, exported_at_unix_ms: u64) -> SnapshotBackupBundle {
        let records = self
            .history
            .iter()
            .filter_map(|version| self.records_by_version.get(version).cloned())
            .collect();
        self.metrics.backup_export_count = self.metrics.backup_export_count.saturating_add(1);
        SnapshotBackupBundle { exported_at_unix_ms, records }
    }

    pub fn restore_backup(
        &mut self,
        backup: &SnapshotBackupBundle,
    ) -> Result<(), SnapshotRestoreError> {
        for record in &backup.records {
            let publish = self.publish_at(
                SnapshotPublishRequest {
                    version: record.version.clone(),
                    snapshot: record.snapshot.clone(),
                    artifact_attestation: record.artifact_attestation.clone(),
                    expected_digest_sha256: Some(record.digest_sha256.clone()),
                    published_by: record.published_by.clone(),
                    reason: record.reason.clone(),
                },
                record.published_at_unix_ms,
            );
            if let Err(error) = publish {
                self.metrics.restore_failure_count =
                    self.metrics.restore_failure_count.saturating_add(1);
                return Err(SnapshotRestoreError::Publication(error));
            }
        }

        self.metrics.restore_success_count = self.metrics.restore_success_count.saturating_add(1);
        Ok(())
    }

    pub fn restore_from_backup(
        backup: &SnapshotBackupBundle,
    ) -> Result<Self, SnapshotRestoreError> {
        let mut service = Self::new();
        service.restore_backup(backup)?;
        Ok(service)
    }

    #[must_use]
    pub fn list_versions(&self) -> Vec<PublishedSnapshotSummary> {
        self.history
            .iter()
            .rev()
            .filter_map(|version| self.records_by_version.get(version))
            .map(PublishedSnapshotSummary::from)
            .collect()
    }

    pub fn get_version(
        &self,
        version: &str,
    ) -> Result<&PublishedSnapshotRecord, SnapshotLookupError> {
        self.records_by_version
            .get(version)
            .ok_or_else(|| SnapshotLookupError::VersionNotFound(version.to_owned()))
    }

    pub fn get_digest(
        &self,
        digest_sha256: &str,
    ) -> Result<&PublishedSnapshotRecord, SnapshotLookupError> {
        let version = self
            .version_by_digest
            .get(digest_sha256)
            .ok_or_else(|| SnapshotLookupError::DigestNotFound(digest_sha256.to_owned()))?;
        self.get_version(version)
    }

    #[must_use]
    pub fn audit_events(&self) -> &[PublishEvent] {
        &self.audit_events
    }

    #[must_use]
    pub const fn metrics(&self) -> SnapshotRegistryMetrics {
        self.metrics
    }

    fn push_event(
        &mut self,
        kind: PublishEventKind,
        version: String,
        digest_sha256: Option<String>,
        occurred_at_unix_ms: u64,
        detail: String,
    ) {
        self.audit_events.push(PublishEvent {
            kind,
            version,
            digest_sha256,
            occurred_at_unix_ms,
            detail,
        });
        self.metrics.active_registry_size = self.records_by_version.len();
    }
}

fn validate_publish_request(request: &SnapshotPublishRequest) -> Result<(), InvalidPublishRequest> {
    let version = request.version.trim();
    if version.is_empty() {
        return Err(InvalidPublishRequest::EmptyVersion);
    }
    if version.len() > MAX_VERSION_LEN {
        return Err(InvalidPublishRequest::VersionTooLong);
    }
    if !version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(InvalidPublishRequest::InvalidVersionFormat);
    }

    let digest_sha256 = request.snapshot.metadata().digest_sha256();
    if !is_lower_hex_digest(digest_sha256) {
        return Err(InvalidPublishRequest::InvalidSnapshotDigest);
    }

    if let Some(expected_digest_sha256) = &request.expected_digest_sha256 {
        if !is_lower_hex_digest(expected_digest_sha256) {
            return Err(InvalidPublishRequest::InvalidExpectedDigestFormat);
        }
        if expected_digest_sha256 != digest_sha256 {
            return Err(InvalidPublishRequest::DigestMismatch);
        }
    }

    verify_snapshot_artifact_integrity(&request.snapshot, request.artifact_attestation.as_ref())
        .map_err(InvalidPublishRequest::ArtifactIntegrity)?;

    if let Some(published_by) = &request.published_by {
        let published_by = published_by.trim();
        if published_by.is_empty() {
            return Err(InvalidPublishRequest::EmptyPublishedBy);
        }
        if published_by.len() > MAX_ACTOR_LEN {
            return Err(InvalidPublishRequest::PublishedByTooLong);
        }
    }

    if let Some(reason) = &request.reason {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(InvalidPublishRequest::EmptyReason);
        }
        if reason.len() > MAX_REASON_LEN {
            return Err(InvalidPublishRequest::ReasonTooLong);
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
        InvalidPublishRequest, PublishEventKind, PublishResponseKind, SnapshotBackupBundle,
        SnapshotControlService, SnapshotLookupError, SnapshotPublicationError,
        SnapshotPublishRequest, SnapshotRestoreError,
    };

    fn foundation_snapshot() -> Result<lb_config_model::WorkspaceSnapshot, Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        configure_test_trusted_signers(&mut config)?;
        Ok(config.compile_snapshot()?)
    }

    fn named_snapshot(
        workspace_name: &str,
    ) -> Result<lb_config_model::WorkspaceSnapshot, Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        config.name = String::from(workspace_name);
        configure_test_trusted_signers(&mut config)?;
        Ok(config.compile_snapshot()?)
    }

    #[test]
    fn publish_success_records_snapshot_and_audit_event() -> Result<(), Box<dyn std::error::Error>>
    {
        let snapshot = foundation_snapshot()?;
        let digest = snapshot.metadata().digest_sha256().to_owned();
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let mut service = SnapshotControlService::new();

        let response = service.publish_at(
            SnapshotPublishRequest {
                version: String::from("v1.0.0"),
                snapshot,
                artifact_attestation: Some(artifact_attestation),
                expected_digest_sha256: Some(digest.clone()),
                published_by: Some(String::from("control-plane")),
                reason: Some(String::from("initial bootstrap")),
            },
            1_710_000_000_000,
        )?;

        assert_eq!(response.kind, PublishResponseKind::Published);
        assert_eq!(response.record.version, "v1.0.0");
        assert_eq!(response.record.digest_sha256, digest);
        assert_eq!(service.list_versions().len(), 1);
        assert_eq!(service.get_version("v1.0.0")?.version, "v1.0.0");
        assert_eq!(service.audit_events().len(), 1);
        assert_eq!(service.audit_events()[0].kind, PublishEventKind::Published);
        assert_eq!(service.metrics().published_versions_count, 1);
        assert_eq!(service.metrics().active_registry_size, 1);
        Ok(())
    }

    #[test]
    fn duplicate_publication_is_idempotent_only_for_same_version_and_digest(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = foundation_snapshot()?;
        let updated_snapshot = named_snapshot("way-balancer-canary")?;
        let snapshot_attestation = test_artifact_attestation(&snapshot)?;
        let updated_snapshot_attestation = test_artifact_attestation(&updated_snapshot)?;

        let mut service = SnapshotControlService::new();
        let request = SnapshotPublishRequest {
            version: String::from("v1.0.0"),
            snapshot: snapshot.clone(),
            artifact_attestation: Some(snapshot_attestation.clone()),
            expected_digest_sha256: Some(snapshot.metadata().digest_sha256().to_owned()),
            published_by: None,
            reason: None,
        };

        let first = service.publish_at(request.clone(), 10)?;
        let second = service.publish_at(request, 20)?;

        assert_eq!(first.kind, PublishResponseKind::Published);
        assert_eq!(second.kind, PublishResponseKind::Unchanged);
        assert_eq!(second.record.published_at_unix_ms, 10);
        assert_eq!(service.metrics().published_versions_count, 1);
        assert_eq!(service.metrics().idempotent_publish_count, 1);

        let version_conflict = service.publish_at(
            SnapshotPublishRequest {
                version: String::from("v1.0.0"),
                snapshot: updated_snapshot.clone(),
                artifact_attestation: Some(updated_snapshot_attestation),
                expected_digest_sha256: Some(
                    updated_snapshot.metadata().digest_sha256().to_owned(),
                ),
                published_by: None,
                reason: None,
            },
            30,
        );
        assert!(matches!(
            version_conflict,
            Err(SnapshotPublicationError::Conflict(
                super::PublishConflict::VersionAlreadyExists { .. }
            ))
        ));

        let digest_conflict = service.publish_at(
            SnapshotPublishRequest {
                version: String::from("v1.0.1"),
                snapshot,
                artifact_attestation: Some(snapshot_attestation),
                expected_digest_sha256: None,
                published_by: None,
                reason: None,
            },
            40,
        );
        assert!(matches!(
            digest_conflict,
            Err(SnapshotPublicationError::Conflict(
                super::PublishConflict::DigestAlreadyPublished { .. }
            ))
        ));
        assert_eq!(service.metrics().publish_conflict_count, 2);
        Ok(())
    }

    #[test]
    fn invalid_metadata_and_digest_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = foundation_snapshot()?;
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let mut service = SnapshotControlService::new();

        let invalid_version = service.publish_at(
            SnapshotPublishRequest {
                version: String::from("bad version"),
                snapshot: snapshot.clone(),
                artifact_attestation: Some(artifact_attestation.clone()),
                expected_digest_sha256: None,
                published_by: None,
                reason: None,
            },
            50,
        );
        assert!(matches!(
            invalid_version,
            Err(SnapshotPublicationError::InvalidRequest(
                InvalidPublishRequest::InvalidVersionFormat
            ))
        ));

        let digest_mismatch = service.publish_at(
            SnapshotPublishRequest {
                version: String::from("v1.0.0"),
                snapshot,
                artifact_attestation: Some(artifact_attestation),
                expected_digest_sha256: Some(String::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )),
                published_by: Some(String::from("publisher")),
                reason: Some(String::from("reason")),
            },
            60,
        );
        assert!(matches!(
            digest_mismatch,
            Err(SnapshotPublicationError::InvalidRequest(InvalidPublishRequest::DigestMismatch))
        ));
        assert_eq!(service.metrics().publish_invalid_count, 2);
        assert_eq!(service.audit_events().len(), 2);
        assert!(service
            .audit_events()
            .iter()
            .all(|event| event.kind == PublishEventKind::Rejected));
        Ok(())
    }

    #[test]
    fn list_and_retrieve_support_version_and_digest_queries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable_snapshot = named_snapshot("stable")?;
        let canary_snapshot = named_snapshot("canary")?;
        let canary_digest = canary_snapshot.metadata().digest_sha256().to_owned();
        let stable_attestation = test_artifact_attestation(&stable_snapshot)?;
        let canary_attestation = test_artifact_attestation(&canary_snapshot)?;

        let mut service = SnapshotControlService::new();
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("stable-2026-04-09"),
                snapshot: stable_snapshot,
                artifact_attestation: Some(stable_attestation),
                expected_digest_sha256: None,
                published_by: Some(String::from("ops")),
                reason: None,
            },
            100,
        )?;
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("canary-2026-04-09"),
                snapshot: canary_snapshot,
                artifact_attestation: Some(canary_attestation),
                expected_digest_sha256: Some(canary_digest.clone()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("pre-rollout validation")),
            },
            200,
        )?;

        let versions = service.list_versions();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "canary-2026-04-09");
        assert_eq!(versions[1].version, "stable-2026-04-09");

        let canary_record = service.get_digest(&canary_digest)?;
        assert_eq!(canary_record.version, "canary-2026-04-09");
        assert_eq!(canary_record.snapshot.workspace_name(), "canary");
        assert!(matches!(
            service.get_version("missing"),
            Err(SnapshotLookupError::VersionNotFound(version)) if version == "missing"
        ));
        Ok(())
    }

    #[test]
    fn publish_rejects_missing_attestation_when_integrity_is_enforced(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = foundation_snapshot()?;
        let mut service = SnapshotControlService::new();

        let error = service.publish_at(
            SnapshotPublishRequest {
                version: String::from("v1.0.0"),
                snapshot,
                artifact_attestation: None,
                expected_digest_sha256: None,
                published_by: Some(String::from("control-plane")),
                reason: Some(String::from("missing integrity metadata")),
            },
            70,
        );

        assert!(matches!(
            error,
            Err(SnapshotPublicationError::InvalidRequest(
                InvalidPublishRequest::ArtifactIntegrity(
                    lb_config_model::ArtifactIntegrityError::MissingAttestation
                )
            ))
        ));
        Ok(())
    }

    #[test]
    fn backup_export_and_restore_preserve_published_snapshots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable_snapshot = named_snapshot("stable")?;
        let canary_snapshot = named_snapshot("canary")?;

        let mut service = SnapshotControlService::new();
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("stable-restore"),
                snapshot: stable_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&stable_snapshot)?),
                expected_digest_sha256: Some(stable_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("backup seed stable")),
            },
            100,
        )?;
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("canary-restore"),
                snapshot: canary_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&canary_snapshot)?),
                expected_digest_sha256: Some(canary_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("backup seed canary")),
            },
            200,
        )?;

        let backup = service.export_backup_at(300);
        let restored = SnapshotControlService::restore_from_backup(&backup)?;

        assert_eq!(backup.records.len(), 2);
        assert_eq!(service.metrics().backup_export_count, 1);
        assert_eq!(restored.metrics().restore_success_count, 1);
        assert_eq!(restored.list_versions().len(), 2);
        assert_eq!(
            restored.get_version("stable-restore")?.digest_sha256,
            stable_snapshot.metadata().digest_sha256()
        );
        assert_eq!(
            restored.get_version("canary-restore")?.digest_sha256,
            canary_snapshot.metadata().digest_sha256()
        );
        Ok(())
    }

    #[test]
    fn restore_rejects_backup_with_invalid_integrity_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = foundation_snapshot()?;
        let backup = SnapshotBackupBundle {
            exported_at_unix_ms: 100,
            records: vec![super::PublishedSnapshotRecord {
                version: String::from("restore-invalid"),
                workspace_name: snapshot.workspace_name().to_owned(),
                digest_sha256: snapshot.metadata().digest_sha256().to_owned(),
                artifact_attestation: None,
                published_at_unix_ms: 100,
                published_by: Some(String::from("ops")),
                reason: Some(String::from("invalid restore fixture")),
                snapshot,
            }],
        };

        let error = SnapshotControlService::restore_from_backup(&backup);

        assert!(matches!(
            error,
            Err(SnapshotRestoreError::Publication(SnapshotPublicationError::InvalidRequest(
                InvalidPublishRequest::ArtifactIntegrity(
                    lb_config_model::ArtifactIntegrityError::MissingAttestation
                )
            )))
        ));
        Ok(())
    }
}
