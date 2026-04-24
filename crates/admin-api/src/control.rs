use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use lb_config_model::{
    verify_snapshot_artifact_integrity, ArtifactAttestation, ArtifactIntegrityError,
    SnapshotChangeKind, SnapshotCompileError, SnapshotResourceChange, WorkspaceSnapshot,
    WorkspaceSnapshotDiff, WorkspaceSnapshotView,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SHA256_HEX_LEN: usize = 64;
const MAX_VERSION_LEN: usize = 128;
const MAX_ACTOR_LEN: usize = 128;
const MAX_REASON_LEN: usize = 256;
const SNAPSHOT_REGISTRY_STATE_VERSION: u32 = 1;
const DEFAULT_MAX_PERSISTED_AUDIT_EVENTS: usize = 128;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedSnapshotRecordDurable {
    pub version: String,
    pub workspace_name: String,
    pub digest_sha256: String,
    pub artifact_attestation: Option<ArtifactAttestation>,
    pub published_at_unix_ms: u64,
    pub published_by: Option<String>,
    pub reason: Option<String>,
    pub snapshot: WorkspaceSnapshotView,
}

impl From<&PublishedSnapshotRecord> for PublishedSnapshotRecordDurable {
    fn from(value: &PublishedSnapshotRecord) -> Self {
        Self {
            version: value.version.clone(),
            workspace_name: value.workspace_name.clone(),
            digest_sha256: value.digest_sha256.clone(),
            artifact_attestation: value.artifact_attestation.clone(),
            published_at_unix_ms: value.published_at_unix_ms,
            published_by: value.published_by.clone(),
            reason: value.reason.clone(),
            snapshot: value.snapshot.view(),
        }
    }
}

impl PublishedSnapshotRecordDurable {
    fn try_into_record(self) -> Result<PublishedSnapshotRecord, SnapshotRegistryStateError> {
        let snapshot = WorkspaceSnapshot::from_view(self.snapshot)
            .map_err(SnapshotRegistryStateError::SnapshotCompile)?;
        Ok(PublishedSnapshotRecord {
            version: self.version,
            workspace_name: self.workspace_name,
            digest_sha256: self.digest_sha256,
            artifact_attestation: self.artifact_attestation,
            published_at_unix_ms: self.published_at_unix_ms,
            published_by: self.published_by,
            reason: self.reason,
            snapshot,
        })
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishResponseKind {
    Published,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishResponse {
    pub kind: PublishResponseKind,
    pub record: PublishedSnapshotRecord,
    pub previous_version: Option<String>,
    pub snapshot_diff: Option<WorkspaceSnapshotDiff>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishEventKind {
    Published,
    Unchanged,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRegistryRetentionPolicy {
    pub max_audit_events: usize,
}

impl Default for SnapshotRegistryRetentionPolicy {
    fn default() -> Self {
        Self { max_audit_events: DEFAULT_MAX_PERSISTED_AUDIT_EVENTS }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRegistryDurableState {
    pub records: Vec<PublishedSnapshotRecordDurable>,
    pub audit_events: Vec<PublishEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRegistryDurableEnvelope {
    pub version: u32,
    pub payload_json: String,
    pub payload_sha256: String,
}

#[derive(Debug)]
pub enum SnapshotRegistryStateError {
    Serialize(serde_json::Error),
    Deserialize(serde_json::Error),
    UnsupportedVersion(u32),
    ChecksumMismatch,
    SnapshotCompile(SnapshotCompileError),
    Publication(SnapshotPublicationError),
}

impl std::fmt::Display for SnapshotRegistryStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(error) => {
                write!(formatter, "failed to serialize snapshot registry state: {error}")
            }
            Self::Deserialize(error) => {
                write!(formatter, "failed to deserialize snapshot registry state: {error}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported snapshot registry state version: {version}")
            }
            Self::ChecksumMismatch => {
                write!(formatter, "snapshot registry state checksum validation failed")
            }
            Self::SnapshotCompile(error) => {
                write!(formatter, "failed to rehydrate snapshot registry state: {error}")
            }
            Self::Publication(error) => {
                write!(formatter, "snapshot registry state restore failed: {error}")
            }
        }
    }
}

impl std::error::Error for SnapshotRegistryStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialize(error) | Self::Deserialize(error) => Some(error),
            Self::SnapshotCompile(error) => Some(error),
            Self::Publication(error) => Some(error),
            Self::UnsupportedVersion(_) | Self::ChecksumMismatch => None,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotImpactSeverity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotResourceImpactSummary {
    pub added: u32,
    pub removed: u32,
    pub updated: u32,
}

impl SnapshotResourceImpactSummary {
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.added + self.removed + self.updated
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotImpactAnalysis {
    pub listeners: SnapshotResourceImpactSummary,
    pub routes: SnapshotResourceImpactSummary,
    pub upstream_clusters: SnapshotResourceImpactSummary,
    pub total_changes: u32,
    pub severity: SnapshotImpactSeverity,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotDiffPreview {
    pub base_version: String,
    pub base_digest_sha256: String,
    pub candidate_digest_sha256: String,
    pub snapshot_diff: WorkspaceSnapshotDiff,
    pub impact_analysis: SnapshotImpactAnalysis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotDiffPreviewError {
    NoBaselineVersion,
    Lookup(SnapshotLookupError),
}

impl std::fmt::Display for SnapshotDiffPreviewError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBaselineVersion => {
                write!(formatter, "snapshot diff preview requires at least one published baseline")
            }
            Self::Lookup(error) => write!(formatter, "snapshot diff preview failed: {error}"),
        }
    }
}

impl std::error::Error for SnapshotDiffPreviewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lookup(error) => Some(error),
            Self::NoBaselineVersion => None,
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
                return Ok(PublishResponse {
                    kind: PublishResponseKind::Unchanged,
                    record,
                    previous_version: None,
                    snapshot_diff: None,
                });
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

        let previous_record = self
            .history
            .last()
            .and_then(|version| self.records_by_version.get(version))
            .cloned();
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
        let previous_version = previous_record.as_ref().map(|record| record.version.clone());
        let snapshot_diff = previous_record
            .as_ref()
            .map(|previous_record| previous_record.snapshot.diff(&record.snapshot));

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
            format_publish_detail(previous_version.as_deref(), snapshot_diff.as_ref()),
        );

        Ok(PublishResponse {
            kind: PublishResponseKind::Published,
            record,
            previous_version,
            snapshot_diff,
        })
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

    pub fn export_durable_state(
        &self,
    ) -> Result<SnapshotRegistryDurableEnvelope, SnapshotRegistryStateError> {
        self.export_durable_state_with_retention(SnapshotRegistryRetentionPolicy::default())
    }

    pub fn export_durable_state_with_retention(
        &self,
        retention: SnapshotRegistryRetentionPolicy,
    ) -> Result<SnapshotRegistryDurableEnvelope, SnapshotRegistryStateError> {
        let payload = SnapshotRegistryDurableState {
            records: self
                .history
                .iter()
                .filter_map(|version| self.records_by_version.get(version))
                .map(PublishedSnapshotRecordDurable::from)
                .collect(),
            audit_events: prune_publish_events(&self.audit_events, retention.max_audit_events),
        };
        let payload_json =
            serde_json::to_string_pretty(&payload).map_err(SnapshotRegistryStateError::Serialize)?;
        Ok(SnapshotRegistryDurableEnvelope {
            version: SNAPSHOT_REGISTRY_STATE_VERSION,
            payload_sha256: sha256_hex(payload_json.as_bytes()),
            payload_json,
        })
    }

    pub fn restore_durable_state(
        envelope: &SnapshotRegistryDurableEnvelope,
    ) -> Result<Self, SnapshotRegistryStateError> {
        Self::restore_durable_state_with_retention(
            envelope,
            SnapshotRegistryRetentionPolicy::default(),
        )
    }

    pub fn restore_durable_state_with_retention(
        envelope: &SnapshotRegistryDurableEnvelope,
        retention: SnapshotRegistryRetentionPolicy,
    ) -> Result<Self, SnapshotRegistryStateError> {
        if envelope.version != SNAPSHOT_REGISTRY_STATE_VERSION {
            return Err(SnapshotRegistryStateError::UnsupportedVersion(envelope.version));
        }
        if sha256_hex(envelope.payload_json.as_bytes()) != envelope.payload_sha256 {
            return Err(SnapshotRegistryStateError::ChecksumMismatch);
        }

        let payload: SnapshotRegistryDurableState = serde_json::from_str(&envelope.payload_json)
            .map_err(SnapshotRegistryStateError::Deserialize)?;
        let mut service = Self::new();
        for record in payload.records {
            service
                .restore_record(record.try_into_record()?)
                .map_err(SnapshotRegistryStateError::Publication)?;
        }
        service.audit_events = prune_publish_events(&payload.audit_events, retention.max_audit_events);
        service.metrics.restore_success_count = service.metrics.restore_success_count.saturating_add(1);
        service.metrics.active_registry_size = service.records_by_version.len();
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

    pub fn preview_diff(
        &self,
        base_version: Option<&str>,
        candidate: &WorkspaceSnapshot,
    ) -> Result<SnapshotDiffPreview, SnapshotDiffPreviewError> {
        let baseline = match base_version {
            Some(version) => self.get_version(version).map_err(SnapshotDiffPreviewError::Lookup)?,
            None => {
                let latest = self.history.last().ok_or(SnapshotDiffPreviewError::NoBaselineVersion)?;
                self.records_by_version
                    .get(latest)
                    .ok_or(SnapshotDiffPreviewError::NoBaselineVersion)?
            }
        };

        let snapshot_diff = baseline.snapshot.diff(candidate);
        let impact_analysis = analyze_snapshot_impact(&snapshot_diff);
        Ok(SnapshotDiffPreview {
            base_version: baseline.version.clone(),
            base_digest_sha256: baseline.digest_sha256.clone(),
            candidate_digest_sha256: candidate.metadata().digest_sha256().to_owned(),
            snapshot_diff,
            impact_analysis,
        })
    }

    #[must_use]
    pub fn audit_events(&self) -> &[PublishEvent] {
        &self.audit_events
    }

    #[must_use]
    pub const fn metrics(&self) -> SnapshotRegistryMetrics {
        self.metrics
    }

    fn restore_record(
        &mut self,
        record: PublishedSnapshotRecord,
    ) -> Result<(), SnapshotPublicationError> {
        validate_publish_request(&SnapshotPublishRequest {
            version: record.version.clone(),
            snapshot: record.snapshot.clone(),
            artifact_attestation: record.artifact_attestation.clone(),
            expected_digest_sha256: Some(record.digest_sha256.clone()),
            published_by: record.published_by.clone(),
            reason: record.reason.clone(),
        })
        .map_err(SnapshotPublicationError::InvalidRequest)?;

        if let Some(existing) = self.records_by_version.get(&record.version) {
            return Err(SnapshotPublicationError::Conflict(PublishConflict::VersionAlreadyExists {
                version: existing.version.clone(),
                existing_digest_sha256: existing.digest_sha256.clone(),
            }));
        }
        if let Some(existing_version) = self.version_by_digest.get(&record.digest_sha256) {
            return Err(SnapshotPublicationError::Conflict(PublishConflict::DigestAlreadyPublished {
                digest_sha256: record.digest_sha256.clone(),
                existing_version: existing_version.clone(),
            }));
        }

        self.version_by_digest
            .insert(record.digest_sha256.clone(), record.version.clone());
        self.history.push(record.version.clone());
        self.records_by_version.insert(record.version.clone(), record);
        self.metrics.published_versions_count = self.records_by_version.len().try_into().unwrap_or(u64::MAX);
        self.metrics.active_registry_size = self.records_by_version.len();
        Ok(())
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

fn prune_publish_events(events: &[PublishEvent], max_audit_events: usize) -> Vec<PublishEvent> {
    if max_audit_events == 0 {
        return Vec::new();
    }
    let keep_from = events.len().saturating_sub(max_audit_events);
    events[keep_from..].to_vec()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn format_publish_detail(
    previous_version: Option<&str>,
    snapshot_diff: Option<&WorkspaceSnapshotDiff>,
) -> String {
    let mut detail = String::from("snapshot version published");
    if let Some(previous_version) = previous_version {
        detail.push_str("; previous version ");
        detail.push_str(previous_version);
    }
    if let Some(snapshot_diff) = snapshot_diff {
        let summary = summarize_snapshot_diff(snapshot_diff);
        if !summary.is_empty() {
            detail.push_str("; ");
            detail.push_str(&summary);
        }
    }
    detail
}

fn summarize_snapshot_diff(diff: &WorkspaceSnapshotDiff) -> String {
    let mut parts = Vec::new();
    let listener_summary = summarize_resource_changes("listener", &diff.listener_changes);
    if !listener_summary.is_empty() {
        parts.push(listener_summary);
    }
    let route_summary = summarize_resource_changes("route", &diff.route_changes);
    if !route_summary.is_empty() {
        parts.push(route_summary);
    }
    let upstream_summary =
        summarize_resource_changes("upstream cluster", &diff.upstream_cluster_changes);
    if !upstream_summary.is_empty() {
        parts.push(upstream_summary);
    }
    parts.join("; ")
}

fn summarize_change_counts(changes: &[SnapshotResourceChange]) -> SnapshotResourceImpactSummary {
    let mut added: u32 = 0;
    let mut removed: u32 = 0;
    let mut updated: u32 = 0;

    for change in changes {
        match change.kind {
            SnapshotChangeKind::Added => added = added.saturating_add(1),
            SnapshotChangeKind::Removed => removed = removed.saturating_add(1),
            SnapshotChangeKind::Updated => updated = updated.saturating_add(1),
        }
    }

    SnapshotResourceImpactSummary { added, removed, updated }
}

fn analyze_snapshot_impact(diff: &WorkspaceSnapshotDiff) -> SnapshotImpactAnalysis {
    let listeners = summarize_change_counts(&diff.listener_changes);
    let routes = summarize_change_counts(&diff.route_changes);
    let upstream_clusters = summarize_change_counts(&diff.upstream_cluster_changes);
    let total_changes = listeners
        .total()
        .saturating_add(routes.total())
        .saturating_add(upstream_clusters.total());

    let mut reasons = Vec::new();

    let has_disruptive_change = listeners.removed > 0
        || listeners.updated > 0
        || routes.removed > 0
        || upstream_clusters.removed > 0;
    let has_behavior_change = routes.updated > 0 || upstream_clusters.updated > 0 || listeners.added > 0;

    let severity = if has_disruptive_change {
        reasons.push(String::from(
            "listener/route/upstream removals or listener updates may disrupt active traffic",
        ));
        SnapshotImpactSeverity::High
    } else if has_behavior_change || total_changes >= 6 {
        reasons.push(String::from(
            "routing or upstream behavior changes detected; use staged promotion/canary gates",
        ));
        SnapshotImpactSeverity::Medium
    } else {
        reasons.push(String::from("limited additive changes; low operational risk"));
        SnapshotImpactSeverity::Low
    };

    SnapshotImpactAnalysis {
        listeners,
        routes,
        upstream_clusters,
        total_changes,
        severity,
        reasons,
    }
}

fn summarize_resource_changes(kind_label: &str, changes: &[SnapshotResourceChange]) -> String {
    if changes.is_empty() {
        return String::new();
    }

    let mut entries = changes
        .iter()
        .take(4)
        .map(summarize_resource_change)
        .collect::<Vec<_>>();
    if changes.len() > 4 {
        entries.push(format!("and {} more", changes.len() - 4));
    }
    format!("{kind_label} changes: {}", entries.join(", "))
}

fn summarize_resource_change(change: &SnapshotResourceChange) -> String {
    let kind = match change.kind {
        SnapshotChangeKind::Added => "added",
        SnapshotChangeKind::Removed => "removed",
        SnapshotChangeKind::Updated => "updated",
    };
    match &change.detail {
        Some(detail) => format!("{} {} ({detail})", change.name, kind),
        None => format!("{} {}", change.name, kind),
    }
}

#[cfg(test)]
mod tests {
    use lb_config_model::WorkspaceConfig;
    use lb_test_support::{configure_test_trusted_signers, test_artifact_attestation};

    use super::{
        InvalidPublishRequest, PublishEventKind, PublishResponseKind, SnapshotBackupBundle,
        SnapshotControlService, SnapshotDiffPreviewError, SnapshotImpactSeverity,
        SnapshotLookupError, SnapshotPublicationError, SnapshotPublishRequest,
        SnapshotRegistryDurableEnvelope,
        SnapshotRegistryRetentionPolicy, SnapshotRegistryStateError, SnapshotRestoreError,
    };

    fn foundation_snapshot(
    ) -> Result<lb_config_model::WorkspaceSnapshot, Box<dyn std::error::Error>> {
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

    fn weighted_route_snapshot(
        stable_weight: u16,
        canary_weight: u16,
    ) -> Result<lb_config_model::WorkspaceSnapshot, Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        config.listeners.push(lb_config_model::ListenerResourceConfig {
            protocol: lb_config_model::ListenerProtocolConfig::Http1,
            routes: vec![String::from("payments-api")],
            ..lb_config_model::ListenerResourceConfig::foundation(
                "public-http",
                lb_config_model::ListenerClassConfig::Public,
                8080,
            )
        });
        config.routes.push(lb_config_model::RouteConfig {
            name: String::from("payments-api"),
            match_rule: lb_config_model::RouteMatchConfig::PathPrefix {
                prefix: String::from("/api"),
                hostnames: vec![String::from("payments.localhost")],
                methods: Vec::new(),
                headers: Vec::new(),
                query_params: Vec::new(),
                content_types: Vec::new(),
                grpc_services: Vec::new(),
                grpc_methods: Vec::new(),
                source_cidrs: Vec::new(),
            },
            upstream_cluster: None,
            destinations: vec![
                lb_config_model::RouteDestinationConfig {
                    upstream_cluster: String::from("payments-stable"),
                    weight: stable_weight,
                    policies: lb_config_model::PolicyBindingConfig::default(),
                },
                lb_config_model::RouteDestinationConfig {
                    upstream_cluster: String::from("payments-canary"),
                    weight: canary_weight,
                    policies: lb_config_model::PolicyBindingConfig::default(),
                },
            ],
            policies: lb_config_model::PolicyBindingConfig::default(),
            upgrade: lb_config_model::UpgradePolicyConfig::default(),
        });
        config.upstream_clusters.push(lb_config_model::UpstreamClusterConfig {
            name: String::from("payments-stable"),
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            endpoints: vec![lb_config_model::UpstreamEndpointConfig::foundation(
                "payments-stable-a",
                "127.0.0.1:9000".parse()?,
            )],
            discovery: None,
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig::default(),
            policies: lb_config_model::PolicyBindingConfig::default(),
        });
        config.upstream_clusters.push(lb_config_model::UpstreamClusterConfig {
            name: String::from("payments-canary"),
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            endpoints: vec![lb_config_model::UpstreamEndpointConfig::foundation(
                "payments-canary-a",
                "127.0.0.1:9001".parse()?,
            )],
            discovery: None,
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig::default(),
            policies: lb_config_model::PolicyBindingConfig::default(),
        });
        configure_test_trusted_signers(&mut config)?;
        Ok(config.compile_snapshot()?)
    }

    fn listener_snapshot(
        bind_address: &str,
    ) -> Result<lb_config_model::WorkspaceSnapshot, Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        config.listeners.push(lb_config_model::ListenerResourceConfig {
            protocol: lb_config_model::ListenerProtocolConfig::Http1,
            routes: vec![String::from("payments-api")],
            ..lb_config_model::ListenerResourceConfig::foundation(
                "public-http",
                lb_config_model::ListenerClassConfig::Public,
                8080,
            )
        });
        config.routes.push(lb_config_model::RouteConfig {
            name: String::from("payments-api"),
            match_rule: lb_config_model::RouteMatchConfig::PathPrefix {
                prefix: String::from("/api"),
                hostnames: vec![String::from("payments.localhost")],
                methods: Vec::new(),
                headers: Vec::new(),
                query_params: Vec::new(),
                content_types: Vec::new(),
                grpc_services: Vec::new(),
                grpc_methods: Vec::new(),
                source_cidrs: Vec::new(),
            },
            upstream_cluster: Some(String::from("payments-stable")),
            destinations: Vec::new(),
            policies: lb_config_model::PolicyBindingConfig::default(),
            upgrade: lb_config_model::UpgradePolicyConfig::default(),
        });
        config.upstream_clusters.push(lb_config_model::UpstreamClusterConfig {
            name: String::from("payments-stable"),
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            endpoints: vec![lb_config_model::UpstreamEndpointConfig::foundation(
                "payments-stable-a",
                "127.0.0.1:9000".parse()?,
            )],
            discovery: None,
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig::default(),
            policies: lb_config_model::PolicyBindingConfig::default(),
        });
        config.listeners[0].bind_address = bind_address.parse()?;
        configure_test_trusted_signers(&mut config)?;
        Ok(config.compile_snapshot()?)
    }

    fn listener_updated_snapshot(
    ) -> Result<lb_config_model::WorkspaceSnapshot, Box<dyn std::error::Error>> {
        listener_snapshot("127.0.0.1:18080")
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
        assert_eq!(response.previous_version, None);
        assert_eq!(response.snapshot_diff, None);
        assert_eq!(service.list_versions().len(), 1);
        assert_eq!(service.get_version("v1.0.0")?.version, "v1.0.0");
        assert_eq!(service.audit_events().len(), 1);
        assert_eq!(service.audit_events()[0].kind, PublishEventKind::Published);
        assert_eq!(service.metrics().published_versions_count, 1);
        assert_eq!(service.metrics().active_registry_size, 1);
        Ok(())
    }

    #[test]
    fn publish_response_includes_weight_shift_diff_and_audit_summary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable_snapshot = weighted_route_snapshot(90, 10)?;
        let canary_snapshot = weighted_route_snapshot(80, 20)?;
        let mut service = SnapshotControlService::new();

        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("v1.0.0"),
                snapshot: stable_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&stable_snapshot)?),
                expected_digest_sha256: Some(
                    stable_snapshot.metadata().digest_sha256().to_owned(),
                ),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("stable baseline")),
            },
            100,
        )?;

        let response = service.publish_at(
            SnapshotPublishRequest {
                version: String::from("v1.1.0"),
                snapshot: canary_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&canary_snapshot)?),
                expected_digest_sha256: Some(
                    canary_snapshot.metadata().digest_sha256().to_owned(),
                ),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("increase canary weight")),
            },
            200,
        )?;

        assert_eq!(response.kind, PublishResponseKind::Published);
        assert_eq!(response.previous_version.as_deref(), Some("v1.0.0"));
        let diff = response.snapshot_diff.as_ref().expect("diff should be present");
        assert_eq!(diff.route_changes.len(), 1);
        assert_eq!(diff.route_changes[0].name, "payments-api");
        assert_eq!(
            diff.route_changes[0].detail.as_deref(),
            Some(
                "destinations payments-canary:10, payments-stable:90 -> payments-canary:20, payments-stable:80"
            )
        );
        let audit_detail = &service.audit_events()[1].detail;
        assert!(audit_detail.contains("previous version v1.0.0"));
        assert!(audit_detail.contains("route changes: payments-api updated"));
        assert!(audit_detail.contains("payments-canary:10"));
        assert!(audit_detail.contains("payments-stable:80"));
        Ok(())
    }

    #[test]
    fn preview_diff_uses_latest_baseline_when_version_not_provided(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable_snapshot = foundation_snapshot()?;
        let canary_snapshot = named_snapshot("canary")?;
        let candidate_snapshot = weighted_route_snapshot(80, 20)?;

        let mut service = SnapshotControlService::new();
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("stable-v1"),
                snapshot: stable_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&stable_snapshot)?),
                expected_digest_sha256: Some(stable_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("operator")),
                reason: Some(String::from("stable baseline")),
            },
            1,
        )?;
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("canary-v2"),
                snapshot: canary_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&canary_snapshot)?),
                expected_digest_sha256: Some(canary_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("operator")),
                reason: Some(String::from("promote canary")),
            },
            2,
        )?;

        let preview = service.preview_diff(None, &candidate_snapshot)?;
        assert_eq!(preview.base_version, "canary-v2");
        assert_eq!(
            preview.base_digest_sha256,
            canary_snapshot.metadata().digest_sha256()
        );
        Ok(())
    }

    #[test]
    fn preview_diff_reports_high_risk_for_listener_updates(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable_snapshot = listener_snapshot("127.0.0.1:8080")?;
        let candidate_snapshot = listener_updated_snapshot()?;

        let mut service = SnapshotControlService::new();
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("stable-v1"),
                snapshot: stable_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&stable_snapshot)?),
                expected_digest_sha256: Some(stable_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("operator")),
                reason: Some(String::from("stable baseline")),
            },
            1,
        )?;

        let preview = service.preview_diff(Some("stable-v1"), &candidate_snapshot)?;
        assert_eq!(preview.impact_analysis.severity, SnapshotImpactSeverity::High);
        assert_eq!(preview.impact_analysis.listeners.updated, 1);
        assert!(preview
            .impact_analysis
            .reasons
            .iter()
            .any(|reason| reason.contains("disrupt active traffic")));
        Ok(())
    }

    #[test]
    fn preview_diff_requires_baseline_version() {
        let candidate_snapshot = foundation_snapshot().expect("snapshot should compile");
        let service = SnapshotControlService::new();

        let error = service
            .preview_diff(None, &candidate_snapshot)
            .expect_err("preview should fail without baseline");
        assert!(matches!(error, SnapshotDiffPreviewError::NoBaselineVersion));
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

    #[test]
    fn durable_state_round_trip_preserves_registry_and_audit_history(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable_snapshot = named_snapshot("stable-durable")?;
        let canary_snapshot = named_snapshot("canary-durable")?;

        let mut service = SnapshotControlService::new();
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("stable-durable-v1"),
                snapshot: stable_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&stable_snapshot)?),
                expected_digest_sha256: Some(stable_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("stable seed")),
            },
            100,
        )?;
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("canary-durable-v1"),
                snapshot: canary_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&canary_snapshot)?),
                expected_digest_sha256: Some(canary_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("canary seed")),
            },
            200,
        )?;

        let envelope = service.export_durable_state()?;
        let restored = SnapshotControlService::restore_durable_state(&envelope)?;

        assert_eq!(restored.list_versions().len(), 2);
        assert_eq!(restored.audit_events().len(), 2);
        assert_eq!(restored.audit_events()[0].kind, PublishEventKind::Published);
        assert_eq!(restored.audit_events()[1].kind, PublishEventKind::Published);
        assert_eq!(
            restored.get_version("stable-durable-v1")?.digest_sha256,
            stable_snapshot.metadata().digest_sha256()
        );
        assert_eq!(
            restored.get_version("canary-durable-v1")?.digest_sha256,
            canary_snapshot.metadata().digest_sha256()
        );
        assert_eq!(restored.metrics().restore_success_count, 1);
        Ok(())
    }

    #[test]
    fn durable_state_restore_rejects_checksum_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = foundation_snapshot()?;
        let mut service = SnapshotControlService::new();
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("checksum-v1"),
                snapshot: snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&snapshot)?),
                expected_digest_sha256: Some(snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("checksum seed")),
            },
            100,
        )?;

        let mut envelope = service.export_durable_state()?;
        envelope.payload_sha256 = String::from("deadbeef");

        let result = SnapshotControlService::restore_durable_state(&envelope);
        assert!(matches!(result, Err(SnapshotRegistryStateError::ChecksumMismatch)));
        Ok(())
    }

    #[test]
    fn durable_state_export_prunes_audit_history_by_retention(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable_snapshot = named_snapshot("stable-prune")?;
        let canary_snapshot = named_snapshot("canary-prune")?;
        let mut service = SnapshotControlService::new();

        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("stable-prune-v1"),
                snapshot: stable_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&stable_snapshot)?),
                expected_digest_sha256: Some(stable_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("stable seed")),
            },
            100,
        )?;
        let duplicate = service.publish_at(
            SnapshotPublishRequest {
                version: String::from("stable-prune-v1"),
                snapshot: stable_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&stable_snapshot)?),
                expected_digest_sha256: Some(stable_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("stable seed")),
            },
            150,
        )?;
        assert_eq!(duplicate.kind, PublishResponseKind::Unchanged);
        service.publish_at(
            SnapshotPublishRequest {
                version: String::from("canary-prune-v1"),
                snapshot: canary_snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&canary_snapshot)?),
                expected_digest_sha256: Some(canary_snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("canary seed")),
            },
            200,
        )?;

        let envelope = service.export_durable_state_with_retention(SnapshotRegistryRetentionPolicy {
            max_audit_events: 2,
        })?;
        let restored = SnapshotControlService::restore_durable_state_with_retention(
            &envelope,
            SnapshotRegistryRetentionPolicy { max_audit_events: 2 },
        )?;

        assert_eq!(restored.list_versions().len(), 2);
        assert_eq!(restored.audit_events().len(), 2);
        assert_eq!(restored.audit_events()[0].kind, PublishEventKind::Unchanged);
        assert_eq!(restored.audit_events()[1].kind, PublishEventKind::Published);
        Ok(())
    }

    #[test]
    fn durable_state_restore_rejects_unsupported_version() -> Result<(), Box<dyn std::error::Error>> {
        let envelope = SnapshotRegistryDurableEnvelope {
            version: 999,
            payload_json: String::from("{}"),
            payload_sha256: String::from("deadbeef"),
        };

        let result = SnapshotControlService::restore_durable_state(&envelope);
        assert!(matches!(result, Err(SnapshotRegistryStateError::UnsupportedVersion(999))));
        Ok(())
    }
}
