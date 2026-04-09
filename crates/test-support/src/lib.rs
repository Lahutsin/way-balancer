#![forbid(unsafe_code)]

use lb_config_model::{
    ArtifactAttestation, ArtifactSigner, TrustedArtifactSignerConfig, WorkspaceConfig,
    WorkspaceSnapshot,
};

pub const TEST_SIGNER_IDENTITY: &str = "control-plane";
pub const TEST_SIGNING_KEY_ED25519: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

/// Returns the canonical workspace smoke-test label.
#[must_use]
pub fn smoke_label() -> &'static str {
    lb_runtime::CRATE_ID
}

/// Returns the canonical runtime release metadata used by productization tests.
#[must_use]
pub fn runtime_release_metadata() -> lb_runtime::RuntimeMetadata {
    lb_runtime::RuntimeMetadata::new()
}

pub fn test_artifact_signer() -> Result<ArtifactSigner, lb_config_model::ArtifactSigningError> {
    ArtifactSigner::from_signing_key_hex(TEST_SIGNER_IDENTITY, TEST_SIGNING_KEY_ED25519)
}

pub fn test_trusted_signers(
) -> Result<Vec<TrustedArtifactSignerConfig>, lb_config_model::ArtifactSigningError> {
    Ok(vec![test_artifact_signer()?.trusted_signer()])
}

pub fn configure_test_trusted_signers(
    config: &mut WorkspaceConfig,
) -> Result<(), lb_config_model::ArtifactSigningError> {
    config.security.artifact_verification.trusted_signers = test_trusted_signers()?;
    Ok(())
}

/// Builds a deterministic test attestation for a compiled snapshot.
pub fn test_artifact_attestation(
    snapshot: &WorkspaceSnapshot,
) -> Result<ArtifactAttestation, lb_config_model::ArtifactSigningError> {
    Ok(test_artifact_signer()?.attest_snapshot(snapshot))
}

/// Builds a compiled workspace snapshot with a deterministic workspace name.
pub fn named_snapshot(
    workspace_name: &str,
) -> Result<WorkspaceSnapshot, Box<dyn std::error::Error>> {
    let mut config = WorkspaceConfig::foundation();
    config.name = String::from(workspace_name);
    configure_test_trusted_signers(&mut config)?;
    Ok(config.compile_snapshot()?)
}

/// Creates a control-plane backup bundle from named snapshots for DR tests.
pub fn backup_bundle_from_snapshots(
    versions_and_workspaces: &[(&str, &str)],
) -> Result<lb_admin_api::SnapshotBackupBundle, Box<dyn std::error::Error>> {
    let mut control = lb_admin_api::SnapshotControlService::new();
    for (index, (version, workspace_name)) in versions_and_workspaces.iter().enumerate() {
        let snapshot = named_snapshot(workspace_name)?;
        control.publish_at(
            lb_admin_api::SnapshotPublishRequest {
                version: String::from(*version),
                snapshot: snapshot.clone(),
                artifact_attestation: Some(test_artifact_attestation(&snapshot)?),
                expected_digest_sha256: Some(snapshot.metadata().digest_sha256().to_owned()),
                published_by: Some(String::from("dr-smoke")),
                reason: Some(String::from("seed backup bundle")),
            },
            u64::try_from(index + 1).unwrap_or(u64::MAX) * 100,
        )?;
    }

    Ok(control.export_backup_at(9_000))
}

#[cfg(test)]
mod tests {
    use super::{runtime_release_metadata, smoke_label};

    #[test]
    fn smoke_label_is_runtime_crate_id() {
        assert_eq!(smoke_label(), "lb-runtime");
    }

    #[test]
    fn runtime_release_metadata_surfaces_release_version() {
        let metadata = runtime_release_metadata();

        assert_eq!(metadata.release_version, env!("CARGO_PKG_VERSION"));
    }
}
