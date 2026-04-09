use lb_admin_api::{
    RollbackRequest, RolloutCoordinator, RolloutRequest, SnapshotControlService,
    SnapshotPublishRequest,
};
use lb_test_support::{named_snapshot, runtime_release_metadata, test_artifact_attestation};

#[test]
fn upgrade_and_rollback_path_is_smoke_tested() -> Result<(), Box<dyn std::error::Error>> {
    let release_metadata = runtime_release_metadata();
    let stable_snapshot = named_snapshot("stable")?;
    let canary_snapshot = named_snapshot("canary")?;

    let stable_digest = stable_snapshot.metadata().digest_sha256().to_owned();
    let canary_digest = canary_snapshot.metadata().digest_sha256().to_owned();

    let mut control = SnapshotControlService::new();
    control.publish_at(
        SnapshotPublishRequest {
            version: format!("{}-stable", release_metadata.release_version),
            snapshot: stable_snapshot.clone(),
            artifact_attestation: Some(test_artifact_attestation(&stable_snapshot)?),
            expected_digest_sha256: Some(stable_digest.clone()),
            published_by: Some(String::from("upgrade-smoke")),
            reason: Some(String::from("seed known-good release")),
        },
        100,
    )?;
    control.publish_at(
        SnapshotPublishRequest {
            version: format!("{}-canary", release_metadata.release_version),
            snapshot: canary_snapshot.clone(),
            artifact_attestation: Some(test_artifact_attestation(&canary_snapshot)?),
            expected_digest_sha256: Some(canary_digest.clone()),
            published_by: Some(String::from("upgrade-smoke")),
            reason: Some(String::from("seed upgrade candidate")),
        },
        200,
    )?;

    let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
    let mut rollout = RolloutCoordinator::new();

    let stable_rollout = rollout.rollout_at(
        &control,
        &mut dataplane,
        RolloutRequest {
            version: format!("{}-stable", release_metadata.release_version),
            requested_by: Some(String::from("upgrade-smoke")),
            reason: Some(String::from("activate known-good")),
        },
        300,
    )?;
    let canary_rollout = rollout.rollout_at(
        &control,
        &mut dataplane,
        RolloutRequest {
            version: format!("{}-canary", release_metadata.release_version),
            requested_by: Some(String::from("upgrade-smoke")),
            reason: Some(String::from("validate upgrade path")),
        },
        400,
    )?;
    let rollback = rollout.rollback_at(
        &control,
        &mut dataplane,
        RollbackRequest {
            target_version: Some(format!("{}-stable", release_metadata.release_version)),
            requested_by: Some(String::from("upgrade-smoke")),
            reason: Some(String::from("validate rollback path")),
        },
        500,
    )?;

    assert_eq!(stable_rollout.active_digest_sha256, stable_digest);
    assert_eq!(canary_rollout.active_digest_sha256, canary_digest);
    assert_eq!(rollback.active_digest_sha256, stable_digest);
    assert_eq!(rollback.last_known_good_version, rollback.active_version);
    assert_eq!(dataplane.metrics().apply_success_count, 3);
    assert!(release_metadata.supports_config_api_version(stable_snapshot.metadata().api_version()));
    Ok(())
}
