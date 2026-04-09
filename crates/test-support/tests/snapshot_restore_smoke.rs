use lb_admin_api::{RolloutCoordinator, RolloutRequest, SnapshotControlService};
use lb_test_support::{backup_bundle_from_snapshots, runtime_release_metadata};

#[test]
fn snapshot_backup_restore_and_rollout_path_is_smoke_tested(
) -> Result<(), Box<dyn std::error::Error>> {
    let release_metadata = runtime_release_metadata();
    let backup = backup_bundle_from_snapshots(&[
        (&format!("{}-stable", release_metadata.release_version), "stable"),
        (&format!("{}-canary", release_metadata.release_version), "canary"),
    ])?;

    let restored = SnapshotControlService::restore_from_backup(&backup)?;
    let stable = restored.get_version(&format!("{}-stable", release_metadata.release_version))?;

    let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
    let mut rollout = RolloutCoordinator::new();
    let response = rollout.rollout_at(
        &restored,
        &mut dataplane,
        RolloutRequest {
            version: stable.version.clone(),
            requested_by: Some(String::from("dr-smoke")),
            reason: Some(String::from("validate restored snapshot rollout")),
        },
        1_000,
    )?;

    assert_eq!(backup.records.len(), 2);
    assert_eq!(response.active_digest_sha256, stable.digest_sha256);
    assert_eq!(dataplane.metrics().apply_success_count, 1);
    Ok(())
}
