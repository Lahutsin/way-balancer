# Upgrade and Rollback Policy

## Upgrade Flow

- validate config and publish an attested snapshot
- roll out to one environment slice first
- confirm cache hit, miss, purge, and revalidation telemetry remains stable
- continue wider rollout only after observability and support-bundle checks pass

## Rollback Flow

- prefer snapshot rollback to the last known-good version rather than ad hoc config edits
- use purge only for cache-content correction, not as a substitute for runtime rollback
- verify post-rollback cache behavior and listener health before resuming rollout

## Validation References

- `upgrade_rollback_smoke`
- `insecure_dev_mode` remains development-only and must not be used to bypass production artifact verification# Upgrade and Rollback Policy

## Preconditions

- Use a workspace release from the supported `0.1.x` line.
- Publish snapshots with matching digest and artifact attestation.
- Confirm the target snapshot uses a supported config API version exposed by `lb_runtime::RuntimeMetadata`.

## Upgrade Flow

1. Build and validate the candidate with `./scripts/quality.sh`.
2. Publish the candidate snapshot with digest verification and trusted attestation.
3. Roll out the candidate through `RolloutCoordinator`.
4. Confirm dataplane activation succeeded and the active digest matches the published digest.
5. Record the upgrade outcome in release evidence.

## Rollback Flow

1. Identify the prior known-good version recorded by `DataplaneSnapshotManager`.
2. Roll back only to a previously successful version on the same supported config API version.
3. Confirm the active digest returned to the known-good digest.
4. Keep the failed candidate in audit history for investigation.

## Validation Hooks

- Upgrade and rollback smoke coverage: `cargo test -p lb-test-support --test upgrade_rollback_smoke`.
- Control-plane rollout and rollback semantics: `cargo test -p lb-admin-api`.
- Artifact integrity enforcement: `cargo test -p lb-config-model -p lb-runtime`.
- Restore validation after recovery: `cargo test -p lb-test-support --test snapshot_restore_smoke`.

## Integrity and Signing Expectations

- Production upgrades require attested artifacts by default.
- `security.insecure_dev_mode` may disable artifact verification only for explicit development scenarios with acknowledgement and must not be used for release evidence.

## Failure Handling

- Digest mismatch or missing attestation blocks rollout before activation.
- Activation failures keep the previous last-known-good snapshot available for rollback.
- Any accepted dependency advisory or tooling gap must be recorded in the release evidence package.

## Release Gate Reference

- This runbook satisfies `EVID-002` in `docs/runbooks/release-evidence-checklist.md` and `artifacts/release-evidence-inventory.md`.