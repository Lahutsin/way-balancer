# Disaster Recovery and Restore Validation

## Backup Flow

- export published snapshot state and release evidence artifacts on a regular cadence
- preserve admin credential rotation material separately from the snapshot payload itself

## Restore Flow

- restore the published snapshot registry into a clean control-plane state
- validate artifact integrity and signer trust before rollout
- re-apply runtime configuration and verify cache policy bindings compile as expected

## Restore Validation Checklist

- confirm listener and route inventory matches the intended state
- confirm cache policy names still resolve correctly
- confirm admin credential handling is restored before enabling privileged operations
- run `snapshot_restore_smoke` or an equivalent environment-specific restore drill# Disaster Recovery and Restore Validation

## Backup Scope

- Backup unit: published snapshot registry exported from `SnapshotControlService::export_backup`.
- Durable local-state unit: checksummed registry envelope exported from `SnapshotControlService::export_durable_state` or `export_durable_state_with_retention`.
- Required contents: version, digest, attestation metadata, publish actor, publish reason, compiled snapshot payload, and bounded publish audit history.
- Backup integrity expectation: restored snapshots must still satisfy digest and artifact attestation validation.

## Backup Flow

1. Confirm the control-plane registry is healthy and audit history is intact.
2. Export a backup bundle from the published snapshot registry.
3. If local crash recovery is part of the exercise, also export the checksummed durable registry state envelope.
4. Store the bundle in the release or ops evidence location with the associated release line.
5. Record the export timestamp and source actor.

## Restore Flow

1. Create a fresh control-plane registry instance.
2. Restore the backup bundle through `SnapshotControlService::restore_from_backup`.
3. For local crash-recovery drills, restore the checksummed durable registry state through `SnapshotControlService::restore_durable_state`.
4. Confirm all expected versions and digests are present after restore.
5. Roll out a restored known-good version to validate operational correctness.

For `lb-dataplane serve`, also inspect the local control-plane journal kept next to the config file as `<config_path>.control-plane.json`. This journal persists the last known desired and applied snapshot identity, reload outcome, and recent admin audit history for serve-mode recovery.

If the local journal is corrupted or fails checksum validation, startup now fails closed rather than guessing. Repair or remove the corrupted journal only after comparing it against the intended config and other recovery evidence.

If startup can bootstrap the current config successfully after a crash, the dataplane may resume serving while still reporting `control_plane_journal.recovery.state = needs_operator_action`. Treat that recovery block and the `reload_recovered_unfinished` audit event as the authoritative signal that a prior reload did not complete cleanly and should be reviewed before wider rollout continues. Use `control_plane_journal.recovery.operator_guidance.operation_age_ms` together with `expected_completion_within_ms` and `exceeded_expected_completion` to distinguish a freshly recovered interruption from an overlap-and-drain operation that has already outlived its expected drain window.

If `control_plane_journal.recovery.in_flight_operation.lifecycle_code` reports `reload_started_overlap_drain`, treat the recovery as replacement-aware: inspect the listed `affected_listeners` and confirm each one has now returned to the expected `replacement.state` in `GET /status` before considering the instance operationally settled. When `operator_guidance.recommended_action` becomes `investigate_stalled_drain`, the recovered drain has already exceeded its persisted expected completion window and should stop being treated as a normal transitional tail.

For recovered instances that resume reload activity, also inspect `reload_drained_listener_count`, `reload_completed_drain_count`, and `reload_drain_timeout_count` in `GET /status`. These counters provide bounded no-drop accounting evidence for listener replacement drains after restart.

For explicit warm-restart operations (`POST /restart`), use `last_restart_outcome_code` plus restart counters in `GET /status` to verify whether replacement drains completed within bounds (`restart_applied_overlap_drain`) or timed out (`restart_applied_overlap_drain_timeout`).

The same recovery block now publishes `reconciled_listeners`, which records the live `listener_state`, `replacement_state`, and a machine-readable `reconciliation_verdict` observed after startup. Use `settled` as the fast path, treat `replacement_still_draining` as transitional, and escalate `replacement_failed_preserved`, `replacement_drain_timeout`, `missing`, or generic `needs_review` before considering the instance fully reconciled.

Once the operator validates the intended config and completes a new successful `POST /reload`, `control_plane_journal.recovery.state` should move to `resolved`. Use that transition as the end of the local crash-recovery workflow for the dataplane instance.

The local journal is intentionally bounded. It keeps the latest recent admin audit slice needed for operator recovery, not a forever-growing full audit archive. The durable snapshot registry state is also intentionally bounded on publish audit history by count, using the configured `max_audit_events` export retention window. Preserve longer-term evidence in your external release and incident records rather than relying on either local artifact as an archival system.

## Restore Validation Checklist

- Restored registry contains every expected version from the backup bundle.
- Restored digests match the pre-backup digests exactly.
- Restored artifact attestation remains valid under the current secure-default policy.
- A restored known-good snapshot can still be rolled out successfully.
- Last-known-good state remains available for follow-up rollback if restore validation fails later.
- `GET /status` on serve-mode dataplanes reports the expected `control_plane_journal.recovery.state` and the restored desired and applied snapshot identity.
- For staged fleet recovery exercises, rebuild staged status via `render_staged_status_surface(...)` and confirm wave/node semantics are coherent (`blocked` only after upstream failure or abort, node-to-wave mapping intact, rollback projection accurate).

## Compromise Recovery Notes

- Treat control-plane compromise as a credential and certificate rotation event.
- Rotate admin credentials and privileged mTLS trust before reusing restored state.
- Re-issue or re-attest snapshot artifacts if signing material is suspected compromised.
- Record any accepted dependency or tooling warnings in the recovery evidence.

## Validation Hooks

- DR smoke coverage: `cargo test -p lb-test-support --test snapshot_restore_smoke`.
- Control-plane backup and restore validation: `cargo test -p lb-admin-api`.
- Artifact consistency and runbook structure: `./scripts/check-release-artifacts.sh`.

## Release Gate Reference

- This runbook satisfies `EVID-003` in `docs/runbooks/release-evidence-checklist.md` and `artifacts/release-evidence-inventory.md`.