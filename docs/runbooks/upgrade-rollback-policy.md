# Upgrade and Rollback Policy

## Preconditions

- Use a workspace release from the supported `0.1.x` line.
- Publish snapshots with matching digest and artifact attestation.
- Confirm the target snapshot uses a supported config API version exposed by `lb_runtime::RuntimeMetadata`.
- Confirm the release still matches the documented stability and breaking-change contract in `docs/runbooks/stability-contract.md`.

## Upgrade Flow

1. Build and validate the candidate with `./scripts/quality.sh`.
2. Publish the candidate snapshot with digest verification and trusted attestation.
3. If the candidate changes route destination weights, inspect the publication diff or publish audit detail and confirm the expected route-level shift before broader rollout.
4. Roll out the candidate through `RolloutCoordinator`.
5. Confirm dataplane activation succeeded and the active digest matches the published digest.
6. For config-driven listener changes, inspect `GET /status` until each affected listener reports `replacement.state = stable` and no unexpected `draining` entries remain.
7. Record the upgrade outcome in release evidence.
8. For active-active fleets, use `FleetRolloutCoordinator` and do not declare success until the fleet convergence report is `converged`.

## Rollback Flow

1. Identify the prior known-good version recorded by `DataplaneSnapshotManager`.
2. Roll back only to a previously successful version on the same supported config API version.
3. Confirm the active digest returned to the known-good digest.
4. Inspect `GET /audit` for the rollback request so the start and completion or failure outcome is preserved alongside the failed candidate.
5. Keep the failed candidate in audit history for investigation.
6. For active-active fleets, prefer a whole-fleet rollback to a shared known-good version instead of leaving a mixed-version steady state in place.

For admin-driven config rollback, also confirm `GET /status` reports the expected `last_reload_outcome_code` and that `GET /audit` records matching reload lifecycle `code` values. That keeps rollback verification machine-readable.

For snapshot-driven route canaries or blue-green shifts, also compare the candidate publication diff against the prior published version before rollback or forward rollout. That avoids treating a digest-only change as sufficient review when the real operational question is the route destination weight shift.

If the instance recently recovered from crash and `GET /status` still reports `control_plane_journal.recovery.state = needs_operator_action`, do not treat rollback or rollout as fully closed until a clean follow-up reload moves that recovery state to `resolved`.

If snapshot publication state itself must survive process restart before rollout resumes, export and restore the checksummed registry envelope through `SnapshotControlService::export_durable_state` and `SnapshotControlService::restore_durable_state`. That keeps published versions, digests, and bounded publish audit history stable across crash recovery instead of relying only on live in-memory registry state.

## Multi-Node Rollout Rules

- Treat fleet consistency as `bounded_eventual`, not instantaneous.
- `immediate` rollout is appropriate only when operators are prepared to handle degraded partial convergence explicitly.
- `sequential` or `canary` rollout is the safer default for higher-risk config changes.
- If the fleet report reaches `degraded`, remediate unreachable or failed nodes before continuing wider rollout.
- If the fleet report reaches `diverged`, prefer a fleet rollback instead of waiting indefinitely.

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
- Supported listener replacements stay rollback-safe because failed replacement startup preserves the prior active listener and surfaces the failure in `GET /status` and `GET /audit`.
- A reload that ends with `reload_applied_overlap_drain_timeout` should be treated as degraded success: the new listener stayed active, but the old draining listener exceeded its configured drain timeout and requires follow-up.
- Any accepted dependency advisory or tooling gap must be recorded in the release evidence package.

## Release Gate Reference

- This runbook satisfies `EVID-002` in `docs/runbooks/release-evidence-checklist.md` and `artifacts/release-evidence-inventory.md`.