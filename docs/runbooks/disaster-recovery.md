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
- Required contents: version, digest, attestation metadata, publish actor, publish reason, and compiled snapshot payload.
- Backup integrity expectation: restored snapshots must still satisfy digest and artifact attestation validation.

## Backup Flow

1. Confirm the control-plane registry is healthy and audit history is intact.
2. Export a backup bundle from the published snapshot registry.
3. Store the bundle in the release or ops evidence location with the associated release line.
4. Record the export timestamp and source actor.

## Restore Flow

1. Create a fresh control-plane registry instance.
2. Restore the backup bundle through `SnapshotControlService::restore_from_backup`.
3. Confirm all expected versions and digests are present after restore.
4. Roll out a restored known-good version to validate operational correctness.

## Restore Validation Checklist

- Restored registry contains every expected version from the backup bundle.
- Restored digests match the pre-backup digests exactly.
- Restored artifact attestation remains valid under the current secure-default policy.
- A restored known-good snapshot can still be rolled out successfully.
- Last-known-good state remains available for follow-up rollback if restore validation fails later.

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