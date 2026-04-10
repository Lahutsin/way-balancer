# Release Evidence Checklist

## Required Evidence

- `EVID-001`: compatibility and supported-version review
- `EVID-002`: upgrade and rollback rehearsal
- `EVID-003`: disaster-recovery restore rehearsal
- `EVID-004`: coverage and workspace test pass
- `EVID-005`: cache performance and soak validation summary
- `EVID-006`: provenance and SBOM artifact refresh
- `EVID-007`: security and secret-scanning review
- `EVID-008`: final GA readiness sign-off
- `EVID-009`: stability-contract review

## Release Candidate Sign-Off Checklist

- required evidence links are present and current
- cache runbooks match shipped config fields and runtime behavior
- release artifacts were regenerated for the candidate build
- GA sign-off references `EVID-008`

# Release Evidence Checklist

## Required Evidence

| Evidence ID | Gate | Required artifact | Verification hook |
| --- | --- | --- | --- |
| `EVID-001` | Compatibility policy | `docs/runbooks/compatibility-matrix.md` | `./scripts/check-release-artifacts.sh` |
| `EVID-002` | Upgrade and rollback policy | `docs/runbooks/upgrade-rollback-policy.md` | `cargo test -p lb-test-support --test upgrade_rollback_smoke` |
| `EVID-003` | Disaster recovery and restore validation | `docs/runbooks/disaster-recovery.md` | `cargo test -p lb-test-support --test snapshot_restore_smoke` |
| `EVID-004` | Secure-default artifact integrity expectations | `plan/features/12c_artifact_integrity_and_secure_defaults.md` | `cargo test -p lb-config-model -p lb-runtime` |
| `EVID-005` | Workspace verification baseline | `./scripts/quality.sh` output for the release candidate | `./scripts/quality.sh` |
| `EVID-006` | SBOM placeholder or generated artifact location | `artifacts/sbom/README.md` | `./scripts/check-release-artifacts.sh` |
| `EVID-007` | Provenance placeholder or generated artifact location | `artifacts/provenance/README.md` | `./scripts/check-release-artifacts.sh` |
| `EVID-008` | Final GA review record | `docs/runbooks/ga-readiness-review-template.md` | `./scripts/check-release-artifacts.sh` |
| `EVID-009` | Stability contract and breaking-change policy | `docs/runbooks/stability-contract.md` | `./scripts/check-release-artifacts.sh` |

## Release Candidate Sign-Off Checklist

- [ ] `EVID-001` compatibility matrix reviewed for the target release line.
- [ ] `EVID-002` upgrade and rollback smoke path executed successfully.
- [ ] `EVID-003` backup, restore, and restored rollout validation executed successfully.
- [ ] `EVID-004` integrity expectations reviewed; any insecure override is explicitly rejected for release.
- [ ] `EVID-005` full workspace quality output attached to release evidence.
- [ ] `EVID-006` SBOM location recorded, even if still populated by placeholder automation.
- [ ] `EVID-007` provenance location recorded, even if still populated by placeholder automation.
- [ ] `EVID-008` GA review template completed with approver names or explicit exceptions.
- [ ] `EVID-009` stability contract reviewed for stable versus experimental scope and breaking-change expectations.

## Security Exceptions

- Any unresolved critical security exception must be recorded with owner, mitigation, and expiration date.
- Dependency advisories accepted temporarily must be referenced explicitly in the final GA review.
- Release evidence is incomplete if security exceptions exist without written acknowledgement.