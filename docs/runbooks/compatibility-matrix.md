# Compatibility Matrix

## Supported Runtime Surfaces

- typed `WorkspaceConfig` snapshots using `api_version: v1_alpha1`
- runtime dataplane activation through published, attested snapshots
- shared HTTP cache policies configured through `policies.http_caches`

## Skew Policy

- Control-plane publish/apply flows must use a snapshot format supported by the active runtime release.
- Cache policy changes should be rolled out only after all targeted dataplanes support the same cache-policy schema.

## Security Patch Process

Security-sensitive runtime behavior changes, especially around cache keying, auth-aware bypass, or invalidation, should be rolled out with the same artifact verification and release evidence process as other dataplane changes.

## Validation

- `check-release-artifacts.sh` verifies this document is present and structurally complete.# Compatibility Matrix

## Release Line

- Workspace release line: `0.1.x`
- Runtime metadata source: `lb_runtime::RuntimeMetadata`
- Supported typed config API versions: `v1_alpha1`

## Component Matrix

| Surface | Supported policy | Notes |
| --- | --- | --- |
| Runtime and admin API | Same workspace release line only | Mixed release lines are not supported for GA evidence in `0.1.x`. |
| Control-plane snapshot artifacts | Same config API version only | Published and applied snapshots must keep the compiled `api_version` within the supported set exposed by `RuntimeMetadata`. |
| Kubernetes translation output | Same workspace release line only | Generated `WorkspaceConfig` must remain on supported config API versions and secure defaults. |
| Artifact attestation | Required by default | Unsigned artifacts are rejected unless `security.insecure_dev_mode` is explicitly acknowledged. |

## Skew Policy

- Supported skew for `0.1.x`: none across runtime, admin API, and Kubernetes integration in production evidence.
- Safe rollback target: a previously known-good snapshot published under the same supported config API version.
- Upgrade candidate rule: publish, attest, roll out, then confirm dataplane activation before declaring success.
- Insecure development overrides are not part of supported production skew and must never be treated as release-compatible.

## Security Patch Process

- Security fixes ship on the current supported `0.1.x` line.
- Release evidence must include `cargo audit` output when available and any accepted warnings recorded explicitly.
- Upgrade and rollback procedures must preserve artifact integrity expectations and require signed or attested snapshots by default.

## Evidence Hooks

- Compatibility artifacts are verified by `./scripts/check-release-artifacts.sh`.
- Runtime release metadata is asserted in `cargo test -p lb-runtime` and `cargo test -p lb-test-support --test upgrade_rollback_smoke`.
- DR restore validation is documented in `docs/runbooks/disaster-recovery.md` and asserted by `cargo test -p lb-test-support --test snapshot_restore_smoke`.

## Release Gate Reference

- This runbook satisfies `EVID-001` in `docs/runbooks/release-evidence-checklist.md` and `artifacts/release-evidence-inventory.md`.