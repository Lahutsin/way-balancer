# Compatibility Matrix

## Release Line

- Workspace release line: `0.1.x`
- Runtime metadata source: `lb_runtime::RuntimeMetadata`
- Supported typed config API versions: `v1_alpha1`

## Component Matrix

| Surface | Supported policy | Notes |
| --- | --- | --- |
| Runtime and admin API | Same workspace release line only | Mixed release lines are not supported for GA evidence in `0.1.x`. |
| Control-plane snapshot artifacts | Same config API version only | Published and applied snapshots must keep the compiled `api_version` within the supported set exposed by `RuntimeMetadata`. |
| Upstream affinity policy | Same `v1_alpha1` schema and `0.1.x` release line | `header_hash` and `cookie_hash` remain opt-in and preserve healthy fallback semantics only. |
| Kubernetes translation output | Same workspace release line only | Generated `WorkspaceConfig` must remain on supported config API versions and secure defaults. |
| Artifact attestation | Required by default | Unsigned artifacts are rejected unless `security.insecure_dev_mode` is explicitly acknowledged. |
| Supported performance claims | Named supported profile evidence only | Absolute capacity claims require a supported artifact such as `lab_small_non_loopback_v1`; loopback-only artifacts stay regression-only. |

## Topology Matrix

| Topology | Support state | Notes |
| --- | --- | --- |
| Single-node dataplane with local admin plane | Supported | Default operational topology for `0.1.x`. |
| Active-active dataplane fleet with shared control plane | Supported | Uses `FleetRolloutCoordinator` and `bounded_eventual` convergence only. |
| HTTP cache peer fan-out across multiple nodes | Supported with degraded partial-convergence semantics | Local purge correctness is primary; peer failure remains operator-visible and does not imply hidden consensus. |
| Kubernetes controller deployment | Supported with lease-based HA packaging | The checked-in chart and raw manifest default to two replicas with Kubernetes `Lease` leader election; do not scale above one replica if leader election is disabled. |
| Mixed release-line production fleet | Unsupported | GA evidence for `0.1.x` assumes one supported release line across targeted components. |

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
- Stability boundaries, deprecation policy, and experimental labels are defined in `docs/runbooks/stability-contract.md`.
- Deployment-shape and support-boundary rules are defined in `docs/runbooks/support-boundaries.md`.

## Release Gate Reference

- This runbook satisfies `EVID-001` in `docs/runbooks/release-evidence-checklist.md` and `artifacts/release-evidence-inventory.md`.