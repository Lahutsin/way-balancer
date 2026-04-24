# Release Evidence Inventory

| Evidence ID | Artifact path | Purpose |
| --- | --- | --- |
| `EVID-001` | `docs/runbooks/compatibility-matrix.md` | Supported versions and skew policy |
| `EVID-002` | `docs/runbooks/upgrade-rollback-policy.md` | Upgrade and rollback release expectations |
| `EVID-003` | `docs/runbooks/disaster-recovery.md` | Backup, restore, and compromise-aware recovery guidance |
| `EVID-004` | `plan/features/13_artifact_integrity_and_secure_defaults.md` | Secure-default and artifact integrity baseline |
| `EVID-005` | `./scripts/quality.sh` output | Full workspace verification evidence |
| `EVID-006` | `artifacts/sbom/README.md` | SBOM artifact location |
| `EVID-007` | `artifacts/provenance/README.md` | Provenance artifact location |
| `EVID-008` | `docs/runbooks/ga-readiness-review-template.md` | Final GA decision record |
| `EVID-009` | `docs/runbooks/stability-contract.md` | Stability boundaries, deprecation policy, and breaking-change contract |
| `EVID-010` | `artifacts/performance-envelope/README.md` | Supported non-loopback performance envelope evidence |
| `EVID-011` | `docs/runbooks/support-boundaries.md` | Explicit HTTP/3 support-boundary evidence (including upstream transport scope and exclusions) |
| `EVID-012` | `artifacts/performance-envelope/soak-capacity-<profile>-<timestamp>.json` | Published long-run soak and capacity-envelope automation evidence manifest |

The release owner should attach generated outputs or references for each artifact path before declaring GA readiness, and should review `docs/runbooks/support-boundaries.md` alongside the final GA decision so the candidate is not presented outside its documented operating envelope.