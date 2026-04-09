# Release Evidence Inventory

- `EVID-001`: `docs/runbooks/compatibility-matrix.md`
- `EVID-002`: `docs/runbooks/upgrade-rollback-policy.md`
- `EVID-003`: `docs/runbooks/disaster-recovery.md`
- `EVID-004`: workspace tests plus coverage gate
- `EVID-005`: `docs/runbooks/cache-performance.md`
- `EVID-006`: `artifacts/sbom/README.md` and `artifacts/provenance/README.md`
- `EVID-007`: security review and secret-scanning outputs
- `EVID-008`: `docs/runbooks/ga-readiness-review-template.md`# Release Evidence Inventory

| Evidence ID | Artifact path | Purpose |
| --- | --- | --- |
| `EVID-001` | `docs/runbooks/compatibility-matrix.md` | Supported versions and skew policy |
| `EVID-002` | `docs/runbooks/upgrade-rollback-policy.md` | Upgrade and rollback release expectations |
| `EVID-003` | `docs/runbooks/disaster-recovery.md` | Backup, restore, and compromise-aware recovery guidance |
| `EVID-004` | `plan/features/12c_artifact_integrity_and_secure_defaults.md` | Secure-default and artifact integrity baseline |
| `EVID-005` | `./scripts/quality.sh` output | Full workspace verification evidence |
| `EVID-006` | `artifacts/sbom/README.md` | SBOM artifact location |
| `EVID-007` | `artifacts/provenance/README.md` | Provenance artifact location |
| `EVID-008` | `docs/runbooks/ga-readiness-review-template.md` | Final GA decision record |

The release owner should attach generated outputs or references for each artifact path before declaring GA readiness.