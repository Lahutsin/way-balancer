# GA Readiness Review Template

## Release Summary

- Release line:
- Candidate identifier:
- Review date:
- Review owner:

## Evidence Inventory

- `EVID-001` Compatibility policy reviewed:
- `EVID-002` Upgrade and rollback validation attached:
- `EVID-003` Disaster recovery validation attached:
- `EVID-004` Secure-default and integrity expectations reviewed:
- `EVID-005` Full quality output attached:
- `EVID-006` SBOM artifact location attached:
- `EVID-007` Provenance artifact location attached:
- `EVID-008` Final review record completed:
- `EVID-009` Stability contract reviewed and aligned with the candidate:
- `EVID-010` Supported performance-envelope artifact attached when the candidate makes absolute capacity claims:
- `EVID-011` HTTP/3 support-boundary contract reviewed and validated for the candidate shape:
- `EVID-012` Published soak-capacity automation manifest attached and validated:

## GA Exit Criteria

- [ ] All required evidence artifacts are present, reproducible, and linked.
- [ ] The intended deployment matches a supported topology in `docs/runbooks/support-boundaries.md`.
- [ ] No unsupported override such as `security.insecure_dev_mode` is part of the candidate posture.
- [ ] Stable versus experimental surfaces are aligned with `docs/runbooks/stability-contract.md`.
- [ ] Capacity or failover claims are backed by the documented supported performance artifact when such claims appear in the release narrative.

## Support-Boundary Review

- Intended deployment topology:
- Supported topology reference:
- Protocol surfaces in scope:
- Explicitly unsupported or deferred surfaces:
- Failure-mode exceptions accepted for this candidate:
- Performance artifact path, if required:

## Readiness Questions

1. Are all required artifacts present and reproducible from repository automation?
2. Are supported versions, skew policy, and rollback expectations explicit for operators?
3. Can the product be restored after failure or compromise using the documented DR path?
4. Are unresolved security exceptions documented with explicit acceptance?
5. Is release metadata visible and aligned with the candidate under review?
6. Does the intended deployment stay within the documented support boundaries?

## Decision

- Outcome: `go` / `go_with_exceptions` / `no_go`
- Blocking issues:
- Accepted exceptions:
- Required follow-up before next release:

## Approvals

- Engineering:
- Security:
- Operations: