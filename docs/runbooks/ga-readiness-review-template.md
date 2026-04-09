# GA Readiness Review Template

## Evidence Inventory

- `EVID-001`
- `EVID-002`
- `EVID-003`
- `EVID-004`
- `EVID-005`
- `EVID-006`
- `EVID-007`
- `EVID-008`

## Decision

- `go`
- `go_with_exceptions`
- `no_go`

## Notes

- summarize release blockers, exceptions, and cache-specific operational guidance for the candidate# GA Readiness Review Template

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

## Readiness Questions

1. Are all required artifacts present and reproducible from repository automation?
2. Are supported versions, skew policy, and rollback expectations explicit for operators?
3. Can the product be restored after failure or compromise using the documented DR path?
4. Are unresolved security exceptions documented with explicit acceptance?
5. Is release metadata visible and aligned with the candidate under review?

## Decision

- Outcome: `go` / `go_with_exceptions` / `no_go`
- Blocking issues:
- Accepted exceptions:
- Required follow-up before next release:

## Approvals

- Engineering:
- Security:
- Operations: