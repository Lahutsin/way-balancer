# Stability Contract

## Purpose

This document defines the compatibility and stability guarantees for config, runtime behavior, and operator-facing interfaces in the current release line.

## Release-Line Scope

- Current supported release line: `0.1.x`
- Stability source of truth: `lb_runtime::RuntimeMetadata`
- Config compatibility anchor: compiled `WorkspaceSnapshot` metadata using supported `api_version` values

The project does not claim cross-release-line compatibility in production evidence. Stability guarantees apply only within the documented supported release line.

## Stable Surfaces

The following surfaces are considered stable within `0.1.x` unless this document and the compatibility runbooks are updated explicitly:

- typed `WorkspaceConfig` input using supported `api_version` values exposed by `RuntimeMetadata`
- opt-in upstream affinity policies under `upstream_clusters[].traffic_policy.affinity`
- compiled snapshot publication, attestation, rollout, and rollback flows
- operator runbooks referenced by release evidence and runtime metadata
- admin and dataplane behaviors already documented as required production workflows
- the versioned `/v1/*` admin API envelope, stable error-code taxonomy, and additive machine-readable status fields documented in `docs/admin-api.md`

Stable means:

- changes must remain backward compatible within the release line, or
- the change must go through the documented breaking-change process before release evidence is updated

## Compatibility Promises

### Config Contract

- A config is supported only if it compiles to a snapshot using a config API version exposed by `RuntimeMetadata`.
- Unsupported `api_version` jumps fail during validation or compilation rather than during live mutation.
- Secure defaults remain part of the supported config contract unless explicitly called out as experimental.

### Runtime Semantic Contract

- Rollout and rollback must preserve digest and attestation validation semantics.
- Listener reload behavior, config preview behavior, and rollback-safe apply guarantees are part of the stable operator-facing contract once documented in the corresponding runbooks.
- Telemetry, counters, and status output may grow additively within the release line, but existing documented semantics must not silently invert.

### Operator Interface Contract

- Canonical runbooks referenced by release evidence are part of the supported operator surface.
- Documented command workflows and release gates must stay reproducible through repository automation.
- Paths surfaced by `RuntimeMetadata` are release artifacts and must remain accurate for the current line.
- The unversioned admin endpoints remain compatibility shims for existing tooling, while the documented `/v1/*` admin API is the stable automation contract for the current release line.

## Experimental Surfaces

Experimental means the surface may change without backward-compatibility guarantees within the same release line, provided it is clearly labeled and not used as a release-evidence dependency.

Current experimental categories in `0.1.x`:

- loopback performance-envelope artifacts under `loopback_regression_v1`: stable as regression tools, experimental as absolute capacity claims across environments
- any insecure-development override such as `security.insecure_dev_mode`: explicitly not a supported production contract
- future or placeholder schema branches not referenced by `RuntimeMetadata` or release-evidence hooks

Supported performance-envelope claims are promoted out of this experimental set only when all of these are true:

- the artifact uses a named supported deployment profile such as `lab_small_non_loopback_v1`
- the artifact records the documented host, network, TLS, and hostile-edge assumptions
- the artifact includes required reload and failover timing evidence
- the artifact passes the profile threshold checks and is stored in the release-evidence location under `artifacts/performance-envelope/`

When promoting a surface from experimental to stable, update this document, the relevant runbook, and any release checks that enforce the artifact.

## Deprecation Policy

Deprecations within a supported release line must follow all of these rules:

1. The replacement behavior or surface must be documented before the old one is removed.
2. The deprecated surface must remain available for the rest of the current release line unless retaining it would create an unacceptable security risk.
3. Operator-facing docs must state the preferred replacement and expected removal point.
4. Release evidence and compatibility docs must be updated before removal lands.

For the admin API specifically, additive fields may be introduced within `/v1/*`, but existing documented fields and error codes must not change meaning silently within `0.1.x`.

For security-driven removals, document the risk and treat the change through the breaking-change process below.

## Breaking-Change Process

A change is breaking if it alters a stable config, runtime, or operator-facing contract in a way that invalidates existing documented workflows or artifacts.

Required process for a breaking change:

1. Update this stability contract and the compatibility matrix before release.
2. Update upgrade and rollback guidance with the new operator expectation.
3. Add or update regression coverage that locks the new boundary in place.
4. Record the change in release evidence so the candidate is not presented as silently compatible.
5. If the change crosses release lines, treat it as unsupported skew until the next release line documents otherwise.

## Upgrade Expectations

- Production upgrades within `0.1.x` assume the same supported config API version set unless `RuntimeMetadata` changes explicitly.
- Operators should upgrade binaries before applying configs that depend on newly supported schema.
- Rollback targets must remain within the same supported config API version set and preserve artifact-integrity guarantees.

## Validation Hooks

This contract is enforced through:

- `lb_runtime::RuntimeMetadata`
- `./scripts/check-release-artifacts.sh`
- `cargo test -p lb-runtime`
- `cargo test -p lb-test-support --test upgrade_rollback_smoke`

## Release Gate Reference

- This runbook complements `docs/runbooks/compatibility-matrix.md` and `docs/runbooks/upgrade-rollback-policy.md` for `EVID-001` and `EVID-002` review.