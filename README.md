# way-balancer

Production-oriented Rust load-balance

## Current Scope

This repository now contains a substantial pre-GA product foundation:

- listener lifecycle and connection admission runtime
- TCP, HTTP/1.1, HTTP/2, and gRPC proxy foundations
- production-oriented HTTP response caching with purge, revalidation, bounded observability, and multi-node invalidation seams
- typed config model, validation, deterministic snapshot compilation, digesting, and diffing
- snapshot publication, rollout, rollback, authn/authz, abuse-control, and DR restore foundations
- Kubernetes Gateway API translation and reconciliation foundations
- secure-default posture, mTLS/certificate validation, and artifact integrity checks
- release compatibility, DR, and GA-readiness runbooks and evidence artifacts

The workspace is still pre-GA, but it already includes runnable dataplane/control-plane foundations and productization gates rather than only repo scaffolding.

## Implemented Subsystems

- `crates/runtime`: dataplane runtime, proxying, overload, probe, source guard, and snapshot-apply logic
- `crates/admin-api`: snapshot publication, rollout/rollback, admin auth, abuse control, mTLS, backup/restore hooks
- `crates/config-model`: typed config schema, validation, security posture, snapshot compiler, digest, and diff model
- `crates/k8s-integration`: Gateway API translation, reconciliation, and EndpointSlice foundations
- `crates/proto-http` and `crates/proto-tls`: protocol hardening and certificate-validation foundations
- `crates/observability`: metrics, tracing, diagnostics, support-bundle, and forensic export foundations
- `crates/test-support`: upgrade/rollback and restore smoke fixtures used by release gates

## Workspace Layout

- `crates/`: shared libraries and architecture layers
- `binaries/`: deployable dataplane and control-plane entrypoints
- `examples/`: typed configuration examples for load balancer workspaces
- `tests/`: integration, property, and fuzz scaffolding
- `scripts/`: local developer and CI helper scripts
- `docs/`: contributor guides plus compatibility, DR, and release runbooks
- `artifacts/`: release-evidence inventory and SBOM/provenance artifact locations

## Build

Build the full workspace:

```sh
cargo build --workspace
```

Build the runnable entrypoints only:

```sh
cargo build -p lb-dataplane -p lb-ctl
```

`lb-dataplane` also supports a local live mode with `serve --config <file>` for the checked-in example topologies.

## Test

Run the full local verification flow:

```sh
./scripts/quality.sh
```

Common focused commands:

```sh
./scripts/check-coverage.sh
cargo test -p lb-test-support --test upgrade_rollback_smoke
cargo test -p lb-test-support --test snapshot_restore_smoke
cargo test -p lb-test-support --test example_configs
```

## Local Quality Commands

Run the primary verification entrypoint:

```sh
./scripts/quality.sh
```

This runs formatting, clippy, workspace tests, docs build, release-artifact consistency checks, secret-scanning hooks, and dependency audits when optional tools are installed.

Code coverage is enforced per Rust source file under `crates/*/src` and `binaries/*/src`: every file must stay at or above 80% line coverage. The coverage gate is backed by `cargo-llvm-cov` and can be run directly with:

```sh
./scripts/check-coverage.sh
```

Optional checks that rely on extra installed tools:

```sh
cargo deny check
cargo audit
./scripts/check-secret-scanning.sh
./scripts/generate-sbom.sh
./scripts/verify-provenance.sh
```

For the full local gate, install:

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov cargo-deny cargo-audit cargo-nextest --locked
```

## Configure

The configuration model is a typed JSON document represented by `lb_config_model::WorkspaceConfig`. A workspace configuration typically includes:

- `api_version` and `name`
- `listeners` with bind address, protocol, class, and attached route names
- `routes` with a match rule and target upstream cluster
- `upstream_clusters` with endpoints and optional traffic policy
- optional `defaults`, `policies`, and `security`

Example configuration files live in `examples/load-balancer/`:

- `basic-http.json`: minimal HTTP edge listener
- `basic-http.json`: minimal HTTP edge listener with a conservative public-cache policy
- `http-cache-public.json`: public HTTP listener with a named shared-cache policy, safe defaults, and purge enabled
- `docker-compose-public-admin.json`: public plus admin listeners for the bundled Docker Compose demo with a conservative public-cache policy on the public route
- `grpc-retries.json`: HTTP/2 or gRPC-style routing with retry-budget policy
- `https-termination.json`: HTTPS listener with file-backed TLS termination material and a conservative public-cache policy
- `public-admin.json`: public application traffic plus a separate admin listener and a conservative public-cache policy on the public route
- `local-dev-insecure.json`: explicit development-only insecure override

Validate those examples locally with:

```sh
cargo test -p lb-test-support --test example_configs
```

Validate the HTTPS listener surface and certificate loading path with:

```sh
cargo test -p lb-test-support --test https_listener_tls_smoke
```

Artifact attestation is enforced during snapshot publication and apply flows, not encoded inside the workspace JSON document. The `security` section controls local secure-default posture such as verification mode and any explicitly acknowledged dev-only override.

When `security.artifact_verification.mode` is `enforced`, the snapshot must be published and applied with an Ed25519 attestation whose `signer_identity` matches one of the configured `security.artifact_verification.trusted_signers` entries. Each trusted signer entry contains an `identity` plus a lowercase hex `public_key_ed25519` value.

The checked-in JSON examples intentionally leave `trusted_signers` empty. In a real deployment, the control-plane or operator must inject the trusted signer set that matches the private key used to attest published snapshots.

HTTPS listeners use `"protocol": "https"` plus a `tls_termination.certificate_source` block that points at PEM certificate and PEM private key files.

HTTP response caching is configured through `policies.http_caches` plus a `cache_policy` reference on a listener or route. Safe shared-cache defaults in this repository are:

- cache only `GET` and `HEAD`
- bypass requests carrying `Authorization` or `Cookie`
- keep `allow_set_cookie_storage` disabled
- use bounded in-memory storage with explicit `max_entries`, `max_bytes`, and `max_object_bytes`
- enable revalidation only when the origin emits stable validators such as `ETag` or `Last-Modified`

Operator-facing cache guidance lives in:

- `docs/runbooks/cache-operations.md`
- `docs/runbooks/cache-invalidation.md`
- `docs/runbooks/cache-performance.md`

The demo binaries also require environment-provided secrets and signing material instead of embedded credentials:

```sh
export LB_CONTROL_PLANE_SIGNING_KEY_ED25519=<32-byte-ed25519-seed-as-lowercase-hex>
export LB_CTL_ADMIN_SECRET=<admin-bearer-token>
export LB_CTL_OPERATOR_SECRET=<operator-bearer-token>
```

Run the live demo stack with Docker Compose:

```sh
export LB_CONTROL_PLANE_SIGNING_KEY_ED25519=<32-byte-ed25519-seed-as-lowercase-hex>
export LB_CTL_ADMIN_SECRET=<admin-bearer-token>
export LB_CTL_OPERATOR_SECRET=<operator-bearer-token>
docker compose up --build
curl http://localhost:8080/
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/healthz
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/status
```

The compose file now requires those variables, forwards them as build args for the image build, and also injects them into the runtime container environment. The admin listener remains bound to `0.0.0.0` inside the container so Docker can publish it, but Compose publishes `9900` only on `127.0.0.1` and the listener itself requires bearer authorization.

## Runbooks And Release Artifacts

- compatibility and upgrade policy: `docs/runbooks/compatibility-matrix.md`, `docs/runbooks/upgrade-rollback-policy.md`
- cache configuration and operations: `docs/runbooks/cache-operations.md`, `docs/runbooks/cache-invalidation.md`, `docs/runbooks/cache-performance.md`
- disaster recovery: `docs/runbooks/disaster-recovery.md`
- release evidence and GA gate: `docs/runbooks/release-evidence-checklist.md`, `docs/runbooks/ga-readiness-review-template.md`
- evidence inventory: `artifacts/release-evidence-inventory.md`

