# way-balancer

Production-oriented Rust load-balancer

way-balancer is a production-oriented Rust load balancer with a typed config model, runtime reload mechanics, admin-plane controls, cache and policy surfaces, Kubernetes translation, and explicit `0.1.x` support-boundary plus release-evidence discipline.

Detailed architecture, support boundaries, configuration shape, and runbooks now live under [docs/](docs/) instead of being duplicated in this file.

Start here:

- [docs/index.md](docs/index.md): documentation home
- [docs/getting-started.md](docs/getting-started.md): local bring-up and developer workflow
- [docs/architecture.md](docs/architecture.md): system architecture and crate boundaries
- [docs/configuration.md](docs/configuration.md): typed `WorkspaceConfig` model and examples
- [docs/admin-api.md](docs/admin-api.md): admin endpoints and operator sequencing
- [docs/runbooks/support-boundaries.md](docs/runbooks/support-boundaries.md): supported and unsupported deployment shapes
- [examples/load-balancer/README.md](examples/load-balancer/README.md): checked-in example configs

## Documentation Site

The repository now includes a GitHub Pages-ready documentation site built with MkDocs Material.

Preview it locally with:

```sh
python3 -m pip install -r requirements-docs.txt
python3 -m mkdocs serve
```

Build the same static output used in CI with:

```sh
python3 -m mkdocs build --strict
```

The publishing workflow lives in `.github/workflows/docs-pages.yml`. To make the site live on GitHub, set the repository `Pages` source to `GitHub Actions` once in repository settings.

## Build

Build the full workspace:

```sh
cargo build --workspace
```

Build the runnable entrypoints only:

```sh
cargo build -p lb-dataplane -p lb-ctl -p lb-k8s-controller
```

`lb-dataplane` also supports a local live mode with `serve --config <file>` for the checked-in example topologies.

Build OCI images from the checked-in `Dockerfile` by selecting the binary with `APP_BIN`:

```sh
docker build -t way-balancer-dataplane .
docker build --build-arg APP_BIN=lb-k8s-controller -t way-balancer-k8s-controller .
```

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

Full developer, configuration, cache, security, TLS, support-boundary, and Kubernetes guidance is documented under [docs/](docs/).

The checked-in `serve --config` admin examples require an environment-provided bearer secret instead of embedded credentials:

```sh
export LB_CTL_ADMIN_SECRET=<admin-bearer-token>
```

Run the live demo stack with Docker Compose:

```sh
export LB_CTL_ADMIN_SECRET=<admin-bearer-token>
docker compose up --build
curl http://localhost:8080/
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/healthz
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/readyz
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/status
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/validate
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/audit
```

The compose file now builds a generic `lb-dataplane` image and injects only runtime environment needed by the checked-in workspace admin example. The admin listener remains bound to `0.0.0.0` inside the container so Docker can publish it, but Compose publishes `9900` only on `127.0.0.1`, and the listener itself requires bearer authorization. `GET /healthz` remains a liveness check, while `GET /readyz` reports whether the instance should receive new traffic based on current listener state, unsafe overload, and reload health. Use `GET /validate` before `POST /reload`, and inspect recent control-plane activity through `GET /audit`.

## Runbooks And Release Artifacts

- compatibility and upgrade policy: `docs/runbooks/compatibility-matrix.md`, `docs/runbooks/upgrade-rollback-policy.md`
- stability contract: `docs/runbooks/stability-contract.md`
- admin-plane security model: `docs/runbooks/admin-plane-hardening.md`
- dataplane performance envelope: `docs/runbooks/performance-envelope.md`
- cache configuration and operations: `docs/runbooks/cache-operations.md`, `docs/runbooks/cache-invalidation.md`, `docs/runbooks/cache-performance.md`
- Kubernetes controller packaging and operations: `docs/runbooks/kubernetes-controller-operations.md`
- disaster recovery: `docs/runbooks/disaster-recovery.md`
- release evidence and GA gate: `docs/runbooks/release-evidence-checklist.md`, `docs/runbooks/ga-readiness-review-template.md`
- evidence inventory: `artifacts/release-evidence-inventory.md`

