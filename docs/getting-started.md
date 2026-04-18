# Getting Started

## Build The Workspace

Build everything:

```sh
cargo build --workspace
```

Build only the main entrypoints:

```sh
cargo build -p lb-dataplane -p lb-ctl -p lb-k8s-controller
```

## Run The Main Quality Gate

The primary local verification command is:

```sh
./scripts/quality.sh
```

Useful focused commands:

```sh
./scripts/check-coverage.sh
cargo test -p lb-test-support --test example_configs
cargo test -p lb-test-support --test https_listener_tls_smoke
```

## Start The Local Demo Stack

The checked-in Docker Compose demo exposes:

- public traffic on `http://localhost:8080/`
- admin traffic on `http://127.0.0.1:9900/`

The admin listener requires a bearer secret from the environment:

```sh
export LB_CTL_ADMIN_SECRET=<admin-bearer-token>
docker compose up --build
```

Smoke-test the running stack:

```sh
curl http://localhost:8080/
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/healthz
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/status
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/validate
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://localhost:9900/audit
```

## Preview This Documentation Locally

Install the documentation dependencies:

```sh
python3 -m pip install -r requirements-docs.txt
```

Run a live preview server:

```sh
python3 -m mkdocs serve
```

Build the same static output used by GitHub Pages:

```sh
python3 -m mkdocs build --strict
```

## Where To Go Next

- Open [Architecture](architecture.md) for the control-plane and dataplane model.
- Open [Configuration](configuration.md) for schema shape, examples, cache policy, and affinity.
- Open the runbooks for security, TLS, DR, and upgrade operations.