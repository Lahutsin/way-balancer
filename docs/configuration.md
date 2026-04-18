# Configuration

## Workspace Model

The runtime configuration is a typed JSON document represented by `lb_config_model::WorkspaceConfig`.

At a high level, a workspace includes:

- `api_version` and `name`
- `listeners`
- `routes`
- `upstream_clusters`
- optional `defaults`, `policies`, and `security`

## Core Objects

| Object | Purpose |
| --- | --- |
| `listeners` | Bind sockets, choose protocol and class, and attach routes or admin policy. |
| `routes` | Match path prefixes and optional hostnames, then target an upstream cluster. |
| `upstream_clusters` | Define backend endpoints and optional traffic policy. |
| `policies` | Carry cache, timeout, retry, circuit-breaker, and related reusable settings. |
| `security` | Controls artifact verification, secure defaults, and optional source filtering. |

## Example Files

The checked-in example configurations under `examples/load-balancer/` cover common shapes:

- `basic-http.json`
- `http-cache-public.json`
- `docker-compose-public-admin.json`
- `grpc-retries.json`
- `https-termination.json`
- `public-admin.json`
- `local-dev-insecure.json`
- `sticky-sessions-cookie.json`
- `virtual-hosts.json`
- `example-com-api.json`

Validate those examples locally:

```sh
cargo test -p lb-test-support --test example_configs
```

## Admin Listener Policy

Admin listeners use the typed `listeners[].admin` block.

The default bootstrap path is bearer auth through `LB_CTL_ADMIN_SECRET`, but the config model also supports:

- per-operator signed headers
- source allow-lists
- bounded request rate limits
- in-memory audit retention for `GET /audit`

For production exposure, prefer the stronger signed-header model documented in the admin-plane hardening runbook.

## Hostname And Route Matching

Routes may now include `match.hostnames` together with `match.prefix`.

Important behavior:

- hostnames are normalized against the incoming `Host` or `:authority`
- ambiguous whitespace-separated forms are rejected
- when multiple routes match, the most specific path prefix wins
- query parameters flow through in the forwarded target and are not configured as match primitives

## Cache Policy

HTTP caching is configured through `policies.http_caches` and referenced through `cache_policy` on a listener or route.

Safe defaults in this repository are:

- cache only `GET` and `HEAD`
- bypass requests carrying `Authorization` or `Cookie`
- keep `allow_set_cookie_storage` disabled
- bound memory usage explicitly with entry and byte caps
- enable revalidation only when origins emit stable validators

Detailed operational guidance lives in the cache runbooks.

## Affinity And Sticky Sessions

Upstream clusters may opt into deterministic affinity with `upstream_clusters[].traffic_policy.affinity`.

The current supported sources are:

- `header_hash`
- `cookie_hash`

Current behavior:

- affinity is opt-in only
- if the configured key is missing, normal balancing continues
- if the preferred backend is unhealthy or ejected, `fallback: balance_healthy` re-enters healthy selection
- affinity is intended for stateful workloads and should be used sparingly because it can amplify hot spots

## Security Posture

Artifact verification and secure-default posture live under `security`.

When `security.artifact_verification.mode = "enforced"`, published and applied snapshots must carry an Ed25519 attestation whose signer identity matches the configured trusted signer set.

The checked-in examples leave `trusted_signers` empty on purpose. Production environments should inject the trusted signer set that matches the signing key used by the control plane.

## Next Step

Open [Publishing](publishing.md) for local docs preview and GitHub Pages deployment, or jump into the runbooks for operator-specific procedures.