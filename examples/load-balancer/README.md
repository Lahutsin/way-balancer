# Load Balancer Configuration Examples

These examples target the typed JSON configuration accepted by `lb_config_model::WorkspaceConfig`.

## Files

- `basic-http.json`: minimal HTTP/1.1 edge listener with a single upstream cluster, local-friendly hostname filters, and a conservative public-cache policy
- `http-cache-public.json`: public HTTP example with a named shared-cache policy, local-friendly hostname filters, and route-level cache binding
- `docker-compose-public-admin.json`: container-friendly public plus admin HTTP listener for `docker compose up`, with cache enabled on the public route, hostname filters matching local Docker Compose curls, and explicit bearer-auth admin policy for `healthz`, `readyz`, `status`, `validate`, `audit`, and `reload`
- `grpc-retries.json`: HTTP/2 or gRPC-style listener with retry-budget policy wiring and hostname-aware route matching
- `http3-public.json`: public HTTP/3 over QUIC example showing the first supported downstream HTTP/3 to upstream HTTP/1 bridge topology
- `https-termination.json`: HTTPS listener with file-backed TLS termination material, hostname-aware route matching, and a conservative public-cache policy
- `public-admin.json`: public application listener plus a separate localhost-only admin HTTP listener, with cache enabled on the public route, local-friendly hostname filters, and explicit admin auth, rate-limit, and audit retention settings
- `local-dev-insecure.json`: development-only example showing explicit insecure override gating with hostname-aware route matching
- `sticky-sessions-cookie.json`: opt-in stateful app example that hashes a `session_id` cookie to a deterministic backend and falls back to healthy balancing when the preferred backend is unavailable
- `virtual-hosts.json`: virtual-host example that routes `shop.localhost` and `api.localhost` to different upstream clusters on the same listener
- `example-com-api.json`: focused hostname-aware API example for `example.com/api?auth=user`, where query forwarding stays automatic, only host plus path are configured, and the shared security section demonstrates the full anonymous-source filter shape
- `route-matchers-http.json`: richer HTTP route-matching example using method, header, query-parameter, and content-type filters on one listener
- `source-aware-routing.json`: source-aware route example that combines trusted client IP resolution with route-level source CIDR matching
- `path-rewrite.json`: transform-policy example showing path rewrite, host rewrite, and request or response header mutation schema
- `websocket-upgrade.json`: HTTP/1.1 WebSocket upgrade example showing listener and route policy allow-lists for `upgrade.protocols: ["websocket"]`
- `proxy-protocol-fronted.json`: public listener example that requires Proxy Protocol on the downstream edge before trusted client IP resolution and source-aware routing
- `weighted-route-canary.json`: route-destination example showing a 90/10 stable/canary split across two upstream clusters
- `weighted-route-blue-green.json`: route-destination example showing a 50/50 blue/green split across two upstream clusters
- `dual-stack-public.json`: explicit dual-stack listener example using `bind_mode: "dual_stack"` on an IPv6 wildcard bind
- `destination-policy-bindings.json`: destination-local policy example showing backend-specific retry, timeout, transform, and local-limit bindings on one route
- `destination-traffic-mirror.json`: destination-local traffic mirroring example that shadows requests to a separate upstream cluster without affecting the primary response
- `destination-fault-injection.json`: destination-local fault injection example showing explicit delay and abort policy wiring for controlled resilience testing
- `cache-peer-node-a.json`: node A of a two-node cache topology, using signed admin headers and a listener-scoped shared-cache policy suitable for HTTP peer invalidation
- `cache-peer-node-b.json`: node B companion config for the same two-node cache topology, using the same signed peer secret contract on a different public/admin bind pair
- `cache-peer-topology.md`: operational note for wiring `HttpCachePeerTransport` across the two checked-in node configs without inventing unsupported config schema
- `multi-node-rollout-example.md`: control-plane example showing canary or sequential fleet rollout semantics and bounded convergence checks

## Important Note

These files model the configuration document only. Snapshot publication metadata such as artifact attestation is part of the control-plane publish flow and is not embedded inside the config JSON itself.

The `security.artifact_verification.trusted_signers` arrays are left empty on purpose in the checked-in examples. Production control-plane workflows should populate them with Ed25519 public keys for the signer identities allowed to publish snapshots.

Examples that keep `security.artifact_verification.mode` set to `enforced` are intentionally not self-sufficient artifacts. They validate as configuration documents, but real publication and rollout still require signer injection from the control plane or operator workflow.

The HTTPS example uses file paths for PEM certificate and key material. Those files are operator-provided deployment inputs rather than repository fixtures.

The Docker Compose example binds `0.0.0.0` explicitly and points at a fixed backend IP on the compose network so the current `SocketAddr`-based upstream model can resolve the demo backend without extra service discovery. The admin listener is HTTP/1, is intended to be used with `LB_CTL_ADMIN_SECRET` bearer authorization, exposes `GET /healthz`, `GET /readyz`, `GET /status`, `GET /validate`, `GET /audit`, and `POST /reload`, and the compose file publishes port `9900` on `127.0.0.1` only.

The HTTP examples now include richer route filters under `match`: `hostnames`, `methods`, `headers`, `query_params`, `content_types`, and `source_cidrs` when needed. Query parameters still forward automatically as part of the request target, but they can now also participate in route selection when you need exact, present, or absent checks.

If multiple routes match the same host, the runtime prefers the most specific path prefix.

The opt-in affinity policy lives under `upstream_clusters[].traffic_policy.affinity`. Missing affinity keys fall back to the configured balancing algorithm, and `fallback: balance_healthy` re-routes to a healthy backend instead of pinning to an unhealthy or ejected endpoint. Use affinity only for workloads that truly need backend-local state, because it can create hot spots and reduce balancing flexibility.

For the current `lb-dataplane serve --config ...` path, each matched route can either target one upstream cluster directly or split traffic across multiple route destinations by weight before balancing inside the chosen cluster.

The shared `security.anonymous_source_filter` block is optional. When enabled in serve mode, it blocks client source IPs that fall inside configured direct `deny_cidrs` entries or VPN, proxy, SOCKS, and Tor CIDR lists and returns a local `403` before proxying. The checked-in examples include both IPv4 and IPv6 `deny_cidrs` entries.

For the focused `example.com/api?auth=user` case, use `example-com-api.json` and send a request like:

```sh
curl -H 'Host: example.com' 'http://127.0.0.1:8080/api?auth=user'
```

The route match checks `Host` plus the `/api` path prefix. The `?auth=user` query string is forwarded automatically and does not need to be declared in the config.

For a fuller route-matching shape, inspect `route-matchers-http.json`. That example shows one route using:

- path prefix
- method filter
- header filter
- query-parameter filter
- content-type filter

For effective-client-IP-aware routing behind a trusted local proxy, inspect `source-aware-routing.json`.

For transform policy behavior, inspect `path-rewrite.json`. It shows the typed `transform_policy` binding with request path rewrite, host rewrite, request header mutation, and response header mutation, and those transforms now execute on the live HTTP proxy path.

For first-phase HTTP/3 listener wiring, inspect `http3-public.json`.

For downstream WebSocket upgrade allow-listing, inspect `websocket-upgrade.json`.

For Proxy Protocol and trusted-edge source identity, inspect `proxy-protocol-fronted.json`.

For explicit IPv4 plus IPv6 listener behavior, inspect `dual-stack-public.json`.

For destination-local backend policy layering, inspect `destination-policy-bindings.json`.

For destination-local mirroring and chaos behavior, inspect `destination-traffic-mirror.json` and `destination-fault-injection.json`.

For route-level traffic shifting, inspect `weighted-route-canary.json` for a 90/10 stable-canary rollout or `weighted-route-blue-green.json` for a 50/50 blue-green split. Both examples use the canonical `destinations` list with explicit route weights.

The cache example is intentionally conservative for a shared cache: it limits methods to `GET` and `HEAD`, keeps `allow_set_cookie_storage` disabled, enables validator-based revalidation, and uses bounded in-memory storage. Cookie-bearing requests still bypass the shared cache at runtime even if the config itself does not mention cookies.

## Validation

The repository validates these examples with:

```sh
cargo test -p lb-test-support --test example_configs
```

The checked-in multi-node cache peer example uses signed admin headers instead of bearer auth and expects a shared peer secret:

```sh
export LB_CACHE_PEER_SECRET=<shared-peer-secret>
```

See `cache-peer-topology.md` for the two-node layout and the current boundary between workspace config and admin-service peer transport wiring.
```