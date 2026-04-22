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
| `routes` | Match request attributes such as path, host, method, headers, query parameters, content type, and source, then target one or more upstream destinations. |
| `upstream_clusters` | Define backend endpoints and optional traffic policy. |
| `policies` | Carry cache, timeout, retry, circuit-breaker, and related reusable settings. |
| `security` | Controls artifact verification, secure defaults, and optional source filtering. |

## Example Files

The checked-in example configurations under `examples/load-balancer/` cover common shapes:

- `basic-http.json`
- `http-cache-public.json`
- `docker-compose-public-admin.json`
- `grpc-retries.json`
- `http3-public.json`
- `https-termination.json`
- `public-admin.json`
- `proxy-protocol-fronted.json`
- `local-dev-insecure.json`
- `sticky-sessions-cookie.json`
- `virtual-hosts.json`
- `example-com-api.json`
- `route-matchers-http.json`
- `source-aware-routing.json`
- `path-rewrite.json`
- `websocket-upgrade.json`
- `weighted-route-canary.json`
- `weighted-route-blue-green.json`
- `dual-stack-public.json`

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

See [Admin API](admin-api.md) for the concrete runtime endpoints and response shapes exposed by `lb-dataplane serve --config ...`.

## Listener Proxy Protocol

Public listeners may now declare `proxy_protocol` to require an HAProxy Proxy Protocol preface before HTTP handoff.

Supported values are:

- `disabled`
- `v1`
- `v2`

Current rules:

- `proxy_protocol` is valid only on `public` listeners
- when enabled, the listener fails closed on malformed or missing proxy prefaces
- the parsed source address becomes the downstream client address seen by HTTP runtime accounting such as `x-forwarded-for`
- trusted forwarded-header resolution still happens later through `security.trusted_client_ip`
- effective source precedence is direct socket peer -> Proxy Protocol source when enabled -> trusted `Forwarded` header -> trusted `X-Forwarded-For`

Example:

```json
{
	"name": "public-web",
	"class": "public",
	"bind_address": "0.0.0.0:8080",
	"protocol": "http1",
	"proxy_protocol": "v1",
	"routes": ["web"]
}
```

See [examples/load-balancer/proxy-protocol-fronted.json](../examples/load-balancer/proxy-protocol-fronted.json).

## HTTP/3 Listener Model

The config model and serve runtime now support `protocol: "http3"` for the first QUIC slice.

Current rules:

- `http3` is currently valid only on `public` listeners
- `http3` listeners must declare `tls_termination`
- `http3` listeners must advertise only `alpn_protocols: ["http3"]`
- `http3` listeners require TLS 1.3 termination material because QUIC runs only on TLS 1.3
- proxy protocol is not currently supported on `http3` listeners

First supported topology:

- downstream HTTP/3 over QUIC on a public listener
- route matching uses the shared HTTP request classification path
- upstream dispatch currently bridges into the existing HTTP/1 proxy runtime

Current non-goals for this first phase:

- no downstream admin `http3` listeners
- no upstream HTTP/3 proxying or passthrough
- no proxy protocol on the QUIC listener

Minimal example:

```json
{
	"name": "public-http3",
	"class": "public",
	"bind_address": "127.0.0.1:8443",
	"protocol": "http3",
	"routes": ["api"],
	"tls_termination": {
		"minimum_version": "tls13",
		"alpn_protocols": ["http3"],
		"certificate_source": {
			"type": "files",
			"cert_path": "certs/server.pem",
			"key_path": "certs/server.key"
		}
	}
}
```

See [examples/load-balancer/http3-public.json](../examples/load-balancer/http3-public.json).

The HTTP/3 serve path now emits a dedicated `runtime_http3_requests_total` counter labeled by listener scope, result, and response class or local failure reason.

## Listener Bind Mode

Listeners may now declare `bind_mode` to make IPv6-only and dual-stack intent explicit.

Supported values are:

- `single_stack`
- `dual_stack`
- `ipv6_only`

Current rules:

- `single_stack` is the default and binds according to the address family encoded in `bind_address`
- `ipv6_only` requires an IPv6 `bind_address`
- `dual_stack` requires an IPv6 `bind_address` and currently only supports the wildcard form `[::]:port`
- when `bind_mode: dual_stack` uses `[::]:port`, `allow_unspecified_bind` must still be enabled explicitly, just like IPv4 `0.0.0.0`

Example:

```json
{
	"name": "public-dual-stack",
	"class": "public",
	"bind_address": "[::]:8080",
	"bind_mode": "dual_stack",
	"allow_unspecified_bind": true,
	"protocol": "http1",
	"routes": ["api"]
}
```

```json
{
	"name": "admin-v6",
	"class": "admin",
	"bind_address": "[::1]:9900",
	"bind_mode": "ipv6_only",
	"protocol": "https",
	"routes": []
}
```

Runtime behavior now follows the declared bind mode:

- `single_stack` on an IPv6 bind forces IPv6-only socket behavior so the listener does not also accept IPv4-mapped traffic implicitly
- `dual_stack` on `[::]:port` enables a shared IPv6 socket that also accepts IPv4 connections through the same listener
- reload planning treats `bind_mode` as part of listener identity, so changing it on the same live socket is surfaced as a rebind-required change instead of an in-place update

See the checked-in example in [examples/load-balancer/dual-stack-public.json](../examples/load-balancer/dual-stack-public.json).

## Route Matching

Routes use `match` blocks that currently support the `path_prefix` matcher shape with additional filters.

Important behavior:

- path matching still starts with `match.prefix`
- hostnames are normalized against the incoming `Host` or `:authority`
- methods are normalized to uppercase token form before matching
- header matcher names are normalized case-insensitively and currently support `exact`, `present`, and `absent`
- query-parameter matcher names and values are canonicalized with the same percent-encoding rules used by request-target normalization
- content-type matching uses the media type only, ignoring parameters such as `charset`
- source CIDR matching uses the effective client IP, not just the raw socket peer, when trusted forwarding is enabled
- ambiguous whitespace-separated forms are rejected
- when multiple routes match, the most specific path prefix wins
- when prefixes are equal, routes with more specific filters win over less specific routes

Current supported route filter fields under `match` are:

- `prefix`
- `hostnames`
- `methods`
- `headers`
- `query_params`
- `content_types`
- `grpc_services`
- `grpc_methods`
- `source_cidrs`

### Header Matchers

Header filters use one of these shapes:

- `{ "type": "exact", "name": "x-tenant", "value": "beta" }`
- `{ "type": "present", "name": "x-debug" }`
- `{ "type": "absent", "name": "x-internal-only" }`

Header names are case-insensitive. Exact-value matches compare the trimmed header value.

### Query Matchers

Query-parameter filters use one of these shapes:

- `{ "type": "exact", "name": "auth", "value": "user" }`
- `{ "type": "present", "name": "preview" }`
- `{ "type": "absent", "name": "debug" }`

These match against canonicalized query pairs after percent-encoding normalization and stable sorting.

### Content-Type Matchers

`match.content_types` accepts media types such as `application/json` or `application/grpc`.

Parameters are ignored during matching, so a request with `Content-Type: application/json; charset=utf-8` still matches `application/json`.

### gRPC Matchers

`match.grpc_services` and `match.grpc_methods` match the canonical gRPC request path form `/<package>.<Service>/<Method>`.

Current rules:

- when `grpc_services` or `grpc_methods` are present, the route must also declare `content_types: ["application/grpc"]`
- when `grpc_services` or `grpc_methods` are present, any declared HTTP methods must be only `POST`
- these matchers are intended for `http2` public listeners carrying gRPC traffic

Example:

```json
{
	"name": "grpc-capture",
	"match": {
		"type": "path_prefix",
		"prefix": "/",
		"methods": ["POST"],
		"content_types": ["application/grpc"],
		"grpc_services": ["grpc.payments.v1.Payments"],
		"grpc_methods": ["Capture"]
	},
	"upstream_cluster": "payments-grpc"
}
```

### Source CIDR Matchers

`match.source_cidrs` matches against the effective client IP. When `security.trusted_client_ip` is enabled, forwarded-address resolution happens before route selection. The runtime first uses the direct socket peer, replaces it with the Proxy Protocol source when the listener requires Proxy Protocol, then prefers `Forwarded` over `X-Forwarded-For` only when the immediate peer is inside `trusted_proxy_cidrs`.

The same effective source identity is also used by listener hostile-edge `source_quota` enforcement on public listeners, so fronted deployments do not collapse every request into the raw L4 proxy address.

### Example

```json
{
	"name": "api-write",
	"match": {
		"type": "path_prefix",
		"prefix": "/api",
		"hostnames": ["example.com"],
		"methods": ["POST"],
		"headers": [
			{ "type": "exact", "name": "x-tenant", "value": "beta" }
		],
		"query_params": [
			{ "type": "exact", "name": "auth", "value": "user" }
		],
		"content_types": ["application/json"],
		"source_cidrs": ["198.51.100.0/24"]
	},
	"upstream_cluster": "api-backend"
}
```

See the checked-in examples in [examples/load-balancer/route-matchers-http.json](../examples/load-balancer/route-matchers-http.json), [examples/load-balancer/source-aware-routing.json](../examples/load-balancer/source-aware-routing.json), and [examples/load-balancer/grpc-retries.json](../examples/load-balancer/grpc-retries.json).

## Route Destinations

Routes now use a canonical `destinations` list for upstream targeting.

Each destination contains:

- `upstream_cluster`
- `weight`
- optional `policies` for backend-local overrides

Example:

```json
{
	"name": "api",
	"match": {
		"type": "path_prefix",
		"prefix": "/api"
	},
	"destinations": [
		{ "upstream_cluster": "payments-stable", "weight": 90 },
		{ "upstream_cluster": "payments-canary", "weight": 10 }
	]
}
```

The legacy `upstream_cluster` field is still accepted as a shorthand for a single destination with weight `1`.

At runtime, route-level weighting happens before endpoint selection inside each destination cluster. The dataplane applies the configured weights deterministically across repeated selections and falls back to other live destinations when one destination pool has no healthy backend.

## Destination-Local Backend Policies

Explicit route destinations may attach backend-local policy bindings through `routes[].destinations[].policies`.

The current typed model allows destination-local references for:

- `retry_budget`

For HTTP/2 gRPC traffic, retry budgets also gate protocol-aware retries derived from final `grpc-status` values. The runtime currently treats `4` (`DEADLINE_EXCEEDED`), `8` (`RESOURCE_EXHAUSTED`), `13` (`INTERNAL`), and `14` (`UNAVAILABLE`) as retryable unary gRPC failures, with `8` classified as overload and `4` classified as timeout.
- `timeout_hierarchy`
- `circuit_breaker`
- `transform_policy`
- `traffic_mirror`
- `fault_injection`
- `local_rate_limits`
- `local_concurrency_limits`

The current validator rejects destination-local references for:

- `hostile_edge_protection`
- `overload_response`
- `cache_policy`

When local limits are bound at the destination layer, the named limit policy must use a `route_destination` scope that matches both the parent route name and the destination `upstream_cluster`.

The intended precedence shape is listener -> route -> destination. This slice only defines the typed contract and validation; effective resolution and runtime enforcement land in later backend-policy slices.

Current compiled-runtime diagnostics now resolve that precedence explicitly for request transforms, response transforms, retry budgets, timeout hierarchies, circuit breakers, traffic mirroring, fault injection, and local limit references. Singular bindings pick the most specific non-empty layer, while local rate-limit and concurrency-limit references accumulate in listener-then-route-then-destination order.

See the checked-in rollout examples in [examples/load-balancer/weighted-route-canary.json](../examples/load-balancer/weighted-route-canary.json) and [examples/load-balancer/weighted-route-blue-green.json](../examples/load-balancer/weighted-route-blue-green.json).

See the checked-in binding examples in [examples/load-balancer/destination-policy-bindings.json](../examples/load-balancer/destination-policy-bindings.json) and [examples/load-balancer/destination-traffic-mirror.json](../examples/load-balancer/destination-traffic-mirror.json).

## Fault Injection Policy

Fault injection is configured through `policies.fault_injections` and referenced through `fault_injection` on an explicit route destination.

Current rules:

- a fault injection policy must declare at least one of `delay` or `abort`
- `delay.percentage` and `abort.percentage` must be between `1` and `100`
- `delay.fixed_delay_ms` must be greater than `0`
- `abort.http_status` must be between `400` and `599`
- listener-level, route-level, and direct upstream-cluster bindings are rejected; fault injection is destination-local only

Example:

```json
{
	"name": "canary-chaos",
	"spec": {
		"delay": {
			"percentage": 10,
			"fixed_delay_ms": 250
		},
		"abort": {
			"percentage": 5,
			"http_status": 503
		}
	}
}
```

```json
{
	"upstream_cluster": "payments-canary",
	"weight": 10,
	"policies": {
		"fault_injection": "canary-chaos"
	}
}
```

Current dataplane support applies destination-local fault injection after local destination limits are enforced and before cache lookup, mirroring, and primary upstream dispatch.

Current runtime behavior:

- delay and abort actions are gated independently with deterministic percentage selection from the normalized request identity
- delay injection sleeps for the configured fixed duration, then continues normal request handling
- abort injection returns the configured local HTTP status without contacting the primary upstream
- connection reports now expose `fault_injection_delay_count` and `fault_injection_abort_count`

Current non-goals and limits for this slice:

- abort injection returns an HTTP status only; custom response bodies and header overrides are not part of this slice
- delay is fixed-duration only; jitter, ranges, and bandwidth throttling are not part of this slice
- fault injection currently reuses destination-local routing scope rather than introducing a separate listener-wide chaos surface

See the checked-in example in [examples/load-balancer/destination-fault-injection.json](../examples/load-balancer/destination-fault-injection.json).

## Traffic Mirroring Policy

Traffic mirroring is configured through `policies.traffic_mirrors` and referenced through `traffic_mirror` on an explicit route destination.

Current rules:

- `spec.percentage` must be between `1` and `100`
- `spec.target_upstream_cluster` must reference an existing upstream cluster
- the mirror target must differ from the primary destination `upstream_cluster`
- listener-level, route-level, and direct upstream-cluster bindings are rejected; mirroring is destination-local only

Example:

```json
{
	"name": "shadow-payments",
	"spec": {
		"percentage": 20,
		"target_upstream_cluster": "payments-shadow"
	}
}
```

```json
{
	"upstream_cluster": "payments-primary",
	"weight": 100,
	"policies": {
		"traffic_mirror": "shadow-payments"
	}
}
```

Current dataplane support launches best-effort non-blocking shadow requests for destination-local mirroring policies on:

- HTTP/1 requests with no request body
- HTTP/2 streams that arrive end-stream with no request body

Current runtime behavior:

- mirror dispatch is percentage-gated deterministically from the normalized request identity
- the primary response path does not wait for the mirror backend and does not fail closed on mirror errors
- mirror target resolution uses the named `target_upstream_cluster` directly, with the same cluster selection policy used for normal upstream dispatch
- connection reports now expose `mirror_dispatch_count`, `mirror_skip_count`, and `mirror_dispatch_failure_count`

Current non-goals and limits for this slice:

- request bodies are not mirrored yet for HTTP/1 or HTTP/2
- upgrade traffic is not mirrored
- mirror delivery is best-effort only and does not affect retry, timeout, or status handling for the primary response

See the checked-in example in [examples/load-balancer/destination-traffic-mirror.json](../examples/load-balancer/destination-traffic-mirror.json).

## Upgrade Policy

HTTP upgrade allowance is configured explicitly through `upgrade.protocols` on either a listener or a route.

Current rules:

- the default is deny-by-default, so omitting `upgrade` allows no HTTP upgrade protocols
- the only supported protocol name in the typed config is `websocket`
- upgrade policy is valid only on `public` listeners using `http1` or `https`
- routes with upgrade policy must be attached only to `public` `http1` or `https` listeners
- admin listeners do not implicitly inherit public upgrade capability

Example:

```json
{
	"name": "public-http",
	"class": "public",
	"bind_address": "127.0.0.1:8080",
	"protocol": "http1",
	"routes": ["chat-websocket"],
	"upgrade": {
		"protocols": ["websocket"]
	}
}
```

```json
{
	"name": "chat-websocket",
	"match": {
		"type": "path_prefix",
		"prefix": "/ws"
	},
	"upstream_cluster": "chat-backend",
	"upgrade": {
		"protocols": ["websocket"]
	}
}
```

Current runtime support is limited to HTTP/1.1 WebSocket upgrade on `public` `http1` and `https` listeners. The dataplane now preserves the required handshake headers, forwards an allowed `101 Switching Protocols` response, and relays the upgraded byte stream bidirectionally.

Explicit non-goals for the current slice:

- no support for arbitrary upgrade protocols beyond `websocket`
- no RFC 8441 or other HTTP/2 upgrade tunneling
- no implicit upgrade support on admin listeners

See the checked-in example in [examples/load-balancer/websocket-upgrade.json](../examples/load-balancer/websocket-upgrade.json).

## Transform Policy

Request and response transforms are configured through `policies.transforms` and referenced through `transform_policy` on a listener, route, or explicit route destination.

The current typed model supports:

- request path rewrite with `replace_prefix`
- request host rewrite through `request.host_rewrite`
- request header mutation with `set` and `remove`
- response header mutation with `set` and `remove`

Example:

```json
{
	"name": "api-transform",
	"spec": {
		"request": {
			"path_rewrite": {
				"type": "replace_prefix",
				"match_prefix": "/edge",
				"replacement": "/v1"
			},
			"host_rewrite": "backend.internal",
			"header_mutations": [
				{ "type": "set", "name": "x-env", "value": "demo" },
				{ "type": "remove", "name": "x-remove-me" }
			]
		},
		"response": {
			"header_mutations": [
				{ "type": "remove", "name": "server" }
			]
		}
	}
}
```

This slice defines the typed transform contract and validation only. Runtime application lands in the next slice, so the current serve path still forwards the original request and response apart from the existing protocol normalization already described elsewhere.

Runtime ordering is now explicit:

- request transforms run after route match and source checks but before upstream selection, cache lookup, and upstream dispatch
- listener-level and route-level request transforms are merged, with route-level path or host rewrite overriding the listener value and header mutations appended in listener-then-route order
- response transforms run after upstream response normalization but before the downstream response head is written
- for cached HTTP/1 responses, the cache stores the normalized origin headers and reapplies the effective response transform on every downstream cache hit so per-listener and per-route behavior stays stable

Destination-local transform bindings are schema-valid now, but they are not enforced by the dataplane until the later backend-policy runtime slices land.

Transform validation rejects illegal mutations of hop-by-hop or framing-sensitive headers such as `connection`, `transfer-encoding`, `upgrade`, and `content-length`. Request header mutation also rejects `host`; use `request.host_rewrite` instead.

See the checked-in schema example in [examples/load-balancer/path-rewrite.json](../examples/load-balancer/path-rewrite.json).

## Cache Policy

HTTP caching is configured through `policies.http_caches` and referenced through `cache_policy` on a listener or route.

Safe defaults in this repository are:

- cache only `GET` and `HEAD`
- bypass requests carrying `Authorization` or `Cookie`
- keep `allow_set_cookie_storage` disabled
- bound memory usage explicitly with entry and byte caps
- enable revalidation only when origins emit stable validators

Detailed operational guidance lives in the cache runbooks.

See [HTTP Cache](cache.md) for a more product-level walkthrough of eligibility, revalidation, purge, and distributed invalidation.

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

See [Affinity](affinity.md) for deployment guidance, example patterns, and failure interpretation.

## Security Posture

Artifact verification and secure-default posture live under `security`.

When `security.artifact_verification.mode = "enforced"`, published and applied snapshots must carry an Ed25519 attestation whose signer identity matches the configured trusted signer set.

The checked-in examples leave `trusted_signers` empty on purpose. Production environments should inject the trusted signer set that matches the signing key used by the control plane.

If you rely on route-level `source_cidrs`, also configure `security.trusted_client_ip` correctly when traffic arrives through trusted proxies. Otherwise, source matching uses the direct socket peer address.

## Next Step

Open [Admin API](admin-api.md), [HTTP Cache](cache.md), or [Affinity](affinity.md) for focused feature guides, then use [Troubleshooting](troubleshooting.md) for operator diagnostics.