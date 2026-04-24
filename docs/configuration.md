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

The config model and serve runtime support `protocol: "http3"` for public QUIC listeners.

Current rules:

- `http3` is currently valid only on `public` listeners
- `http3` listeners must declare `tls_termination`
- `http3` listeners must advertise only `alpn_protocols: ["http3"]`
- `http3` listeners require TLS 1.3 termination material because QUIC runs only on TLS 1.3
- proxy protocol is not currently supported on `http3` listeners

Current supported topology:

- downstream HTTP/3 over QUIC on a public listener
- route matching uses the shared HTTP request classification path
- upstream dispatch uses runtime transport selection and can target upstream clusters configured with `transport: http1|http2|http3`

Current non-goals:

- no downstream admin `http3` listeners
- no proxy protocol on the QUIC listener
- no transparent QUIC passthrough/tunnel mode

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
- `timeout_hierarchy`
- `circuit_breaker`
- `transform_policy`
- `traffic_mirror`
- `fault_injection`
- `jwt_auth_policy`
- `external_auth_policy`
- `authorization_policy`
- `upstream_identity_policy`
- `local_rate_limits`
- `local_concurrency_limits`

For HTTP/2 gRPC traffic, retry budgets also gate protocol-aware retries derived from final `grpc-status` values. The runtime currently treats `4` (`DEADLINE_EXCEEDED`), `8` (`RESOURCE_EXHAUSTED`), `13` (`INTERNAL`), and `14` (`UNAVAILABLE`) as retryable unary gRPC failures, with `8` classified as overload and `4` classified as timeout.

Timeout hierarchy policies support request-level and per-try shaping:

- `request_timeout_ms`: outer request lifetime bound
- `attempt_timeout_ms`: compatibility field for per-attempt bound
- `per_try_timeout_ms` (optional): explicit per-try bound that overrides `attempt_timeout_ms` when set
- `connect_timeout_ms` and `idle_timeout_ms`: must remain less than or equal to the effective per-try timeout

The current validator rejects destination-local references for:

- `hostile_edge_protection`
- `overload_response`
- `cache_policy`

When local limits are bound at the destination layer, the named limit policy must use a `route_destination` scope that matches both the parent route name and the destination `upstream_cluster`.

The intended precedence shape is listener -> route -> destination. This slice only defines the typed contract and validation; effective resolution and runtime enforcement land in later backend-policy slices.

Current compiled-runtime diagnostics now resolve that precedence explicitly for request transforms, response transforms, retry budgets, timeout hierarchies, circuit breakers, traffic mirroring, fault injection, and local limit references. Singular bindings pick the most specific non-empty layer, while local rate-limit and concurrency-limit references accumulate in listener-then-route-then-destination order.

See the checked-in rollout examples in [examples/load-balancer/weighted-route-canary.json](../examples/load-balancer/weighted-route-canary.json) and [examples/load-balancer/weighted-route-blue-green.json](../examples/load-balancer/weighted-route-blue-green.json).

See the checked-in binding examples in [examples/load-balancer/destination-policy-bindings.json](../examples/load-balancer/destination-policy-bindings.json) and [examples/load-balancer/destination-traffic-mirror.json](../examples/load-balancer/destination-traffic-mirror.json).

## L7 Auth And Upstream Identity Policy Schema

Feature 07 item 1 adds typed policy resources and binding references for application-layer auth and upstream identity.

Named policy resources under `policies`:

- `jwt_auth_policies`
- `external_auth_policies`
- `authorization_policies`
- `upstream_identity_policies`

Policy binding references on listeners, routes, destinations, and upstream clusters now include:

- `jwt_auth_policy`
- `external_auth_policy`
- `authorization_policy`
- `upstream_identity_policy`

Current validation and scope rules:

- `jwt_auth_policy`, `external_auth_policy`, and `authorization_policy` may be bound on listeners, routes, and route destinations.
- `jwt_auth_policy`, `external_auth_policy`, and `authorization_policy` are rejected on direct upstream-cluster bindings.
- `upstream_identity_policy` may be bound only on upstream clusters or explicit route destinations.
- `upstream_identity_policy` is rejected on listener and route bindings.
- JWT policy validation currently enforces issuer and audience presence, non-empty required claim names, a bounded `clock_skew_secs`, and a concrete JWKS source.
- External auth policy validation currently enforces a non-empty endpoint, positive timeout, header name validity, and non-empty context mapping keys.
- Upstream identity policy validation currently enforces a trust bundle source plus at least one allowed trust domain or SPIFFE identity.

Current runtime behavior for JWT auth bindings:

- when an effective `jwt_auth_policy` is bound for the selected route destination, requests must include `Authorization: Bearer <token>`
- missing bearer headers are rejected locally with `401`
- local verification enforces signature validation and issuer/audience checks plus required-claim presence
- successful verification allows normal upstream forwarding

Current runtime behavior for external auth bindings:

- when an effective `external_auth_policy` is bound for the selected route destination, runtime performs an HTTP JSON authorization call to the configured endpoint
- deny decisions from the external service are rejected locally with `403`
- transport or response failures return `503` or `502` unless `fail_open = true`, in which case runtime allows the request
- configured `context_mappings` copy values from external auth response `context` into target request headers before upstream dispatch

Current runtime behavior for authorization bindings:

- when an effective `authorization_policy` is bound for the selected route destination, runtime evaluates rules after JWT and external auth checks and before upstream dispatch
- first matching rule applies; unmatched requests use `default_decision`
- deny decisions are rejected locally with `403`
- rule matching supports claim/header presence and scope or role checks using request headers
- scopes are read from `x-auth-scopes` or `x-auth-scope` (space/comma tokenized)
- roles are read from `x-auth-roles` or `x-auth-role` (space/comma tokenized)
- claim presence checks accept header names `claim`, `x-auth-<claim>`, or `x-auth-claim-<claim>`
- authorization decisions emit request-flow decision trace telemetry with `decision=policy_enforcement` and `policy=authorization`

Current runtime behavior for upstream identity bindings:

- when an effective `upstream_identity_policy` is bound for the selected route destination, runtime requires upstream peer identity from mTLS transport
- current upstream HTTP/1 and HTTP/2 forwarding paths do not expose upstream peer identity yet
- until upstream mTLS transport identity plumbing lands, bound upstream identity policies fail closed with local `503`
- effective policy precedence for upstream identity is destination override first, then upstream-cluster binding

Current limitations for this slice:

- remote JWKS fetch (`jwt_jwks_source.type = remote`) is not executed in runtime yet
- file-based JWT JWKS and upstream identity trust bundles are refreshed on request-path verification according to configured `refresh_secs`
- invalid refreshed JWKS or trust bundles fail closed (`401` for JWT verification failure, `503` for upstream identity policy enforcement failure)

## Extension Surface Runtime Contract

Feature 08 defines the extension execution contract used by custom auth and policy integrations.

Current runtime contract:

- extension API compatibility is negotiated through `api_version` and enforced at plugin registration time
- incompatible plugin versions are rejected before request-path execution
- optional plugins may be disabled with explicit fallback behavior (`allow`, `deny`, `abstain`)
- required plugins fail closed when disabled
- plugin execution is sandboxed in-process with bounded execution timeout and panic containment
- repeated plugin execution failures trigger temporary isolation (cooldown quarantine)
- isolated optional plugins use configured fallback behavior; isolated required plugins fail closed

Current extension observability surface:

- `runtime_extension_policy_plugin_evaluations_total` tracks plugin outcomes by plugin name, result, and reason
- `runtime_extension_compatibility_rejections_total` tracks rejected plugin registrations by plugin name and reason
- extension policy/plugin outcomes emit machine-readable decision events (`decision.policy.enforced`) with scope and policy labels

Current compatibility note:

- stable extension hook and policy plugin contract in this release line is `api_version = v1`

## WAF Request Classification Model

Feature 09 item 1 introduces typed request classification policy resources that define anomaly-score behavior and classifier context projection.

Named policy resources under `policies`:

- `request_classification_policies`

Policy binding references:

- `request_classification_policy` may be bound on listeners, routes, and route destinations
- `request_classification_policy` is rejected on direct upstream-cluster bindings

Current model fields:

- sensitivity profile (`low`, `medium`, `high`)
- challenge and block thresholds over normalized score range `0..=100`
- weighted signal model (`header_anomaly`, `body_anomaly`, `query_anomaly`, `user_agent_anomaly`, `reputation`, `bot_signal`)
- classifier context projection controls for method, path, source IP, user-agent, selected headers, and selected query keys
- bounded body inspection controls (`body_scoring.max_inspect_bytes`, `body_scoring.max_body_bytes`, `body_scoring.min_suspicious_token_length`, `body_scoring.suspicious_patterns`, `body_scoring.allowlisted_content_types`)

Current validation rules:

- `challenge_threshold` must be strictly less than `block_threshold`
- at least one classifier signal weight must be non-zero
- configured context header names must be valid HTTP header names
- configured context query parameter names must be non-empty
- `body_scoring.max_inspect_bytes`, `body_scoring.max_body_bytes`, and `body_scoring.min_suspicious_token_length` must be non-zero
- `body_scoring.suspicious_patterns` and `body_scoring.allowlisted_content_types` must not contain empty entries

Current runtime model behavior for this slice:

- runtime supports deterministic anomaly-score normalization from weighted classifier signals
- normalized score maps to action suggestion: `allow`, `challenge`, or `block`
- this slice defines typed model and normalization only; header scoring and enforcement wiring land in subsequent Feature 09 slices

Current header anomaly scoring behavior:

- `header_scoring.max_header_count` raises header-anomaly signals when request header count exceeds the threshold
- `header_scoring.max_header_value_length` raises header-anomaly signals when any header value is oversized
- `header_scoring.max_duplicate_headers_per_name` raises header-anomaly signals for repeated normalized header names
- `header_scoring.suspicious_headers` raises high-confidence header-anomaly signals when matched
- `header_scoring.suspicious_user_agent_patterns` raises user-agent-anomaly signals on case-insensitive pattern match
- header and user-agent anomaly signals are normalized into the same weighted anomaly-score pipeline used by request classification

Current reputation and bot-signal adapter behavior:

- runtime exposes pluggable provider contracts for reputation and bot-signal ingestion
- each adapter chain can ingest multiple providers and emit normalized `reputation` or `bot_signal` classifier signals
- provider errors can optionally emit bounded fallback signals, allowing operators to keep deterministic scoring when upstream feeds are degraded
- adapter-originated signals are folded into the same weighted anomaly-score pipeline and threshold mapping (`allow`, `challenge`, `block`)

Current enforcement and audit behavior:

- runtime maps classifier outputs and auth context into enforcement actions: `allow`, `tag`, `challenge`, `throttle`, `block`
- `challenge` recommendations downgrade to `throttle` when external auth fail-open is active to reduce false-negative abuse acceptance during auth-service degradation
- trusted-principal exceptions can bypass challenge-path false positives while still preserving audit visibility
- auth context can request explicit block disposition via `x-way-balancer-abuse-disposition: block`
- auth context risk-tier hints (`x-way-balancer-risk-tier: elevated|high`) can force `tag` on otherwise-allow requests for downstream monitoring
- each enforcement decision emits an audit record with classifier action, final action, signal scores, principal, fail-open state, and explainable reasons

Current bounded body inspection behavior:

- runtime body scoring inspects at most `body_scoring.max_inspect_bytes` bytes and never scans the full payload when larger bodies are present
- payloads larger than `body_scoring.max_body_bytes` emit high-confidence `body_anomaly` signals
- configured suspicious body patterns are matched case-insensitively against the bounded inspected window
- text-like content-types can emit `body_anomaly` when payload bytes look binary or heavily obfuscated
- content-type allowlist prefixes in `body_scoring.allowlisted_content_types` skip pattern and obfuscation checks to reduce false positives on known binary protocols

Current adaptive mitigation behavior with overload controls:

- classification and enforcement can be coordinated with overload shedding state through runtime adaptive mitigation
- under active overload shedding, enforcement `tag` can be escalated to `challenge`
- under brownout shedding, enforcement `challenge` can be escalated to `throttle`
- trusted-principal false-positive exceptions are preserved and are not escalated by overload adaptation

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
- `spec.methods` (when non-empty) must contain only valid HTTP methods and acts as an allow-list for mirrored requests
- the mirror target must differ from the primary destination `upstream_cluster`
- listener-level, route-level, and direct upstream-cluster bindings are rejected; mirroring is destination-local only

Example:

```json
{
	"name": "shadow-payments",
	"spec": {
		"percentage": 20,
		"target_upstream_cluster": "payments-shadow",
		"methods": ["GET", "HEAD"]
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
- when `spec.methods` is set, only matching request methods are mirrored
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

## Upstream Transport Selection

Upstream clusters can now explicitly declare an application transport via `upstream_clusters[].transport`.

Supported values:

- `http1`
- `http2`
- `http3`

Current behavior:

- the field defaults to `http1` when omitted
- this slice introduces explicit modeling and runtime selection wiring
- full HTTP/3 upstream dispatch semantics are delivered in the next HTTP/3 slices

## Service Discovery Sources

Upstream clusters can now declare a dynamic discovery source through `upstream_clusters[].discovery`.

Important constraints:

- choose one endpoint mode per cluster: static `endpoints` or dynamic `discovery`
- do not set both `endpoints` and `discovery` in the same cluster
- each discovery provider requires non-empty identity fields

Supported discovery source types:

- `dns_aaaa`: resolve one hostname to A/AAAA addresses, then map to `hostname:port`
- `dns_srv`: resolve SRV records for service-driven host+port membership
- `kubernetes_endpoint_slice`: consume EndpointSlice updates for one Kubernetes Service
- `consul_like`: consume service-catalog style updates (watch or long-poll adapter)

Example discovery-backed upstream:

```json
{
	"name": "payments",
	"transport": "http1",
	"endpoints": [],
	"discovery": {
		"type": "kubernetes_endpoint_slice",
		"namespace": "edge",
		"service": "payments"
	},
	"traffic_policy": {
		"algorithm": "round_robin",
		"locality": "disabled",
		"no_healthy_fallback": "fail"
	}
}
```

## Security Posture

Artifact verification and secure-default posture live under `security`.

When `security.artifact_verification.mode = "enforced"`, published and applied snapshots must carry an Ed25519 attestation whose signer identity matches the configured trusted signer set.

The checked-in examples leave `trusted_signers` empty on purpose. Production environments should inject the trusted signer set that matches the signing key used by the control plane.

If you rely on route-level `source_cidrs`, also configure `security.trusted_client_ip` correctly when traffic arrives through trusted proxies. Otherwise, source matching uses the direct socket peer address.

## Next Step

Open [Admin API](admin-api.md), [HTTP Cache](cache.md), or [Affinity](affinity.md) for focused feature guides, then use [Troubleshooting](troubleshooting.md) for operator diagnostics.