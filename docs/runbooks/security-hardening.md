# Security Hardening

## Purpose

This runbook summarizes the current edge and control-plane hardening posture for the runtime.

## Edge Parser Hardening

- HTTP/1 request parsing rejects ambiguous `content-length` and `transfer-encoding` combinations.
- HTTP/1 request parsing rejects unsupported `Transfer-Encoding` chains such as `gzip, chunked`.
- HTTP/1 request parsing rejects missing or duplicated `host` headers.
- HTTP/2 malformed prefaces and invalid forwarding metadata are rejected and classified by focused regressions.

## Header Normalization Invariants

- Hop-by-hop request headers are stripped before forwarding.
- Ancillary framing headers such as `te` and `trailer` are stripped before forwarding.
- Only the canonical framing header required for the detected body kind is preserved, such as `transfer-encoding: chunked` for chunked HTTP/1 request bodies.
- User-supplied forwarding identity headers are replaced with runtime-derived values.

## Proxy Protocol Boundary

- Enable `listeners[].proxy_protocol` only on sockets that are actually fronted by a trusted L4 proxy or load balancer.
- Treat `proxy_protocol: v1` and `proxy_protocol: v2` as fail-closed listener modes: a direct client that does not send the expected preface is rejected before HTTP parsing.
- Proxy Protocol source identity and forwarded-header trust are separate controls. Proxy Protocol establishes the immediate downstream source address; `security.trusted_client_ip` still decides whether later `Forwarded` or `X-Forwarded-For` hops are trusted.
- The effective precedence is: direct socket peer, then Proxy Protocol source if enabled, then a trusted `Forwarded` chain, and finally trusted `X-Forwarded-For` only when `Forwarded` is absent.
- A spoofed forwarded chain is rejected even if the raw TCP peer is local, as long as the Proxy Protocol source itself is outside `trusted_proxy_cidrs`.
- Do not enable Proxy Protocol on admin listeners.

## Cache Poisoning Boundaries

- Cache lookup and storage fail closed on ambiguous host and authority shapes.
- Authorization-bearing and cookie-bearing requests bypass shared cache storage.
- Unsafe vary handling fails closed instead of broadening cache keys implicitly.
- Canonical request-target parsing rejects invalid percent-encoding and ambiguous query forms.

## Control-Plane Trust Boundaries

- Snapshot publication and application require artifact attestation verification when security posture is enforced.
- Disabling artifact verification requires explicit insecure-dev acknowledgement.
- Privileged control-plane channels require peer certificate validation and optional identity pinning.
- Admin-plane credentials support file-backed secret rotation through `<SECRET_ENV>_FILE` without exposing secret contents in status, logs, or audit payloads.
- HTTPS listener status now exposes certificate fingerprints, validity bounds, expiry-warning state, minimum TLS version, ALPN policy, and session resumption mode so operators can verify live TLS posture without shelling into the pod.

## Hostile-Edge Listener Protections

- Public and admin listeners can now attach named `policies.hostile_edge_protections` resources through `listeners[].policies.hostile_edge_protection`.
- `source_quota` applies fail-closed per-source admission fairness before a connection can consume steady-state listener capacity.
- On public listeners with Proxy Protocol enabled, `source_quota` now keys off the proxy-resolved downstream source rather than the raw socket peer, so abuse controls stay meaningful behind trusted L4 frontends.
- `handshake_guard` caps in-flight protected handshakes so slow or abusive connection setup cannot starve healthy clients.
- Protected listeners expose a first-class `abuse_protection` block in `GET /status` with configured limits, current tracked-source and handshake pressure, cumulative rejection counters, and stable reason codes.
- `GET /readyz` remains ready during normal enforcement, but reports not-ready when hostile-edge state is currently saturated enough to stop admitting new tracked sources or new protected handshakes.

## Stable Hostile-Edge Reason Codes

- `source_quota_exceeded`: a source bucket hit its configured active-connection ceiling.
- `tracked_source_limit_reached`: the listener exhausted bounded tracking state for distinct sources.
- `handshake_limit_reached`: the listener exhausted the configured in-flight handshake budget.
- `tracked_source_capacity_saturated`: status/readiness indicator showing the source-tracking pool is currently full.
- `handshake_guard_saturated`: status/readiness indicator showing the handshake guard is currently at capacity.

## Metrics And Status Surfaces

- `runtime_listener_abuse_rejections_total{listener,reason}` counts hostile-edge listener rejections by stable reason code.
- `runtime_listener_abuse_tracked_sources{listener}` reports the current number of tracked hostile-edge source buckets.
- `runtime_listener_abuse_active_handshakes{listener}` reports the current protected handshake concurrency.
- HTTP/1 and admin listeners return `503 Service Unavailable` with `X-LB-Abuse-Reason` when hostile-edge admission rejects the connection before proxying.

## Tuning Notes

- Keep `max_tracked_sources` comfortably above expected distinct healthy source cardinality so enforcement remains focused on abuse rather than normal fan-in.
- Set `max_active_per_source` low enough to preserve fairness, but high enough for legitimate client retry bursts and shared egress NATs.
- Reserve `handshake_guard.max_inflight` for listeners that terminate TLS or otherwise spend meaningful work in early connection setup.
- Prefer tightening source aggregation and quotas over raising global `max_connections` when healthy traffic is being crowded out by a small number of sources.

## Secure-Default Boundary Expansion Gate

Before broadening support boundaries for discovery, auth, extension, or HTTP/3 surfaces, release owners must confirm all of the following in release evidence:

- artifact attestation remains required in the default production posture and unsigned flows stay outside supported production scope
- `security.insecure_dev_mode` is absent from the candidate production posture and any temporary exception is time-bounded and explicitly acknowledged
- `artifacts/sbom/README.md` and `artifacts/provenance/README.md` references are updated to the candidate artifact locations
- extension API compatibility and fail-closed plugin behavior remain documented in `docs/runbooks/compatibility-matrix.md`
- HTTP/3 supported and unsupported topology statements remain explicit in `docs/runbooks/support-boundaries.md`

If any item above cannot be demonstrated, treat the candidate as not ready for support-boundary expansion and keep the affected surface outside the supported contract.

## Focused Validation

Security-sensitive regression coverage currently includes:

- `cargo test -p lb-proto-http`
- `cargo test -p lb-runtime --test http1_proxy`
- `cargo test -p lb-runtime --test http2_proxy`
- `cargo test -p lb-runtime --test source_guards`
- `cargo test -p lb-runtime --test telemetry`
- `cargo test -p lb-runtime --test tracing`
- `cargo test -p lb-dataplane workspace_serve -- --nocapture`

These suites cover malformed parser shapes, forwarding-header trust, cache fail-closed behavior, and control-plane trust primitives.