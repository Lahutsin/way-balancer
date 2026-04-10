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

## Cache Poisoning Boundaries

- Cache lookup and storage fail closed on ambiguous host and authority shapes.
- Authorization-bearing and cookie-bearing requests bypass shared cache storage.
- Unsafe vary handling fails closed instead of broadening cache keys implicitly.
- Canonical request-target parsing rejects invalid percent-encoding and ambiguous query forms.

## Control-Plane Trust Boundaries

- Snapshot publication and application require artifact attestation verification when security posture is enforced.
- Disabling artifact verification requires explicit insecure-dev acknowledgement.
- Privileged control-plane channels require peer certificate validation and optional identity pinning.

## Focused Validation

Security-sensitive regression coverage currently includes:

- `cargo test -p lb-proto-http`
- `cargo test -p lb-runtime --test http1_proxy`
- `cargo test -p lb-runtime --test http2_proxy`
- `cargo test -p lb-runtime --test telemetry`
- `cargo test -p lb-runtime --test tracing`

These suites cover malformed parser shapes, forwarding-header trust, cache fail-closed behavior, and control-plane trust primitives.