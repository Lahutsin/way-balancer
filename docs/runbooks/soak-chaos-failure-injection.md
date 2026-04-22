# Soak, Chaos, And Failure Injection

## Purpose

This runbook defines the repeatable in-repo soak and failure-injection coverage used to catch runtime instability that only shows up under repeated upstream faults.

## Covered Matrix

The dedicated suite in `crates/runtime/tests/soak_chaos.rs` repeatedly injects these upstream behaviors:

- HTTP/1 partial response writes
- upstream resets before a complete response
- stalled upstream responses that must trip idle timeouts
- degraded upstream responses that stay visible as `503`

The targeted destination-local fault-injection coverage in `crates/runtime/tests/http1_proxy.rs` and `crates/runtime/tests/http2_proxy.rs` also exercises config-driven pre-dispatch chaos behavior:

- fixed request delay before primary upstream dispatch
- local abort with a configured `4xx` or `5xx` status
- no-contact guarantees for locally aborted requests

The suite cycles those behaviors over 24 iterations per protocol so the runtime sees repeated flap patterns instead of a single isolated fault.

## Resource Growth Checks

The soak suite performs bounded file-descriptor growth checks before and after the repeated fault loops.

- On platforms with `/dev/fd` or `/proc/self/fd`, descriptor growth must stay within a small fixed allowance after all proxy tasks have drained.
- HTTP/2 coverage also asserts `active_streams == 0` at the end of each proxied connection and keeps peak concurrency bounded.

This is an in-process leak guard, not a replacement for multi-hour environment-level memory profiling.

## How To Run

Use:

- `./scripts/check-soak-chaos.sh`

- `cargo test -p lb-runtime delays_http1_request_before_primary_upstream_dispatch --test http1_proxy -- --exact`
- `cargo test -p lb-runtime aborts_http1_request_locally_without_contacting_primary_upstream --test http1_proxy -- --exact`
- `cargo test -p lb-runtime delays_http2_request_before_primary_upstream_dispatch --test http2_proxy -- --exact`
- `cargo test -p lb-runtime aborts_http2_request_locally_without_contacting_primary_upstream --test http2_proxy -- --exact`

Or directly:

- `cargo test -p lb-runtime --test soak_chaos`

## Failure Visibility Contract

- HTTP/1 partial-write cases must still complete successfully.
- Reset cases must surface as proxy-visible failures rather than hanging indefinitely.
- Stall cases must terminate via timeout rather than leaking open work.
- Degraded responses must remain visible to callers as upstream `503` results.
- Config-driven delay injection must increase end-to-end latency without suppressing a successful upstream response.
- Config-driven abort injection must return the configured local status without contacting the selected upstream.

## Operational Notes

- This suite is the repository-level repeatable fault loop.
- It complements the narrower lifecycle, parser-hardening, and cache-soak regressions already present elsewhere in the runtime tests.
- Destination-local fault injection is intentionally explicit and bounded. Use it for controlled chaos on specific canary destinations, not as a substitute for environment-level network fault tools.
- Longer multi-process or kernel-pressure chaos runs still belong in environment-level validation outside this repository.