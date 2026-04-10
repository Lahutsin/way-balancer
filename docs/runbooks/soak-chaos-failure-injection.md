# Soak, Chaos, And Failure Injection

## Purpose

This runbook defines the repeatable in-repo soak and failure-injection coverage used to catch runtime instability that only shows up under repeated upstream faults.

## Covered Matrix

The dedicated suite in `crates/runtime/tests/soak_chaos.rs` repeatedly injects these upstream behaviors:

- HTTP/1 partial response writes
- upstream resets before a complete response
- stalled upstream responses that must trip idle timeouts
- degraded upstream responses that stay visible as `503`

The suite cycles those behaviors over 24 iterations per protocol so the runtime sees repeated flap patterns instead of a single isolated fault.

## Resource Growth Checks

The soak suite performs bounded file-descriptor growth checks before and after the repeated fault loops.

- On platforms with `/dev/fd` or `/proc/self/fd`, descriptor growth must stay within a small fixed allowance after all proxy tasks have drained.
- HTTP/2 coverage also asserts `active_streams == 0` at the end of each proxied connection and keeps peak concurrency bounded.

This is an in-process leak guard, not a replacement for multi-hour environment-level memory profiling.

## How To Run

Use:

- `./scripts/check-soak-chaos.sh`

Or directly:

- `cargo test -p lb-runtime --test soak_chaos`

## Failure Visibility Contract

- HTTP/1 partial-write cases must still complete successfully.
- Reset cases must surface as proxy-visible failures rather than hanging indefinitely.
- Stall cases must terminate via timeout rather than leaking open work.
- Degraded responses must remain visible to callers as upstream `503` results.

## Operational Notes

- This suite is the repository-level repeatable fault loop.
- It complements the narrower lifecycle, parser-hardening, and cache-soak regressions already present elsewhere in the runtime tests.
- Longer multi-process or kernel-pressure chaos runs still belong in environment-level validation outside this repository.