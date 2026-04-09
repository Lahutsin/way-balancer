# Cache Performance And Soak Runbook

## What Is Covered

- `crates/runtime/src/http_cache.rs` includes bounded churn tests for eviction pressure and concurrent insert-plus-lookup traffic.
- `crates/runtime/tests/http1_proxy.rs` includes a repeated revalidation soak scenario that exercises stale serving plus `304 Not Modified` metadata refresh.
- `crates/runtime/benches/http_cache.rs` provides repeatable Criterion measurements for the hottest cache-store lookup paths.

## Local Measurements

`cargo bench -p lb-runtime --bench http_cache -- --sample-size 10` produced the following timings on this workspace:

- `http_cache_lookup_hit`: 81 ns to 95 ns
- `http_cache_lookup_miss`: 14 ns to 15 ns
- `http_cache_lookup_stale_revalidation_candidate`: 88 ns to 150 ns

These numbers are for the in-process cache-store path only. They do not include socket I/O, HTTP parsing, upstream latency, or external invalidation transport.

## Expected Operating Ranges

- Cache occupancy must remain within `max_entries`, `max_bytes`, and `max_object_bytes` even under sustained churn.
- Revalidation soak coverage should preserve a single cached object across repeated stale-to-`304` refresh cycles without byte growth.
- Bench variance should stay modest; persistent large regressions on the hit or stale lookup path should be treated as a runtime regression even if functional tests still pass.

## Failure Modes

- Bench regressions on the miss path usually indicate extra work in cache key normalization or store miss accounting.
- Bench regressions on the stale lookup path usually indicate extra work in freshness classification or metadata copying before revalidation.
- Churn-test failures usually indicate eviction, expiration, or byte-accounting regressions that can cause cache growth beyond configured bounds.
- These checks do not replace cross-process soak testing. Distributed invalidation transport, upstream saturation, and kernel socket pressure still need environment-level validation outside the unit and integration suite.