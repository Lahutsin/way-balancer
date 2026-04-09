# Cache Operations Runbook

## Scope

This runbook covers the production HTTP response-cache surface shipped in this workspace:

- typed cache policy configuration through `policies.http_caches`
- route-level or listener-level policy attachment through `cache_policy`
- bounded in-memory storage
- purge workflows, validator-based revalidation, stale serving, and capacity troubleshooting

Supporting runbooks:

- `docs/runbooks/cache-invalidation.md`
- `docs/runbooks/cache-performance.md`

## Configuration Model

Configure a named cache policy under `policies.http_caches` and attach it by name through `routes[].policies.cache_policy` or the equivalent listener binding.

Important fields:

- `methods`: cacheable request methods. Shared-cache safe default is `get` and `head` only.
- `default_ttl_secs` and `max_ttl_secs`: base freshness window and cap.
- `stale_while_revalidate_secs`: stale-serving window while validators refresh metadata.
- `stale_if_error_secs`: stale-serving window allowed after upstream failures.
- `max_object_bytes`: per-object bound for storage.
- `revalidation_enabled`: enables `If-None-Match` and `If-Modified-Since` refresh logic when validators are available.
- `purge_enabled`: explicit feature switch for admin-driven purge.
- `storage`: bounded in-memory store with `max_entries` and `max_bytes`.

## Safe Shared-Cache Defaults

- Keep `authorization` set to `bypass` unless you have a clear partitioning strategy and a correctness proof for authenticated traffic.
- Do not enable `allow_set_cookie_storage` for shared caches.
- Restrict `vary_headers` and `cache_key.headers` to stable, low-cardinality request headers.
- Keep `include_host` enabled unless you are certain hostnames are interchangeable.
- Size `max_object_bytes` low enough that a few large responses cannot evict the whole store.

The runtime is fail-closed for request `Cookie` and unsafe origin `Vary` handling. Cookie-bearing traffic bypasses the shared cache even when the configured policy would otherwise be eligible.

## Purge And Authorization

- Purge remains explicitly gated by `purge_enabled` on the cache policy.
- Admin callers still need the dedicated `PurgeHttpCache` permission.
- Exact-key purge is the narrowest and safest operational action.
- Path-prefix purge is useful for content families such as `/assets` or `/catalog`, but should be used sparingly because it can invalidate many objects at once.
- Current admin API validation also bounds purge metadata: `scope <= 128`, `requested_by <= 128`, `reason <= 256`, and `path_prefix <= 512` bytes.

If you need multi-node convergence, use the distributed invalidation flow described in `docs/runbooks/cache-invalidation.md`. Without that opt-in wiring, purge remains local to the current process.

## Observability And Diagnostics

The cache emits bounded metrics and events only. Operators should rely on:

- request outcomes such as hit, miss, stale-hit, fill, bypass, purge, and revalidation
- occupancy counters and object-size gauges
- support-bundle `cache.txt` diagnostics when cache diagnostics collection is enabled

Do not expect per-key metrics or raw cache-key dumps. That limitation is intentional to prevent high-cardinality telemetry and accidental exposure of sensitive request material.

## Capacity Pressure And Failure Modes

- Rising eviction counts under normal traffic usually indicate `max_entries`, `max_bytes`, or `max_object_bytes` is too small for the working set.
- Frequent bypass on authenticated or cookie-bearing traffic is expected in the default shared-cache posture.
- Revalidation helps only when origins emit stable validators such as `ETag` or `Last-Modified`.
- Fully expired entries are removed on lookup, so stale windows must be sized deliberately if you want revalidation and stale fallback to remain available.

## Rollout Guidance

- Roll out cache policy changes conservatively and prefer one named policy per traffic class rather than one global catch-all cache.
- Enable purge only where the operating team actually has a purge workflow.
- Change storage bounds and TTL policy before enabling broader traffic classes, not after observing memory pressure in production.
- Re-run `cargo test -p lb-test-support --test example_configs` after editing checked-in cache examples.
- Examples that keep `security.artifact_verification.mode = enforced` still require trusted signer injection during the real publish/apply flow; they are not production-complete until the control plane supplies `trusted_signers`.