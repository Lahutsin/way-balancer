# HTTP Cache

## Scope

way-balancer ships a bounded in-memory shared HTTP response cache with explicit operational controls:

- named cache policies under `policies.http_caches`
- route-level or listener-level attachment through `cache_policy`
- validator-based revalidation
- stale-while-revalidate and stale-if-error windows
- local purge and optional distributed invalidation

## How The Cache Decides

At a high level, each request flows through these questions:

1. Is the method cacheable for this policy?
2. Does the request carry `Authorization` or `Cookie` and therefore need a safe bypass?
3. Does the cache key match an existing entry?
4. Is that entry fresh, stale-but-revalidatable, stale-if-error eligible, or expired?
5. If there is no usable entry, can the response be safely stored under the configured bounds?

The runtime is intentionally fail-closed for unsafe shared-cache cases. Cookie-bearing traffic bypasses the shared cache even when a looser policy might appear to allow it.

When transform policies are also attached, cache ordering works like this:

- request transforms run before cache-key construction, so rewritten request path, host, and headers are what the cache evaluates
- HTTP/1 cache storage keeps the normalized origin response headers, not the transformed downstream copy
- response transforms are applied on the downstream write path for both origin fills and cache hits, which keeps route-level and listener-level response header policy stable even when multiple policies share one cache store

## Example Policy

The checked-in `http-cache-public.json` example uses this posture:

```json
{
  "name": "public-cache",
  "spec": {
    "methods": ["get", "head"],
    "default_ttl_secs": 60,
    "max_ttl_secs": 300,
    "stale_while_revalidate_secs": 30,
    "stale_if_error_secs": 120,
    "max_object_bytes": 262144,
    "allow_set_cookie_storage": false,
    "authorization": "bypass",
    "revalidation_enabled": true,
    "purge_enabled": true,
    "storage": {
      "type": "memory",
      "max_entries": 2048,
      "max_bytes": 16777216
    }
  }
}
```

This is a conservative shared-cache baseline suitable for public content and metadata-style APIs.

## Core Behavior

### Eligibility

The safest default policy is still the recommended one:

- cache only `GET` and `HEAD`
- bypass `Authorization`
- do not store `Set-Cookie`
- treat request cookies as cache-bypass traffic
- keep key material based on stable, low-cardinality request attributes

### Freshness

The runtime distinguishes:

- fresh entries
- stale-but-revalidatable entries
- stale-if-error entries
- fully expired entries

Revalidation uses validators such as `ETag` or `Last-Modified` when present.

### Storage Bounds

The cache is bounded on three axes:

- `max_entries`
- `max_bytes`
- `max_object_bytes`

Those are not optional safety rails. They are the core mechanism that prevents the cache from growing into an uncontrolled memory sink.

## Purge And Invalidation

There are two different operator actions:

### Local Or Operator-Initiated Purge

Use `POST /cache/purge` when you want to remove an exact cache key or a path family from the current node and optionally fan that action out.

Typical use cases:

- stale catalog listing under `/catalog`
- invalidated assets under `/assets`
- a known incorrect single object using an exact key

### Distributed Invalidation Event Application

Use `POST /cache/invalidate` when an upstream node or service is already producing replay-safe invalidation events and you need the current node to apply them.

This is more of a systems-integration surface than a human-first cache operation.

## Operational Signals

When cache behavior looks wrong, check these categories first:

- request outcomes such as hit, miss, stale-hit, fill, bypass, purge, and revalidation
- occupancy and object-size signals
- invalidation fan-out counts and failed target details
- support-bundle cache diagnostics when enabled

The runtime intentionally avoids per-key telemetry to keep cardinality bounded and request material out of metrics.

## Failure Modes

### Cache Hits Are Lower Than Expected

Likely causes:

- requests carry `Authorization` or `Cookie`
- the origin does not emit stable validators, so revalidation value is low
- `vary_headers` or key headers are too high-cardinality
- the TTL windows are too short for the working set

### Memory Pressure Or Evictions Are High

Likely causes:

- `max_entries` is too low for the working set
- `max_bytes` is too low for object volume
- `max_object_bytes` is large enough that a few big objects churn the store

### Invalidation Did Not Converge Cluster-Wide

Look for:

- `degraded = true` in the purge response
- non-zero `fanout_delivery_failure_count`
- populated `fanout_failed_targets`

That means the initiating node purged locally but remote convergence is incomplete.

In the current multi-node model, peer invalidation remains best-effort on final outcome, but delivery attempts are no longer fire-and-forget. `HttpCachePeerTransport` applies a bounded retry policy and records a per-peer fan-out report so operators can distinguish a temporary retryable miss from a sustained partition or dead peer.

## Safe Rollout Pattern

1. Start with one named cache policy for one traffic class.
2. Keep `authorization = bypass` and `allow_set_cookie_storage = false`.
3. Enable purge only where there is a clear operator workflow.
4. Watch occupancy, eviction, and invalidation signals before broadening scope.

## Related Pages

- [Admin API](admin-api.md) for the live cache-control endpoints
- [Troubleshooting](troubleshooting.md) for cache miss and invalidation failure workflows
- [Cache Operations](runbooks/cache-operations.md) and [Cache Invalidation](runbooks/cache-invalidation.md) for deeper operator runbooks
- [Multi-Node Topology](runbooks/multi-node-topology.md) for the supported active-active contract