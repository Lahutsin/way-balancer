# Cache Invalidation Runbook

## Modes

Local-only mode:
- Create `HttpCacheAdminService` without an invalidation bus.
- Purge requests remove entries only from the local `HttpCacheStore`.
- This is the default mode and requires no extra wiring.

Distributed fan-out mode:
- Create a shared `HttpCacheInvalidationBus` for the cache scope.
- Build each node's `HttpCacheAdminService` with `with_invalidation_bus(node_id, bus)`.
- Register any peer-only stores as `HttpCacheStoreInvalidationSubscriber` instances on the same bus.

HTTP peer fan-out mode:
- Build each node's `HttpCacheAdminService` with `with_http_peer_transport(node_id, peers)`.
- Configure one `HttpCachePeerConfig` per remote node using an `http://host:port` origin, a dedicated admin actor, and a shared secret exposed through `secret_env`.
- Peer delivery uses signed `POST /cache/invalidate` requests carrying the bounded `HttpCacheInvalidationEvent` envelope.
- The initiating node always applies the invalidation locally first and then attempts best-effort remote delivery.

## Operational Guarantees

- Invalidation events are replay-safe per node through bounded recent-event tracking on each `HttpCacheStore`.
- Duplicate exact-key or path-prefix events are ignored after the first successful local application.
- Fan-out is scope-bound, so only subscribers registered for the matching cache scope receive an event.
- HTTP peer delivery is best-effort in this phase: one unreachable or failing peer does not roll back the local purge or successful deliveries to other peers.

## Operator Checks

- Use the admin purge response to distinguish local-only invalidations from fan-out invalidations.
- `fanout_subscriber_count > 0` indicates the request was propagated through the distributed path.
- `fanout_transport` identifies the transport used for remote delivery, currently `in_memory_bus` or `http_peer`.
- `fanout_delivery_success_count` counts peers that accepted the event.
- `fanout_delivery_failure_count` counts peers that did not accept the event.
- `fanout_duplicate_count > 0` indicates at least one subscriber had already applied the same event ID.
- `degraded = true` means the local purge succeeded but one or more peers failed, so operator follow-up is required.
- `fanout_failed_targets` contains bounded `node_id:error` details for failed remote peers.

## Failure Notes

- If distributed invalidation is not configured, purge behavior remains local and deterministic.
- Path-prefix invalidations still require canonical prefixes that start with `/` and do not include query or fragment delimiters.
- The in-memory bus remains valid for same-process tests and embedded integrations, but it does not provide cross-process or cross-host delivery.
- HTTP peer fan-out requires every target node to expose the invalidation endpoint and share the same signing secret material expected by the peer config.
- A degraded fan-out result should be treated as a partial convergence event: verify peer reachability, replay the purge if needed, and audit the failed nodes before declaring the cluster converged.