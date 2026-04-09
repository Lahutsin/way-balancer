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

## Operational Guarantees

- Invalidation events are replay-safe per node through bounded recent-event tracking on each `HttpCacheStore`.
- Duplicate exact-key or path-prefix events are ignored after the first successful local application.
- Fan-out is scope-bound, so only subscribers registered for the matching cache scope receive an event.

## Operator Checks

- Use the admin purge response to distinguish local-only invalidations from fan-out invalidations.
- `fanout_subscriber_count > 0` indicates the request was propagated through the distributed path.
- `fanout_duplicate_count > 0` indicates at least one subscriber had already applied the same event ID.

## Failure Notes

- If distributed invalidation is not configured, purge behavior remains local and deterministic.
- Path-prefix invalidations still require canonical prefixes that start with `/` and do not include query or fragment delimiters.
- The bus is an in-memory integration seam for this phase; operators still need an external transport if they want cross-process or cross-host delivery.