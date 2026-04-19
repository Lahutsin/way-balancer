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
- Use `with_http_peer_transport_and_retry_policy(...)` when the control plane needs explicit retry tuning.
- Configure one `HttpCachePeerConfig` per remote node using an `https://host:port` origin, a dedicated admin actor, a shared secret exposed through `secret_env`, and a trust anchor exposed through `tls_ca_cert_env`.
- Plaintext `http://` origins are accepted only for loopback peers in local development.
- Peer delivery uses signed `POST /cache/invalidate` requests carrying the bounded `HttpCacheInvalidationEvent` envelope, and the signature includes a SHA-256 digest of the serialized request body.
- The initiating node always applies the invalidation locally first and then attempts best-effort remote delivery.

## Operational Guarantees

- Invalidation events are replay-safe per node through bounded recent-event tracking on each `HttpCacheStore`.
- Duplicate exact-key or path-prefix events are ignored after the first successful local application.
- Fan-out is scope-bound, so only subscribers registered for the matching cache scope receive an event.
- HTTP peer delivery is best-effort in this phase: one unreachable or failing peer does not roll back the local purge or successful deliveries to other peers.
- HTTP peer delivery now includes bounded retries plus a machine-readable fan-out report with per-peer attempts and failure detail.

## Operator Checks

- Use the admin purge response to distinguish local-only invalidations from fan-out invalidations.
- `fanout_subscriber_count > 0` indicates the request was propagated through the distributed path.
- `fanout_transport` identifies the transport used for remote delivery, currently `in_memory_bus` or `http_peer`.
- `fanout_delivery_success_count` counts peers that accepted the event.
- `fanout_delivery_failure_count` counts peers that did not accept the event.
- `fanout_duplicate_count > 0` indicates at least one subscriber had already applied the same event ID.
- `degraded = true` means the local purge succeeded but one or more peers failed, so operator follow-up is required.
- `fanout_failed_targets` contains bounded `node_id:error` details for failed remote peers.

If you keep a handle to `HttpCachePeerTransport`, the last fan-out report also tells you:

- whether a peer needed more than one attempt
- which peers returned `duplicate` instead of `applied`
- whether the control plane should treat the result as a partition signal rather than a single transient miss

## Failure Notes

- If distributed invalidation is not configured, purge behavior remains local and deterministic.
- Path-prefix invalidations still require canonical prefixes that start with `/` and do not include query or fragment delimiters.
- The in-memory bus remains valid for same-process tests and embedded integrations, but it does not provide cross-process or cross-host delivery.
- HTTP peer fan-out requires every target node to expose the invalidation endpoint and share the same signing secret material expected by the peer config.
- A degraded fan-out result should be treated as a partial convergence event: verify peer reachability, replay the purge if needed, and audit the failed nodes before declaring the cluster converged.
- The current supported guarantee under partition is still explicit partial convergence, not automatic cluster repair.