# Multi-Node Cache Peer Fan-Out

This example models two cache-bearing edge nodes that expose signed admin endpoints suitable for the first-generation HTTP peer invalidation transport.

Files:

- `cache-peer-node-a.json`
- `cache-peer-node-b.json`

Topology:

- Node A public listener: `127.0.0.1:8080`
- Node A admin listener: `127.0.0.1:9900`
- Node B public listener: `127.0.0.1:8081`
- Node B admin listener: `127.0.0.1:9901`
- Shared signing secret env: `LB_CACHE_PEER_SECRET`
- Shared signed admin actor: `cache-peer`

What the checked-in configs cover:

- listener-scoped response cache with `purge_enabled = true`
- signed admin listeners with `read`, `audit`, and `write` permissions
- concrete public/admin bind layout for two nodes

What stays outside the workspace JSON today:

- the peer list itself
- `HttpCachePeerTransport` wiring between nodes
- fleet-level orchestration policy around best-effort fan-out

That split is intentional. The current repository supports peer fan-out in the admin service layer and dataplane admin endpoints, but the workspace config schema does not yet embed a transport topology resource.

Minimal operator flow:

1. Export a shared secret on both nodes:

```sh
export LB_CACHE_PEER_SECRET=<shared-secret>
```

2. Run node A and node B with their respective configs.

3. Build peer fan-out in the control-plane or admin-service layer using origins `http://127.0.0.1:9900` and `http://127.0.0.1:9901`, actor `cache-peer`, and secret env `LB_CACHE_PEER_SECRET`.

4. Apply a bounded retry policy when constructing `HttpCachePeerTransport` so transient peer misses do not immediately become operator-visible degraded events.

5. Trigger a local purge on one node through `POST /cache/purge`; that node can then fan the bounded invalidation event out to the peer node through signed `POST /cache/invalidate`.

Operational semantics:

- local purge correctness comes first
- remote peer delivery is best-effort
- remote peer delivery may retry before declaring failure
- duplicate invalidation events are replay-safe and do not double-purge
- degraded peer delivery must be surfaced and followed up operationally

For a larger fleet and full snapshot rollout semantics, see `multi-node-rollout-example.md`.