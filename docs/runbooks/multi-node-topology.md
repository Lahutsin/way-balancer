# Multi-Node Topology Runbook

## Scope

This runbook defines the supported active-active multi-node operating model for the current workspace.

The supported model is intentionally explicit:

- snapshot publication remains a control-plane concern
- each dataplane node still applies snapshots independently
- fleet convergence is observed and coordinated through `lb_admin_api::FleetRolloutCoordinator`
- convergence is `bounded_eventual`, not hidden distributed consensus

## Supported Topologies

### Active-Active Dataplane With Shared Control Plane

- multiple `lb-dataplane` instances serve the same logical service
- one control-plane workflow publishes a snapshot version and digest once
- rollout then targets each node through fleet coordination using `immediate`, `sequential`, or `canary` strategy
- success means every node reports the same desired and active snapshot identity within the configured divergence budget

This is the primary supported topology for `F24`.

### Active-Active Cache Peer Fan-Out

- multiple nodes carry the same cache scope
- a local purge applies first on the initiating node
- peer invalidation fans out through `HttpCachePeerTransport`
- remote delivery is retried with a bounded policy and surfaced as degraded if any peer still fails

This topology is supported when operators accept best-effort peer transport plus strong visibility.

## Unsupported Or Out-Of-Scope Topologies

- hidden two-phase commit across every dataplane node
- distributed consensus embedded inside the dataplane runtime
- automatic partition healing that claims fleet convergence without per-node status evidence
- service-mesh style global transaction semantics for every cache or config mutation

## Consistency Contract

Current fleet rollout semantics are:

- `bounded_eventual` consistency for config rollout and rollback
- per-node readiness and applied snapshot status remain authoritative at the node level
- fleet state is derived from node-reported desired and active snapshot identity
- a rollout is `converged` only when every targeted node matches the desired version and digest
- a rollout is `progressing` when nodes are still within the configured divergence budget
- a rollout is `degraded` when at least one node rejects the operation or becomes unreachable
- a rollout is `diverged` when the fleet exceeds the configured divergence budget without full convergence

## Rollout Strategies

`FleetRolloutCoordinator` currently supports:

- `immediate`: attempt every node in the fleet during the same coordination pass
- `sequential`: stop further node rollout after the first node-level failure
- `canary`: roll out the configured canary subset first; if canary fails, the remaining nodes stay untouched

## Operator Checks

Before declaring a fleet converged, confirm:

- the fleet convergence report says `state = converged`
- every node reports the same `desired_version` and `active_version`
- every node reports the same active digest as the published snapshot digest
- no node is marked `unavailable`
- any degraded cache peer fan-out has been replayed or manually remediated

## Partition And Partial-Failure Handling

If a node becomes unreachable during rollout:

- treat the fleet as `degraded`
- do not claim full convergence from the successful subset alone
- use the reported `recommended_action` to decide whether to retry failed nodes or roll back the fleet

If cache peer fan-out loses one or more peers:

- local purge result remains valid for the initiating node
- cluster-wide cache convergence is incomplete until failed peers accept a replayed invalidation event
- duplicate replay is safe because invalidation events remain replay-safe per node

## Recovery Guidance

- prefer rolling back the whole fleet to a shared known-good version instead of leaving a mixed-version steady state
- if no shared known-good candidate exists, use an explicit fleet rollback target
- if a rollout is `degraded` because of unreachable nodes, restore node reachability first and then re-run the same target rollout or a clean rollback

## Related Runbooks

- [Upgrade And Rollback Policy](upgrade-rollback-policy.md)
- [Cache Operations](cache-operations.md)
- [Cache Invalidation](cache-invalidation.md)
- [Troubleshooting](../troubleshooting.md)