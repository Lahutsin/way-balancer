# Multi-Node Rollout Example

This example shows the intended control-plane flow for an active-active fleet.

## Assumptions

- one published snapshot version exists in `SnapshotControlService`
- each node exposes a privileged admin endpoint
- the control plane uses `FleetRolloutCoordinator` with a node backend that can query node status and issue rollout or rollback requests

## Example Flow

1. Publish snapshot `stable-2026-04-19` with its verified digest.
2. Build a fleet rollout request with node order:

   - `edge-a`
   - `edge-b`
   - `edge-c`

3. Start with canary rollout:

```rust
let request = lb_admin_api::FleetRolloutRequest {
    version: String::from("stable-2026-04-19"),
    requested_by: Some(String::from("release-bot")),
    reason: Some(String::from("regional edge rollout")),
    node_ids: vec![
        String::from("edge-a"),
        String::from("edge-b"),
        String::from("edge-c"),
    ],
    strategy: lb_admin_api::FleetRolloutStrategy::Canary { canary_nodes: 1 },
    max_allowed_divergence_ms: 30_000,
};
```

4. Inspect the returned convergence report.
5. Continue only if the canary node converged and no degraded state was reported.

## What To Treat As Healthy

- `convergence.state = converged`
- `convergence.partial_rollout = false`
- every node result is `applied` or `unchanged`
- shared last-known-good version remains visible for rollback

## What To Treat As Degraded

- any node action result is `failed`
- any node convergence state is `unavailable`
- the fleet exceeds the configured divergence budget

## Recovery Rule

If the fleet is mixed and the rollout is no longer actively progressing, prefer a full fleet rollback to the shared known-good version before attempting another forward rollout.