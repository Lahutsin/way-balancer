# Support Boundaries

## Purpose

This runbook defines what `way-balancer` supports in the `0.1.x` line, what remains explicitly unsupported or deferred, and which operational conditions require operator intervention rather than hidden automation.

Use this document together with the compatibility matrix, stability contract, and final GA review record before presenting a candidate as a supported release.

## Supported Deployment Topologies

### Single-Node Dataplane With Local Admin Plane

- Supported as the default `0.1.x` deployment shape.
- Assumes one dataplane instance exposes the documented admin endpoints and applies attested snapshots from the same supported release line.
- Suitable for local, edge, and small-footprint environments where horizontal convergence is not required.

### Active-Active Dataplane Fleet With Shared Control Plane

- Supported when rollout and rollback are coordinated through `lb_admin_api::FleetRolloutCoordinator`.
- Convergence semantics are `bounded_eventual`, not instantaneous and not consensus-backed.
- Success requires every targeted node to converge on the same desired version and digest within the configured divergence budget.

### Multi-Node Cache Peer Fan-Out

- Supported when `HttpCachePeerTransport` is used with explicit retry policy and degraded peer delivery remains operator-visible.
- Local purge correctness is part of the supported contract.
- Cross-node convergence is supported only as replay-safe best-effort fan-out with bounded diagnostics, not hidden global transaction semantics.

### Kubernetes Gateway Translation And Controller Packaging

- Supported for Gateway API translation and the checked-in lease-based HA controller packaging.
- The checked-in controller chart and raw deployment example assume at least two replicas with Kubernetes `Lease`-based leader election fencing write-bearing reconcile work to one active controller.
- Treat the controller packaging as an HA operator contract only within the documented lease-based topology and rollback procedures.

## Unsupported Or Deferred Topologies

- Mixed release-line runtime, admin API, or Kubernetes integration fleets in production evidence.
- Controller deployments that disable leader election while scaling above one replica.
- Hidden distributed consensus or two-phase commit embedded in dataplane runtime behavior.
- Automatic partition healing that claims fleet or cache convergence without per-node evidence.
- Internet-wide capacity claims or generic non-loopback performance claims without a supported performance artifact.
- Production candidates that rely on `security.insecure_dev_mode` or unsigned artifact flows.

## Protocol And Feature Boundaries

- Supported config API surface for `0.1.x`: `v1_alpha1` as exposed by `lb_runtime::RuntimeMetadata`.
- Supported proxy foundations: TCP, HTTP/1.1, HTTP/2, downstream HTTP/3 over QUIC, upstream HTTP/3 request dispatch, gRPC-shaped HTTP/2 traffic, HTTPS termination with configured PEM material, and documented admin HTTP control endpoints.
- Supported configuration features include typed routing, cache policy, affinity, overload handling, hostile-edge guards, and attested snapshot rollout or rollback.
- Supported listener deployment shapes include IPv4 single-stack, IPv6-only, and dual-stack public listeners when they follow the documented `bind_mode` constraints.
- Loopback performance artifacts remain supported only as regression tools.
- Absolute performance or capacity claims are supported only when backed by a named supported profile artifact such as `lab_small_non_loopback_v1`.

The current HTTP/3 support boundary for `0.1.x` is:

- supported: public HTTP/3 listeners that terminate QUIC plus TLS 1.3
- supported: downstream HTTP/1 and HTTP/3 paths can target upstream clusters configured with `transport: http3`
- supported: graceful upstream drain handling for HTTP/3 (`H3_NO_ERROR`/no-error close patterns) with local `503 upstream draining` behavior
- not yet supported: admin HTTP/3 listeners, proxy protocol on QUIC listeners, or transparent upstream QUIC passthrough/tunnel mode

## Failure-Mode Support Boundaries

- Reloads are supported as rollback-safe operations, but `reload_applied_overlap_drain_timeout` is a degraded success that still requires operator follow-up.
- Fleet state `degraded` or `diverged` is not silently self-healing. Operators must retry failed nodes, restore reachability, or roll back the fleet.
- Cache peer delivery marked degraded is not treated as converged until operators replay or remediate failed peers.
- Crash-recovery journal checksum failures remain fail-closed and require repair or removal with operator review.
- Security exceptions, accepted advisories, and unsupported overrides must be recorded explicitly in release evidence rather than normalized into the supported contract.

## Release Use Rule

A candidate should be presented as supported only when:

- the deployment shape fits one of the supported topologies above
- the compatibility matrix, stability contract, and GA review record are complete
- the secure-default boundary expansion gate in `docs/runbooks/security-hardening.md` is satisfied for any newly broadened surface
- all required evidence in the release checklist is attached
- any capacity claim stays inside the documented supported performance profile assumptions

## Related Runbooks

- [Compatibility Matrix](compatibility-matrix.md)
- [Stability Contract](stability-contract.md)
- [Multi-Node Topology](multi-node-topology.md)
- [Performance Envelope](performance-envelope.md)
- [GA Readiness Review Template](ga-readiness-review-template.md)