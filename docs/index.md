# way-balancer

way-balancer is a production-oriented Rust load balancer with a pre-GA but already operational scope: typed config validation, runtime reload mechanics, admin-plane controls, HTTP caching, Kubernetes translation foundations, and security-focused runbooks.

!!! warning "Pre-GA status"

    The repository already supports real build, test, and operational workflows, but it should still be treated as pre-GA software with explicit release and operational review before broad production rollout.

## What This Site Covers

- how to build, verify, and run the project locally
- how the dataplane and control-plane pieces fit together
- how configuration, examples, cache policy, and affinity are modeled
- where to find runbooks for security, TLS, cache, DR, upgrade, and release evidence

## Start Here

<div class="grid cards" markdown>

- `Getting Started`

  Build the workspace, run the local quality gates, start the demo stack, and exercise the public and admin endpoints.

- `Architecture`

  Understand the control plane, dataplane, runtime boundaries, and the role of each crate and binary.

- `Configuration`

  Learn the core `WorkspaceConfig` shape, example topologies, admin auth, caching, and sticky-session affinity.

- `Runbooks`

  Jump straight to hardening, cache operations, compatibility, DR, TLS, observability, and release guidance.

</div>

## Current Scope

The current repository includes:

- listener lifecycle and connection admission runtime
- TCP, HTTP/1.1, HTTP/2, and gRPC proxy foundations
- production-oriented shared HTTP caching with purge and revalidation hooks
- typed config compilation, digesting, validation, and diffing
- snapshot publication, rollout, rollback, authn/authz, and abuse-control foundations
- Kubernetes Gateway API translation and reconciliation foundations
- artifact integrity, TLS validation, and secure-default posture

## Fast Navigation

- For a local bring-up path, open [Getting Started](getting-started.md).
- For config structure and example files, open [Configuration](configuration.md).
- For operator workflows, open the `Runbooks` section in the left navigation.