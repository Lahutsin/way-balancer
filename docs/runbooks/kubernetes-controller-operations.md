# Kubernetes Controller Operations

## Scope

This runbook covers packaging and operating the checked-in `lb-k8s-controller` deployment example and the Helm chart at `charts/lb-k8s-controller`.

## Current Deployment Model

- deploy at least two controller replicas for warm failover
- Kubernetes `Lease` objects in `coordination.k8s.io` fence write-bearing reconcile work so only one replica is active at a time
- RBAC must cover cluster-scoped `GatewayClass` plus namespaced `Gateway`, `HTTPRoute`, `Service`, `EndpointSlice`, and `Lease` access
- `LB_K8S_CONTROLLER_NAMESPACE` narrows reconciles to one namespace when set, but the example watch RBAC remains cluster-scoped because `GatewayClass` is cluster-scoped
- `LB_K8S_CONTROLLER_LEASE_NAMESPACE` should point at the operator namespace, not the Gateway workload namespace

## Build And Image Publication

Build the controller image from the repository root:

```sh
docker build --build-arg APP_BIN=lb-k8s-controller -t ghcr.io/your-org/way-balancer-k8s-controller:0.1.0 .
```

Push the image to the registry used by the cluster before applying the manifest.

## Deploy

The checked-in example manifest lives at `examples/kubernetes/lb-k8s-controller/deployment.yaml`.

Apply it with:

```sh
kubectl apply -f examples/kubernetes/lb-k8s-controller/deployment.yaml
```

The example sets:

- two replicas
- explicit controller name matching `lb_k8s_integration::SUPPORTED_GATEWAY_CONTROLLER_NAME`
- namespace-scoped reconciliation for `edge`
- public listener class and HTTP/1 translation defaults
- explicit leader election lease identity from the pod name
- lease timing defaults of 15s lease duration, 10s renew deadline, and 2s retry cadence

Adjust the image reference and `LB_K8S_CONTROLLER_NAMESPACE` value before production use.

## Deploy With Helm

The repository also ships a Helm chart at `charts/lb-k8s-controller`.

Install it with:

```sh
helm upgrade --install lb-k8s-controller ./charts/lb-k8s-controller \
	-n way-balancer-system \
	--create-namespace \
	--set image.repository=ghcr.io/your-org/way-balancer-k8s-controller \
	--set image.tag=0.1.0 \
	--set controller.namespaceScope=edge
```

The chart templates the same core objects as the raw example:

- optional `Namespace`
- `ServiceAccount`
- `ClusterRole`
- `ClusterRoleBinding`
- namespaced `Role` and `RoleBinding` for leases
- multi-replica `Deployment`

Key values to review before production use:

- `image.repository`
- `image.tag`
- `controller.name`
- `controller.namespaceScope`
- `controller.listenerClass`
- `controller.listenerProtocol`
- `controller.leaderElection.enabled`
- `controller.leaderElection.leaseName`
- `controller.leaderElection.leaseNamespace`
- `controller.leaderElection.leaseDurationMs`
- `controller.leaderElection.renewDeadlineMs`
- `controller.leaderElection.retryPeriodMs`

The checked-in chart defaults to two replicas with lease-based leader election enabled.

## Verify Startup

Confirm the deployment rolled out:

```sh
kubectl rollout status deployment/lb-k8s-controller -n way-balancer-system
kubectl logs deployment/lb-k8s-controller -n way-balancer-system
```

At startup the binary logs the configured controller name, namespace scope, bind IP, and watched resource set. Use those logs as the current operator-facing verification surface.

Verify the active lease holder separately:

```sh
kubectl get lease lb-k8s-controller -n way-balancer-system -o yaml
```

Expected failover timing with the default settings is approximately $15$ to $17$ seconds from the last successful renewal, depending on API-server latency and scheduling delay.

## Upgrade

1. Build and push the new controller image.
2. Update the deployment image tag or the Helm values.
3. Wait for `kubectl rollout status` to report success.
4. Confirm startup logs still show the expected controller name, namespace scope, and watched resources.

Prefer immutable image tags rather than mutable `latest` tags.

## Rollback

1. Inspect the current ReplicaSet and rollout history.
2. Run `kubectl rollout undo deployment/lb-k8s-controller -n way-balancer-system`, or roll back the Helm release with `helm rollback`, or pin the previous image tag explicitly.
3. Re-check startup logs after rollback.

Rollback of the controller deployment does not roll back dataplane snapshots. Dataplane snapshot rollback still follows `docs/runbooks/upgrade-rollback-policy.md`.

## RBAC Notes

- the example grants read-only watch access to the Gateway API and service discovery resources the controller watches today
- the example does not grant write access to resource status subresources yet
- the example adds only the `coordination.k8s.io` lease permissions required for leader election and keeps them namespaced to the controller namespace

## Operational Limits

- this example is packaging for the current HA controller runtime, but it still does not persist external controller state beyond the Kubernetes lease and published snapshots
- scaling below two replicas removes warm failover coverage, even though the binary can still run
- use a dedicated namespace such as `way-balancer-system` for service account and rollout isolation