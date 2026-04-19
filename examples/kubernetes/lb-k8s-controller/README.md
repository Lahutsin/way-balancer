# lb-k8s-controller Kubernetes Example

This directory contains a checked-in HA deployment example for `lb-k8s-controller`.

If you prefer Helm packaging instead of applying the raw manifest directly, use the chart at `charts/lb-k8s-controller`.

## Current Assumptions

- two warm replicas with Kubernetes lease-based leader election
- cluster-scoped RBAC for watched resources plus namespaced lease access in `way-balancer-system`
- namespace-scoped reconcile target set through `LB_K8S_CONTROLLER_NAMESPACE`
- pod name is used as the explicit lease identity

## Build The Image

```sh
docker build --build-arg APP_BIN=lb-k8s-controller -t ghcr.io/your-org/way-balancer-k8s-controller:0.1.0 .
```

Replace the image reference in `deployment.yaml` before applying it.

## Apply The Manifest

```sh
kubectl apply -f examples/kubernetes/lb-k8s-controller/deployment.yaml
kubectl rollout status deployment/lb-k8s-controller -n way-balancer-system
kubectl logs deployment/lb-k8s-controller -n way-balancer-system
```

## Install With Helm

```sh
helm upgrade --install lb-k8s-controller ./charts/lb-k8s-controller \
	-n way-balancer-system \
	--create-namespace \
	--set image.repository=ghcr.io/your-org/way-balancer-k8s-controller \
	--set image.tag=0.1.0 \
	--set controller.namespaceScope=edge
kubectl rollout status deployment/lb-k8s-controller -n way-balancer-system
kubectl logs deployment/lb-k8s-controller -n way-balancer-system
```

## What The Manifest Includes

- `Namespace`
- `ServiceAccount`
- `ClusterRole`
- `ClusterRoleBinding`
- namespaced `Role` and `RoleBinding` for `coordination.k8s.io` leases
- two-replica `Deployment`

The example watches `GatewayClass`, `Gateway`, `HTTPRoute`, `Service`, and `EndpointSlice` resources.

Lease defaults target approximately 15 seconds to declare a leader dead, with renewal attempts every 2 seconds and a 10 second self-fencing renew deadline.

## Operational Notes

- check lease ownership with `kubectl get lease lb-k8s-controller -n way-balancer-system -o yaml`
- keep at least two replicas if you want warm failover coverage
- use immutable image tags for upgrades
- use `kubectl rollout undo` or pin the previous image tag to roll back controller packaging changes
- dataplane snapshot rollback remains separate from controller deployment rollback