# lb-k8s-controller Kubernetes Example

This directory contains a checked-in deployment example for the current `lb-k8s-controller` runtime.

If you prefer Helm packaging instead of applying the raw manifest directly, use the chart at `charts/lb-k8s-controller`.

## Current Assumptions

- single replica only
- no leader election
- cluster-scoped RBAC for watched resources
- namespace-scoped reconcile target set through `LB_K8S_CONTROLLER_NAMESPACE`

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
- single-replica `Deployment`

The example watches `GatewayClass`, `Gateway`, `HTTPRoute`, `Service`, and `EndpointSlice` resources.

## Operational Notes

- keep the deployment at one replica because leader election is not implemented yet
- use immutable image tags for upgrades
- use `kubectl rollout undo` or pin the previous image tag to roll back controller packaging changes
- dataplane snapshot rollback remains separate from controller deployment rollback