# lb-k8s-controller Helm Chart

This chart packages the current pre-GA `lb-k8s-controller` runtime.

## Important Limits

- deploy only one replica
- leader election is not implemented yet
- RBAC remains cluster-scoped because `GatewayClass` is cluster-scoped

## Install

```sh
helm upgrade --install lb-k8s-controller ./charts/lb-k8s-controller \
  -n way-balancer-system \
  --create-namespace \
  --set image.repository=ghcr.io/your-org/way-balancer-k8s-controller \
  --set image.tag=0.1.0 \
  --set controller.namespaceScope=edge
```

## Common Values

- `image.repository`, `image.tag`: controller image reference
- `controller.name`: Gateway controller name
- `controller.namespaceScope`: optional namespace filter; empty means all namespaces
- `controller.bindIP`: bind IP used for translated listener defaults
- `controller.listenerClass`: translated listener class
- `controller.listenerProtocol`: translated listener protocol
- `rbac.create`: create the `ClusterRole` and `ClusterRoleBinding`
- `serviceAccount.create`: create the service account for the controller pod

## Render Without Installing

```sh
helm template lb-k8s-controller ./charts/lb-k8s-controller -n way-balancer-system
```

## Upgrade

```sh
helm upgrade lb-k8s-controller ./charts/lb-k8s-controller \
  -n way-balancer-system \
  --set image.repository=ghcr.io/your-org/way-balancer-k8s-controller \
  --set image.tag=0.1.1
```