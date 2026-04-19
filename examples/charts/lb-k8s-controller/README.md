# lb-k8s-controller Helm Chart

This chart packages the HA `lb-k8s-controller` deployment.

## Important Limits

- Gateway API watches remain cluster-scoped because `GatewayClass` is cluster-scoped
- lease coordination remains namespaced and defaults to the release namespace
- failover timing depends on the configured lease duration, renew deadline, and retry period

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
- `controller.leaderElection.enabled`: turn lease-based leader election on or off
- `controller.leaderElection.leaseName`: lease object name
- `controller.leaderElection.leaseNamespace`: optional lease namespace override; empty uses the release namespace
- `controller.leaderElection.leaseDurationMs`: lease timeout before takeover
- `controller.leaderElection.renewDeadlineMs`: self-fencing deadline for the active leader
- `controller.leaderElection.retryPeriodMs`: renew/acquire retry cadence
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