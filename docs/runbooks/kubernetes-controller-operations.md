# Kubernetes Controller Operations

## Scope

This runbook covers packaging and operating the checked-in `lb-k8s-controller` deployment example.

## Current Deployment Model

- deploy a single controller replica only
- leader election is not implemented in the current binary, so multiple active replicas are not supported yet
- RBAC must cover cluster-scoped `GatewayClass` plus namespaced `Gateway`, `HTTPRoute`, `Service`, and `EndpointSlice` watches
- `LB_K8S_CONTROLLER_NAMESPACE` narrows reconciles to one namespace when set, but the example RBAC remains cluster-scoped because `GatewayClass` is cluster-scoped

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

- one replica
- explicit controller name matching `lb_k8s_integration::SUPPORTED_GATEWAY_CONTROLLER_NAME`
- namespace-scoped reconciliation for `edge`
- public listener class and HTTP/1 translation defaults

Adjust the image reference and `LB_K8S_CONTROLLER_NAMESPACE` value before production use.

## Verify Startup

Confirm the deployment rolled out:

```sh
kubectl rollout status deployment/lb-k8s-controller -n way-balancer-system
kubectl logs deployment/lb-k8s-controller -n way-balancer-system
```

At startup the binary logs the configured controller name, namespace scope, bind IP, and watched resource set. Use those logs as the current operator-facing verification surface.

## Upgrade

1. Build and push the new controller image.
2. Update the deployment image tag.
3. Wait for `kubectl rollout status` to report success.
4. Confirm startup logs still show the expected controller name, namespace scope, and watched resources.

Prefer immutable image tags rather than mutable `latest` tags.

## Rollback

1. Inspect the current ReplicaSet and rollout history.
2. Run `kubectl rollout undo deployment/lb-k8s-controller -n way-balancer-system` or pin the previous image tag explicitly.
3. Re-check startup logs after rollback.

Rollback of the controller deployment does not roll back dataplane snapshots. Dataplane snapshot rollback still follows `docs/runbooks/upgrade-rollback-policy.md`.

## RBAC Notes

- the example grants read-only watch access to the Gateway API and service discovery resources the controller watches today
- the example does not grant write access to resource status subresources yet
- if leader election is added later, `coordination.k8s.io` lease permissions must be added explicitly

## Operational Limits

- this example is packaging for the current pre-GA controller runtime, not a full HA operator deployment
- because leader election is absent, do not scale the deployment above one replica
- use a dedicated namespace such as `way-balancer-system` for service account and rollout isolation