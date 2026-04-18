use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_repo_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(fs::read_to_string(repo_root().join(path))?)
}

#[test]
fn controller_packaging_examples_and_runbook_stay_in_sync() -> Result<(), Box<dyn std::error::Error>>
{
    let dockerfile = read_repo_file("Dockerfile")?;
    assert!(dockerfile.contains("ARG APP_BIN=lb-dataplane"));
    assert!(dockerfile.contains("cargo build --release -p ${APP_BIN}"));
    assert!(dockerfile.contains("/usr/local/bin/lb-entrypoint"));

    let manifest = read_repo_file("examples/kubernetes/lb-k8s-controller/deployment.yaml")?;
    for expected in [
        "kind: Namespace",
        "kind: ServiceAccount",
        "kind: ClusterRole",
        "kind: ClusterRoleBinding",
        "kind: Deployment",
        "replicas: 1",
        "gatewayclasses",
        "gateways",
        "httproutes",
        "services",
        "endpointslices",
        "LB_K8S_CONTROLLER_NAME",
        "LB_K8S_CONTROLLER_NAMESPACE",
        "LB_K8S_CONTROLLER_BIND_IP",
        "LB_K8S_CONTROLLER_LISTENER_CLASS",
        "LB_K8S_CONTROLLER_LISTENER_PROTOCOL",
    ] {
        assert!(manifest.contains(expected), "missing manifest snippet: {expected}");
    }

    let example_readme = read_repo_file("examples/kubernetes/lb-k8s-controller/README.md")?;
    for expected in [
        "docker build --build-arg APP_BIN=lb-k8s-controller",
        "kubectl apply -f examples/kubernetes/lb-k8s-controller/deployment.yaml",
        "single replica",
        "leader election",
        "kubectl rollout undo",
    ] {
        assert!(example_readme.contains(expected), "missing example README snippet: {expected}");
    }

    let runbook = read_repo_file("docs/runbooks/kubernetes-controller-operations.md")?;
    for expected in [
        "single controller replica only",
        "leader election is not implemented",
        "kubectl rollout status",
        "kubectl rollout undo deployment/lb-k8s-controller -n way-balancer-system",
        "GatewayClass",
        "HTTPRoute",
        "EndpointSlice",
    ] {
        assert!(runbook.contains(expected), "missing runbook snippet: {expected}");
    }

    Ok(())
}
