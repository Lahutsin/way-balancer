use std::fs;
use std::path::PathBuf;

fn example_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("load-balancer")
        .join(file_name)
}

#[test]
fn documented_example_configs_parse_and_compile() -> Result<(), Box<dyn std::error::Error>> {
    for file_name in [
        "basic-http.json",
        "cache-peer-node-a.json",
        "cache-peer-node-b.json",
        "http-cache-public.json",
        "grpc-retries.json",
        "http3-public.json",
        "https-termination.json",
        "public-admin.json",
        "local-dev-insecure.json",
        "sticky-sessions-cookie.json",
        "virtual-hosts.json",
        "example-com-api.json",
        "route-matchers-http.json",
        "source-aware-routing.json",
        "path-rewrite.json",
        "websocket-upgrade.json",
        "weighted-route-canary.json",
        "weighted-route-blue-green.json",
        "dual-stack-public.json",
        "destination-policy-bindings.json",
        "destination-traffic-mirror.json",
        "destination-fault-injection.json",
    ] {
        let contents = fs::read_to_string(example_path(file_name))?;
        let config = lb_config_model::WorkspaceConfig::parse_json_str(&contents)?;
        config.validate()?;
        let snapshot = config.compile_snapshot()?;

        assert!(!snapshot.metadata().digest_sha256().is_empty(), "{file_name}");
    }
    Ok(())
}

#[test]
fn docker_compose_example_config_parses() -> Result<(), Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(example_path("docker-compose-public-admin.json"))?;
    let _config = lb_config_model::WorkspaceConfig::parse_json_str(&contents)?;
    Ok(())
}
