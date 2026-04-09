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
fn documented_example_configs_parse_and_compile(
) -> Result<(), Box<dyn std::error::Error>> {
    for file_name in [
        "basic-http.json",
        "http-cache-public.json",
        "grpc-retries.json",
        "https-termination.json",
        "public-admin.json",
        "local-dev-insecure.json",
    ] {
        let contents = fs::read_to_string(example_path(file_name))?;
        let config = lb_config_model::WorkspaceConfig::parse_json_str(&contents)?;
        config.validate()?;
        let snapshot = config.compile_snapshot()?;

        assert!(!snapshot.metadata().digest_sha256().is_empty(), "{file_name}");
    }
    Ok(())
}