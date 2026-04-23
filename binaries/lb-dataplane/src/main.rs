#[path = "workspace_serve/mod.rs"]
mod workspace_serve;

use std::error::Error;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoRequestHead {
    method: String,
    target: String,
    headers: Vec<DemoHeader>,
    authorization_bearer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoHeader {
    name: String,
    value: String,
}

impl DemoRequestHead {
    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
}

const UNIQUE_SECURITY_HEADERS: &[&str] = &[
    "authorization",
    "x-lb-admin-actor",
    "x-lb-admin-timestamp",
    "x-lb-admin-nonce",
    "x-lb-admin-signature",
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ServeArgs {
    config_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServeRuntimeConfig {
    public_addr: SocketAddr,
    admin_addr: SocketAddr,
    upstream_addr: SocketAddr,
    route_rules: Vec<lb_proto_http::RoutePrefixRule>,
    route_upstreams: Vec<lb_runtime::Http1RouteUpstream>,
    trusted_client_ip: Option<lb_runtime::TrustedClientIpPolicy>,
    anonymous_source_filter: Option<lb_runtime::AnonymousSourceFilterPolicy>,
    spawn_demo_upstream: bool,
    source_label: String,
}

#[derive(Debug)]
struct DemoServeState {
    started_at: Instant,
    public_addr: SocketAddr,
    admin_addr: SocketAddr,
    upstream_addr: SocketAddr,
    proxied_connections: AtomicU64,
    proxied_requests: AtomicU64,
    admin_requests: AtomicU64,
    last_proxy_result: Mutex<Option<String>>,
}

impl DemoServeState {
    fn new(public_addr: SocketAddr, admin_addr: SocketAddr, upstream_addr: SocketAddr) -> Self {
        Self {
            started_at: Instant::now(),
            public_addr,
            admin_addr,
            upstream_addr,
            proxied_connections: AtomicU64::new(0),
            proxied_requests: AtomicU64::new(0),
            admin_requests: AtomicU64::new(0),
            last_proxy_result: Mutex::new(None),
        }
    }

    async fn status_body(&self) -> String {
        let last_proxy_result = self.last_proxy_result.lock().await.clone();
        let last_proxy_result = last_proxy_result.unwrap_or_else(|| String::from("none"));
        format!(
            concat!(
                "{{\n",
                "  \"service\": \"lb-dataplane-demo\",\n",
                "  \"uptime_secs\": {},\n",
                "  \"public_listener\": \"{}\",\n",
                "  \"admin_listener\": \"{}\",\n",
                "  \"upstream_target\": \"{}\",\n",
                "  \"proxied_connections\": {},\n",
                "  \"proxied_requests\": {},\n",
                "  \"admin_requests\": {},\n",
                "  \"last_proxy_result\": \"{}\"\n",
                "}}\n"
            ),
            self.started_at.elapsed().as_secs(),
            self.public_addr,
            self.admin_addr,
            self.upstream_addr,
            self.proxied_connections.load(Ordering::SeqCst),
            self.proxied_requests.load(Ordering::SeqCst),
            self.admin_requests.load(Ordering::SeqCst),
            escape_json_string(&last_proxy_result),
        )
    }
}

fn control_plane_signer() -> Result<lb_config_model::ArtifactSigner, Box<dyn Error>> {
    let signer_identity = std::env::var("LB_CONTROL_PLANE_SIGNER_IDENTITY")
        .unwrap_or_else(|_| String::from("control-plane"));
    let signing_key = std::env::var("LB_CONTROL_PLANE_SIGNING_KEY_ED25519").map_err(|error| {
        format!(
            "required environment variable LB_CONTROL_PLANE_SIGNING_KEY_ED25519 is missing or invalid: {error}"
        )
    })?;

    lb_config_model::ArtifactSigner::from_signing_key_hex(signer_identity, &signing_key)
        .map_err(Into::into)
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    std::env::var(name).map_err(|error| {
        format!("required environment variable {name} is missing or invalid: {error}").into()
    })
}

fn admin_bearer_secret() -> Result<String, Box<dyn Error>> {
    required_env("LB_CTL_ADMIN_SECRET")
}

fn parse_port_env(name: &str, default_port: u16) -> Result<u16, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|error| format!("failed to parse {name} as port: {error}").into()),
        Err(std::env::VarError::NotPresent) => Ok(default_port),
        Err(error) => Err(format!("failed to read {name}: {error}").into()),
    }
}

fn local_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn run_mode(arguments: &[String]) -> RunMode {
    if arguments.first().map(String::as_str) == Some("serve") {
        RunMode::Serve
    } else {
        RunMode::Smoke
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Smoke,
    Serve,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run_mode(&arguments) {
        RunMode::Smoke => smoke_main(),
        RunMode::Serve => {
            let serve_args = parse_serve_args(&arguments[1..])?;
            let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            runtime.block_on(serve_main(&serve_args))
        }
    }
}

fn parse_serve_args(arguments: &[String]) -> Result<ServeArgs, Box<dyn Error>> {
    let mut serve_args = ServeArgs { config_path: std::env::var("LB_CONFIG_PATH").ok() };
    let mut index = 0;

    while index < arguments.len() {
        let argument = &arguments[index];
        if let Some(path) = argument.strip_prefix("--config=") {
            if path.is_empty() {
                return Err("--config requires a non-empty path".into());
            }
            serve_args.config_path = Some(String::from(path));
            index += 1;
            continue;
        }

        match argument.as_str() {
            "--config" => {
                let path = arguments.get(index + 1).ok_or("--config requires a path argument")?;
                serve_args.config_path = Some(path.clone());
                index += 2;
            }
            _ => return Err(format!("unsupported serve argument: {argument}").into()),
        }
    }

    Ok(serve_args)
}

fn smoke_main() -> Result<(), Box<dyn Error>> {
    let signer = control_plane_signer()?;

    let runtime = lb_runtime::RuntimeMetadata::new();
    let network_defaults = lb_net_core::NetworkDefaults::default();
    let listener = lb_net_core::ListenerConfig::foundation_local(
        "foundation-public",
        lb_net_core::ListenerClass::Public,
    );
    let http = lb_proto_http::SupportedHttpVersion::Http1;
    let tls = lb_proto_tls::TlsMode::Passthrough;
    let logging = lb_observability::LoggingPolicy::default();

    let mut config = lb_config_model::WorkspaceConfig::foundation();
    config.security.artifact_verification.trusted_signers = vec![signer.trusted_signer()];
    let snapshot = config.compile_snapshot()?;
    let digest = snapshot.metadata().digest_sha256().to_owned();
    let artifact_attestation = signer.attest_snapshot(&snapshot);

    let mut control = lb_admin_api::SnapshotControlService::new();
    let published = control.publish(lb_admin_api::SnapshotPublishRequest {
        version: String::from("foundation-v1"),
        snapshot,
        artifact_attestation: Some(artifact_attestation),
        expected_digest_sha256: Some(digest.clone()),
        published_by: Some(String::from("lb-dataplane")),
        reason: Some(String::from("local dataplane apply smoke test")),
    })?;

    let mut manager = lb_runtime::DataplaneSnapshotManager::new();
    let applied = manager.apply(lb_runtime::SnapshotApplyRequest {
        version: published.record.version.clone(),
        snapshot: published.record.snapshot.clone(),
        artifact_attestation: published.record.artifact_attestation.clone(),
        expected_digest_sha256: published.record.digest_sha256.clone(),
        acknowledged_by: Some(String::from("lb-dataplane")),
    })?;

    println!(
        "{} dataplane ready: service={}, backlog={}, listener={}, http={http:?}, tls={tls:?}, structured_logging={}, published_version={}, active_version={}, last_good={}, digest={}",
        lb_runtime::CRATE_ID,
        runtime.service_name,
        network_defaults.backlog,
        listener.name,
        logging.structured,
        published.record.version,
        applied.active.version,
        applied.last_known_good.version,
        applied.active.digest_sha256,
    );
    Ok(())
}

fn load_workspace_config(path: &str) -> Result<lb_config_model::WorkspaceConfig, Box<dyn Error>> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read workspace config from {path}: {error}"))?;
    let config = lb_config_model::WorkspaceConfig::parse_json_str(&content)
        .map_err(|error| format!("failed to parse workspace config from {path}: {error}"))?;

    config
        .validate()
        .map_err(|report| format!("workspace config validation failed for {path}: {report}"))?;
    config
        .compile_listeners()
        .map_err(|error| format!("workspace listener compilation failed for {path}: {error}"))?;
    config
        .compile_http_route_rules()
        .map_err(|error| format!("workspace route compilation failed for {path}: {error}"))?;
    config
        .compile_upstream_clusters()
        .map_err(|error| format!("workspace upstream compilation failed for {path}: {error}"))?;

    Ok(config)
}

fn serve_runtime_config_from_workspace(
    config: &lb_config_model::WorkspaceConfig,
) -> Result<ServeRuntimeConfig, Box<dyn Error>> {
    let public_listener = config
        .listeners
        .iter()
        .find(|listener| listener.class == lb_config_model::ListenerClassConfig::Public)
        .ok_or("workspace config must declare a public listener")?;
    if public_listener.protocol != lb_config_model::ListenerProtocolConfig::Http1 {
        return Err(format!(
            "serve mode currently supports only public http1 listeners, found {:?}",
            public_listener.protocol
        )
        .into());
    }

    let admin_listener = config
        .listeners
        .iter()
        .find(|listener| listener.class == lb_config_model::ListenerClassConfig::Admin)
        .ok_or("workspace config must declare an admin listener")?;
    if admin_listener.protocol != lb_config_model::ListenerProtocolConfig::Http1 {
        return Err(format!(
            "serve mode currently supports only admin http1 listeners, found {:?}",
            admin_listener.protocol
        )
        .into());
    }
    let compiled_routes = config.compile_http_route_rules()?;
    let mut route_rules = Vec::with_capacity(public_listener.routes.len());
    let mut route_upstreams = Vec::with_capacity(public_listener.routes.len());

    for route_name in &public_listener.routes {
        let route = config
            .routes
            .iter()
            .find(|route| route.name == *route_name)
            .ok_or_else(|| format!("public listener references unknown route {route_name}"))?;
        let compiled_route = compiled_routes
            .iter()
            .find(|compiled| compiled.label == *route_name)
            .ok_or_else(|| format!("compiled route {route_name} is missing"))?;
        route_rules.push(compiled_route.clone());
        for destination in route.normalized_destinations() {
            let cluster = config
                .upstream_clusters
                .iter()
                .find(|cluster| cluster.name == destination.upstream_cluster)
                .ok_or_else(|| {
                    format!(
                        "route {} references unknown upstream cluster {}",
                        route.name, destination.upstream_cluster
                    )
                })?;
            if cluster.endpoints.is_empty() {
                return Err(format!(
                    "upstream cluster {} must declare at least one endpoint",
                    cluster.name
                )
                .into());
            }

            route_upstreams.extend(cluster.endpoints.iter().map(|endpoint| {
                lb_runtime::Http1RouteUpstream {
                    route_label: route.name.clone(),
                    upstream: lb_net_core::UpstreamTarget::new(
                        format!("{}:{}", cluster.name, endpoint.id),
                        endpoint.address,
                    ),
                }
            }));
        }
    }

    let upstream_addr = route_upstreams
        .first()
        .map(|route_upstream| route_upstream.upstream.address)
        .ok_or("public listener must reference at least one route")?;

    Ok(ServeRuntimeConfig {
        public_addr: public_listener.bind_address,
        admin_addr: admin_listener.bind_address,
        upstream_addr,
        route_rules,
        route_upstreams,
        trusted_client_ip: compile_trusted_client_ip(&config.security.trusted_client_ip)?,
        anonymous_source_filter: compile_anonymous_source_filter(
            &config.security.anonymous_source_filter,
        )?,
        spawn_demo_upstream: false,
        source_label: format!("config={}", config.name),
    })
}

fn compile_trusted_client_ip(
    config: &lb_config_model::TrustedClientIpConfig,
) -> Result<Option<lb_runtime::TrustedClientIpPolicy>, Box<dyn Error>> {
    if !config.enabled {
        return Ok(None);
    }

    Ok(Some(lb_runtime::TrustedClientIpPolicy {
        enabled: true,
        trusted_proxy_cidrs: config
            .trusted_proxy_cidrs
            .iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?,
    }))
}

fn compile_anonymous_source_filter(
    filter: &lb_config_model::AnonymousSourceFilterConfig,
) -> Result<Option<lb_runtime::AnonymousSourceFilterPolicy>, Box<dyn Error>> {
    if !filter.enabled {
        return Ok(None);
    }

    Ok(Some(lb_runtime::AnonymousSourceFilterPolicy {
        enabled: true,
        deny_cidrs: filter
            .deny_cidrs
            .iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?,
        deny_vpn: filter.deny_vpn,
        deny_proxy: filter.deny_proxy,
        deny_socks: filter.deny_socks,
        deny_tor: filter.deny_tor,
        vpn_cidrs: filter
            .vpn_cidrs
            .iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?,
        proxy_cidrs: filter
            .proxy_cidrs
            .iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?,
        socks_cidrs: filter
            .socks_cidrs
            .iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?,
        tor_exit_cidrs: filter
            .tor_exit_cidrs
            .iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?,
    }))
}

fn resolve_serve_runtime_config(
    serve_args: &ServeArgs,
) -> Result<ServeRuntimeConfig, Box<dyn Error>> {
    if let Some(config_path) = serve_args.config_path.as_deref() {
        let config = load_workspace_config(config_path)?;
        let mut runtime_config = serve_runtime_config_from_workspace(&config)?;
        runtime_config.source_label = format!("config_path={config_path}");
        return Ok(runtime_config);
    }

    Ok(ServeRuntimeConfig {
        public_addr: local_addr(parse_port_env("LB_PUBLIC_PORT", 8080)?),
        admin_addr: local_addr(parse_port_env("LB_ADMIN_PORT", 9900)?),
        upstream_addr: local_addr(parse_port_env("LB_DEMO_UPSTREAM_PORT", 18080)?),
        route_rules: Vec::new(),
        route_upstreams: Vec::new(),
        trusted_client_ip: None,
        anonymous_source_filter: None,
        spawn_demo_upstream: true,
        source_label: String::from("built-in demo topology"),
    })
}

fn curl_hint_addr(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
        }
        _ => address,
    }
}

async fn serve_main(serve_args: &ServeArgs) -> Result<(), Box<dyn Error>> {
    if serve_args.config_path.is_some() {
        return workspace_serve::serve_workspace_main(serve_args)
            .await
            .map_err(|error| -> Box<dyn Error> { error });
    }

    let runtime_config = resolve_serve_runtime_config(serve_args)?;
    let admin_secret = Arc::new(admin_bearer_secret()?);
    let public_listener = TcpListener::bind(runtime_config.public_addr).await?;
    let public_addr = public_listener.local_addr()?;
    let admin_listener = TcpListener::bind(runtime_config.admin_addr).await?;
    let admin_addr = admin_listener.local_addr()?;

    let upstream_task = if runtime_config.spawn_demo_upstream {
        let upstream_listener = TcpListener::bind(runtime_config.upstream_addr).await?;
        Some(tokio::spawn(run_demo_upstream_listener(upstream_listener)))
    } else {
        None
    };

    let state =
        Arc::new(DemoServeState::new(public_addr, admin_addr, runtime_config.upstream_addr));
    let mut proxy_config = lb_runtime::Http1ProxyConfig::new(lb_net_core::UpstreamTarget::new(
        "demo-upstream",
        runtime_config.upstream_addr,
    ));
    proxy_config.routes = runtime_config.route_rules.clone();
    if !runtime_config.route_upstreams.is_empty() {
        proxy_config = proxy_config
            .with_route_upstreams(runtime_config.route_upstreams.clone())
            .with_route_enumeration_protection(lb_runtime::RouteEnumerationProtectionPolicy {
                source_aggregation: lb_runtime::SourceAggregation::ExactIp,
                evaluation_window: std::time::Duration::from_secs(30),
                max_unmatched_route_events: 3,
                max_distinct_query_signatures_per_route: 6,
                base_ban_duration: std::time::Duration::from_secs(60),
                max_ban_duration: std::time::Duration::from_secs(15 * 60),
                max_tracked_sources: 4096,
            })
            .rejecting_unmatched_routes();
    }
    if let Some(policy) = runtime_config.trusted_client_ip.clone() {
        proxy_config = proxy_config.with_trusted_client_ip(policy);
    }
    if let Some(filter) = runtime_config.anonymous_source_filter.clone() {
        proxy_config = proxy_config.with_anonymous_source_filter(filter);
    }

    let public_task =
        tokio::spawn(run_public_proxy_listener(public_listener, proxy_config, Arc::clone(&state)));
    let admin_task = tokio::spawn(run_admin_listener(
        admin_listener,
        Arc::clone(&state),
        Arc::clone(&admin_secret),
    ));

    println!(
        "lb-dataplane serve mode ready ({}): public=http://{} admin=http://{} upstream={}",
        runtime_config.source_label, public_addr, admin_addr, runtime_config.upstream_addr
    );
    println!("try: curl http://{}/", curl_hint_addr(public_addr));
    println!(
        "try: curl -H 'Authorization: Bearer $LB_CTL_ADMIN_SECRET' http://{}/status",
        curl_hint_addr(admin_addr)
    );
    println!(
        "try: curl -H 'Authorization: Bearer $LB_CTL_ADMIN_SECRET' http://{}/healthz",
        curl_hint_addr(admin_addr)
    );
    println!("press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;

    public_task.abort();
    admin_task.abort();

    let _ = public_task.await;
    let _ = admin_task.await;
    if let Some(upstream_task) = upstream_task {
        upstream_task.abort();
        let _ = upstream_task.await;
    }
    Ok(())
}

async fn run_public_proxy_listener(
    listener: TcpListener,
    proxy_config: lb_runtime::Http1ProxyConfig,
    state: Arc<DemoServeState>,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let proxy_config = proxy_config.clone();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let result = lb_runtime::proxy_http1_connection(stream, &proxy_config).await;
            match result {
                Ok(report) => {
                    state.proxied_connections.fetch_add(1, Ordering::SeqCst);
                    state
                        .proxied_requests
                        .fetch_add(report.metrics.request_count, Ordering::SeqCst);
                    let mut last_proxy_result = state.last_proxy_result.lock().await;
                    *last_proxy_result = Some(format!(
                        "{} requests via {}",
                        report.metrics.request_count, report.upstream_name
                    ));
                }
                Err(error) => {
                    let mut last_proxy_result = state.last_proxy_result.lock().await;
                    *last_proxy_result = Some(format!("error: {error}"));
                }
            }
        });
    }
}

async fn run_admin_listener(
    listener: TcpListener,
    state: Arc<DemoServeState>,
    admin_secret: Arc<String>,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        let admin_secret = Arc::clone(&admin_secret);
        tokio::spawn(async move {
            let _ = handle_admin_connection(stream, state, admin_secret).await;
        });
    }
}

async fn run_demo_upstream_listener(listener: TcpListener) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = handle_demo_upstream_connection(stream).await;
        });
    }
}

async fn handle_admin_connection(
    mut stream: TcpStream,
    state: Arc<DemoServeState>,
    admin_secret: Arc<String>,
) -> io::Result<()> {
    state.admin_requests.fetch_add(1, Ordering::SeqCst);
    serve_admin_http(&mut stream, &state, admin_secret.as_str()).await
}

async fn handle_demo_upstream_connection(mut stream: TcpStream) -> io::Result<()> {
    serve_demo_upstream_http(&mut stream).await
}

async fn serve_admin_http<S>(
    stream: &mut S,
    state: &DemoServeState,
    admin_secret: &str,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_request_head(stream).await?;
    let Some(request) = request else {
        return Ok(());
    };

    let Some(bearer_token) = request.authorization_bearer.as_deref() else {
        return write_http_response_with_headers(
            stream,
            "401 Unauthorized",
            "text/plain; charset=utf-8",
            &["WWW-Authenticate: Bearer"],
            b"admin authorization required\n",
        )
        .await;
    };
    if !constant_time_eq(bearer_token.as_bytes(), admin_secret.as_bytes()) {
        return write_http_response_with_headers(
            stream,
            "401 Unauthorized",
            "text/plain; charset=utf-8",
            &["WWW-Authenticate: Bearer"],
            b"admin authorization required\n",
        )
        .await;
    }

    let (status, content_type, body) = match request.target.as_str() {
        "/healthz" => ("200 OK", "text/plain; charset=utf-8", String::from("ok\n")),
        "/status" => ("200 OK", "application/json", state.status_body().await),
        _ => ("404 Not Found", "text/plain; charset=utf-8", String::from("not found\n")),
    };
    write_http_response_with_headers(stream, status, content_type, &[], body.as_bytes()).await
}

async fn serve_demo_upstream_http<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_request_head(stream).await?;
    let Some(request) = request else {
        return Ok(());
    };
    let body = format!(
        concat!(
            "{{\n",
            "  \"service\": \"demo-upstream\",\n",
            "  \"method\": \"{}\",\n",
            "  \"path\": \"{}\"\n",
            "}}\n"
        ),
        escape_json_string(&request.method),
        escape_json_string(&request.target),
    );
    write_http_response(stream, "200 OK", "application/json", body.as_bytes()).await
}

async fn read_http_request_head<S>(stream: &mut S) -> io::Result<Option<DemoRequestHead>>
where
    S: AsyncRead + Unpin,
{
    read_http_request_head_and_body(stream).await.map(|request| request.map(|(head, _body)| head))
}

async fn read_http_request_head_and_body<S>(
    stream: &mut S,
) -> io::Result<Option<(DemoRequestHead, Vec<u8>)>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut chunk).await?;
        if bytes_read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::other("unexpected EOF while reading HTTP request head"));
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);
        if let Some(index) = find_double_crlf(&buffer) {
            let head = std::str::from_utf8(&buffer[..index])
                .map_err(|_| io::Error::other("request head is not valid UTF-8"))?;
            let request = parse_request_head(head)?;
            let header_len = index + 4;
            let content_length = request_content_length(&request)?;
            let mut body = buffer[header_len..].to_vec();
            while body.len() < content_length {
                let bytes_read = stream.read(&mut chunk).await?;
                if bytes_read == 0 {
                    return Err(io::Error::other("unexpected EOF while reading HTTP request body"));
                }
                body.extend_from_slice(&chunk[..bytes_read]);
                if body.len() > 64 * 1024 {
                    return Err(io::Error::other("HTTP request body exceeded demo limit"));
                }
            }
            body.truncate(content_length);
            return Ok(Some((request, body)));
        }

        if buffer.len() > 16 * 1024 {
            return Err(io::Error::other("HTTP request head exceeded demo limit"));
        }
    }
}

fn find_double_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_request_head(head: &str) -> io::Result<DemoRequestHead> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or_else(|| io::Error::other("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| io::Error::other("missing request method"))?;
    let target = parts.next().ok_or_else(|| io::Error::other("missing request target"))?;
    let version = parts.next().ok_or_else(|| io::Error::other("missing request version"))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(io::Error::other("unsupported request version"));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        headers.push(parse_header_line(line)?);
    }
    reject_duplicate_security_headers(&headers)?;
    let authorization_bearer = headers.iter().find_map(|header| {
        parse_authorization_bearer(&format!("{}: {}", header.name, header.value))
    });

    Ok(DemoRequestHead {
        method: String::from(method),
        target: String::from(target),
        headers,
        authorization_bearer,
    })
}

fn parse_header_line(header_line: &str) -> io::Result<DemoHeader> {
    let (name, value) = header_line
        .split_once(':')
        .ok_or_else(|| io::Error::other("invalid request header line"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(io::Error::other("request header name must not be empty"));
    }
    Ok(DemoHeader { name: String::from(name), value: String::from(value.trim()) })
}

fn parse_authorization_bearer(header_line: &str) -> Option<String> {
    let (name, value) = header_line.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("authorization") {
        return None;
    }

    let value = value.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = token.trim();
    if token.is_empty() {
        return None;
    }

    Some(String::from(token))
}

fn request_content_length(request: &DemoRequestHead) -> io::Result<usize> {
    let Some(value) = request.header_value("content-length") else {
        return Ok(0);
    };
    value.parse::<usize>().map_err(|_| io::Error::other("invalid content-length header"))
}

fn reject_duplicate_security_headers(headers: &[DemoHeader]) -> io::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for header in headers {
        if UNIQUE_SECURITY_HEADERS
            .iter()
            .any(|candidate| header.name.eq_ignore_ascii_case(candidate))
        {
            let normalized = header.name.to_ascii_lowercase();
            if !seen.insert(normalized.clone()) {
                return Err(io::Error::other(format!(
                    "duplicate security-sensitive header {normalized}"
                )));
            }
        }
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        diff |= usize::from(left_byte ^ right_byte);
    }

    diff == 0
}

async fn write_http_response<S>(
    stream: &mut S,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_http_response_with_headers(stream, status, content_type, &[], body).await
}

async fn write_http_response_with_headers<S>(
    stream: &mut S,
    status: &str,
    content_type: &str,
    extra_headers: &[&str],
    body: &[u8],
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
        body.len(),
        if extra_headers.is_empty() {
            String::new()
        } else {
            format!("{}\r\n", extra_headers.join("\r\n"))
        }
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

fn escape_json_string(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, curl_hint_addr, escape_json_string, parse_authorization_bearer,
        parse_port_env, parse_request_head, parse_serve_args, read_http_request_head,
        read_http_request_head_and_body, resolve_serve_runtime_config, run_admin_listener,
        run_demo_upstream_listener, run_mode, run_public_proxy_listener, serve_admin_http,
        serve_demo_upstream_http, serve_runtime_config_from_workspace, DemoServeState, RunMode,
        ServeArgs,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn run_mode_switches_to_serve_only_for_explicit_argument() {
        assert_eq!(run_mode(&[]), RunMode::Smoke);
        assert_eq!(run_mode(&[String::from("serve")]), RunMode::Serve);
        assert_eq!(run_mode(&[String::from("other")]), RunMode::Smoke);
    }

    #[test]
    fn parse_serve_args_supports_flag_and_env_override() -> Result<(), Box<dyn std::error::Error>> {
        std::env::remove_var("LB_CONFIG_PATH");
        assert_eq!(parse_serve_args(&[])?, ServeArgs { config_path: None });

        std::env::set_var("LB_CONFIG_PATH", "/tmp/from-env.json");
        assert_eq!(
            parse_serve_args(&[])?,
            ServeArgs { config_path: Some(String::from("/tmp/from-env.json")) }
        );
        assert_eq!(
            parse_serve_args(&[String::from("--config"), String::from("/tmp/from-flag.json")])?,
            ServeArgs { config_path: Some(String::from("/tmp/from-flag.json")) }
        );
        assert_eq!(
            parse_serve_args(&[String::from("--config=/tmp/from-inline.json")])?,
            ServeArgs { config_path: Some(String::from("/tmp/from-inline.json")) }
        );
        std::env::remove_var("LB_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn parse_port_env_uses_default_and_parses_explicit_values(
    ) -> Result<(), Box<dyn std::error::Error>> {
        std::env::remove_var("LB_TEST_PORT_ENV");
        assert_eq!(parse_port_env("LB_TEST_PORT_ENV", 12345)?, 12345);

        std::env::set_var("LB_TEST_PORT_ENV", "23456");
        assert_eq!(parse_port_env("LB_TEST_PORT_ENV", 12345)?, 23456);
        std::env::remove_var("LB_TEST_PORT_ENV");
        Ok(())
    }

    #[test]
    fn parse_request_head_extracts_method_and_target() -> Result<(), Box<dyn std::error::Error>> {
        let request = parse_request_head(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token",
        )?;

        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/status");
        assert_eq!(request.authorization_bearer.as_deref(), Some("test-token"));
        Ok(())
    }

    #[test]
    fn escape_json_string_escapes_quotes_and_newlines() {
        assert_eq!(escape_json_string("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn curl_hint_addr_maps_unspecified_ipv4_to_localhost() {
        assert_eq!(
            curl_hint_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
        assert_eq!(
            curl_hint_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
    }

    #[test]
    fn parse_authorization_bearer_accepts_bearer_scheme_only() {
        assert_eq!(
            parse_authorization_bearer("Authorization: Bearer admin-secret").as_deref(),
            Some("admin-secret")
        );
        assert!(parse_authorization_bearer("Authorization: Basic abc").is_none());
        assert!(parse_authorization_bearer("Host: localhost").is_none());
    }

    #[test]
    fn parse_request_head_rejects_duplicate_security_sensitive_headers() {
        let result = parse_request_head(concat!(
            "GET /status HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Authorization: Bearer one\r\n",
            "Authorization: Bearer two"
        ));
        assert!(result.as_ref().is_err_and(|error| {
            error.to_string().contains("duplicate security-sensitive header authorization")
        }));
    }

    #[test]
    fn constant_time_eq_requires_exact_match() {
        assert!(constant_time_eq(b"admin-secret", b"admin-secret"));
        assert!(!constant_time_eq(b"admin-secret", b"admin-secreu"));
        assert!(!constant_time_eq(b"admin-secret", b"admin-secret-extra"));
    }

    #[test]
    fn serve_runtime_config_from_workspace_builds_route_dispatch_table(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = lb_config_model::WorkspaceConfig::parse_json_str(
            r#"{
                "api_version": "v1_alpha1",
                "name": "docker-demo",
                "listeners": [
                    {
                        "name": "public-web",
                        "class": "public",
                        "bind_address": "0.0.0.0:8080",
                        "protocol": "http1",
                        "allow_unspecified_bind": true,
                        "routes": ["web"]
                    },
                    {
                        "name": "admin-http",
                        "class": "admin",
                        "bind_address": "0.0.0.0:9900",
                        "protocol": "http1",
                        "allow_unspecified_bind": true
                    }
                ],
                "routes": [
                    {
                        "name": "web",
                        "match": {
                            "type": "path_prefix",
                            "prefix": "/",
                            "hostnames": ["example.com"]
                        },
                        "upstream_cluster": "frontend"
                    }
                ],
                "upstream_clusters": [
                    {
                        "name": "frontend",
                        "endpoints": [
                            {
                                "id": "frontend-a",
                                "address": "172.28.0.10:8080",
                                "state": "ready",
                                "zone": null,
                                "locality": null,
                                "weight": 1
                            }
                        ]
                    }
                ]
            }"#,
        )?;

        let runtime_config = serve_runtime_config_from_workspace(&config)?;
        assert_eq!(runtime_config.public_addr, "0.0.0.0:8080".parse()?);
        assert_eq!(runtime_config.admin_addr, "0.0.0.0:9900".parse()?);
        assert_eq!(runtime_config.upstream_addr, "172.28.0.10:8080".parse()?);
        assert_eq!(runtime_config.route_rules.len(), 1);
        assert_eq!(runtime_config.route_rules[0].hostnames, vec![String::from("example.com")]);
        assert_eq!(runtime_config.route_upstreams.len(), 1);
        assert_eq!(runtime_config.route_upstreams[0].route_label, "web");
        assert_eq!(runtime_config.route_upstreams[0].upstream.address, "172.28.0.10:8080".parse()?);
        assert!(!runtime_config.spawn_demo_upstream);
        Ok(())
    }

    #[test]
    fn resolve_serve_runtime_config_defaults_to_builtin_demo(
    ) -> Result<(), Box<dyn std::error::Error>> {
        std::env::remove_var("LB_PUBLIC_PORT");
        std::env::remove_var("LB_ADMIN_PORT");
        std::env::remove_var("LB_DEMO_UPSTREAM_PORT");

        let runtime_config = resolve_serve_runtime_config(&ServeArgs::default())?;
        assert_eq!(runtime_config.public_addr, "127.0.0.1:8080".parse()?);
        assert_eq!(runtime_config.admin_addr, "127.0.0.1:9900".parse()?);
        assert_eq!(runtime_config.upstream_addr, "127.0.0.1:18080".parse()?);
        assert!(runtime_config.route_rules.is_empty());
        assert!(runtime_config.route_upstreams.is_empty());
        assert!(runtime_config.spawn_demo_upstream);
        Ok(())
    }

    #[test]
    fn serve_runtime_config_from_workspace_keeps_all_cluster_endpoints(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = lb_config_model::WorkspaceConfig::parse_json_str(
            r#"{
                "api_version": "v1_alpha1",
                "name": "multi-endpoint-demo",
                "listeners": [
                    {
                        "name": "public-web",
                        "class": "public",
                        "bind_address": "127.0.0.1:8080",
                        "protocol": "http1",
                        "routes": ["web"]
                    },
                    {
                        "name": "admin-http",
                        "class": "admin",
                        "bind_address": "127.0.0.1:9900",
                        "protocol": "http1"
                    }
                ],
                "routes": [
                    {
                        "name": "web",
                        "match": { "type": "path_prefix", "prefix": "/" },
                        "upstream_cluster": "frontend"
                    }
                ],
                "upstream_clusters": [
                    {
                        "name": "frontend",
                        "endpoints": [
                            {
                                "id": "frontend-a",
                                "address": "127.0.0.1:8081",
                                "state": "ready",
                                "zone": null,
                                "locality": null,
                                "weight": 1
                            },
                            {
                                "id": "frontend-b",
                                "address": "127.0.0.1:8082",
                                "state": "ready",
                                "zone": null,
                                "locality": null,
                                "weight": 1
                            }
                        ]
                    }
                ]
            }"#,
        )?;

        let runtime_config = serve_runtime_config_from_workspace(&config)?;

        assert_eq!(runtime_config.route_upstreams.len(), 2);
        assert_eq!(runtime_config.route_upstreams[0].upstream.address, "127.0.0.1:8081".parse()?);
        assert_eq!(runtime_config.route_upstreams[1].upstream.address, "127.0.0.1:8082".parse()?);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_http_request_head_reads_complete_request(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let request = async {
            tokio::io::AsyncWriteExt::write_all(
                &mut client,
                b"GET /demo HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .await?;
            tokio::io::AsyncWriteExt::shutdown(&mut client).await
        };
        let read = read_http_request_head(&mut server);
        let ((), parsed) = tokio::try_join!(request, read)?;

        let parsed = parsed.ok_or("request should be present")?;
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.target, "/demo");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_http_request_head_and_body_reads_json_payload(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let request = async {
            tokio::io::AsyncWriteExt::write_all(
                &mut client,
                b"POST /cache/purge HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\n{\"scope\":1}",
            )
            .await?;
            tokio::io::AsyncWriteExt::shutdown(&mut client).await
        };
        let read = read_http_request_head_and_body(&mut server);
        let ((), parsed) = tokio::try_join!(request, read)?;

        let (parsed, body) = parsed.ok_or("request should be present")?;
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/cache/purge");
        assert_eq!(std::str::from_utf8(&body)?, "{\"scope\":1}");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_http_requires_authorization_and_exposes_status(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = Arc::new(DemoServeState::new(
            "127.0.0.1:8080".parse()?,
            "127.0.0.1:9900".parse()?,
            "127.0.0.1:18080".parse()?,
        ));
        state.proxied_connections.store(2, Ordering::SeqCst);
        state.proxied_requests.store(3, Ordering::SeqCst);

        let (mut unauthorized_client, mut unauthorized_server) = tokio::io::duplex(4096);
        let unauthorized_write = async {
            tokio::io::AsyncWriteExt::write_all(
                &mut unauthorized_client,
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .await?;
            tokio::io::AsyncWriteExt::shutdown(&mut unauthorized_client).await
        };
        let unauthorized_serve = serve_admin_http(&mut unauthorized_server, &state, "admin-secret");
        let ((), ()) = tokio::try_join!(unauthorized_write, unauthorized_serve)?;
        let mut unauthorized_response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut unauthorized_client, &mut unauthorized_response)
            .await?;
        let unauthorized_response = String::from_utf8(unauthorized_response)?;
        assert!(unauthorized_response.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(unauthorized_response.contains("WWW-Authenticate: Bearer"));

        let (mut health_client, mut health_server) = tokio::io::duplex(4096);
        let health_write = async {
            tokio::io::AsyncWriteExt::write_all(
                &mut health_client,
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\n\r\n",
            )
            .await?;
            tokio::io::AsyncWriteExt::shutdown(&mut health_client).await
        };
        let health_serve = serve_admin_http(&mut health_server, &state, "admin-secret");
        let ((), ()) = tokio::try_join!(health_write, health_serve)?;
        let mut health_response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut health_client, &mut health_response).await?;
        let health_response = String::from_utf8(health_response)?;
        assert!(health_response.starts_with("HTTP/1.1 200 OK"));
        assert!(health_response.ends_with("ok\n"));

        let (mut status_client, mut status_server) = tokio::io::duplex(4096);
        let status_write = async {
            tokio::io::AsyncWriteExt::write_all(
                &mut status_client,
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\n\r\n",
            )
            .await?;
            tokio::io::AsyncWriteExt::shutdown(&mut status_client).await
        };
        let status_serve = serve_admin_http(&mut status_server, &state, "admin-secret");
        let ((), ()) = tokio::try_join!(status_write, status_serve)?;
        let mut status_response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut status_client, &mut status_response).await?;
        let status_response = String::from_utf8(status_response)?;
        assert!(status_response.starts_with("HTTP/1.1 200 OK"));
        assert!(status_response.contains("\"public_listener\": \"127.0.0.1:8080\""));
        assert!(status_response.contains("\"upstream_target\": \"127.0.0.1:18080\""));
        assert!(status_response.contains("\"proxied_requests\": 3"));

        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn demo_upstream_returns_json_payload() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let write = async {
            tokio::io::AsyncWriteExt::write_all(
                &mut client,
                b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .await?;
            tokio::io::AsyncWriteExt::shutdown(&mut client).await
        };
        let serve = serve_demo_upstream_http(&mut server);
        let ((), ()) = tokio::try_join!(write, serve)?;
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response).await?;
        let response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"service\": \"demo-upstream\""));
        assert!(response.contains("\"path\": \"/hello\""));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_listeners_proxy_and_report_status_end_to_end(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let public_listener = TcpListener::bind("127.0.0.1:0").await?;
        let public_addr = public_listener.local_addr()?;
        let admin_listener = TcpListener::bind("127.0.0.1:0").await?;
        let admin_addr = admin_listener.local_addr()?;
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
        let upstream_addr = upstream_listener.local_addr()?;

        let state = Arc::new(DemoServeState::new(public_addr, admin_addr, upstream_addr));
        let public_task = tokio::spawn(run_public_proxy_listener(
            public_listener,
            lb_runtime::Http1ProxyConfig::new(lb_net_core::UpstreamTarget::new(
                "demo-upstream",
                upstream_addr,
            )),
            Arc::clone(&state),
        ));
        let admin_task = tokio::spawn(run_admin_listener(
            admin_listener,
            Arc::clone(&state),
            Arc::new(String::from("admin-secret")),
        ));
        let upstream_task = tokio::spawn(run_demo_upstream_listener(upstream_listener));

        let mut public_client = TcpStream::connect(public_addr).await?;
        public_client
            .write_all(b"GET /demo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut public_response = Vec::new();
        public_client.read_to_end(&mut public_response).await?;
        let public_response = String::from_utf8(public_response)?;
        assert!(public_response.starts_with("HTTP/1.1 200 OK"));
        assert!(public_response.contains("\"path\": \"/demo\""));

        let mut admin_client = TcpStream::connect(admin_addr).await?;
        admin_client
            .write_all(
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut admin_response = Vec::new();
        admin_client.read_to_end(&mut admin_response).await?;
        let admin_response = String::from_utf8(admin_response)?;
        assert!(admin_response.starts_with("HTTP/1.1 200 OK"));
        assert!(admin_response.contains("\"proxied_connections\": 1"));
        assert!(admin_response.contains("\"proxied_requests\": 1"));

        public_task.abort();
        admin_task.abort();
        upstream_task.abort();
        let _ = public_task.await;
        let _ = admin_task.await;
        let _ = upstream_task.await;
        Ok(())
    }

    #[test]
    fn binary_smoke_runs_successfully() -> Result<(), Box<dyn std::error::Error>> {
        std::env::set_var(
            "LB_CONTROL_PLANE_SIGNING_KEY_ED25519",
            lb_test_support::TEST_SIGNING_KEY_ED25519,
        );
        super::smoke_main()
    }
}
