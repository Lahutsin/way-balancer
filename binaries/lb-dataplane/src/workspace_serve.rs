use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fs;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use rustls::server::{ProducesTickets, ResolvesServerCert};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, watch};
use tokio::task::JoinSet;
use tokio::time;
use tokio_rustls::TlsAcceptor;

use crate::{ServeArgs, admin_bearer_secret, compile_anonymous_source_filter, compile_trusted_client_ip};

type DynError = Box<dyn Error + Send + Sync>;

static TLS12_AND_TLS13: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS13, &rustls::version::TLS12];
static TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
const ACTIVE_HEALTH_PROBE_INTERVAL: Duration = Duration::from_millis(500);
const ACTIVE_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_millis(150);
const ROUTE_BACKEND_WARMUP_DURATION: Duration = Duration::from_secs(1);
const ADMIN_AUDIT_DEFAULT_CAPACITY: usize = 64;

fn to_dyn_error(error: impl std::fmt::Display) -> DynError {
    Box::new(io::Error::other(error.to_string()))
}

#[derive(Debug)]
struct FallbackServerCertResolver {
    default_key: Arc<rustls::sign::CertifiedKey>,
    sni_keys: BTreeMap<String, Arc<rustls::sign::CertifiedKey>>,
}

#[derive(Debug)]
struct DisabledTicketer;

impl ProducesTickets for DisabledTicketer {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

impl ResolvesServerCert for FallbackServerCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        client_hello
            .server_name()
            .and_then(|name| self.sni_keys.get(&name.to_ascii_lowercase()).cloned())
            .or_else(|| Some(Arc::clone(&self.default_key)))
    }
}

#[derive(Debug, Clone)]
enum ManagedProxyConfig {
    Http1(lb_runtime::Http1ProxyConfig),
    Http2(lb_runtime::Http2ProxyConfig),
    Https(ManagedHttpsProxyConfig),
}

#[derive(Debug, Clone)]
struct ManagedHttpsProxyConfig {
    http1: lb_runtime::Http1ProxyConfig,
    http2: lb_runtime::Http2ProxyConfig,
    tls_server_config: Arc<rustls::ServerConfig>,
}

#[derive(Debug, Clone)]
struct CompiledListenerOverloadPolicy {
    signal_window: Duration,
    constrained_signal_threshold: u64,
    shedding_signal_threshold: u64,
    brownout_signal_threshold: u64,
    brownout_features: Vec<CompiledBrownoutFeature>,
}

#[derive(Debug, Clone)]
struct CompiledBrownoutFeature {
    name: String,
    priority: lb_runtime::TrafficClass,
}

#[derive(Debug)]
struct ListenerOverloadRuntime {
    manager: lb_runtime::OverloadManager,
}

impl ListenerOverloadRuntime {
    fn new(policy: &CompiledListenerOverloadPolicy) -> Result<Self, DynError> {
        Ok(Self {
            manager: lb_runtime::OverloadManager::new(
                lb_runtime::OverloadPolicy {
                    signal_window: policy.signal_window,
                    constrained_signal_threshold: policy.constrained_signal_threshold,
                    shedding_signal_threshold: policy.shedding_signal_threshold,
                    brownout_signal_threshold: policy.brownout_signal_threshold,
                },
                lb_runtime::BrownoutHookRegistry::new(
                    policy
                        .brownout_features
                        .iter()
                        .map(|feature| lb_runtime::BrownoutFeature {
                            name: feature.name.clone(),
                            priority: feature.priority,
                        })
                        .collect(),
                )
                .map_err(to_dyn_error)?,
            )
            .map_err(to_dyn_error)?,
        })
    }

    fn record_concurrency_signal(
        &self,
        observed_at: Duration,
    ) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
        let snapshot = self.manager.record_signal(
            observed_at,
            lb_runtime::OverloadSignal {
                concurrency_limited: true,
                ..lb_runtime::OverloadSignal::default()
            },
        );
        (snapshot, self.manager.disabled_features().into_iter().collect())
    }

    fn snapshot(&self, observed_at: Duration) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
        let snapshot = self.manager.snapshot(observed_at);
        (snapshot, self.manager.disabled_features().into_iter().collect())
    }

    fn recent_events(&self) -> Vec<lb_observability::OverloadEvent> {
        self.manager.recent_events()
    }
}

#[derive(Debug)]
struct ListenerRuntimeCounters {
    accepted_connections: AtomicU64,
    shed_connections: AtomicU64,
    active_connections: AtomicUsize,
    completed_connections: AtomicU64,
    overload_state: AtomicUsize,
    state: RwLock<String>,
}

impl ListenerRuntimeCounters {
    fn new() -> Self {
        Self {
            accepted_connections: AtomicU64::new(0),
            shed_connections: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            completed_connections: AtomicU64::new(0),
            overload_state: AtomicUsize::new(overload_state_index(lb_runtime::OverloadState::Normal)),
            state: RwLock::new(String::from("starting")),
        }
    }
}

#[derive(Debug)]
enum ManagedListenerKind {
    Public { shared_proxy: Arc<RwLock<ManagedProxyConfig>> },
    Admin { runtime: AdminRuntimeHandles },
}

#[derive(Debug, Clone)]
struct AdminRuntimeHandles {
    shared_policy: Arc<RwLock<CompiledAdminPolicy>>,
    rate_limit_state: Arc<StdMutex<AdminRateLimitState>>,
    replay_state: Arc<StdMutex<AdminReplayState>>,
}

#[derive(Debug, Clone)]
struct CompiledAdminPolicy {
    auth: CompiledAdminAuthPolicy,
    allowed_source_cidrs: Vec<IpNet>,
    rate_limit: CompiledAdminRateLimit,
    audit_capacity: usize,
}

#[derive(Debug, Clone)]
enum CompiledAdminAuthPolicy {
    Bearer {
        secret_env: String,
        permissions: BTreeSet<AdminPermission>,
    },
    SignedHeaders {
        operators: BTreeMap<String, CompiledAdminOperator>,
        max_clock_skew: Duration,
        nonce_ttl: Duration,
    },
}

#[derive(Debug, Clone)]
struct CompiledAdminOperator {
    secret_env: String,
    permissions: BTreeSet<AdminPermission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AdminPermission {
    Read,
    Audit,
    Write,
}

#[derive(Debug, Clone, Copy)]
struct CompiledAdminRateLimit {
    requests_per_minute: u32,
    burst: u32,
}

#[derive(Debug, Default)]
struct AdminRateLimitState {
    buckets: BTreeMap<AdminRateLimitKey, AdminTokenBucket>,
}

#[derive(Debug, Clone, Copy)]
struct AdminTokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AdminRateLimitKey {
    source: IpAddr,
    actor: String,
    auth_mode: String,
}

#[derive(Debug, Default)]
struct AdminReplayState {
    nonces: BTreeMap<String, Instant>,
}

#[derive(Debug, Clone, Serialize)]
struct AdminAuditEvent {
    observed_at_unix_ms: u64,
    request_id: String,
    listener: String,
    actor: String,
    auth_mode: String,
    action: String,
    source: String,
    outcome: String,
    detail: String,
}

#[derive(Debug, Clone)]
struct AdminRequestContext {
    request_id: String,
    actor: String,
    auth_mode: String,
    source: IpAddr,
}

#[derive(Debug, Clone, Copy)]
enum AdminRequestAction {
    Healthz,
    Status,
    Validate,
    Audit,
    Reload,
    Unknown,
}

impl AdminRequestAction {
    fn permission(self) -> AdminPermission {
        match self {
            Self::Audit => AdminPermission::Audit,
            Self::Reload => AdminPermission::Write,
            Self::Healthz | Self::Status | Self::Validate | Self::Unknown => {
                AdminPermission::Read
            }
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Healthz => "healthz",
            Self::Status => "status",
            Self::Validate => "validate",
            Self::Audit => "audit",
            Self::Reload => "reload",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug)]
struct ManagedServeListener {
    name: String,
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    configured_bind: SocketAddr,
    local_addr: SocketAddr,
    drain_timeout: Duration,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    counters: Arc<ListenerRuntimeCounters>,
    kind: ManagedListenerKind,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<io::Result<()>>,
    probe_task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone)]
enum CompiledServeListener {
    Public {
        class: lb_config_model::ListenerClassConfig,
        protocol: lb_config_model::ListenerProtocolConfig,
        bind_address: SocketAddr,
        max_connections: usize,
        drain_timeout: Duration,
        overload_policy: Option<CompiledListenerOverloadPolicy>,
        proxy: ManagedProxyConfig,
    },
    Admin {
        bind_address: SocketAddr,
        max_connections: usize,
        drain_timeout: Duration,
        overload_policy: Option<CompiledListenerOverloadPolicy>,
        admin_policy: CompiledAdminPolicy,
    },
}

impl CompiledServeListener {
    fn class(&self) -> lb_config_model::ListenerClassConfig {
        match self {
            Self::Public { class, .. } => *class,
            Self::Admin { .. } => lb_config_model::ListenerClassConfig::Admin,
        }
    }

    fn protocol(&self) -> lb_config_model::ListenerProtocolConfig {
        match self {
            Self::Public { protocol, .. } => *protocol,
            Self::Admin { .. } => lb_config_model::ListenerProtocolConfig::Http1,
        }
    }

    fn bind_address(&self) -> SocketAddr {
        match self {
            Self::Public { bind_address, .. } | Self::Admin { bind_address, .. } => *bind_address,
        }
    }

    fn drain_timeout(&self) -> Duration {
        match self {
            Self::Public { drain_timeout, .. } | Self::Admin { drain_timeout, .. } => *drain_timeout,
        }
    }

    fn max_connections(&self) -> usize {
        match self {
            Self::Public { max_connections, .. } | Self::Admin { max_connections, .. } => *max_connections,
        }
    }

    fn overload_policy(&self) -> Option<&CompiledListenerOverloadPolicy> {
        match self {
            Self::Public { overload_policy, .. } | Self::Admin { overload_policy, .. } => {
                overload_policy.as_ref()
            }
        }
    }
}

#[derive(Debug)]
struct CompiledWorkspaceRuntime {
    source_label: String,
    snapshot: lb_config_model::WorkspaceSnapshot,
    listeners: BTreeMap<String, CompiledServeListener>,
}

#[derive(Debug)]
struct WorkspaceServeState {
    started_at: Instant,
    config_path: String,
    telemetry: lb_runtime::RuntimeTelemetry,
    proxied_connections: AtomicU64,
    proxied_requests: AtomicU64,
    admin_requests: AtomicU64,
    reload_requests: AtomicU64,
    reload_success_count: AtomicU64,
    reload_failure_count: AtomicU64,
    admin_audit_sequence: AtomicU64,
    admin_audit_capacity: AtomicUsize,
    last_reload_result: Mutex<String>,
    recent_admin_audit: Mutex<VecDeque<AdminAuditEvent>>,
}

impl WorkspaceServeState {
    fn new(config_path: String) -> Result<Self, DynError> {
        Ok(Self {
            started_at: Instant::now(),
            config_path,
            telemetry: lb_runtime::RuntimeTelemetry::new().map_err(to_dyn_error)?,
            proxied_connections: AtomicU64::new(0),
            proxied_requests: AtomicU64::new(0),
            admin_requests: AtomicU64::new(0),
            reload_requests: AtomicU64::new(0),
            reload_success_count: AtomicU64::new(0),
            reload_failure_count: AtomicU64::new(0),
            admin_audit_sequence: AtomicU64::new(1),
            admin_audit_capacity: AtomicUsize::new(ADMIN_AUDIT_DEFAULT_CAPACITY),
            last_reload_result: Mutex::new(String::from("not requested")),
            recent_admin_audit: Mutex::new(VecDeque::new()),
        })
    }

    async fn status_body(&self, supervisor: &ServeSupervisor) -> String {
        let listener_statuses = supervisor.listener_statuses().await;
        let last_reload_result = self.last_reload_result.lock().await.clone();
        let listeners_json = listener_statuses
            .iter()
            .map(ListenerStatus::to_json)
            .collect::<Vec<_>>()
            .join(",\n");
        let overload_events_json = self
            .telemetry
            .snapshot()
            .events
            .into_iter()
            .filter(|event| event.category == lb_observability::TelemetryEventCategory::Overload)
            .map(|event| OverloadEventStatus::from_telemetry(event).to_json())
            .collect::<Vec<_>>()
            .join(",\n");

        format!(
            concat!(
                "{{\n",
                "  \"service\": \"lb-dataplane\",\n",
                "  \"mode\": \"workspace\",\n",
                "  \"config_path\": \"{}\",\n",
                "  \"uptime_secs\": {},\n",
                "  \"proxied_connections\": {},\n",
                "  \"proxied_requests\": {},\n",
                "  \"admin_requests\": {},\n",
                "  \"reload_requests\": {},\n",
                "  \"reload_success_count\": {},\n",
                "  \"reload_failure_count\": {},\n",
                "  \"admin_audit_events\": {},\n",
                "  \"last_reload_result\": \"{}\",\n",
                "  \"listeners\": [\n{}\n  ],\n",
                "  \"recent_overload_events\": [\n{}\n  ]\n",
                "}}\n"
            ),
            crate::escape_json_string(&self.config_path),
            self.started_at.elapsed().as_secs(),
            self.proxied_connections.load(Ordering::SeqCst),
            self.proxied_requests.load(Ordering::SeqCst),
            self.admin_requests.load(Ordering::SeqCst),
            self.reload_requests.load(Ordering::SeqCst),
            self.reload_success_count.load(Ordering::SeqCst),
            self.reload_failure_count.load(Ordering::SeqCst),
            self.recent_admin_audit.lock().await.len(),
            crate::escape_json_string(&last_reload_result),
            if listeners_json.is_empty() {
                String::new()
            } else {
                format!("    {listeners_json}")
            },
            if overload_events_json.is_empty() {
                String::new()
            } else {
                format!("    {overload_events_json}")
            },
        )
    }

    fn record_overload_event(
        &self,
        listener_name: &str,
        kind: lb_observability::OverloadEventKind,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        let scope = overload_scope(listener_name);
        if let Err(error) = self.telemetry.record_overload_event(&lb_observability::OverloadEvent {
            kind,
            scope,
            detail,
        }) {
            eprintln!("overload telemetry emission failed: {error}");
        }
    }

    fn set_admin_audit_capacity(&self, capacity: usize) {
        self.admin_audit_capacity
            .store(capacity.max(1), Ordering::SeqCst);
    }

    async fn record_admin_audit(&self, event: AdminAuditEvent) {
        let max_events = self.admin_audit_capacity.load(Ordering::SeqCst).max(1);
        let mut recent = self.recent_admin_audit.lock().await;
        recent.push_back(event);
        while recent.len() > max_events {
            recent.pop_front();
        }
    }

    async fn audit_body(&self) -> Result<String, DynError> {
        let recent = self.recent_admin_audit.lock().await;
        serde_json::to_string_pretty(&recent.iter().cloned().collect::<Vec<_>>())
            .map_err(to_dyn_error)
    }

    fn next_admin_request_id(&self) -> String {
        format!(
            "admin-{:016x}",
            self.admin_audit_sequence.fetch_add(1, Ordering::SeqCst)
        )
    }

    fn sync_listener_overload_snapshot(
        &self,
        listener_name: &str,
        counters: &ListenerRuntimeCounters,
        limit: usize,
        overload_runtime: &StdMutex<Option<ListenerOverloadRuntime>>,
        record_concurrency_signal: bool,
    ) {
        let (snapshot, _brownout_features) = snapshot_listener_overload(
            self.started_at.elapsed(),
            counters,
            limit,
            overload_runtime,
            record_concurrency_signal,
        );
        let next_state = overload_state_index(snapshot.state);
        let previous_state = counters.overload_state.swap(next_state, Ordering::SeqCst);
        if previous_state != next_state {
            self.record_overload_event(
                listener_name,
                lb_observability::OverloadEventKind::StateChanged,
                format!("listener overload state transitioned to {:?}", snapshot.state),
            );
        }
        if let Err(error) = self.telemetry.record_overload_snapshot(
            &overload_scope(listener_name),
            &snapshot,
        ) {
            eprintln!("overload snapshot emission failed: {error}");
        }
    }
}

#[derive(Debug, Clone)]
struct OverloadEventStatus {
    code: String,
    scope: String,
    detail: String,
}

impl OverloadEventStatus {
    fn from_telemetry(event: lb_observability::TelemetryEvent) -> Self {
        Self {
            code: String::from(event.code.as_str()),
            scope: event.scope,
            detail: event.detail,
        }
    }

    fn from_overload_event(event: lb_observability::OverloadEvent) -> Self {
        Self {
            code: String::from(match event.kind {
                lb_observability::OverloadEventKind::StateChanged => "overload.state.changed",
                lb_observability::OverloadEventKind::RequestShed => "overload.request.shed",
                lb_observability::OverloadEventKind::BrownoutFeaturesChanged => {
                    "overload.brownout.features_changed"
                }
            }),
            scope: event.scope,
            detail: event.detail,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"code\":\"{}\",\"scope\":\"{}\",\"detail\":\"{}\"}}",
            crate::escape_json_string(&self.code),
            crate::escape_json_string(&self.scope),
            crate::escape_json_string(&self.detail),
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ServeSupervisor {
    shared: Arc<ServeSupervisorShared>,
}

#[derive(Debug)]
struct ServeSupervisorShared {
    config_path: String,
    admin_secret: Arc<String>,
    state: Arc<WorkspaceServeState>,
    reload_guard: Mutex<()>,
    inner: Mutex<ServeSupervisorInner>,
}

#[derive(Debug, Default)]
struct ServeSupervisorInner {
    source_label: String,
    active_snapshot: Option<lb_config_model::WorkspaceSnapshot>,
    listeners: BTreeMap<String, ManagedServeListener>,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigSafetyWarning {
    code: String,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigApplyPreview {
    strategy: String,
    rollback_safe: bool,
    summary: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigCompatibilityPreview {
    active_api_version: Option<lb_config_model::ConfigApiVersion>,
    candidate_api_version: lb_config_model::ConfigApiVersion,
    snapshot_format_version: String,
    migration_strategy: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigValidationPreview {
    config_path: String,
    active_snapshot: Option<lb_config_model::WorkspaceSnapshotView>,
    candidate_snapshot: lb_config_model::WorkspaceSnapshotView,
    diff_preview: Option<lb_config_model::WorkspaceSnapshotDiff>,
    warnings: Vec<ConfigSafetyWarning>,
    apply_preview: ConfigApplyPreview,
    compatibility: ConfigCompatibilityPreview,
}

#[derive(Debug, Clone)]
struct ListenerStatus {
    name: String,
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    configured_bind: SocketAddr,
    local_addr: SocketAddr,
    state: String,
    overload_state: String,
    accepted_connections: u64,
    active_connections: usize,
    completed_connections: u64,
    shed_connections: u64,
    brownout_features: Vec<String>,
    recent_overload_events: Vec<OverloadEventStatus>,
}

impl ListenerStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"name\":\"{}\",",
                "\"class\":\"{}\",",
                "\"protocol\":\"{}\",",
                "\"configured_bind\":\"{}\",",
                "\"local_addr\":\"{}\",",
                "\"state\":\"{}\",",
                "\"overload_state\":\"{}\",",
                "\"accepted_connections\":{},",
                "\"active_connections\":{},",
                "\"shed_connections\":{},",
                "\"completed_connections\":{},",
                "\"brownout_features\":[{}],",
                "\"recent_overload_events\":[{}]",
                "}}"
            ),
            crate::escape_json_string(&self.name),
            listener_class_name(self.class),
            listener_protocol_name(self.protocol),
            self.configured_bind,
            self.local_addr,
            crate::escape_json_string(&self.state),
            crate::escape_json_string(&self.overload_state),
            self.accepted_connections,
            self.active_connections,
            self.shed_connections,
            self.completed_connections,
            self.brownout_features
                .iter()
                .map(|feature| format!("\"{}\"", crate::escape_json_string(feature)))
                .collect::<Vec<_>>()
                .join(","),
            self.recent_overload_events
                .iter()
                .map(OverloadEventStatus::to_json)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

impl ConfigValidationPreview {
    fn render_json(&self) -> Result<String, DynError> {
        serde_json::to_string_pretty(self).map_err(to_dyn_error)
    }
}

pub(crate) async fn serve_workspace_main(serve_args: &ServeArgs) -> Result<(), DynError> {
    let config_path = serve_args
        .config_path
        .clone()
        .ok_or("workspace serve mode requires a config path")?;
    let admin_secret = Arc::new(admin_bearer_secret().map_err(to_dyn_error)?);
    let supervisor = ServeSupervisor::start(config_path, admin_secret).await?;

    for status in supervisor.listener_statuses().await {
        match status.class {
            lb_config_model::ListenerClassConfig::Public => {
                println!(
                    "public listener ready: name={} protocol={} addr={}",
                    status.name,
                    listener_protocol_name(status.protocol),
                    status.local_addr
                );
            }
            lb_config_model::ListenerClassConfig::Admin => {
                println!(
                    "admin listener ready: name={} addr={}",
                    status.name,
                    status.local_addr
                );
            }
        }
    }
    println!("reload with POST /reload on an admin listener or send SIGHUP");
    println!("validate with GET /validate on an admin listener before reload");
    println!("press Ctrl+C to stop");

    #[cfg(unix)]
    {
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        loop {
            tokio::select! {
                ctrl_c = tokio::signal::ctrl_c() => {
                    ctrl_c?;
                    break;
                }
                _ = sighup.recv() => {
                    if let Err(error) = supervisor.reload().await {
                        eprintln!("reload failed: {error}");
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    supervisor.shutdown().await?;
    Ok(())
}

impl ServeSupervisor {
    async fn start(config_path: String, admin_secret: Arc<String>) -> Result<Self, DynError> {
        let state = Arc::new(WorkspaceServeState::new(config_path.clone())?);
        let supervisor = Self {
            shared: Arc::new(ServeSupervisorShared {
                config_path,
                admin_secret,
                state,
                reload_guard: Mutex::new(()),
                inner: Mutex::new(ServeSupervisorInner::default()),
            }),
        };
        supervisor.reload().await?;
        Ok(supervisor)
    }

    fn reload(&self) -> Pin<Box<dyn Future<Output = Result<(), DynError>> + Send + '_>> {
        Box::pin(async move {
            let _guard = self.shared.reload_guard.lock().await;
            self.shared.state.reload_requests.fetch_add(1, Ordering::SeqCst);

            let compiled = compile_workspace_runtime(&self.shared.config_path)?;
            let result = self.apply_compiled_runtime(compiled).await;
            match &result {
                Ok(()) => {
                    self.shared.state.reload_success_count.fetch_add(1, Ordering::SeqCst);
                    *self.shared.state.last_reload_result.lock().await =
                        String::from("configuration applied");
                }
                Err(error) => {
                    self.shared.state.reload_failure_count.fetch_add(1, Ordering::SeqCst);
                    *self.shared.state.last_reload_result.lock().await = error.to_string();
                }
            }
            result
        })
    }

    async fn validate_current_config(&self) -> Result<ConfigValidationPreview, DynError> {
        let (active_snapshot, current_identities) = {
            let inner = self.shared.inner.lock().await;
            let current_identities = inner
                .listeners
                .iter()
                .map(|(name, listener)| {
                    (
                        name.clone(),
                        (
                            listener.class,
                            listener.protocol,
                            listener.configured_bind,
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            (inner.active_snapshot.clone(), current_identities)
        };
        let candidate = compile_workspace_runtime(&self.shared.config_path)?;

        Ok(build_config_validation_preview(
            &self.shared.config_path,
            active_snapshot.as_ref(),
            &current_identities,
            &candidate,
        ))
    }

    async fn apply_compiled_runtime(
        &self,
        compiled: CompiledWorkspaceRuntime,
    ) -> Result<(), DynError> {
        self.shared.state.set_admin_audit_capacity(
            compiled
                .listeners
                .values()
                .filter_map(|listener| match listener {
                    CompiledServeListener::Admin { admin_policy, .. } => Some(admin_policy.audit_capacity),
                    CompiledServeListener::Public { .. } => None,
                })
                .max()
                .unwrap_or(ADMIN_AUDIT_DEFAULT_CAPACITY),
        );
        let current_identities = {
            let inner = self.shared.inner.lock().await;
            inner
                .listeners
                .iter()
                .map(|(name, listener)| {
                    (
                        name.clone(),
                        (
                            listener.class,
                            listener.protocol,
                            listener.configured_bind,
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };

        let mut start_specs = Vec::new();
        for (name, spec) in &compiled.listeners {
            match current_identities.get(name) {
                Some((class, protocol, bind_address))
                    if *class == spec.class()
                        && *protocol == spec.protocol()
                        && *bind_address == spec.bind_address() => {}
                Some((_, _, bind_address)) if *bind_address == spec.bind_address() => {
                    return Err(format!(
                        "reload would require rebinding active listener {name} on {}; zero-downtime replacement is not available for this change",
                        bind_address
                    )
                    .into());
                }
                _ => start_specs.push((name.clone(), spec.clone())),
            }
        }

        let mut started = Vec::new();
        for (name, spec) in start_specs {
            let handle = start_managed_listener(
                name.clone(),
                spec,
                Arc::clone(&self.shared.state),
                self.clone(),
            )
            .await?;
            started.push((name, handle));
        }

        let mut retired = Vec::new();
        {
            let mut inner = self.shared.inner.lock().await;

            for (name, spec) in &compiled.listeners {
                if let Some(listener) = inner.listeners.get_mut(name) {
                    if listener.can_update_in_place(spec) {
                        listener.apply_update(spec).await?;
                    }
                }
            }

            let retired_names = inner
                .listeners
                .keys()
                .filter(|name| !compiled.listeners.contains_key(*name))
                .cloned()
                .collect::<Vec<_>>();
            for name in retired_names {
                if let Some(listener) = inner.listeners.remove(&name) {
                    retired.push(listener);
                }
            }

            for (name, _) in &started {
                if let Some(listener) = inner.listeners.remove(name) {
                    retired.push(listener);
                }
            }
            for (name, listener) in started {
                inner.listeners.insert(name, listener);
            }
            inner.source_label = compiled.source_label;
            inner.active_snapshot = Some(compiled.snapshot);
        }

        for listener in retired {
            listener.shutdown().await?;
        }

        Ok(())
    }

    async fn shutdown(&self) -> Result<(), DynError> {
        let listeners = {
            let mut inner = self.shared.inner.lock().await;
            std::mem::take(&mut inner.listeners).into_values().collect::<Vec<_>>()
        };
        for listener in listeners {
            listener.shutdown().await?;
        }
        Ok(())
    }

    async fn listener_statuses(&self) -> Vec<ListenerStatus> {
        let listeners = {
            let inner = self.shared.inner.lock().await;
            inner
                .listeners
                .values()
                .map(|listener| {
                    (
                        listener.name.clone(),
                        listener.class,
                        listener.protocol,
                        listener.configured_bind,
                        listener.local_addr,
                        Arc::clone(&listener.counters),
                        Arc::clone(&listener.overload_runtime),
                    )
                })
                .collect::<Vec<_>>()
        };

        let mut statuses = Vec::with_capacity(listeners.len());
        for (name, class, protocol, configured_bind, local_addr, counters, overload_runtime) in listeners {
            let (overload_state, brownout_features, recent_overload_events) = snapshot_listener_overload_status(
                self.shared.state.started_at.elapsed(),
                &counters,
                &overload_runtime,
            );
            statuses.push(ListenerStatus {
                name,
                class,
                protocol,
                configured_bind,
                local_addr,
                state: counters.state.read().await.clone(),
                overload_state: String::from(overload_state_name(overload_state)),
                accepted_connections: counters.accepted_connections.load(Ordering::SeqCst),
                active_connections: counters.active_connections.load(Ordering::SeqCst),
                shed_connections: counters.shed_connections.load(Ordering::SeqCst),
                completed_connections: counters.completed_connections.load(Ordering::SeqCst),
                brownout_features,
                recent_overload_events,
            });
        }
        statuses
    }
}

impl ManagedServeListener {
    fn can_update_in_place(&self, spec: &CompiledServeListener) -> bool {
        self.class == spec.class()
            && self.protocol == spec.protocol()
            && self.configured_bind == spec.bind_address()
    }

    async fn apply_update(&mut self, spec: &CompiledServeListener) -> Result<(), DynError> {
        self.drain_timeout = spec.drain_timeout();
        self.admission_limit.store(spec.max_connections(), Ordering::SeqCst);
        *self
            .overload_runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            build_listener_overload_runtime(spec.overload_policy())?;
        if let (ManagedListenerKind::Public { shared_proxy }, CompiledServeListener::Public { proxy, .. }) =
            (&self.kind, spec)
        {
            *shared_proxy.write().await = proxy.clone();
        } else if let (
            ManagedListenerKind::Admin { runtime },
            CompiledServeListener::Admin { admin_policy, .. },
        ) = (&self.kind, spec)
        {
            *runtime.shared_policy.write().await = admin_policy.clone();
        }
        Ok(())
    }

    async fn shutdown(self) -> io::Result<()> {
        let _ = self.shutdown_tx.send(true);
        self.join().await
    }

    async fn join(self) -> io::Result<()> {
        match self.task.await {
            Ok(result) => result?,
            Err(error) => return Err(io::Error::other(error.to_string())),
        }
        if let Some(probe_task) = self.probe_task {
            probe_task.await.map_err(|error| io::Error::other(error.to_string()))?;
        }
        Ok(())
    }
}

async fn start_managed_listener(
    name: String,
    spec: CompiledServeListener,
    state: Arc<WorkspaceServeState>,
    supervisor: ServeSupervisor,
) -> Result<ManagedServeListener, DynError> {
    let listener = TcpListener::bind(spec.bind_address()).await?;
    let local_addr = listener.local_addr()?;
    let drain_timeout = spec.drain_timeout();
    let admission_limit = Arc::new(AtomicUsize::new(spec.max_connections()));
    let overload_runtime = Arc::new(StdMutex::new(build_listener_overload_runtime(spec.overload_policy())?));
    let counters = Arc::new(ListenerRuntimeCounters::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    match spec {
        CompiledServeListener::Public {
            class,
            protocol,
            bind_address,
            proxy,
            ..
        } => {
            let shared_proxy = Arc::new(RwLock::new(proxy));
            let task = tokio::spawn(run_public_listener_loop(
                listener,
                name.clone(),
                Arc::clone(&shared_proxy),
                Arc::clone(&admission_limit),
                Arc::clone(&overload_runtime),
                Arc::clone(&counters),
                Arc::clone(&state),
                shutdown_rx,
                drain_timeout,
            ));
            let probe_task = Some(tokio::spawn(run_active_health_probe_loop(
                Arc::clone(&shared_proxy),
                shutdown_tx.subscribe(),
            )));
            Ok(ManagedServeListener {
                name,
                class,
                protocol,
                configured_bind: bind_address,
                local_addr,
                drain_timeout,
                admission_limit,
                overload_runtime,
                counters,
                kind: ManagedListenerKind::Public { shared_proxy },
                shutdown_tx,
                task,
                probe_task,
            })
        }
        CompiledServeListener::Admin {
            bind_address,
            admin_policy,
            ..
        } => {
            let admin_runtime = AdminRuntimeHandles {
                shared_policy: Arc::new(RwLock::new(admin_policy)),
                rate_limit_state: Arc::new(StdMutex::new(AdminRateLimitState::default())),
                replay_state: Arc::new(StdMutex::new(AdminReplayState::default())),
            };
            let task = tokio::spawn(run_admin_listener_loop(
                listener,
                name.clone(),
                Arc::clone(&admission_limit),
                Arc::clone(&overload_runtime),
                Arc::clone(&counters),
                Arc::clone(&state),
                shutdown_rx,
                drain_timeout,
                admin_runtime.clone(),
                Arc::clone(&supervisor.shared.admin_secret),
                supervisor,
            ));
            Ok(ManagedServeListener {
                name,
                class: lb_config_model::ListenerClassConfig::Admin,
                protocol: lb_config_model::ListenerProtocolConfig::Http1,
                configured_bind: bind_address,
                local_addr,
                drain_timeout,
                admission_limit,
                overload_runtime,
                counters,
                kind: ManagedListenerKind::Admin { runtime: admin_runtime },
                shutdown_tx,
                task,
                probe_task: None,
            })
        }
    }
}

async fn run_active_health_probe_loop(
    shared_proxy: Arc<RwLock<ManagedProxyConfig>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = time::interval(ACTIVE_HEALTH_PROBE_INTERVAL);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    ticker.tick().await;
    let mut last_tick = Instant::now();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(last_tick);
                last_tick = now;
                let pools = {
                    let proxy = shared_proxy.read().await.clone();
                    collect_active_probe_pools(&proxy)
                };

                for pool in pools {
                    pool.advance_time(elapsed);
                    let probe_targets = match pool.active_probe_targets() {
                        Ok(probe_targets) => probe_targets,
                        Err(_) => continue,
                    };
                    for probe_target in probe_targets {
                        let probe_result = time::timeout(
                            ACTIVE_HEALTH_PROBE_TIMEOUT,
                            TcpStream::connect(probe_target.address),
                        )
                        .await;
                        match probe_result {
                            Ok(Ok(stream)) => {
                                drop(stream);
                                let _ = pool.note_active_success(&probe_target.endpoint_id);
                            }
                            _ => {
                                let _ = pool.note_active_failure(&probe_target.endpoint_id);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn collect_active_probe_pools(proxy: &ManagedProxyConfig) -> Vec<lb_runtime::RouteBackendPool> {
    let mut pools_by_cluster = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();
    let mut insert_pool = |pool: &lb_runtime::RouteBackendPool| {
        pools_by_cluster
            .entry(pool.cluster_name().to_string())
            .or_insert_with(|| pool.clone());
    };

    match proxy {
        ManagedProxyConfig::Http1(config) => {
            for pool in config.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
        ManagedProxyConfig::Http2(config) => {
            for pool in config.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
        ManagedProxyConfig::Https(config) => {
            for pool in config.http1.route_backend_pools.values() {
                insert_pool(pool);
            }
            for pool in config.http2.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
    }

    pools_by_cluster.into_values().collect()
}

async fn run_public_listener_loop(
    listener: TcpListener,
    listener_name: String,
    shared_proxy: Arc<RwLock<ManagedProxyConfig>>,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    counters: Arc<ListenerRuntimeCounters>,
    state: Arc<WorkspaceServeState>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
) -> io::Result<()> {
    *counters.state.write().await = String::from("running");
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut stream, peer_addr) = accepted?;
                counters.accepted_connections.fetch_add(1, Ordering::SeqCst);
                if !try_acquire_listener_slot(&counters, &admission_limit) {
                    counters.shed_connections.fetch_add(1, Ordering::SeqCst);
                    state.record_overload_event(
                        &listener_name,
                        lb_observability::OverloadEventKind::RequestShed,
                        format!(
                            "listener shed public connection at capacity {}",
                            admission_limit.load(Ordering::SeqCst)
                        ),
                    );
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        true,
                    );
                    let proxy = shared_proxy.read().await.clone();
                    if matches!(proxy, ManagedProxyConfig::Http1(_)) {
                        let _ = write_overload_response(&mut stream).await;
                    }
                    continue;
                }
                state.sync_listener_overload_snapshot(
                    &listener_name,
                    &counters,
                    admission_limit.load(Ordering::SeqCst),
                    &overload_runtime,
                    false,
                );
                let counters = Arc::clone(&counters);
                let state = Arc::clone(&state);
                let shared_proxy = Arc::clone(&shared_proxy);
                let listener_name = listener_name.clone();
                let admission_limit = Arc::clone(&admission_limit);
                let overload_runtime = Arc::clone(&overload_runtime);
                tasks.spawn(async move {
                    let proxy = shared_proxy.read().await.clone();
                    let result: io::Result<u64> = match proxy {
                        ManagedProxyConfig::Http1(config) => lb_runtime::proxy_http1_connection(stream, &config)
                            .await
                            .map(|report| report.metrics.request_count)
                            .map_err(|error| io::Error::other(error.to_string())),
                        ManagedProxyConfig::Http2(config) => lb_runtime::proxy_http2_connection(stream, &config)
                            .await
                            .map(|report| report.metrics.request_count)
                            .map_err(|error| io::Error::other(error.to_string())),
                        ManagedProxyConfig::Https(config) => {
                            proxy_https_connection(stream, peer_addr, config).await
                        }
                    };
                    if let Ok(request_count) = result {
                        state.proxied_connections.fetch_add(1, Ordering::SeqCst);
                        state.proxied_requests.fetch_add(request_count, Ordering::SeqCst);
                    }
                    counters.active_connections.fetch_sub(1, Ordering::SeqCst);
                    counters.completed_connections.fetch_add(1, Ordering::SeqCst);
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        false,
                    );
                });
            }
        }
    }

    *counters.state.write().await = String::from("draining");
    let _ = time::timeout(drain_timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    *counters.state.write().await = String::from("stopped");
    Ok(())
}

async fn run_admin_listener_loop(
    listener: TcpListener,
    listener_name: String,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    counters: Arc<ListenerRuntimeCounters>,
    state: Arc<WorkspaceServeState>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
    admin_runtime: AdminRuntimeHandles,
    admin_secret: Arc<String>,
    supervisor: ServeSupervisor,
) -> io::Result<()> {
    *counters.state.write().await = String::from("running");
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut stream, peer_addr) = accepted?;
                counters.accepted_connections.fetch_add(1, Ordering::SeqCst);
                if !try_acquire_listener_slot(&counters, &admission_limit) {
                    counters.shed_connections.fetch_add(1, Ordering::SeqCst);
                    state.record_overload_event(
                        &listener_name,
                        lb_observability::OverloadEventKind::RequestShed,
                        format!(
                            "listener shed admin connection at capacity {}",
                            admission_limit.load(Ordering::SeqCst)
                        ),
                    );
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        true,
                    );
                    let _ = write_overload_response(&mut stream).await;
                    continue;
                }
                state.sync_listener_overload_snapshot(
                    &listener_name,
                    &counters,
                    admission_limit.load(Ordering::SeqCst),
                    &overload_runtime,
                    false,
                );
                let counters = Arc::clone(&counters);
                let state = Arc::clone(&state);
                let admin_runtime = admin_runtime.clone();
                let admin_secret = Arc::clone(&admin_secret);
                let supervisor = supervisor.clone();
                let listener_name = listener_name.clone();
                let admission_limit = Arc::clone(&admission_limit);
                let overload_runtime = Arc::clone(&overload_runtime);
                tasks.spawn(async move {
                    let state_for_connection = Arc::clone(&state);
                    let _ = handle_workspace_admin_connection(
                        stream,
                        peer_addr,
                        listener_name.clone(),
                        state_for_connection,
                        admin_runtime,
                        admin_secret,
                        supervisor,
                    )
                    .await;
                    counters.active_connections.fetch_sub(1, Ordering::SeqCst);
                    counters.completed_connections.fetch_add(1, Ordering::SeqCst);
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        false,
                    );
                });
            }
        }
    }

    *counters.state.write().await = String::from("draining");
    let _ = time::timeout(drain_timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    *counters.state.write().await = String::from("stopped");
    Ok(())
}

async fn handle_workspace_admin_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    listener_name: String,
    state: Arc<WorkspaceServeState>,
    admin_runtime: AdminRuntimeHandles,
    admin_secret: Arc<String>,
    supervisor: ServeSupervisor,
) -> io::Result<()> {
    state.admin_requests.fetch_add(1, Ordering::SeqCst);
    let request = crate::read_http_request_head(&mut stream).await?;
    let Some(request) = request else {
        return Ok(());
    };

    let policy = admin_runtime.shared_policy.read().await.clone();
    let action = classify_admin_request_action(request.method.as_str(), request.target.as_str());
    let request_id = state.next_admin_request_id();
    let source_ip = peer_addr.ip();

    if !admin_source_allowed(source_ip, &policy) {
        record_admin_audit(
            &state,
            AdminAuditEvent {
                observed_at_unix_ms: unix_time_ms(),
                request_id,
                listener: listener_name,
                actor: String::from("anonymous"),
                auth_mode: String::from("source_policy"),
                action: String::from(action.as_str()),
                source: source_ip.to_string(),
                outcome: String::from("denied"),
                detail: String::from("source address is outside the admin allow-list"),
            },
        )
        .await;
        return crate::write_http_response(
            &mut stream,
            "403 Forbidden",
            "text/plain; charset=utf-8",
            b"admin source not allowed\n",
        )
        .await;
    }

    let request_context = match authenticate_admin_request(
        &request,
        action,
        source_ip,
        &policy,
        &admin_runtime.replay_state,
        admin_secret.as_str(),
        &request_id,
    ) {
        Ok(request_context) => request_context,
        Err(auth_error) => {
            record_admin_audit(
                &state,
                AdminAuditEvent {
                    observed_at_unix_ms: unix_time_ms(),
                    request_id,
                    listener: listener_name,
                    actor: auth_error.actor,
                    auth_mode: auth_error.auth_mode,
                    action: String::from(action.as_str()),
                    source: source_ip.to_string(),
                    outcome: String::from(auth_error.outcome),
                    detail: auth_error.detail,
                },
            )
            .await;
            return crate::write_http_response_with_headers(
                &mut stream,
                auth_error.status,
                "text/plain; charset=utf-8",
                auth_error.headers.as_slice(),
                auth_error.body.as_bytes(),
            )
            .await;
        }
    };

    if !consume_admin_rate_limit(
        AdminRateLimitKey {
            source: source_ip,
            actor: request_context.actor.clone(),
            auth_mode: request_context.auth_mode.clone(),
        },
        &policy,
        &admin_runtime.rate_limit_state,
    ) {
        record_admin_audit(
            &state,
            AdminAuditEvent {
                observed_at_unix_ms: unix_time_ms(),
                request_id: request_context.request_id.clone(),
                listener: listener_name,
                actor: request_context.actor.clone(),
                auth_mode: request_context.auth_mode.clone(),
                action: String::from(action.as_str()),
                source: source_ip.to_string(),
                outcome: String::from("rate_limited"),
                detail: String::from("admin identity exceeded configured rate limits"),
            },
        )
        .await;
        return crate::write_http_response(
            &mut stream,
            "429 Too Many Requests",
            "text/plain; charset=utf-8",
            b"admin rate limit exceeded\n",
        )
        .await;
    }

    let action_name = String::from(action.as_str());
    let audit_outcome = match action {
        AdminRequestAction::Healthz => {
            crate::write_http_response(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok\n")
                .await?;
            (String::from("served"), String::from("health check completed"))
        }
        AdminRequestAction::Validate => match supervisor.validate_current_config().await {
            Ok(preview) => {
                let body = preview
                    .render_json()
                    .map_err(|error| io::Error::other(error.to_string()))?;
                crate::write_http_response(&mut stream, "200 OK", "application/json", body.as_bytes())
                    .await?;
                (String::from("served"), String::from("validation preview generated"))
            }
            Err(error) => {
                let detail = format!("validation preview failed: {error}");
                crate::write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain; charset=utf-8",
                    format!("{detail}\n").as_bytes(),
                )
                .await?;
                (String::from("failed"), detail)
            }
        },
        AdminRequestAction::Status => {
            let body = state.status_body(&supervisor).await;
            crate::write_http_response(&mut stream, "200 OK", "application/json", body.as_bytes())
                .await?;
            (String::from("served"), String::from("status response generated"))
        }
        AdminRequestAction::Audit => {
            let body = state
                .audit_body()
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            crate::write_http_response(&mut stream, "200 OK", "application/json", body.as_bytes())
                .await?;
            (String::from("served"), String::from("audit log response generated"))
        }
        AdminRequestAction::Reload => match supervisor.reload().await {
            Ok(()) => {
                crate::write_http_response(
                    &mut stream,
                    "200 OK",
                    "text/plain; charset=utf-8",
                    b"configuration applied\n",
                )
                .await?;
                (String::from("executed"), String::from("configuration applied"))
            }
            Err(error) => {
                let detail = format!("reload failed: {error}");
                crate::write_http_response(
                    &mut stream,
                    "500 Internal Server Error",
                    "text/plain; charset=utf-8",
                    format!("{detail}\n").as_bytes(),
                )
                .await?;
                (String::from("failed"), detail)
            }
        },
        AdminRequestAction::Unknown => {
            crate::write_http_response(&mut stream, "404 Not Found", "text/plain; charset=utf-8", b"not found\n")
                .await?;
            (String::from("not_found"), String::from("unknown admin endpoint"))
        }
    };

    record_admin_audit(
        &state,
        AdminAuditEvent {
            observed_at_unix_ms: unix_time_ms(),
            request_id: request_context.request_id,
            listener: listener_name,
            actor: request_context.actor,
            auth_mode: request_context.auth_mode,
            action: action_name,
            source: request_context.source.to_string(),
            outcome: audit_outcome.0,
            detail: audit_outcome.1,
        },
    )
    .await;

    Ok(())
}

fn classify_admin_request_action(method: &str, target: &str) -> AdminRequestAction {
    match (method, target) {
        ("GET", "/healthz") => AdminRequestAction::Healthz,
        ("GET", "/status") => AdminRequestAction::Status,
        ("GET", "/validate") => AdminRequestAction::Validate,
        ("GET", "/audit") => AdminRequestAction::Audit,
        ("POST", "/reload") => AdminRequestAction::Reload,
        _ => AdminRequestAction::Unknown,
    }
}

fn admin_source_allowed(source_ip: IpAddr, policy: &CompiledAdminPolicy) -> bool {
    policy.allowed_source_cidrs.is_empty()
        || policy
            .allowed_source_cidrs
            .iter()
            .any(|cidr| cidr.contains(&source_ip))
}

fn consume_admin_rate_limit(
    key: AdminRateLimitKey,
    policy: &CompiledAdminPolicy,
    rate_limit_state: &StdMutex<AdminRateLimitState>,
) -> bool {
    let now = Instant::now();
    let mut guard = rate_limit_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .buckets
        .retain(|_, bucket| now.saturating_duration_since(bucket.last_refill) <= Duration::from_secs(600));
    let bucket = guard.buckets.entry(key).or_insert(AdminTokenBucket {
        tokens: f64::from(policy.rate_limit.burst),
        last_refill: now,
    });
    let refill_rate_per_sec = f64::from(policy.rate_limit.requests_per_minute) / 60.0;
    let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * refill_rate_per_sec)
        .min(f64::from(policy.rate_limit.burst));
    bucket.last_refill = now;
    if bucket.tokens < 1.0 {
        return false;
    }
    bucket.tokens -= 1.0;
    true
}

struct AdminAuthFailure {
    status: &'static str,
    headers: Vec<&'static str>,
    body: String,
    actor: String,
    auth_mode: String,
    outcome: &'static str,
    detail: String,
}

struct ResolvedAdminSecret {
    value: String,
    actor: String,
    auth_mode: &'static str,
}

fn authenticate_admin_request(
    request: &crate::DemoRequestHead,
    action: AdminRequestAction,
    source_ip: IpAddr,
    policy: &CompiledAdminPolicy,
    replay_state: &StdMutex<AdminReplayState>,
    legacy_admin_secret: &str,
    request_id: &str,
) -> Result<AdminRequestContext, AdminAuthFailure> {
    let required_permission = action.permission();
    match &policy.auth {
        CompiledAdminAuthPolicy::Bearer {
            secret_env,
            permissions,
        } => {
            let Some(bearer_token) = request.authorization_bearer.as_deref() else {
                return Err(AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: vec!["WWW-Authenticate: Bearer"],
                    body: String::from("admin authorization required\n"),
                    actor: String::from("anonymous"),
                    auth_mode: String::from("bearer"),
                    outcome: "unauthenticated",
                    detail: String::from("missing bearer token"),
                });
            };
            let expected = resolve_admin_secret(
                secret_env,
                legacy_admin_secret,
                "bearer",
                "shared-bearer",
            )?;
            if !crate::constant_time_eq(bearer_token.as_bytes(), expected.value.as_bytes()) {
                return Err(AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: vec!["WWW-Authenticate: Bearer"],
                    body: String::from("admin authorization required\n"),
                    actor: String::from("shared-bearer"),
                    auth_mode: String::from("bearer"),
                    outcome: "unauthenticated",
                    detail: String::from("bearer token mismatch"),
                });
            }
            if !permissions.contains(&required_permission) {
                return Err(AdminAuthFailure {
                    status: "403 Forbidden",
                    headers: Vec::new(),
                    body: String::from("admin action not permitted\n"),
                    actor: String::from("shared-bearer"),
                    auth_mode: String::from("bearer"),
                    outcome: "forbidden",
                    detail: format!(
                        "shared bearer lacks {} permission",
                        admin_permission_name(required_permission)
                    ),
                });
            }
            Ok(AdminRequestContext {
                request_id: String::from(request_id),
                actor: expected.actor,
                auth_mode: String::from(expected.auth_mode),
                source: source_ip,
            })
        }
        CompiledAdminAuthPolicy::SignedHeaders {
            operators,
            max_clock_skew,
            nonce_ttl,
        } => {
            let actor = request
                .header_value("x-lb-admin-actor")
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: String::from("anonymous"),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("missing x-lb-admin-actor header"),
                })?;
            let operator = operators.get(actor).ok_or_else(|| AdminAuthFailure {
                status: "401 Unauthorized",
                headers: Vec::new(),
                body: String::from("signed admin authorization required\n"),
                actor: actor.to_string(),
                auth_mode: String::from("signed_headers"),
                outcome: "unauthenticated",
                detail: String::from("unknown admin operator"),
            })?;
            if !operator.permissions.contains(&required_permission) {
                return Err(AdminAuthFailure {
                    status: "403 Forbidden",
                    headers: Vec::new(),
                    body: String::from("admin action not permitted\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "forbidden",
                    detail: format!(
                        "operator lacks {} permission",
                        admin_permission_name(required_permission)
                    ),
                });
            }

            let timestamp_header = request
                .header_value("x-lb-admin-timestamp")
                .ok_or_else(|| AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("missing x-lb-admin-timestamp header"),
                })?;
            let timestamp = timestamp_header.parse::<u64>().map_err(|_| AdminAuthFailure {
                status: "401 Unauthorized",
                headers: Vec::new(),
                body: String::from("signed admin authorization required\n"),
                actor: actor.to_string(),
                auth_mode: String::from("signed_headers"),
                outcome: "unauthenticated",
                detail: String::from("invalid x-lb-admin-timestamp header"),
            })?;
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default();
            let skew = now_secs.abs_diff(timestamp);
            if skew > max_clock_skew.as_secs() {
                return Err(AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin timestamp rejected\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "rejected",
                    detail: String::from("signed admin timestamp exceeded clock skew allowance"),
                });
            }

            let nonce = request
                .header_value("x-lb-admin-nonce")
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("missing x-lb-admin-nonce header"),
                })?;
            let signature = request
                .header_value("x-lb-admin-signature")
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("missing x-lb-admin-signature header"),
                })?;

            let expected_secret = resolve_admin_secret(
                &operator.secret_env,
                legacy_admin_secret,
                "signed_headers",
                actor,
            )?;
            let expected = sign_admin_request(
                &expected_secret.value,
                actor,
                request.method.as_str(),
                request.target.as_str(),
                timestamp,
                nonce,
            );
            if !crate::constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
                return Err(AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("signed admin signature mismatch"),
                });
            }

            let nonce_key = format!("{actor}:{nonce}");
            let mut guard = replay_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            guard
                .nonces
                .retain(|_, seen_at| now.saturating_duration_since(*seen_at) <= *nonce_ttl);
            if guard.nonces.contains_key(&nonce_key) {
                return Err(AdminAuthFailure {
                    status: "409 Conflict",
                    headers: Vec::new(),
                    body: String::from("admin command replay rejected\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "replay_rejected",
                    detail: String::from("signed admin nonce has already been used"),
                });
            }
            guard.nonces.insert(nonce_key, now);

            Ok(AdminRequestContext {
                request_id: String::from(request_id),
                actor: actor.to_string(),
                auth_mode: String::from("signed_headers"),
                source: source_ip,
            })
        }
    }
}

fn resolve_admin_secret(
    secret_env: &str,
    legacy_admin_secret: &str,
    auth_mode: &'static str,
    actor: &str,
) -> Result<ResolvedAdminSecret, AdminAuthFailure> {
    let value = std::env::var(secret_env).unwrap_or_else(|_| {
        if secret_env == "LB_CTL_ADMIN_SECRET" {
            String::from(legacy_admin_secret)
        } else {
            String::new()
        }
    });

    if value.is_empty() {
        return Err(AdminAuthFailure {
            status: "503 Service Unavailable",
            headers: Vec::new(),
            body: String::from("admin authorization unavailable\n"),
            actor: actor.to_string(),
            auth_mode: String::from(auth_mode),
            outcome: "misconfigured",
            detail: format!("admin secret env {secret_env} is not configured"),
        });
    }

    Ok(ResolvedAdminSecret {
        value,
        actor: actor.to_string(),
        auth_mode,
    })
}

fn sign_admin_request(
    secret: &str,
    actor: &str,
    method: &str,
    target: &str,
    timestamp: u64,
    nonce: &str,
) -> String {
    let block_size = 64;
    let mut key = secret.as_bytes().to_vec();
    if key.len() > block_size {
        key = Sha256::digest(&key).to_vec();
    }
    key.resize(block_size, 0);

    let mut inner_pad = vec![0x36_u8; block_size];
    let mut outer_pad = vec![0x5c_u8; block_size];
    for (index, key_byte) in key.iter().enumerate() {
        inner_pad[index] ^= *key_byte;
        outer_pad[index] ^= *key_byte;
    }

    let payload = format!("{actor}\n{method}\n{target}\n{timestamp}\n{nonce}\n");
    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    inner.update(payload.as_bytes());
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn admin_permission_name(permission: AdminPermission) -> &'static str {
    match permission {
        AdminPermission::Read => "read",
        AdminPermission::Audit => "audit",
        AdminPermission::Write => "write",
    }
}

async fn record_admin_audit(state: &WorkspaceServeState, event: AdminAuditEvent) {
    state.record_admin_audit(event).await;
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn try_acquire_listener_slot(
    counters: &ListenerRuntimeCounters,
    admission_limit: &AtomicUsize,
) -> bool {
    loop {
        let active = counters.active_connections.load(Ordering::SeqCst);
        let limit = admission_limit.load(Ordering::SeqCst);
        if active >= limit {
            return false;
        }

        if counters
            .active_connections
            .compare_exchange(active, active + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return true;
        }
    }
}

async fn write_overload_response(stream: &mut TcpStream) -> io::Result<()> {
    crate::write_http_response(
        stream,
        "503 Service Unavailable",
        "text/plain; charset=utf-8",
        b"listener overloaded\n",
    )
    .await?;
    stream.shutdown().await
}

fn build_listener_overload_runtime(
    policy: Option<&CompiledListenerOverloadPolicy>,
) -> Result<Option<ListenerOverloadRuntime>, DynError> {
    policy.map(ListenerOverloadRuntime::new).transpose()
}

fn snapshot_listener_overload(
    observed_at: Duration,
    counters: &ListenerRuntimeCounters,
    limit: usize,
    overload_runtime: &StdMutex<Option<ListenerOverloadRuntime>>,
    record_concurrency_signal: bool,
) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
    let guard = overload_runtime
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(runtime) = guard.as_ref() {
        if record_concurrency_signal {
            runtime.record_concurrency_signal(observed_at)
        } else {
            runtime.snapshot(observed_at)
        }
    } else {
        let active = counters.active_connections.load(Ordering::SeqCst);
        let shed = counters.shed_connections.load(Ordering::SeqCst);
        let state = if active >= limit {
            lb_runtime::OverloadState::Shedding
        } else {
            lb_runtime::OverloadState::Normal
        };
        (
            lb_runtime::OverloadSnapshot {
                state,
                active_signal_count: if matches!(state, lb_runtime::OverloadState::Shedding) { 1 } else { 0 },
                rate_limited_count: 0,
                concurrency_limited_count: active as u64,
                breaker_open_count: 0,
                retry_budget_exhausted_count: 0,
                shed_request_count: shed,
                brownout_feature_count: 0,
            },
            Vec::new(),
        )
    }
}

fn snapshot_listener_overload_status(
    observed_at: Duration,
    counters: &ListenerRuntimeCounters,
    overload_runtime: &StdMutex<Option<ListenerOverloadRuntime>>,
) -> (lb_runtime::OverloadState, Vec<String>, Vec<OverloadEventStatus>) {
    let fallback_state = match counters.overload_state.load(Ordering::SeqCst) {
        1 => lb_runtime::OverloadState::Constrained,
        2 => lb_runtime::OverloadState::Shedding,
        3 => lb_runtime::OverloadState::Brownout,
        _ => lb_runtime::OverloadState::Normal,
    };
    let guard = overload_runtime
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .as_ref()
        .map(|runtime| {
            let (snapshot, brownout_features) = runtime.snapshot(observed_at);
            (
                snapshot.state,
                brownout_features,
                runtime
                    .recent_events()
                    .into_iter()
                    .map(OverloadEventStatus::from_overload_event)
                    .collect(),
            )
        })
        .unwrap_or((fallback_state, Vec::new(), Vec::new()))
}

fn build_config_validation_preview(
    config_path: &str,
    active_snapshot: Option<&lb_config_model::WorkspaceSnapshot>,
    current_identities: &BTreeMap<
        String,
        (
            lb_config_model::ListenerClassConfig,
            lb_config_model::ListenerProtocolConfig,
            SocketAddr,
        ),
    >,
    candidate: &CompiledWorkspaceRuntime,
) -> ConfigValidationPreview {
    let diff_preview = active_snapshot.map(|active| active.diff(&candidate.snapshot));
    let warnings = build_config_safety_warnings(active_snapshot, current_identities, candidate);
    let rebind_blocks = collect_listener_rebind_blocks(current_identities, &candidate.listeners);
    let apply_preview = if rebind_blocks.is_empty() {
        ConfigApplyPreview {
            strategy: String::from("in_place_or_additive_swap"),
            rollback_safe: true,
            summary: String::from(
                "candidate config compiles before apply; new listeners are started before old listeners retire, and failed reloads leave the active runtime unchanged",
            ),
        }
    } else {
        ConfigApplyPreview {
            strategy: String::from("blocked_requires_rebind"),
            rollback_safe: true,
            summary: format!(
                "reload would be blocked because these listeners would need an in-place rebind or protocol/class swap: {}",
                rebind_blocks.join(", ")
            ),
        }
    };

    ConfigValidationPreview {
        config_path: config_path.to_string(),
        active_snapshot: active_snapshot.map(lb_config_model::WorkspaceSnapshot::view),
        candidate_snapshot: candidate.snapshot.view(),
        diff_preview,
        warnings,
        apply_preview,
        compatibility: ConfigCompatibilityPreview {
            active_api_version: active_snapshot.map(|snapshot| snapshot.metadata().api_version()),
            candidate_api_version: candidate.snapshot.metadata().api_version(),
            snapshot_format_version: candidate
                .snapshot
                .metadata()
                .format_version()
                .to_string(),
            migration_strategy: String::from(
                "candidate configs must compile to the current snapshot format and supported api_version before apply; unsupported version jumps fail during validation and the active snapshot remains available for rollback",
            ),
        },
    }
}

fn build_config_safety_warnings(
    active_snapshot: Option<&lb_config_model::WorkspaceSnapshot>,
    current_identities: &BTreeMap<
        String,
        (
            lb_config_model::ListenerClassConfig,
            lb_config_model::ListenerProtocolConfig,
            SocketAddr,
        ),
    >,
    candidate: &CompiledWorkspaceRuntime,
) -> Vec<ConfigSafetyWarning> {
    let mut warnings = Vec::new();

    if let Some(active_snapshot) = active_snapshot {
        let diff = active_snapshot.diff(&candidate.snapshot);
        if !diff.listener_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("listener_topology_changed"),
                message: format!(
                    "listener changes detected: {}",
                    summarize_snapshot_changes(&diff.listener_changes)
                ),
            });
        }
        if !diff.route_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("route_table_changed"),
                message: format!(
                    "route matching changes detected: {}",
                    summarize_snapshot_changes(&diff.route_changes)
                ),
            });
        }
        if !diff.upstream_cluster_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("upstream_clusters_changed"),
                message: format!(
                    "upstream topology changes detected: {}",
                    summarize_snapshot_changes(&diff.upstream_cluster_changes)
                ),
            });
        }
        if active_snapshot.security() != candidate.snapshot.security() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("security_posture_changed"),
                message: String::from(
                    "workspace security settings changed; review trusted proxy, anonymous-source, and artifact verification posture before apply",
                ),
            });
        }
    } else {
        warnings.push(ConfigSafetyWarning {
            code: String::from("bootstrap_apply"),
            message: String::from(
                "no active snapshot is loaded yet; this validation is for the first apply and has no prior diff baseline",
            ),
        });
    }

    for listener_name in collect_listener_rebind_blocks(current_identities, &candidate.listeners) {
        warnings.push(ConfigSafetyWarning {
            code: String::from("listener_rebind_required"),
            message: format!(
                "listener {listener_name} changes class or protocol on the current bind address, so reload will be rejected instead of risking a partial in-place swap"
            ),
        });
    }

    warnings
}

fn collect_listener_rebind_blocks(
    current_identities: &BTreeMap<
        String,
        (
            lb_config_model::ListenerClassConfig,
            lb_config_model::ListenerProtocolConfig,
            SocketAddr,
        ),
    >,
    candidate_listeners: &BTreeMap<String, CompiledServeListener>,
) -> Vec<String> {
    let mut blocked = Vec::new();
    for (name, spec) in candidate_listeners {
        if let Some((class, protocol, bind_address)) = current_identities.get(name) {
            if *bind_address == spec.bind_address()
                && (*class != spec.class() || *protocol != spec.protocol())
            {
                blocked.push(name.clone());
            }
        }
    }
    blocked
}

fn summarize_snapshot_changes(
    changes: &[lb_config_model::SnapshotResourceChange],
) -> String {
    changes
        .iter()
        .map(|change| format!("{}:{:?}", change.name, change.kind))
        .collect::<Vec<_>>()
        .join(", ")
}

fn compile_workspace_runtime(config_path: &str) -> Result<CompiledWorkspaceRuntime, DynError> {
    let config = crate::load_workspace_config(config_path).map_err(to_dyn_error)?;
    let snapshot = config.compile_snapshot().map_err(to_dyn_error)?;
    let compiled_listeners = config.compile_listeners()?;
    let compiled_routes = config.compile_http_route_rules()?;
    let mut listeners = BTreeMap::new();

    for (listener, compiled_listener) in config.listeners.iter().zip(compiled_listeners.iter()) {
        let compiled = match (listener.class, listener.protocol) {
            (lb_config_model::ListenerClassConfig::Public, lb_config_model::ListenerProtocolConfig::Http1) => {
                CompiledServeListener::Public {
                    class: listener.class,
                    protocol: listener.protocol,
                    bind_address: compiled_listener.bind_address,
                    max_connections: compiled_listener.max_connections,
                    drain_timeout: compiled_listener.drain_timeout,
                    overload_policy: compile_listener_overload_policy(&config, listener)?,
                    proxy: ManagedProxyConfig::Http1(compile_http1_proxy_config(
                        &config,
                        listener,
                        &compiled_routes,
                    )?),
                }
            }
            (lb_config_model::ListenerClassConfig::Public, lb_config_model::ListenerProtocolConfig::Http2) => {
                CompiledServeListener::Public {
                    class: listener.class,
                    protocol: listener.protocol,
                    bind_address: compiled_listener.bind_address,
                    max_connections: compiled_listener.max_connections,
                    drain_timeout: compiled_listener.drain_timeout,
                    overload_policy: compile_listener_overload_policy(&config, listener)?,
                    proxy: ManagedProxyConfig::Http2(compile_http2_proxy_config(
                        &config,
                        listener,
                        &compiled_routes,
                    )?),
                }
            }
            (lb_config_model::ListenerClassConfig::Public, lb_config_model::ListenerProtocolConfig::Https) => {
                CompiledServeListener::Public {
                    class: listener.class,
                    protocol: listener.protocol,
                    bind_address: compiled_listener.bind_address,
                    max_connections: compiled_listener.max_connections,
                    drain_timeout: compiled_listener.drain_timeout,
                    overload_policy: compile_listener_overload_policy(&config, listener)?,
                    proxy: ManagedProxyConfig::Https(compile_https_proxy_config(
                        &config,
                        listener,
                        compiled_listener,
                        &compiled_routes,
                    )?),
                }
            }
            (lb_config_model::ListenerClassConfig::Public, protocol) => {
                return Err(format!(
                    "listener {} uses unsupported public protocol {:?} in serve mode",
                    listener.name, protocol
                )
                .into());
            }
            (lb_config_model::ListenerClassConfig::Admin, lb_config_model::ListenerProtocolConfig::Http1) => {
                CompiledServeListener::Admin {
                    bind_address: compiled_listener.bind_address,
                    max_connections: compiled_listener.max_connections,
                    drain_timeout: compiled_listener.drain_timeout,
                    overload_policy: compile_listener_overload_policy(&config, listener)?,
                    admin_policy: compile_admin_policy(listener)?,
                }
            }
            (lb_config_model::ListenerClassConfig::Admin, protocol) => {
                return Err(format!(
                    "listener {} uses unsupported admin protocol {:?} in serve mode",
                    listener.name, protocol
                )
                .into());
            }
        };

        listeners.insert(listener.name.clone(), compiled);
    }

    Ok(CompiledWorkspaceRuntime {
        source_label: format!("config_path={config_path}"),
        snapshot,
        listeners,
    })
}

fn compile_admin_policy(
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<CompiledAdminPolicy, DynError> {
    let auth = match &listener.admin.auth {
        lb_config_model::AdminAuthPolicyConfig::Bearer {
            secret_env,
            permissions,
        } => CompiledAdminAuthPolicy::Bearer {
            secret_env: secret_env.clone(),
            permissions: compile_admin_permissions(permissions),
        },
        lb_config_model::AdminAuthPolicyConfig::SignedHeaders {
            operators,
            max_clock_skew_secs,
            nonce_ttl_secs,
        } => CompiledAdminAuthPolicy::SignedHeaders {
            operators: operators
                .iter()
                .map(|operator| {
                    (
                        operator.id.clone(),
                        CompiledAdminOperator {
                            secret_env: operator.secret_env.clone(),
                            permissions: compile_admin_permissions(&operator.permissions),
                        },
                    )
                })
                .collect(),
            max_clock_skew: Duration::from_secs(*max_clock_skew_secs),
            nonce_ttl: Duration::from_secs(*nonce_ttl_secs),
        },
    };

    Ok(CompiledAdminPolicy {
        auth,
        allowed_source_cidrs: listener
            .admin
            .allowed_source_cidrs
            .iter()
            .map(|cidr| cidr.parse::<IpNet>().map_err(to_dyn_error))
            .collect::<Result<Vec<_>, _>>()?,
        rate_limit: CompiledAdminRateLimit {
            requests_per_minute: listener.admin.rate_limit.requests_per_minute,
            burst: listener.admin.rate_limit.burst,
        },
        audit_capacity: listener.admin.audit.max_retained_events,
    })
}

fn compile_admin_permissions(
    permissions: &[lb_config_model::AdminAuthorizationScopeConfig],
) -> BTreeSet<AdminPermission> {
    permissions
        .iter()
        .map(|permission| match permission {
            lb_config_model::AdminAuthorizationScopeConfig::Read => AdminPermission::Read,
            lb_config_model::AdminAuthorizationScopeConfig::Audit => AdminPermission::Audit,
            lb_config_model::AdminAuthorizationScopeConfig::Write => AdminPermission::Write,
        })
        .collect()
}

fn compile_http1_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<lb_runtime::Http1ProxyConfig, DynError> {
    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http1_route_backends(config, listener, compiled_routes)?;
    let mut proxy = lb_runtime::Http1ProxyConfig::new(primary_upstream);
    proxy.routes = route_rules;
    proxy = proxy
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        proxy = proxy.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        proxy = proxy.with_anonymous_source_filter(filter);
    }
    Ok(proxy)
}

fn compile_http2_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<lb_runtime::Http2ProxyConfig, DynError> {
    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http2_route_backends(config, listener, compiled_routes)?;
    let mut proxy = lb_runtime::Http2ProxyConfig::new(primary_upstream);
    proxy.routes = route_rules;
    proxy.limits = config.defaults.http.http2_limits();
    proxy = proxy
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        proxy = proxy.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        proxy = proxy.with_anonymous_source_filter(filter);
    }
    Ok(proxy)
}

fn compile_https_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_listener: &lb_net_core::ListenerConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<ManagedHttpsProxyConfig, DynError> {
    let _compiled_tls_termination = compiled_listener
        .tls_termination
        .as_ref()
        .ok_or_else(|| to_dyn_error(format!("listener {} is missing tls_termination", listener.name)))?;
    let tls_termination = listener
        .tls_termination
        .as_ref()
        .ok_or_else(|| to_dyn_error(format!("listener {} is missing tls_termination", listener.name)))?;

    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http1_route_backends(config, listener, compiled_routes)?;
    let route_upstreams_http2 = route_upstreams
        .iter()
        .map(|upstream| lb_runtime::Http2RouteUpstream {
            route_label: upstream.route_label.clone(),
            upstream: upstream.upstream.clone(),
        })
        .collect::<Vec<_>>();

    let mut http1 = lb_runtime::Http1ProxyConfig::new(primary_upstream.clone());
    http1.routes = route_rules.clone();
    http1 = http1
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools.clone())
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        http1 = http1.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        http1 = http1.with_anonymous_source_filter(filter);
    }

    let mut http2 = lb_runtime::Http2ProxyConfig::new(primary_upstream);
    http2.routes = route_rules;
    http2.limits = config.defaults.http.http2_limits();
    http2 = http2
        .with_route_upstreams(route_upstreams_http2)
        .with_route_backend_pools(route_backend_pools)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        http2 = http2.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        http2 = http2.with_anonymous_source_filter(filter);
    }

    Ok(ManagedHttpsProxyConfig {
        http1,
        http2,
        tls_server_config: Arc::new(build_tls_server_config(tls_termination)?),
    })
}

fn build_tls_server_config(
    tls_termination: &lb_config_model::ListenerTlsTerminationConfig,
) -> Result<rustls::ServerConfig, DynError> {
    let cert_resolver = build_tls_cert_resolver(tls_termination)?;
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(
        protocol_versions_for_minimum(tls_termination.minimum_version),
    )
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(cert_resolver));
    config.alpn_protocols = tls_termination
        .alpn_protocols
        .iter()
        .map(|protocol| protocol.wire_id().to_vec())
        .collect();
    apply_tls_session_resumption_policy(&mut config, &tls_termination.session_resumption)?;
    Ok(config)
}

fn apply_tls_session_resumption_policy(
    config: &mut rustls::ServerConfig,
    session_resumption: &lb_config_model::ListenerTlsSessionResumptionConfig,
) -> Result<(), DynError> {
    match session_resumption.mode {
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Disabled => {
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.ticketer = Arc::new(DisabledTicketer);
            config.send_tls13_tickets = 0;
        }
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Stateful => {
            config.session_storage = rustls::server::ServerSessionMemoryCache::new(
                session_resumption.session_cache_size,
            );
            config.ticketer = Arc::new(DisabledTicketer);
            config.send_tls13_tickets = 0;
        }
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Tickets => {
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().map_err(to_dyn_error)?;
            config.send_tls13_tickets = session_resumption.tls13_ticket_count;
        }
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Hybrid => {
            config.session_storage = rustls::server::ServerSessionMemoryCache::new(
                session_resumption.session_cache_size,
            );
            config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().map_err(to_dyn_error)?;
            config.send_tls13_tickets = session_resumption.tls13_ticket_count;
        }
    }
    Ok(())
}

fn build_tls_cert_resolver(
    tls_termination: &lb_config_model::ListenerTlsTerminationConfig,
) -> Result<FallbackServerCertResolver, DynError> {
    let default_key = Arc::new(load_certified_key_from_source(&tls_termination.certificate_source)?);
    let mut sni_keys = BTreeMap::new();
    for certificate in &tls_termination.sni_certificates {
        let certified_key = Arc::new(load_certified_key_from_source(&certificate.certificate_source)?);
        for server_name in &certificate.server_names {
            let normalized = lb_proto_http::canonicalize_host(server_name).map_err(to_dyn_error)?;
            sni_keys.insert(normalized, Arc::clone(&certified_key));
        }
    }
    Ok(FallbackServerCertResolver { default_key, sni_keys })
}

fn load_certified_key_from_source(
    certificate_source: &lb_config_model::ListenerCertificateSourceConfig,
) -> Result<rustls::sign::CertifiedKey, DynError> {
    let loaded = lb_proto_tls::load_tls_identity_from_files(
        certificate_source.cert_path(),
        certificate_source.key_path(),
    )
    .map_err(to_dyn_error)?;
    let certificates = loaded
        .certificate_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let private_key = PrivateKeyDer::try_from(loaded.private_key_der).map_err(to_dyn_error)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut certified_key =
        rustls::sign::CertifiedKey::from_der(certificates, private_key, &provider)
            .map_err(to_dyn_error)?;
    if let Some(ocsp_path) = certificate_source.ocsp_path() {
        certified_key.ocsp = Some(fs::read(ocsp_path).map_err(to_dyn_error)?);
    }
    Ok(certified_key)
}

fn protocol_versions_for_minimum(
    minimum_version: lb_config_model::ListenerTlsMinimumVersionConfig,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match minimum_version {
        lb_config_model::ListenerTlsMinimumVersionConfig::Tls12 => &TLS12_AND_TLS13,
        lb_config_model::ListenerTlsMinimumVersionConfig::Tls13 => &TLS13_ONLY,
    }
}

async fn proxy_https_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: ManagedHttpsProxyConfig,
) -> io::Result<u64> {
    let acceptor = TlsAcceptor::from(Arc::clone(&config.tls_server_config));
    let tls_stream = acceptor.accept(stream).await.map_err(|error| io::Error::other(error.to_string()))?;
    let negotiated_h2 = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .is_some_and(|protocol| protocol == b"h2");

    if negotiated_h2 {
        lb_runtime::proxy_http2_connection_with_downstream_addr(tls_stream, peer_addr, &config.http2)
            .await
            .map(|report| report.metrics.request_count)
            .map_err(|error| io::Error::other(error.to_string()))
    } else {
        lb_runtime::proxy_http1_connection_with_downstream_addr(tls_stream, peer_addr, &config.http1)
            .await
            .map(|report| report.metrics.request_count)
            .map_err(|error| io::Error::other(error.to_string()))
    }
}

fn compile_http1_route_backends(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<
    (
        Vec<lb_proto_http::RoutePrefixRule>,
        Vec<lb_runtime::Http1RouteUpstream>,
        Vec<(String, lb_runtime::RouteBackendPool)>,
        lb_net_core::UpstreamTarget,
    ),
    DynError,
> {
    let mut route_rules = Vec::with_capacity(listener.routes.len());
    let mut route_upstreams = Vec::new();
    let mut route_backend_pools = Vec::new();
    let mut pools_by_cluster = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();

    for route_name in &listener.routes {
        let route = config
            .routes
            .iter()
            .find(|route| route.name == *route_name)
            .ok_or_else(|| format!("listener {} references unknown route {route_name}", listener.name))?;
        let compiled_route = compiled_routes
            .iter()
            .find(|compiled| compiled.label == *route_name)
            .ok_or_else(|| format!("compiled route {route_name} is missing"))?;
        let cluster = config
            .upstream_clusters
            .iter()
            .find(|cluster| cluster.name == route.upstream_cluster)
            .ok_or_else(|| format!("route {} references unknown upstream cluster {}", route.name, route.upstream_cluster))?;
        if cluster.endpoints.is_empty() {
            return Err(format!("upstream cluster {} must declare at least one endpoint", cluster.name).into());
        }

        route_rules.push(compiled_route.clone());
        route_upstreams.extend(cluster.endpoints.iter().map(|endpoint| lb_runtime::Http1RouteUpstream {
            route_label: route.name.clone(),
            upstream: lb_net_core::UpstreamTarget::new(
                format!("{}:{}", cluster.name, endpoint.id),
                endpoint.address,
            ),
        }));
        let route_backend_pool = match pools_by_cluster.get(&cluster.name) {
            Some(pool) => pool.clone(),
            None => {
                let pool = compile_route_backend_pool(cluster)?;
                pools_by_cluster.insert(cluster.name.clone(), pool.clone());
                pool
            }
        };
        route_backend_pools.push((route.name.clone(), route_backend_pool));
    }

    let primary_upstream = route_upstreams
        .first()
        .map(|route_upstream| route_upstream.upstream.clone())
        .ok_or_else(|| format!("public listener {} must reference at least one route", listener.name))?;
    Ok((route_rules, route_upstreams, route_backend_pools, primary_upstream))
}

fn compile_http2_route_backends(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<
    (
        Vec<lb_proto_http::RoutePrefixRule>,
        Vec<lb_runtime::Http2RouteUpstream>,
        Vec<(String, lb_runtime::RouteBackendPool)>,
        lb_net_core::UpstreamTarget,
    ),
    DynError,
> {
    let mut route_rules = Vec::with_capacity(listener.routes.len());
    let mut route_upstreams = Vec::new();
    let mut route_backend_pools = Vec::new();
    let mut pools_by_cluster = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();

    for route_name in &listener.routes {
        let route = config
            .routes
            .iter()
            .find(|route| route.name == *route_name)
            .ok_or_else(|| format!("listener {} references unknown route {route_name}", listener.name))?;
        let compiled_route = compiled_routes
            .iter()
            .find(|compiled| compiled.label == *route_name)
            .ok_or_else(|| format!("compiled route {route_name} is missing"))?;
        let cluster = config
            .upstream_clusters
            .iter()
            .find(|cluster| cluster.name == route.upstream_cluster)
            .ok_or_else(|| format!("route {} references unknown upstream cluster {}", route.name, route.upstream_cluster))?;
        if cluster.endpoints.is_empty() {
            return Err(format!("upstream cluster {} must declare at least one endpoint", cluster.name).into());
        }

        route_rules.push(compiled_route.clone());
        route_upstreams.extend(cluster.endpoints.iter().map(|endpoint| lb_runtime::Http2RouteUpstream {
            route_label: route.name.clone(),
            upstream: lb_net_core::UpstreamTarget::new(
                format!("{}:{}", cluster.name, endpoint.id),
                endpoint.address,
            ),
        }));
        let route_backend_pool = match pools_by_cluster.get(&cluster.name) {
            Some(pool) => pool.clone(),
            None => {
                let pool = compile_route_backend_pool(cluster)?;
                pools_by_cluster.insert(cluster.name.clone(), pool.clone());
                pool
            }
        };
        route_backend_pools.push((route.name.clone(), route_backend_pool));
    }

    let primary_upstream = route_upstreams
        .first()
        .map(|route_upstream| route_upstream.upstream.clone())
        .ok_or_else(|| format!("public listener {} must reference at least one route", listener.name))?;
    Ok((route_rules, route_upstreams, route_backend_pools, primary_upstream))
}

fn compile_route_backend_pool(
    cluster: &lb_config_model::UpstreamClusterConfig,
) -> Result<lb_runtime::RouteBackendPool, DynError> {
    let cluster_name = lb_net_core::UpstreamClusterName::new(cluster.name.clone()).map_err(to_dyn_error)?;
    let endpoints = cluster
        .endpoints
        .iter()
        .map(|endpoint| {
            lb_net_core::UpstreamEndpoint::new(
                lb_net_core::UpstreamEndpointId::new(endpoint.id.clone()).map_err(to_dyn_error)?,
                endpoint.address,
                match endpoint.state {
                    lb_config_model::EndpointStateConfig::Ready => lb_net_core::EndpointState::Ready,
                    lb_config_model::EndpointStateConfig::Draining => lb_net_core::EndpointState::Draining,
                    lb_config_model::EndpointStateConfig::Unavailable => lb_net_core::EndpointState::Unavailable,
                },
                lb_net_core::EndpointMetadata {
                    zone: endpoint.zone.clone(),
                    locality: endpoint.locality.clone(),
                    weight: endpoint.weight,
                },
            )
            .map_err(to_dyn_error)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_dyn_error)?;
    let cluster_model = lb_net_core::UpstreamCluster::new(cluster_name, endpoints).map_err(to_dyn_error)?;
    lb_runtime::RouteBackendPool::from_cluster(
        cluster_model,
        lb_runtime::EndpointHealthPolicy {
            warmup_duration: ROUTE_BACKEND_WARMUP_DURATION,
            ..lb_runtime::EndpointHealthPolicy::default()
        },
        lb_runtime::UpstreamSelectionPolicy {
            algorithm: match cluster.traffic_policy.algorithm {
                lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin => lb_runtime::LoadBalancingAlgorithm::RoundRobin,
                lb_config_model::LoadBalancingAlgorithmConfig::WeightedRoundRobin => {
                    lb_runtime::LoadBalancingAlgorithm::WeightedRoundRobin
                }
                lb_config_model::LoadBalancingAlgorithmConfig::PowerOfTwoChoices => {
                    lb_runtime::LoadBalancingAlgorithm::PowerOfTwoChoices
                }
            },
            locality: match cluster.traffic_policy.locality {
                lb_config_model::LocalityRoutingConfig::Disabled => lb_runtime::LocalityRoutingPolicy::Disabled,
                lb_config_model::LocalityRoutingConfig::PreferLocality => {
                    lb_runtime::LocalityRoutingPolicy::PreferLocality
                }
                lb_config_model::LocalityRoutingConfig::PreferZone => lb_runtime::LocalityRoutingPolicy::PreferZone,
                lb_config_model::LocalityRoutingConfig::PreferLocalityThenZone => {
                    lb_runtime::LocalityRoutingPolicy::PreferLocalityThenZone
                }
            },
            no_healthy_fallback: match cluster.traffic_policy.no_healthy_fallback {
                lb_config_model::NoHealthyFallbackConfig::Fail => lb_runtime::NoHealthyFallback::Fail,
                lb_config_model::NoHealthyFallbackConfig::IncludeUnhealthy => {
                    lb_runtime::NoHealthyFallback::IncludeUnhealthy
                }
            },
        },
    )
    .map_err(to_dyn_error)
}

fn default_route_enumeration_policy() -> lb_runtime::RouteEnumerationProtectionPolicy {
    lb_runtime::RouteEnumerationProtectionPolicy {
        source_aggregation: lb_runtime::SourceAggregation::ExactIp,
        evaluation_window: Duration::from_secs(30),
        max_unmatched_route_events: 3,
        max_distinct_query_signatures_per_route: 6,
        base_ban_duration: Duration::from_secs(60),
        max_ban_duration: Duration::from_secs(15 * 60),
        max_tracked_sources: 4096,
    }
}

fn listener_class_name(class: lb_config_model::ListenerClassConfig) -> &'static str {
    match class {
        lb_config_model::ListenerClassConfig::Public => "public",
        lb_config_model::ListenerClassConfig::Admin => "admin",
    }
}

fn listener_protocol_name(protocol: lb_config_model::ListenerProtocolConfig) -> &'static str {
    match protocol {
        lb_config_model::ListenerProtocolConfig::Tcp => "tcp",
        lb_config_model::ListenerProtocolConfig::Http1 => "http1",
        lb_config_model::ListenerProtocolConfig::Https => "https",
        lb_config_model::ListenerProtocolConfig::Http2 => "http2",
        lb_config_model::ListenerProtocolConfig::Auto => "auto",
    }
}

fn overload_state_name(state: lb_runtime::OverloadState) -> &'static str {
    match state {
        lb_runtime::OverloadState::Normal => "normal",
        lb_runtime::OverloadState::Constrained => "constrained",
        lb_runtime::OverloadState::Shedding => "shedding",
        lb_runtime::OverloadState::Brownout => "brownout",
    }
}

fn overload_scope(listener_name: &str) -> String {
    format!("workspace_listener_{}", listener_name)
}

const fn overload_state_index(state: lb_runtime::OverloadState) -> usize {
    match state {
        lb_runtime::OverloadState::Normal => 0,
        lb_runtime::OverloadState::Constrained => 1,
        lb_runtime::OverloadState::Shedding => 2,
        lb_runtime::OverloadState::Brownout => 3,
    }
}

fn compile_listener_overload_policy(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<Option<CompiledListenerOverloadPolicy>, DynError> {
    let Some(policy_name) = listener.policies.overload_response.as_deref() else {
        return Ok(None);
    };

    let policy = config
        .policies
        .overload_responses
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!(
                "listener {} references unknown overload response policy {policy_name}",
                listener.name,
            ))
        })?;

    Ok(Some(CompiledListenerOverloadPolicy {
        signal_window: Duration::from_millis(policy.spec.signal_window_ms),
        constrained_signal_threshold: policy.spec.constrained_signal_threshold,
        shedding_signal_threshold: policy.spec.shedding_signal_threshold,
        brownout_signal_threshold: policy.spec.brownout_signal_threshold,
        brownout_features: policy
            .spec
            .brownout_features
            .iter()
            .map(|feature| CompiledBrownoutFeature {
                name: feature.name.clone(),
                priority: match feature.priority {
                    lb_config_model::TrafficClassConfig::Critical => lb_runtime::TrafficClass::Critical,
                    lb_config_model::TrafficClassConfig::Default => lb_runtime::TrafficClass::Default,
                    lb_config_model::TrafficClassConfig::BestEffort => lb_runtime::TrafficClass::BestEffort,
                },
            })
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::fs;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use bytes::Bytes;
    use h2::{client, server};
    use http::{Request, Response, StatusCode};
    use rcgen::generate_simple_self_signed;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};

    use super::{
        ACTIVE_HEALTH_PROBE_INTERVAL, CompiledServeListener, DynError, ManagedProxyConfig,
        ROUTE_BACKEND_WARMUP_DURATION, ServeSupervisor, build_tls_server_config,
        compile_route_backend_pool,
        compile_workspace_runtime, sign_admin_request, to_dyn_error,
    };

    #[test]
    fn compile_workspace_runtime_accepts_http2_public_listener(
    ) -> Result<(), DynError> {
        let path = write_temp_config(
            "http2-runtime",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http2", "127.0.0.1:19080"),
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;

        assert_eq!(compiled.listeners.len(), 2);
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_respects_weighted_round_robin_policy(
    ) -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![
                lb_config_model::UpstreamEndpointConfig {
                    id: String::from("a"),
                    address: "127.0.0.1:18081".parse()?,
                    state: lb_config_model::EndpointStateConfig::Ready,
                    zone: None,
                    locality: None,
                    weight: 3,
                },
                lb_config_model::UpstreamEndpointConfig {
                    id: String::from("b"),
                    address: "127.0.0.1:18082".parse()?,
                    state: lb_config_model::EndpointStateConfig::Ready,
                    zone: None,
                    locality: None,
                    weight: 1,
                },
            ],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::WeightedRoundRobin,
                locality: lb_config_model::LocalityRoutingConfig::Disabled,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;
        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);

        let selected = (0..8)
            .map(|request_hash| pool.select_upstream(request_hash).map(|upstream| upstream.name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_dyn_error)?;

        assert_eq!(
            selected,
            vec![
                String::from("frontend:a"),
                String::from("frontend:a"),
                String::from("frontend:b"),
                String::from("frontend:a"),
                String::from("frontend:a"),
                String::from("frontend:a"),
                String::from("frontend:b"),
                String::from("frontend:a"),
            ]
        );
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_supports_locality_preferences(
    ) -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![
                lb_config_model::UpstreamEndpointConfig {
                    id: String::from("west"),
                    address: "127.0.0.1:18081".parse()?,
                    state: lb_config_model::EndpointStateConfig::Ready,
                    zone: Some(String::from("zone-west")),
                    locality: Some(String::from("edge-west")),
                    weight: 1,
                },
                lb_config_model::UpstreamEndpointConfig {
                    id: String::from("east"),
                    address: "127.0.0.1:18082".parse()?,
                    state: lb_config_model::EndpointStateConfig::Ready,
                    zone: Some(String::from("zone-east")),
                    locality: Some(String::from("edge-east")),
                    weight: 1,
                },
            ],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin,
                locality: lb_config_model::LocalityRoutingConfig::PreferLocalityThenZone,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;
        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);

        let locality_selected = pool
            .select_upstream_with_context(&lb_runtime::SelectionContext {
                preferred_locality: Some(String::from("edge-west")),
                preferred_zone: Some(String::from("zone-east")),
                request_hash: 7,
            })
            .map_err(to_dyn_error)?;
        assert_eq!(locality_selected.name, "frontend:west");

        let zone_selected = pool
            .select_upstream_with_context(&lb_runtime::SelectionContext {
                preferred_locality: Some(String::from("missing-locality")),
                preferred_zone: Some(String::from("zone-east")),
                request_hash: 11,
            })
            .map_err(to_dyn_error)?;
        assert_eq!(zone_selected.name, "frontend:east");
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_keeps_power_of_two_choices_deterministic(
    ) -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "a",
                    "127.0.0.1:18081".parse()?,
                ),
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "b",
                    "127.0.0.1:18082".parse()?,
                ),
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "c",
                    "127.0.0.1:18083".parse()?,
                ),
            ],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::PowerOfTwoChoices,
                locality: lb_config_model::LocalityRoutingConfig::Disabled,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;
        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);

        let first = pool.select_upstream(0xfeed_beef).map_err(to_dyn_error)?;
        let second = pool.select_upstream(0xfeed_beef).map_err(to_dyn_error)?;
        let third = pool.select_upstream(0xfeed_beef).map_err(to_dyn_error)?;

        assert_eq!(first.name, second.name);
        assert_eq!(second.name, third.name);
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_applies_passive_failure_and_recovery_feedback(
    ) -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "a",
                    "127.0.0.1:18081".parse()?,
                ),
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "b",
                    "127.0.0.1:18082".parse()?,
                ),
            ],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin,
                locality: lb_config_model::LocalityRoutingConfig::Disabled,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;
        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);

        let first = pool.select_backend(1).map_err(to_dyn_error)?;
        assert_eq!(first.upstream().name, "frontend:a");

        first.note_passive_failure().map_err(to_dyn_error)?;
        first.note_passive_failure().map_err(to_dyn_error)?;

        let excluded = (0..3)
            .map(|request_hash| pool.select_backend(request_hash).map(|backend| backend.upstream().name.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_dyn_error)?;
        assert!(excluded.iter().all(|name| name == "frontend:b"));

        first.note_passive_success().map_err(to_dyn_error)?;
        first.note_passive_success().map_err(to_dyn_error)?;

        let recovered = (0..4)
            .map(|request_hash| pool.select_backend(request_hash).map(|backend| backend.upstream().name.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_dyn_error)?;
        assert!(recovered.iter().any(|name| name == "frontend:a"));
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_applies_active_recovery_and_warmup_progression(
    ) -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![lb_config_model::UpstreamEndpointConfig {
                id: String::from("a"),
                address: "127.0.0.1:18081".parse()?,
                state: lb_config_model::EndpointStateConfig::Ready,
                zone: None,
                locality: None,
                weight: 10,
            }],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin,
                locality: lb_config_model::LocalityRoutingConfig::Disabled,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;

        let initial = pool.active_probe_targets().map_err(to_dyn_error)?;
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].health.status, lb_runtime::EndpointHealthStatus::Warming);
        assert_eq!(initial[0].health.effective_weight, 1);

        pool.advance_time(Duration::from_millis(500));
        let midpoint = pool.active_probe_targets().map_err(to_dyn_error)?;
        assert_eq!(midpoint[0].health.status, lb_runtime::EndpointHealthStatus::Warming);
        assert!((1..10).contains(&midpoint[0].health.effective_weight));

        pool.advance_time(Duration::from_millis(500));
        let endpoint_id = pool.active_probe_targets().map_err(to_dyn_error)?[0].endpoint_id.clone();
        assert_eq!(
            pool.active_probe_targets().map_err(to_dyn_error)?[0].health.status,
            lb_runtime::EndpointHealthStatus::Healthy
        );

        assert_eq!(
            pool.note_active_failure(&endpoint_id).map_err(to_dyn_error)?.status,
            lb_runtime::EndpointHealthStatus::Degraded
        );
        assert_eq!(
            pool.note_active_failure(&endpoint_id).map_err(to_dyn_error)?.status,
            lb_runtime::EndpointHealthStatus::Unhealthy
        );
        assert_eq!(
            pool.note_active_success(&endpoint_id).map_err(to_dyn_error)?.status,
            lb_runtime::EndpointHealthStatus::Unhealthy
        );
        let recovering = pool.note_active_success(&endpoint_id).map_err(to_dyn_error)?;
        assert_eq!(recovering.status, lb_runtime::EndpointHealthStatus::Warming);
        assert!((1..10).contains(&recovering.effective_weight));

        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);
        let healed = pool.active_probe_targets().map_err(to_dyn_error)?;
        assert_eq!(healed[0].health.status, lb_runtime::EndpointHealthStatus::Healthy);
        assert_eq!(healed[0].health.effective_weight, 10);
        Ok(())
    }

        #[test]
        fn compile_workspace_runtime_shares_cluster_health_across_routes(
        ) -> Result<(), DynError> {
                let path = write_temp_config(
                        "shared-cluster-health",
                        &format!(
                                r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "127.0.0.1:0",
            "protocol": "http1",
            "routes": ["web-a", "web-b"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "127.0.0.1:0",
            "protocol": "http1"
        }}
    ],
    "routes": [
        {{
            "name": "web-a",
            "match": {{ "type": "path_prefix", "prefix": "/a" }},
            "upstream_cluster": "frontend"
        }},
        {{
            "name": "web-b",
            "match": {{ "type": "path_prefix", "prefix": "/b" }},
            "upstream_cluster": "frontend"
        }}
    ],
    "upstream_clusters": [
        {{
            "name": "frontend",
            "endpoints": [
                {{
                    "id": "a",
                    "address": "127.0.0.1:18081",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }},
                {{
                    "id": "b",
                    "address": "127.0.0.1:18082",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
                        ),
                )?;

                let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
                let CompiledServeListener::Public {
                        proxy: ManagedProxyConfig::Http1(config),
                        ..
                } = compiled.listeners.get("public").ok_or("missing public listener")?
                else {
                        return Err("expected public HTTP/1 listener".into());
                };

                let first_pool = config
                        .route_backend_pools
                        .get("web-a")
                        .ok_or("missing first route backend pool")?
                        .clone();
                let second_pool = config
                        .route_backend_pools
                        .get("web-b")
                        .ok_or("missing second route backend pool")?
                        .clone();

                let selected = first_pool.select_backend(0).map_err(to_dyn_error)?;
                assert_eq!(selected.upstream().name, "frontend:a");
                selected.note_passive_failure().map_err(to_dyn_error)?;
                selected.note_passive_failure().map_err(to_dyn_error)?;

                let routed = (0_u64..4)
                        .map(|request_hash| second_pool.select_backend(request_hash).map(|backend| backend.upstream().name.clone()))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(to_dyn_error)?;
                assert!(routed.iter().all(|name| name == "frontend:b"));
                Ok(())
        }

    #[test]
    fn tls_server_config_disables_session_resumption_when_requested(
    ) -> Result<(), DynError> {
        let (cert_path, key_path, _cert_der) = write_temp_tls_identity()?;
        let tls_termination = lb_config_model::ListenerTlsTerminationConfig {
            certificate_source: lb_config_model::ListenerCertificateSourceConfig::Files {
                cert_path,
                key_path,
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: lb_config_model::ListenerTlsSessionResumptionConfig {
                mode: lb_config_model::ListenerTlsSessionResumptionModeConfig::Disabled,
                session_cache_size: 256,
                tls13_ticket_count: 2,
            },
            minimum_version: lb_config_model::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![lb_config_model::ListenerAlpnProtocolConfig::Http11],
        };

        let config = build_tls_server_config(&tls_termination)?;

        assert!(!config.session_storage.can_cache());
        assert!(!config.ticketer.enabled());
        assert_eq!(config.send_tls13_tickets, 0);
        Ok(())
    }

    #[test]
    fn tls_server_config_enables_hybrid_session_resumption_when_requested(
    ) -> Result<(), DynError> {
        let (cert_path, key_path, _cert_der) = write_temp_tls_identity()?;
        let tls_termination = lb_config_model::ListenerTlsTerminationConfig {
            certificate_source: lb_config_model::ListenerCertificateSourceConfig::Files {
                cert_path,
                key_path,
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: lb_config_model::ListenerTlsSessionResumptionConfig {
                mode: lb_config_model::ListenerTlsSessionResumptionModeConfig::Hybrid,
                session_cache_size: 64,
                tls13_ticket_count: 3,
            },
            minimum_version: lb_config_model::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![lb_config_model::ListenerAlpnProtocolConfig::Http11],
        };

        let config = build_tls_server_config(&tls_termination)?;

        assert!(config.session_storage.can_cache());
        assert!(config.ticketer.enabled());
        assert_eq!(config.send_tls13_tickets, 3);
        Ok(())
    }

    #[test]
    fn load_certified_key_from_source_attaches_ocsp_bytes(
    ) -> Result<(), DynError> {
        let (cert_path, key_path, _cert_der) = write_temp_tls_identity()?;
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let ocsp_path = std::env::temp_dir().join(format!("way-balancer-ocsp-{unique}.der"));
        fs::write(&ocsp_path, b"fake-ocsp-response")?;

        let certified_key = super::load_certified_key_from_source(
            &lb_config_model::ListenerCertificateSourceConfig::Files {
                cert_path,
                key_path,
                ocsp_path: Some(ocsp_path.to_string_lossy().into_owned()),
            },
        )?;

        assert_eq!(certified_key.ocsp.as_deref(), Some(b"fake-ocsp-response".as_slice()));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_serves_http2_public_listener(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_h2_upstream("http2-ok").await?;
        let path = write_temp_config(
            "http2-supervisor",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http2", &upstream_addr.to_string()),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let mut client = connect_h2_client(public_addr).await?;
        let response = send_h2_request(&mut client, "/").await.map_err(to_dyn_error)?;
        let received = receive_h2_response(response).await?;
        assert_eq!(received.0, StatusCode::OK);
        assert_eq!(received.1, "http2-ok");

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_active_health_probes_fail_over_and_recover_http1_route_backends(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let failed_addr = reserve_unused_addr().await?;
        let healthy_addr = spawn_tagged_http1_upstream("healthy-active").await?;
        let endpoints = vec![
            (String::from("frontend-a"), failed_addr.to_string()),
            (String::from("frontend-b"), healthy_addr.to_string()),
        ];
        let path = write_temp_config(
            "active-health-route-backends",
            &workspace_config_json_with_upstream_endpoints(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &endpoints,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        time::sleep(ACTIVE_HEALTH_PROBE_INTERVAL * 2 + Duration::from_millis(150)).await;
        let healthy_response = send_http1_request(public_addr, "/").await?;
        assert!(healthy_response.ends_with("healthy-active"));

        let _recovered_addr =
            spawn_tagged_http1_upstream_on(failed_addr, "recovered-active").await?;
        time::sleep(ACTIVE_HEALTH_PROBE_INTERVAL * 2 + Duration::from_millis(150)).await;

        let mut saw_recovered = false;
        for _ in 0..6 {
            let response = send_http1_request(public_addr, "/").await?;
            if response.ends_with("recovered-active") {
                saw_recovered = true;
                break;
            }
        }
        assert!(saw_recovered, "recovered endpoint never re-entered rotation");

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_reload_swaps_http1_upstream_in_place(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "reload-runtime",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_a.to_string()),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let first = send_http1_request(public_addr, "/").await?;
        assert!(first.contains("upstream-a"));

        fs::write(
            &path,
            workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_b.to_string()),
        )?;
        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));

        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.contains("upstream-b"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_validate_previews_candidate_diff_and_warnings(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "validate-preview",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_a.to_string()),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_b.to_string()),
        )?;
        let preview = send_admin_validate(admin_addr).await?;
        assert!(preview.starts_with("HTTP/1.1 200 OK"));
        assert!(preview.contains("\"candidate_snapshot\""));
        assert!(preview.contains("\"diff_preview\""));
        assert!(preview.contains("\"upstream_clusters_changed\""));
        assert!(preview.contains("\"strategy\": \"in_place_or_additive_swap\""));
        assert!(preview.contains("\"rollback_safe\": true"));
        assert!(preview.contains("\"digest_sha256\""));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocked_rebind_reload_leaves_active_listener_unchanged(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "validate-blocked-rebind",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_addr.to_string()),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http2", &upstream_addr.to_string()),
        )?;

        let preview = send_admin_validate(admin_addr).await?;
        assert!(preview.starts_with("HTTP/1.1 200 OK"));
        assert!(preview.contains("\"listener_rebind_required\""));
        assert!(preview.contains("\"strategy\": \"blocked_requires_rebind\""));

        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(reload.contains("zero-downtime replacement is not available"));

        let response = send_http1_request(public_addr, "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("upstream-a"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_signed_headers_enforce_permissions_and_reload_with_writer(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_READ_SECRET", "reader-secret");
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "signed-admin-authz",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_a.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let status = send_signed_admin_request(
            admin_addr,
            "reader-secret",
            "reader",
            "GET",
            "/status",
            "reader-status",
        )
        .await?;
        assert!(status.starts_with("HTTP/1.1 200 OK"));

        fs::write(
            &path,
            workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_b.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;

        let forbidden_reload = send_signed_admin_request(
            admin_addr,
            "reader-secret",
            "reader",
            "POST",
            "/reload",
            "reader-reload",
        )
        .await?;
        assert!(forbidden_reload.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(forbidden_reload.contains("admin action not permitted"));

        let unchanged = send_http1_request(public_addr, "/").await?;
        assert!(unchanged.contains("upstream-a"));

        let writer_reload = send_signed_admin_request(
            admin_addr,
            "writer-secret",
            "writer",
            "POST",
            "/reload",
            "writer-reload",
        )
        .await?;
        assert!(writer_reload.starts_with("HTTP/1.1 200 OK"));

        let updated = send_http1_request(public_addr, "/").await?;
        assert!(updated.contains("upstream-b"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_audit_endpoint_reports_forbidden_signed_action(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_READ_SECRET", "reader-secret");
        std::env::set_var("LB_CTL_OPERATOR_AUDIT_SECRET", "auditor-secret");
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let upstream_addr = spawn_tagged_http1_upstream("audit-upstream").await?;
        let path = write_temp_config(
            "signed-admin-audit",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let forbidden_reload = send_signed_admin_request(
            admin_addr,
            "reader-secret",
            "reader",
            "POST",
            "/reload",
            "audit-reload",
        )
        .await?;
        assert!(forbidden_reload.starts_with("HTTP/1.1 403 Forbidden"));

        let forbidden_audit = send_signed_admin_request(
            admin_addr,
            "reader-secret",
            "reader",
            "GET",
            "/audit",
            "reader-audit-denied",
        )
        .await?;
        assert!(forbidden_audit.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(forbidden_audit.contains("admin action not permitted"));

        let audit = send_signed_admin_request(
            admin_addr,
            "auditor-secret",
            "auditor",
            "GET",
            "/audit",
            "audit-read",
        )
        .await?;
        assert!(audit.starts_with("HTTP/1.1 200 OK"));
        assert!(audit.contains("\"actor\": \"reader\""));
        assert!(audit.contains("\"action\": \"reload\""));
        assert!(audit.contains("\"outcome\": \"forbidden\""));
        assert!(audit.contains("operator lacks write permission"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_signed_headers_missing_operator_secret_fails_closed(
    ) -> Result<(), DynError> {
        let upstream_addr = spawn_tagged_http1_upstream("missing-secret-upstream").await?;
        let path = write_temp_config(
            "signed-admin-missing-secret",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                r#",
            "admin": {
                "auth": {
                    "mode": "signed_headers",
                    "operators": [
                        {
                            "id": "reader",
                            "secret_env": "LB_CTL_OPERATOR_MISSING_SECRET",
                            "permissions": ["read"]
                        }
                    ],
                    "max_clock_skew_secs": 30,
                    "nonce_ttl_secs": 120
                }
            }"#,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let response = send_signed_admin_request(
            admin_addr,
            "",
            "reader",
            "GET",
            "/status",
            "missing-secret",
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("admin authorization unavailable"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_invalid_requests_do_not_consume_authenticated_rate_limit_bucket(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let upstream_addr = spawn_tagged_http1_upstream("rate-limit-upstream").await?;
        let path = write_temp_config(
            "admin-rate-limit-authenticated-bucket",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                r#",
            "admin": {
                "auth": {
                    "mode": "signed_headers",
                    "operators": [
                        {
                            "id": "writer",
                            "secret_env": "LB_CTL_OPERATOR_WRITE_SECRET",
                            "permissions": ["read", "audit", "write"]
                        }
                    ]
                },
                "rate_limit": {
                    "requests_per_minute": 60,
                    "burst": 1
                }
            }"#,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let invalid = send_signed_admin_request(
            admin_addr,
            "wrong-secret",
            "writer",
            "GET",
            "/status",
            "bad-auth-first",
        )
        .await?;
        assert!(invalid.starts_with("HTTP/1.1 401 Unauthorized"));

        let valid = send_signed_admin_request(
            admin_addr,
            "writer-secret",
            "writer",
            "GET",
            "/status",
            "good-auth-second",
        )
        .await?;
        assert!(valid.starts_with("HTTP/1.1 200 OK"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_signed_headers_reject_replayed_nonce(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let upstream_addr = spawn_tagged_http1_upstream("replay-upstream").await?;
        let path = write_temp_config(
            "signed-admin-replay",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let first = send_signed_admin_request_with_timestamp(
            admin_addr,
            "writer-secret",
            "writer",
            "GET",
            "/status",
            timestamp,
            "reused-nonce",
        )
        .await?;
        assert!(first.starts_with("HTTP/1.1 200 OK"));

        let replay = send_signed_admin_request_with_timestamp(
            admin_addr,
            "writer-secret",
            "writer",
            "GET",
            "/status",
            timestamp,
            "reused-nonce",
        )
        .await?;
        assert!(replay.starts_with("HTTP/1.1 409 Conflict"));
        assert!(replay.contains("admin command replay rejected"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_source_allow_list_blocks_loopback_requests(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("source-policy-upstream").await?;
        let path = write_temp_config(
            "admin-source-allow-list",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                                r#",
            "admin": {
                "allowed_source_cidrs": ["192.0.2.0/24"]
            }"#,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let status = send_admin_status(admin_addr).await?;
        assert!(status.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(status.contains("admin source not allowed"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_rate_limit_rejects_burst_excess(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("rate-limit-upstream").await?;
        let path = write_temp_config(
            "admin-rate-limit",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                                r#",
            "admin": {
                "rate_limit": {
                    "requests_per_minute": 1,
                    "burst": 1
                }
            }"#,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let first = send_admin_status(admin_addr).await?;
        assert!(first.starts_with("HTTP/1.1 200 OK"));

        let second = send_admin_status(admin_addr).await?;
        assert!(second.starts_with("HTTP/1.1 429 Too Many Requests"));
        assert!(second.contains("admin rate limit exceeded"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_sheds_overloaded_http1_listener_and_reports_status(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("delayed-upstream").await?;
        let path = write_temp_config(
            "http1-overload",
            &workspace_config_json_with_limits(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(second.contains("listener overloaded"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.starts_with("HTTP/1.1 200 OK"));
        assert!(status.contains("\"name\":\"public\""));
        assert!(status.contains("\"shed_connections\":1"));
        assert!(status.contains("\"recent_overload_events\""));
        assert!(status.contains("overload.request.shed"));
        assert!(status.contains("workspace_listener_public"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;
        let first_response = String::from_utf8(first_response).map_err(to_dyn_error)?;
        assert!(first_response.starts_with("HTTP/1.1 200 OK"));
        assert!(first_response.contains("delayed-upstream"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_applies_named_overload_policy_and_reports_brownout_features(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("policy-upstream").await?;
        let path = write_temp_config(
            "http1-overload-policy",
            &workspace_config_json_with_listener_overload_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
                "listener-overload",
                &["expensive_search"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.starts_with("HTTP/1.1 503 Service Unavailable"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"overload_state\":\"brownout\""));
        assert!(status.contains("\"brownout_features\":[\"expensive_search\"]"));
        assert!(status.contains("\"recent_overload_events\":[{"));
        assert!(status.contains("overload.brownout.features_changed"));
        assert!(status.contains("overload.request.shed"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_reload_updates_overload_policy_in_place(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("reload-policy-upstream").await?;
        let path = write_temp_config(
            "reload-overload-policy",
            &workspace_config_json_with_listener_overload_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
                "listener-overload-a",
                &["expensive_search"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json_with_listener_overload_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
                "listener-overload-b",
                &["cheap_reads"],
            ),
        )?;
        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));

        let post_reload_statuses = supervisor.listener_statuses().await;
        let reloaded_public_addr = post_reload_statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener after reload")?
            .local_addr;
        assert_eq!(reloaded_public_addr, public_addr);

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;
        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.starts_with("HTTP/1.1 503 Service Unavailable"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"brownout_features\":[\"cheap_reads\"]"));
        assert!(!status.contains("\"brownout_features\":[\"expensive_search\"]"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_bounds_concurrent_overload_with_multiple_sheds(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("stress-upstream").await?;
        let path = write_temp_config(
            "http1-overload-stress",
            &workspace_config_json_with_limits(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        let mut tasks = Vec::new();
        for _ in 0..8 {
            tasks.push(tokio::spawn(send_http1_request(public_addr, "/")));
        }

        let mut shed_count = 0usize;
        for task in tasks {
            let response = task.await.map_err(to_dyn_error)??;
            if response.starts_with("HTTP/1.1 503 Service Unavailable") {
                shed_count += 1;
            }
        }
        assert_eq!(shed_count, 8);

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"active_connections\":1"));
        assert!(status.contains("\"shed_connections\":8"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_serves_https_public_listener() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-ok").await?;
        let (cert_path, key_path, cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "https-supervisor",
            &workspace_config_json_with_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &cert_path,
                &key_path,
                "tls12",
                &["http2", "http11"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let response = send_https_http1_request(public_addr, &cert_der, "localhost", "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("https-ok"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_serves_https_listener_with_http11_only_alpn() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-http11").await?;
        let (cert_path, key_path, cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "https-http11-only",
            &workspace_config_json_with_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &cert_path,
                &key_path,
                "tls13",
                &["http11"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let response = send_https_http1_request(public_addr, &cert_der, "localhost", "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("https-http11"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_rejects_tls12_client_when_https_listener_requires_tls13(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-tls13").await?;
        let (cert_path, key_path, cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "https-tls13-only",
            &workspace_config_json_with_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &cert_path,
                &key_path,
                "tls13",
                &["http11"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let result = send_https_http1_request_with_policy(
            public_addr,
            &[cert_der],
            "localhost",
            "/",
            &[&rustls::version::TLS12],
            &[b"http/1.1"],
        )
        .await;
        assert!(result.is_err());

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_selects_sni_certificate_for_named_host() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-sni").await?;
        let (default_cert_path, default_key_path, default_cert_der) =
            write_temp_tls_identity_for_host("fallback.local")?;
        let (tenant_cert_path, tenant_key_path, tenant_cert_der) =
            write_temp_tls_identity_for_host("tenant.local")?;
        let path = write_temp_config(
            "https-sni",
            &workspace_config_json_with_tls_and_sni(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &default_cert_path,
                &default_key_path,
                "tls12",
                &["http11"],
                &[(vec!["tenant.local"], tenant_cert_path.as_str(), tenant_key_path.as_str())],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let tenant_response = send_https_http1_request_with_roots(
            public_addr,
            &[default_cert_der.clone(), tenant_cert_der.clone()],
            "tenant.local",
            "/",
        )
        .await?;
        assert!(tenant_response.starts_with("HTTP/1.1 200 OK"));
        assert!(tenant_response.contains("https-sni"));

        let fallback_response = send_https_http1_request_with_roots(
            public_addr,
            &[default_cert_der, tenant_cert_der],
            "fallback.local",
            "/",
        )
        .await?;
        assert!(fallback_response.starts_with("HTTP/1.1 200 OK"));
        assert!(fallback_response.contains("https-sni"));

        supervisor.shutdown().await?;
        Ok(())
    }

    fn write_temp_config(
        prefix: &str,
        contents: &str,
    ) -> Result<PathBuf, DynError> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("way-balancer-{prefix}-{unique}.json"));
        fs::write(&path, contents)?;
        Ok(path)
    }

    fn workspace_config_json(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
    ) -> String {
                workspace_config_json_with_limits(public_addr, admin_addr, public_protocol, upstream_addr, 128, 128)
        }

        fn workspace_config_json_with_admin_policy(
                public_addr: &str,
                admin_addr: &str,
                public_protocol: &str,
                upstream_addr: &str,
                admin_policy_json: &str,
        ) -> String {
                format!(
                        r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"{admin_policy_json}
        }}
    ],
    "routes": [
        {{
            "name": "web",
            "match": {{ "type": "path_prefix", "prefix": "/" }},
            "upstream_cluster": "frontend"
        }}
    ],
    "upstream_clusters": [
        {{
            "name": "frontend",
            "endpoints": [
                {{
                    "id": "frontend-a",
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
                )
        }

        fn signed_headers_admin_policy_json() -> &'static str {
                r#",
            "admin": {
                "auth": {
                    "mode": "signed_headers",
                    "operators": [
                        {
                            "id": "reader",
                            "secret_env": "LB_CTL_OPERATOR_READ_SECRET",
                            "permissions": ["read"]
                        },
                        {
                            "id": "auditor",
                            "secret_env": "LB_CTL_OPERATOR_AUDIT_SECRET",
                            "permissions": ["audit"]
                        },
                        {
                            "id": "writer",
                            "secret_env": "LB_CTL_OPERATOR_WRITE_SECRET",
                            "permissions": ["read", "audit", "write"]
                        }
                    ],
                    "max_clock_skew_secs": 30,
                    "nonce_ttl_secs": 120
                },
                "audit": {
                    "max_retained_events": 16
                }
            }"#
        }

        fn workspace_config_json_with_limits(
                public_addr: &str,
                admin_addr: &str,
                public_protocol: &str,
                upstream_addr: &str,
                public_max_connections: usize,
                admin_max_connections: usize,
        ) -> String {
        format!(
            r#"{{
  "api_version": "v1_alpha1",
  "name": "workspace-runtime",
  "listeners": [
    {{
      "name": "public",
      "class": "public",
      "bind_address": "{public_addr}",
      "protocol": "{public_protocol}",
            "max_connections": {public_max_connections},
      "routes": ["web"]
    }},
    {{
      "name": "admin",
      "class": "admin",
      "bind_address": "{admin_addr}",
            "max_connections": {admin_max_connections},
      "protocol": "http1"
    }}
  ],
  "routes": [
    {{
      "name": "web",
      "match": {{ "type": "path_prefix", "prefix": "/" }},
      "upstream_cluster": "frontend"
    }}
  ],
  "upstream_clusters": [
    {{
      "name": "frontend",
      "endpoints": [
        {{
          "id": "frontend-a",
          "address": "{upstream_addr}",
          "state": "ready",
          "zone": null,
          "locality": null,
          "weight": 1
        }}
      ]
    }}
  ]
}}"#
        )
    }

        fn workspace_config_json_with_upstream_endpoints(
                public_addr: &str,
                admin_addr: &str,
                public_protocol: &str,
            endpoints: &[(String, String)],
        ) -> String {
                let endpoints_json = endpoints
                        .iter()
                        .map(|(id, address)| {
                                format!(
                                        r#"        {{
                    "id": "{}",
                    "address": "{}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}"#,
                                        id.as_str(),
                                        address.as_str(),
                                )
                        })
                        .collect::<Vec<_>>()
                        .join(",\n");
                format!(
                        r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
        }}
    ],
    "routes": [
        {{
            "name": "web",
            "match": {{ "type": "path_prefix", "prefix": "/" }},
            "upstream_cluster": "frontend"
        }}
    ],
    "upstream_clusters": [
        {{
            "name": "frontend",
            "endpoints": [
{endpoints_json}
            ]
        }}
    ]
}}"#
                )
        }

        fn workspace_config_json_with_listener_overload_policy(
                public_addr: &str,
                admin_addr: &str,
                public_protocol: &str,
                upstream_addr: &str,
                public_max_connections: usize,
                admin_max_connections: usize,
                policy_name: &str,
                brownout_features: &[&str],
        ) -> String {
                let brownout_features_json = brownout_features
                        .iter()
                        .map(|feature| {
                                format!(
                                        "{{ \"name\": \"{feature}\", \"priority\": \"best_effort\" }}"
                                )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");

                format!(
                        r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "max_connections": {public_max_connections},
            "routes": ["web"],
            "policies": {{
                "overload_response": "{policy_name}"
            }}
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "max_connections": {admin_max_connections},
            "protocol": "http1"
        }}
    ],
    "routes": [
        {{
            "name": "web",
            "match": {{ "type": "path_prefix", "prefix": "/" }},
            "upstream_cluster": "frontend"
        }}
    ],
    "upstream_clusters": [
        {{
            "name": "frontend",
            "endpoints": [
                {{
                    "id": "frontend-a",
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ],
    "policies": {{
        "overload_responses": [
            {{
                "name": "{policy_name}",
                "spec": {{
                    "signal_window_ms": 10000,
                    "constrained_signal_threshold": 1,
                    "shedding_signal_threshold": 1,
                    "brownout_signal_threshold": 1,
                    "brownout_features": [{brownout_features_json}]
                }}
            }}
        ]
    }}
}}"#,
                )
        }

    fn workspace_config_json_with_tls(
        public_addr: &str,
        admin_addr: &str,
        upstream_addr: &str,
        cert_path: &str,
        key_path: &str,
        minimum_version: &str,
        alpn_protocols: &[&str],
    ) -> String {
        workspace_config_json_with_tls_and_sni(
            public_addr,
            admin_addr,
            upstream_addr,
            cert_path,
            key_path,
            minimum_version,
            alpn_protocols,
            &[],
        )
    }

    fn workspace_config_json_with_tls_and_sni(
        public_addr: &str,
        admin_addr: &str,
        upstream_addr: &str,
        cert_path: &str,
        key_path: &str,
        minimum_version: &str,
        alpn_protocols: &[&str],
        sni_certificates: &[(Vec<&str>, &str, &str)],
    ) -> String {
        let alpn_json = alpn_protocols
            .iter()
            .map(|protocol| format!("\"{protocol}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let sni_json = if sni_certificates.is_empty() {
            String::from("[]")
        } else {
            format!(
                "[{}]",
                sni_certificates
                    .iter()
                    .map(|(server_names, cert_path, key_path)| {
                        let server_names_json = server_names
                            .iter()
                            .map(|name| format!("\"{name}\""))
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!(
                            "{{\n                    \"server_names\": [{server_names_json}],\n                    \"certificate_source\": {{\n                        \"type\": \"files\",\n                        \"cert_path\": \"{cert_path}\",\n                        \"key_path\": \"{key_path}\"\n                    }}\n                }}"
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "https",
            "routes": ["web"],
            "tls_termination": {{
                "minimum_version": "{minimum_version}",
                "alpn_protocols": [{alpn_json}],
                "sni_certificates": {sni_json},
                "certificate_source": {{
                    "type": "files",
                    "cert_path": "{cert_path}",
                    "key_path": "{key_path}"
                }}
            }}
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
        }}
    ],
    "routes": [
        {{
            "name": "web",
            "match": {{ "type": "path_prefix", "prefix": "/" }},
            "upstream_cluster": "frontend"
        }}
    ],
    "upstream_clusters": [
        {{
            "name": "frontend",
            "endpoints": [
                {{
                    "id": "frontend-a",
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
        )
    }

    fn write_temp_tls_identity() -> Result<(String, String, Vec<u8>), DynError> {
        write_temp_tls_identity_for_host("localhost")
    }

    fn write_temp_tls_identity_for_host(
        host: &str,
    ) -> Result<(String, String, Vec<u8>), DynError> {
        let certified = generate_simple_self_signed(vec![host.to_string()]).map_err(to_dyn_error)?;
        let cert_pem = certified.cert.pem();
        let cert_der = certified.cert.der().to_vec();
        let key_pem = certified.key_pair.serialize_pem();
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let cert_path = std::env::temp_dir().join(format!("way-balancer-cert-{host}-{unique}.pem"));
        let key_path = std::env::temp_dir().join(format!("way-balancer-key-{host}-{unique}.pem"));
        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;
        Ok((
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
            cert_der,
        ))
    }

    async fn spawn_tagged_http1_upstream(body: &'static str) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        spawn_http1_listener(listener, body);
        Ok(address)
    }

    async fn spawn_tagged_http1_upstream_on(
        address: SocketAddr,
        body: &'static str,
    ) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        spawn_http1_listener(listener, body);
        Ok(address)
    }

    fn spawn_http1_listener(listener: TcpListener, body: &'static str) {
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 2048];
                    let _ = stream.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
    }

    async fn spawn_blocked_http1_upstream(
        body: &'static str,
    ) -> io::Result<(SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        Ok((address, accepted_rx, release_tx))
    }

    async fn spawn_tagged_h2_upstream(body: &'static str) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let mut connection = match server::handshake(stream).await {
                    Ok(connection) => connection,
                    Err(_) => return,
                };

                while let Some(result) = connection.accept().await {
                    let Ok((_request, mut respond)) = result else {
                        break;
                    };
                    let response = Response::builder().status(StatusCode::OK).body(());
                    if let Ok(response) = response {
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from(body.to_string()), true);
                        }
                    }
                }
            }
        });
        Ok(address)
    }

    async fn connect_h2_client(
        address: SocketAddr,
    ) -> Result<client::SendRequest<Bytes>, DynError> {
        let stream = TcpStream::connect(address).await?;
        let (client, connection) = client::handshake(stream).await.map_err(to_dyn_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    async fn send_h2_request(
        client: &mut client::SendRequest<Bytes>,
        path: &str,
    ) -> Result<h2::client::ResponseFuture, h2::Error> {
        let request = Request::builder().method("GET").uri(path).body(())
            .map_err(|_| h2::Reason::INTERNAL_ERROR)?;
        let (response, _) = client.send_request(request, true)?;
        Ok(response)
    }

    async fn receive_h2_response(
        response: h2::client::ResponseFuture,
    ) -> Result<(StatusCode, String), DynError> {
        let response = response.await.map_err(to_dyn_error)?;
        let status = response.status();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(to_dyn_error)?;
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, String::from_utf8(bytes).map_err(to_dyn_error)?))
    }

    async fn send_http1_request(
        address: SocketAddr,
        target: &str,
    ) -> Result<String, DynError> {
        let mut stream = start_http1_request(address, target).await?;
        let mut response = Vec::new();
        match stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => return Err(to_dyn_error(error)),
        }
        Ok(String::from_utf8(response).map_err(to_dyn_error)?)
    }

    async fn start_http1_request(
        address: SocketAddr,
        target: &str,
    ) -> Result<TcpStream, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                format!(
                    "GET {target} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        Ok(stream)
    }

    async fn send_admin_reload(
        address: SocketAddr,
    ) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"POST /reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response).map_err(to_dyn_error)?)
    }

    async fn send_admin_status(
        address: SocketAddr,
    ) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response).map_err(to_dyn_error)?)
    }

    async fn send_admin_validate(
        address: SocketAddr,
    ) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /validate HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response).map_err(to_dyn_error)?)
    }

    async fn send_signed_admin_request(
        address: SocketAddr,
        secret: &str,
        actor: &str,
        method: &str,
        target: &str,
        nonce: &str,
    ) -> Result<String, DynError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        send_signed_admin_request_with_timestamp(
            address,
            secret,
            actor,
            method,
            target,
            timestamp,
            nonce,
        )
        .await
    }

    async fn send_signed_admin_request_with_timestamp(
        address: SocketAddr,
        secret: &str,
        actor: &str,
        method: &str,
        target: &str,
        timestamp: u64,
        nonce: &str,
    ) -> Result<String, DynError> {
        let signature = sign_admin_request(secret, actor, method, target, timestamp, nonce);
        let request = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\nX-LB-Admin-Actor: {actor}\r\nX-LB-Admin-Timestamp: {timestamp}\r\nX-LB-Admin-Nonce: {nonce}\r\nX-LB-Admin-Signature: {signature}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        send_admin_request_bytes(address, request.as_bytes()).await
    }

    async fn send_admin_request_bytes(
        address: SocketAddr,
        request: &[u8],
    ) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request).await?;
        let mut response = Vec::new();
        match stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => return Err(to_dyn_error(error)),
        }
        Ok(String::from_utf8(response).map_err(to_dyn_error)?)
    }

    async fn reserve_unused_addr() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        drop(listener);
        Ok(address)
    }

    async fn send_https_http1_request(
        address: SocketAddr,
        cert_der: &[u8],
        server_name: &str,
        target: &str,
    ) -> Result<String, DynError> {
        send_https_http1_request_with_roots(address, &[cert_der.to_vec()], server_name, target).await
    }

    async fn send_https_http1_request_with_roots(
        address: SocketAddr,
        cert_ders: &[Vec<u8>],
        server_name: &str,
        target: &str,
    ) -> Result<String, DynError> {
        send_https_http1_request_with_policy(
            address,
            cert_ders,
            server_name,
            target,
            &[&rustls::version::TLS13, &rustls::version::TLS12],
            &[b"http/1.1"],
        )
        .await
    }

    async fn send_https_http1_request_with_policy(
        address: SocketAddr,
        cert_ders: &[Vec<u8>],
        server_name: &str,
        target: &str,
        protocol_versions: &[&'static rustls::SupportedProtocolVersion],
        alpn_protocols: &[&[u8]],
    ) -> Result<String, DynError> {
        let mut root_store = RootCertStore::empty();
        for cert_der in cert_ders {
            root_store
                .add(CertificateDer::from(cert_der.clone()))
                .map_err(to_dyn_error)?;
        }
        let mut client_config = ClientConfig::builder_with_protocol_versions(protocol_versions)
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols = alpn_protocols.iter().map(|protocol| protocol.to_vec()).collect();
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(address).await?;
        let server_name = ServerName::try_from(server_name.to_string()).map_err(to_dyn_error)?;
        let mut tls_stream = connector.connect(server_name, stream).await.map_err(to_dyn_error)?;
        tls_stream
            .write_all(
                format!(
                    "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        match tls_stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::UnexpectedEof
                    && error.to_string().contains("close_notify") => {}
            Err(error) => return Err(to_dyn_error(error)),
        }
        Ok(String::from_utf8(response).map_err(to_dyn_error)?)
    }
}