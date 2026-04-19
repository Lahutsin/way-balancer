#![forbid(unsafe_code)]

mod anonymous_sources;
mod config_application;
mod emergency_protection;
mod failure_management;
mod http1_proxy;
mod http2_proxy;
mod http_cache;
mod local_limits;
mod overload_management;
mod probe_semantics;
mod protocol_protection;
mod route_enumeration;
mod source_guards;
mod tcp_proxy;
mod telemetry;
mod trusted_client_ip;
mod upstream_balancer;
mod upstream_health;
mod upstream_registry;

pub use anonymous_sources::{
    AnonymousSourceCategory, AnonymousSourceFilterPolicy, AnonymousSourceFilterSnapshot,
    AnonymousSourceFilterState,
};
pub use config_application::{
    AppliedSnapshotRecord, AppliedSnapshotSummary, DataplaneSnapshotManager,
    DataplaneSnapshotStatus, InvalidApplyRequest, NoopSnapshotActivationHook,
    SnapshotActivationError, SnapshotActivationHook, SnapshotApplyAck, SnapshotApplyError,
    SnapshotApplyFailure, SnapshotApplyFailureCategory, SnapshotApplyLifecycle,
    SnapshotApplyMetrics, SnapshotApplyOutcome, SnapshotApplyRequest,
};
pub use emergency_protection::{
    AbuseEventCategory, AbuseEventInput, AbuseEventLabel, AbuseForensicsError,
    AbuseForensicsExport, AbuseForensicsMetrics, EmergencyModeSwitchError,
    EmergencyModeSwitchRecord, EmergencyModeSwitchRequest, EmergencyModeSwitchResponse,
    EmergencyModeSwitchResult, EmergencyProtectionController, EmergencyProtectionMode,
    EmergencyProtectionProfile, EmergencyProtectionSnapshot, SlowClientMitigationLevel,
};
pub use failure_management::{
    CircuitBreaker, CircuitBreakerPolicy, CircuitBreakerSnapshot, CircuitBreakerState,
    FailureManagementError, FailureManagementMetrics, FailureManager, RetryBudget,
    RetryBudgetPolicy, RetryBudgetSnapshot, TimeoutCategory, TimeoutHierarchy,
    UpstreamFailureClass,
};
pub use http1_proxy::{
    proxy_http1_connection, proxy_http1_connection_with_downstream_addr, Http1ConnectionMetrics,
    Http1ConnectionReport, Http1ProxyConfig, Http1ProxyError, Http1ResponseCacheConfig,
    Http1RouteUpstream,
};
pub use http2_proxy::{
    proxy_http2_connection, proxy_http2_connection_with_downstream_addr, Http2ConnectionMetrics,
    Http2ConnectionReport, Http2ProxyConfig, Http2ProxyError, Http2RouteUpstream,
};
pub use http_cache::{
    build_http_cache_key_material, HttpCacheEntry, HttpCacheEntrySnapshot, HttpCacheFreshness,
    HttpCacheHeader, HttpCacheInsertResult, HttpCacheInvalidationApplyResult,
    HttpCacheInvalidationBus, HttpCacheInvalidationBusTransport, HttpCacheInvalidationError,
    HttpCacheInvalidationEvent, HttpCacheInvalidationPublishResult,
    HttpCacheInvalidationSubscriber, HttpCacheInvalidationTarget, HttpCacheInvalidationTransport,
    HttpCacheInvalidationTransportError, HttpCacheKey, HttpCacheKeyMaterial, HttpCacheLookup,
    HttpCacheMetadata, HttpCacheRequest, HttpCacheStore, HttpCacheStoreConfig, HttpCacheStoreError,
    HttpCacheStoreInvalidationSubscriber, HttpCacheStoreMetrics, HttpCacheStoreSnapshot,
    HTTP_CACHE_INVALIDATION_MAX_EVENT_ID_LEN, HTTP_CACHE_INVALIDATION_MAX_ISSUER_LEN,
    HTTP_CACHE_INVALIDATION_MAX_PATH_PREFIX_LEN, HTTP_CACHE_INVALIDATION_MAX_SCOPE_LEN,
};
pub use local_limits::{
    LimitContext, LocalConcurrencyLease, LocalConcurrencyLimitConfig, LocalConcurrencyLimiter,
    LocalConcurrencyLimiterMetrics, LocalLimitError, LocalLimitKeyKind, LocalLimitScope,
    LocalRateLimitConfig, LocalRateLimiter, LocalRateLimiterMetrics, RateLimitDecision,
};
pub use overload_management::{
    BrownoutFeature, BrownoutFeatureState, BrownoutHookRegistry, OverloadManagementError,
    OverloadManager, OverloadMetrics, OverloadPolicy, OverloadSignal, OverloadSignalKind,
    OverloadSnapshot, OverloadState, ShedReason, SheddingAction, SheddingDecision, TrafficClass,
};
pub use probe_semantics::{
    LivenessProbeState, ProbeEvaluation, ProbeMetrics, ProbeSemanticsEvaluator,
    ReadinessProbeState, RuntimeProbeInput, StartupProbeState,
};
pub use protocol_protection::{ProtocolAnomalyCategory, SlowClientStage};
pub use route_enumeration::{
    RouteEnumerationProtectionPolicy, RouteEnumerationProtectionSnapshot,
    RouteEnumerationProtectionState,
};
pub use source_guards::{
    AbuseRejectionReason, HandshakeGuardPolicy, HandshakePermit,
    ListenerAbuseProtectionPolicy, ListenerAbuseProtectionSnapshot,
    ListenerAbuseProtectionState, SourceAggregation, SourceQuotaPolicy,
};
pub use tcp_proxy::{
    proxy_tcp_stream, ConnectionContext, ConnectionEventKind, ConnectionMetadata,
    ProxySessionReport, TcpProxyConfig, TcpProxyError,
};
pub use telemetry::{HttpCacheRequestOutcome, HttpCacheRevalidationResult, RuntimeTelemetry};
pub use trusted_client_ip::{TrustedClientIpError, TrustedClientIpPolicy};
pub use upstream_balancer::{
    ActiveProbeTarget, AffinityFallbackPolicy, AffinityPolicy, EndpointSelectionCandidate,
    LoadBalancingAlgorithm, LocalityRoutingPolicy, NoHealthyFallback, RouteBackendPool,
    SelectedEndpoint, SelectedRouteBackend, SelectionContext, UpstreamBalancer,
    UpstreamSelectionError, UpstreamSelectionMetrics, UpstreamSelectionPolicy,
};
pub use upstream_health::{
    EndpointHealthPolicy, EndpointHealthSnapshot, EndpointHealthStatus, UpstreamHealthError,
    UpstreamHealthMetrics, UpstreamHealthRegistry,
};
pub use upstream_registry::{EndpointRegistry, EndpointRegistryError, EndpointRegistryMetrics};

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time;

/// Returns the crate identifier for the runtime layer.
pub const CRATE_ID: &str = "lb-runtime";
const COMPATIBILITY_MATRIX_PATH: &str = "docs/runbooks/compatibility-matrix.md";
const STABILITY_CONTRACT_PATH: &str = "docs/runbooks/stability-contract.md";
const UPGRADE_POLICY_PATH: &str = "docs/runbooks/upgrade-rollback-policy.md";
const SUPPORTED_RELEASE_LINE: &str = "0.1.x";
const SUPPORTED_CONFIG_API_VERSIONS: [lb_config_model::ConfigApiVersion; 1] =
    [lb_config_model::ConfigApiVersion::V1Alpha1];

/// Basic runtime metadata used by future dataplane components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeMetadata {
    /// Service identifier exposed by the runtime layer.
    pub service_name: &'static str,
    /// Release version reported by the built artifact.
    pub release_version: &'static str,
    /// Supported typed config API versions for this release.
    pub supported_config_api_versions: &'static [lb_config_model::ConfigApiVersion],
    /// Supported workspace release line for this binary.
    pub supported_release_line: &'static str,
    /// Canonical compatibility matrix artifact for this release line.
    pub compatibility_matrix_path: &'static str,
    /// Canonical stability contract artifact for this release line.
    pub stability_contract_path: &'static str,
    /// Canonical upgrade and rollback policy artifact for this release line.
    pub upgrade_policy_path: &'static str,
}

impl RuntimeMetadata {
    /// Creates the default runtime metadata for this workspace.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            service_name: lb_observability::SERVICE_NAME,
            release_version: env!("CARGO_PKG_VERSION"),
            supported_config_api_versions: &SUPPORTED_CONFIG_API_VERSIONS,
            supported_release_line: SUPPORTED_RELEASE_LINE,
            compatibility_matrix_path: COMPATIBILITY_MATRIX_PATH,
            stability_contract_path: STABILITY_CONTRACT_PATH,
            upgrade_policy_path: UPGRADE_POLICY_PATH,
        }
    }

    #[must_use]
    pub fn supports_config_api_version(&self, version: lb_config_model::ConfigApiVersion) -> bool {
        self.supported_config_api_versions.contains(&version)
    }
}

impl Default for RuntimeMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic lifecycle states for a running listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerState {
    /// Listener has been created but is not accepting connections yet.
    Starting,
    /// Listener accepts new connections and enforces admission limits.
    Running,
    /// Listener no longer accepts connections and waits for active drains.
    Draining,
    /// Listener has fully stopped.
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerStateSignal {
    Started,
    ShutdownRequested,
    Drained,
}

const fn transition_state(state: ListenerState, signal: ListenerStateSignal) -> ListenerState {
    match (state, signal) {
        (ListenerState::Starting, ListenerStateSignal::Started) => ListenerState::Running,
        (ListenerState::Running, ListenerStateSignal::ShutdownRequested) => ListenerState::Draining,
        (ListenerState::Draining, ListenerStateSignal::Drained) => ListenerState::Stopped,
        (ListenerState::Stopped, _) => ListenerState::Stopped,
        (current, _) => current,
    }
}

/// High-level categories for runtime lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerEventKind {
    /// Listener started accepting connections.
    Started,
    /// A connection was admitted.
    Accepted,
    /// A connection was rejected due to limits.
    Rejected,
    /// Shutdown was requested.
    ShutdownRequested,
    /// Listener entered drain mode.
    Draining,
    /// Listener stopped fully.
    Stopped,
    /// Listener accept loop observed an I/O error.
    AcceptError,
}

/// Structured runtime event for listener lifecycle observability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerEvent {
    /// Event category.
    pub kind: ListenerEventKind,
    /// Short human-readable detail.
    pub detail: String,
}

/// Observable snapshot of listener state and counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerSnapshot {
    /// Listener display name.
    pub name: String,
    /// Listener network classification.
    pub class: lb_net_core::ListenerClass,
    /// Local bound address.
    pub local_addr: SocketAddr,
    /// Current lifecycle state.
    pub state: ListenerState,
    /// Number of active admitted connections.
    pub active_connections: usize,
    /// Total admitted connections since start.
    pub accepted_connections: usize,
    /// Total rejected connections since start.
    pub rejected_connections: usize,
    /// Recent bounded lifecycle events.
    pub recent_events: Vec<ListenerEvent>,
}

struct ConnectionProtectionLease {
    _source_lease: Option<source_guards::SourceQuotaLease>,
    handshake_permit: Option<source_guards::HandshakePermit>,
    handshake_timeout: Option<std::time::Duration>,
}

#[derive(Debug)]
struct ListenerShared {
    name: String,
    class: lb_net_core::ListenerClass,
    local_addr: SocketAddr,
    state: RwLock<ListenerState>,
    active_connections: AtomicUsize,
    accepted_connections: AtomicUsize,
    rejected_connections: AtomicUsize,
    recent_events: Mutex<VecDeque<ListenerEvent>>,
    zero_active: Notify,
}

impl ListenerShared {
    fn new(config: &lb_net_core::ListenerConfig, local_addr: SocketAddr) -> Self {
        Self {
            name: config.name.clone(),
            class: config.class,
            local_addr,
            state: RwLock::new(ListenerState::Starting),
            active_connections: AtomicUsize::new(0),
            accepted_connections: AtomicUsize::new(0),
            rejected_connections: AtomicUsize::new(0),
            recent_events: Mutex::new(VecDeque::with_capacity(32)),
            zero_active: Notify::new(),
        }
    }

    fn snapshot(&self) -> ListenerSnapshot {
        let state = *self.state.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let recent_events = self
            .recent_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect();

        ListenerSnapshot {
            name: self.name.clone(),
            class: self.class,
            local_addr: self.local_addr,
            state,
            active_connections: self.active_connections.load(Ordering::SeqCst),
            accepted_connections: self.accepted_connections.load(Ordering::SeqCst),
            rejected_connections: self.rejected_connections.load(Ordering::SeqCst),
            recent_events,
        }
    }

    fn push_event(&self, kind: ListenerEventKind, detail: impl Into<String>) {
        const MAX_EVENTS: usize = 32;

        let mut events = self.recent_events.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() == MAX_EVENTS {
            let _ = events.pop_front();
        }
        events.push_back(ListenerEvent { kind, detail: detail.into() });
    }

    fn transition(&self, signal: ListenerStateSignal) -> ListenerState {
        let mut state = self.state.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        *state = transition_state(*state, signal);
        *state
    }

    async fn wait_for_zero_connections(&self) {
        while self.active_connections.load(Ordering::SeqCst) != 0 {
            self.zero_active.notified().await;
        }
    }
}

/// Errors produced by the listener runtime skeleton.
#[derive(Debug)]
pub enum ListenerRuntimeError {
    /// Listener configuration failed validation.
    InvalidConfig(lb_net_core::ListenerConfigError),
    /// Listener bind failed.
    Bind(std::io::Error),
    /// Listener background task failed to complete normally.
    Join(tokio::task::JoinError),
}

impl fmt::Display for ListenerRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "invalid listener config: {error}"),
            Self::Bind(error) => write!(formatter, "failed to bind listener: {error}"),
            Self::Join(error) => write!(formatter, "listener task failed to join: {error}"),
        }
    }
}

impl std::error::Error for ListenerRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error),
            Self::Bind(error) => Some(error),
            Self::Join(error) => Some(error),
        }
    }
}

/// Handle for a running listener and its observable state.
#[derive(Debug)]
pub struct ListenerHandle {
    shared: Arc<ListenerShared>,
    protections: Arc<ListenerAbuseProtectionState>,
    shutdown_tx: watch::Sender<bool>,
    task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
}

impl ListenerHandle {
    /// Returns the currently bound local socket address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local_addr
    }

    /// Returns an observable snapshot of the listener state.
    #[must_use]
    pub fn snapshot(&self) -> ListenerSnapshot {
        self.shared.snapshot()
    }

    #[must_use]
    pub fn abuse_protection_snapshot(&self) -> ListenerAbuseProtectionSnapshot {
        self.protections.snapshot()
    }

    /// Requests graceful shutdown and waits for listener drain completion.
    pub async fn shutdown(&self) -> Result<(), ListenerRuntimeError> {
        if !*self.shutdown_tx.borrow() {
            self.shared
                .push_event(ListenerEventKind::ShutdownRequested, "graceful shutdown requested");
            let _ = self.shutdown_tx.send(true);
        }

        let mut task = self.task.lock().await;
        if let Some(join_handle) = task.take() {
            join_handle.await.map_err(ListenerRuntimeError::Join)?;
        }

        Ok(())
    }
}

/// Starts a bounded listener runtime from a validated network config.
pub async fn start_listener(
    config: lb_net_core::ListenerConfig,
) -> Result<ListenerHandle, ListenerRuntimeError> {
    start_listener_with_protection(config, ListenerAbuseProtectionPolicy::default()).await
}

/// Starts a bounded listener runtime with optional early abuse protections.
pub async fn start_listener_with_protection(
    config: lb_net_core::ListenerConfig,
    protection_policy: ListenerAbuseProtectionPolicy,
) -> Result<ListenerHandle, ListenerRuntimeError> {
    config.validate().map_err(ListenerRuntimeError::InvalidConfig)?;

    let listener =
        TcpListener::bind(config.bind_address).await.map_err(ListenerRuntimeError::Bind)?;
    let local_addr = listener.local_addr().map_err(ListenerRuntimeError::Bind)?;
    let shared = Arc::new(ListenerShared::new(&config, local_addr));
    let protections = Arc::new(ListenerAbuseProtectionState::new(protection_policy));
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task_shared = Arc::clone(&shared);
    let task_config = config.clone();
    let task_protections = Arc::clone(&protections);
    let task = tokio::spawn(async move {
        run_listener(listener, task_config, task_shared, semaphore, task_protections, shutdown_rx)
            .await;
    });

    Ok(ListenerHandle {
        shared,
        protections,
        shutdown_tx,
        task: Arc::new(AsyncMutex::new(Some(task))),
    })
}

async fn run_listener(
    listener: TcpListener,
    config: lb_net_core::ListenerConfig,
    shared: Arc<ListenerShared>,
    semaphore: Arc<Semaphore>,
    protections: Arc<ListenerAbuseProtectionState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let state = shared.transition(ListenerStateSignal::Started);
    shared.push_event(
        ListenerEventKind::Started,
        format!("listener entered {state:?} on {}", shared.local_addr),
    );

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    let draining = shared.transition(ListenerStateSignal::ShutdownRequested);
                    shared.push_event(ListenerEventKind::Draining, format!("listener entered {draining:?}"));
                    break;
                }

                if changed.is_err() {
                    let draining = shared.transition(ListenerStateSignal::ShutdownRequested);
                    shared.push_event(ListenerEventKind::Draining, format!("listener entered {draining:?} after control channel closed"));
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer_addr)) => {
                        let source_lease = match protections.try_acquire_source(peer_addr) {
                            Ok(lease) => lease,
                            Err(reason) => {
                                shared.rejected_connections.fetch_add(1, Ordering::SeqCst);
                                shared.push_event(
                                    ListenerEventKind::Rejected,
                                    format!(
                                        "rejected connection from {peer_addr}: {}",
                                        reason.detail()
                                    ),
                                );
                                drop(stream);
                                continue;
                            }
                        };

                        let handshake_permit = match protections.try_acquire_handshake() {
                            Ok(permit) => permit,
                            Err(reason) => {
                                shared.rejected_connections.fetch_add(1, Ordering::SeqCst);
                                shared.push_event(
                                    ListenerEventKind::Rejected,
                                    format!(
                                        "rejected connection from {peer_addr}: {}",
                                        reason.detail()
                                    ),
                                );
                                drop(source_lease);
                                drop(stream);
                                continue;
                            }
                        };

                        if let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() {
                            shared.accepted_connections.fetch_add(1, Ordering::SeqCst);
                            shared.active_connections.fetch_add(1, Ordering::SeqCst);
                            shared.push_event(ListenerEventKind::Accepted, format!("accepted connection from {peer_addr}"));
                            let connection_shared = Arc::clone(&shared);
                            let connection_shutdown = shutdown_rx.clone();
                            let protection_lease = ConnectionProtectionLease {
                                _source_lease: source_lease,
                                handshake_permit,
                                handshake_timeout: protections.handshake_timeout(),
                            };
                            tokio::spawn(async move {
                                drive_placeholder_connection(
                                    stream,
                                    permit,
                                    protection_lease,
                                    config.idle_timeout,
                                    connection_shared,
                                    connection_shutdown,
                                ).await;
                            });
                        } else {
                            shared.rejected_connections.fetch_add(1, Ordering::SeqCst);
                            shared.push_event(ListenerEventKind::Rejected, format!("rejected connection from {peer_addr}: admission limit reached"));
                            drop(handshake_permit);
                            drop(source_lease);
                            drop(stream);
                        }
                    }
                    Err(error) => {
                        shared.push_event(ListenerEventKind::AcceptError, format!("accept loop error: {error}"));
                    }
                }
            }
        }
    }

    let drain = time::timeout(config.drain_timeout, shared.wait_for_zero_connections()).await;
    let state = shared.transition(ListenerStateSignal::Drained);
    let detail = if drain.is_ok() {
        format!("listener entered {state:?} after graceful drain")
    } else {
        format!("listener entered {state:?} after drain timeout elapsed")
    };
    shared.push_event(ListenerEventKind::Stopped, detail);
}

async fn drive_placeholder_connection(
    mut stream: tokio::net::TcpStream,
    _permit: OwnedSemaphorePermit,
    mut protection_lease: ConnectionProtectionLease,
    idle_timeout: std::time::Duration,
    shared: Arc<ListenerShared>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut buffer = [0_u8; 64];

    if let Some(timeout) = protection_lease.handshake_timeout {
        let handshake_result = tokio::select! {
            _changed = shutdown_rx.changed() => None,
            read_result = time::timeout(timeout, stream.read(&mut buffer[..1])) => {
                Some(read_result)
            }
        };

        match handshake_result {
            Some(Ok(Ok(0))) => {}
            Some(Ok(Ok(_))) => {}
            Some(Ok(Err(_))) => {}
            Some(Err(_)) => {}
            None => {}
        }

        if let Some(permit) = protection_lease.handshake_permit.as_mut() {
            permit.release();
        }
    }

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }

                if changed.is_err() {
                    break;
                }
            }
            read_result = time::timeout(idle_timeout, stream.read(&mut buffer)) => {
                match read_result {
                    Ok(Ok(0)) => break,
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }
        }
    }

    if shared.active_connections.fetch_sub(1, Ordering::SeqCst) == 1 {
        shared.zero_active.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::{transition_state, ListenerState, ListenerStateSignal, RuntimeMetadata};

    #[test]
    fn listener_state_machine_is_deterministic() {
        let state = transition_state(ListenerState::Starting, ListenerStateSignal::Started);
        let state = transition_state(state, ListenerStateSignal::ShutdownRequested);
        let state = transition_state(state, ListenerStateSignal::Drained);

        assert_eq!(state, ListenerState::Stopped);
    }

    #[test]
    fn runtime_metadata_exposes_release_and_compatibility_artifacts() {
        let metadata = RuntimeMetadata::new();

        assert_eq!(metadata.release_version, env!("CARGO_PKG_VERSION"));
        assert!(metadata.supports_config_api_version(lb_config_model::ConfigApiVersion::V1Alpha1));
        assert_eq!(metadata.supported_release_line, "0.1.x");
        assert_eq!(metadata.compatibility_matrix_path, "docs/runbooks/compatibility-matrix.md");
        assert_eq!(metadata.stability_contract_path, "docs/runbooks/stability-contract.md");
        assert_eq!(metadata.upgrade_policy_path, "docs/runbooks/upgrade-rollback-policy.md");
    }
}
