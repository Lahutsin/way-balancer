use std::collections::BTreeMap;
use std::fmt;
use std::future::poll_fn;
use std::hash::Hasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::{
    AnonymousSourceFilterPolicy, AnonymousSourceFilterState, ProtocolAnomalyCategory,
    RouteEnumerationProtectionPolicy, RouteEnumerationProtectionState, SlowClientStage,
    TrustedClientIpPolicy,
};
use bytes::{Buf, Bytes};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{client, server, Reason, RecvStream, SendStream};
use http::header::{HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time;

/// Runtime configuration for a bounded HTTP/2 proxy connection.
#[derive(Debug, Clone)]
pub struct Http2ProxyConfig {
    /// Static upstream target used for forwarding streams.
    pub upstream: lb_net_core::UpstreamTarget,
    /// Connection timeout model reused from shared network primitives.
    pub timeouts: lb_net_core::ConnectionTimeouts,
    /// HTTP/2 concurrency and body limits.
    pub limits: lb_proto_http::Http2Limits,
    /// Shared route-prefix rules compatible with HTTP/1.1 routing placeholders.
    pub routes: Vec<lb_proto_http::RoutePrefixRule>,
    /// Optional route-to-upstream pools keyed by route label.
    pub route_upstreams: BTreeMap<String, Vec<lb_net_core::UpstreamTarget>>,
    /// Optional health-aware route backend pools keyed by route label.
    pub route_backend_pools: BTreeMap<String, crate::RouteBackendPool>,
    /// Deterministic round-robin cursors for route upstream pools.
    route_upstream_cursors: Arc<Mutex<BTreeMap<String, usize>>>,
    /// Whether unmatched routes should be rejected locally.
    pub reject_unmatched_routes: bool,
    /// Optional CIDR-based anonymous source filter.
    pub anonymous_source_filter: Option<Arc<AnonymousSourceFilterState>>,
    /// Optional progressive ban guard for route and query enumeration by source.
    pub route_enumeration_protection: Option<Arc<RouteEnumerationProtectionState>>,
    /// Optional trusted-proxy model used to determine the effective client IP.
    pub trusted_client_ip: Option<TrustedClientIpPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2RouteUpstream {
    pub route_label: String,
    pub upstream: lb_net_core::UpstreamTarget,
}

impl Http2ProxyConfig {
    /// Creates a baseline HTTP/2 config for a static upstream.
    #[must_use]
    pub fn new(upstream: lb_net_core::UpstreamTarget) -> Self {
        Self {
            upstream,
            timeouts: lb_net_core::ConnectionTimeouts::default(),
            limits: lb_proto_http::Http2Limits::default(),
            routes: Vec::new(),
            route_upstreams: BTreeMap::new(),
            route_backend_pools: BTreeMap::new(),
            route_upstream_cursors: Arc::new(Mutex::new(BTreeMap::new())),
            reject_unmatched_routes: false,
            anonymous_source_filter: None,
            route_enumeration_protection: None,
            trusted_client_ip: None,
        }
    }

    #[must_use]
    pub fn with_route_upstreams(
        mut self,
        route_upstreams: impl IntoIterator<Item = Http2RouteUpstream>,
    ) -> Self {
        self.route_upstreams.clear();
        for route_upstream in route_upstreams {
            self.route_upstreams
                .entry(route_upstream.route_label)
                .or_default()
                .push(route_upstream.upstream);
        }
        self
    }

    #[must_use]
    pub fn with_route_backend_pools(
        mut self,
        route_backend_pools: impl IntoIterator<Item = (String, crate::RouteBackendPool)>,
    ) -> Self {
        self.route_backend_pools = route_backend_pools.into_iter().collect();
        self
    }

    #[must_use]
    pub fn rejecting_unmatched_routes(mut self) -> Self {
        self.reject_unmatched_routes = true;
        self
    }

    #[must_use]
    pub fn with_anonymous_source_filter(mut self, policy: AnonymousSourceFilterPolicy) -> Self {
        self.anonymous_source_filter = Some(Arc::new(AnonymousSourceFilterState::new(policy)));
        self
    }

    #[must_use]
    pub fn with_route_enumeration_protection(
        mut self,
        policy: RouteEnumerationProtectionPolicy,
    ) -> Self {
        self.route_enumeration_protection =
            Some(Arc::new(RouteEnumerationProtectionState::new(policy)));
        self
    }

    #[must_use]
    pub fn with_trusted_client_ip(mut self, policy: TrustedClientIpPolicy) -> Self {
        self.trusted_client_ip = Some(policy);
        self
    }
}

/// Observable counters for an HTTP/2 proxy connection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Http2ConnectionMetrics {
    /// Final active stream count once the connection has finished.
    pub active_streams: usize,
    /// Peak number of concurrently active streams.
    pub peak_active_streams: usize,
    /// Count of requests seen on the connection.
    pub request_count: u64,
    /// Count of streams reset by the proxy.
    pub stream_reset_count: u64,
    /// Count of stream or upstream forwarding failures.
    pub stream_error_count: u64,
    /// Count of concurrent stream limit violations.
    pub stream_limit_violation_count: u64,
    /// Count of request or response body limit violations.
    pub body_limit_violation_count: u64,
    /// Count of gRPC requests observed on the connection.
    pub grpc_request_count: u64,
    /// Count of gRPC statuses observed in trailers or headers.
    pub grpc_status_counts: BTreeMap<u16, u64>,
    /// Count of protocol hardening rejections.
    pub hardening_rejection_count: u64,
    /// Count of slow-client protections triggered.
    pub slow_client_trigger_count: u64,
    /// Categorized protocol anomaly counters.
    pub anomaly_counts: BTreeMap<ProtocolAnomalyCategory, u64>,
    /// Categorized slow-client trigger counters.
    pub slow_client_counts: BTreeMap<SlowClientStage, u64>,
    /// Count of responses by status code.
    pub response_status_counts: BTreeMap<u16, u64>,
}

/// Summary of a completed HTTP/2 proxied connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2ConnectionReport {
    /// Downstream peer address.
    pub downstream_addr: SocketAddr,
    /// Upstream peer address.
    pub upstream_addr: SocketAddr,
    /// Upstream display name.
    pub upstream_name: String,
    /// Time spent connecting to the upstream.
    pub connect_duration: Duration,
    /// Aggregate counters for the proxied HTTP/2 connection.
    pub metrics: Http2ConnectionMetrics,
}

/// Errors returned by the HTTP/2 proxy runtime.
#[derive(Debug)]
pub enum Http2ProxyError {
    /// Upstream connect exceeded the configured timeout.
    ConnectTimeout { target: SocketAddr },
    /// Upstream connect failed with an I/O error.
    Connect { target: SocketAddr, source: std::io::Error },
    /// Downstream HTTP/2 handshake failed.
    DownstreamHandshake(h2::Error),
    /// Upstream HTTP/2 handshake failed.
    UpstreamHandshake(h2::Error),
    /// Downstream HTTP/2 connection failed while accepting streams.
    DownstreamConnection(h2::Error),
    /// A spawned stream task failed unexpectedly.
    StreamTask(tokio::task::JoinError),
}

impl fmt::Display for Http2ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectTimeout { target } => {
                write!(formatter, "timed out connecting HTTP/2 upstream {target}")
            }
            Self::Connect { target, source } => {
                write!(formatter, "failed to connect HTTP/2 upstream {target}: {source}")
            }
            Self::DownstreamHandshake(source) => {
                write!(formatter, "downstream HTTP/2 handshake failed: {source}")
            }
            Self::UpstreamHandshake(source) => {
                write!(formatter, "upstream HTTP/2 handshake failed: {source}")
            }
            Self::DownstreamConnection(source) => {
                write!(formatter, "downstream HTTP/2 connection failed: {source}")
            }
            Self::StreamTask(source) => write!(formatter, "HTTP/2 stream task failed: {source}"),
        }
    }
}

impl std::error::Error for Http2ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect { source, .. } => Some(source),
            Self::DownstreamHandshake(source) => Some(source),
            Self::UpstreamHandshake(source) => Some(source),
            Self::DownstreamConnection(source) => Some(source),
            Self::StreamTask(source) => Some(source),
            _ => None,
        }
    }
}

impl Http2ProxyError {
    #[must_use]
    pub fn anomaly_category(&self) -> Option<ProtocolAnomalyCategory> {
        match self {
            Self::DownstreamHandshake(_) | Self::DownstreamConnection(_) => {
                Some(ProtocolAnomalyCategory::MalformedPreface)
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
struct MetricsState {
    active_streams: AtomicUsize,
    peak_active_streams: AtomicUsize,
    request_count: AtomicU64,
    stream_reset_count: AtomicU64,
    stream_error_count: AtomicU64,
    stream_limit_violation_count: AtomicU64,
    body_limit_violation_count: AtomicU64,
    grpc_request_count: AtomicU64,
    grpc_status_counts: Mutex<BTreeMap<u16, u64>>,
    hardening_rejection_count: AtomicU64,
    slow_client_trigger_count: AtomicU64,
    anomaly_counts: Mutex<BTreeMap<ProtocolAnomalyCategory, u64>>,
    slow_client_counts: Mutex<BTreeMap<SlowClientStage, u64>>,
    response_status_counts: Mutex<BTreeMap<u16, u64>>,
}

impl MetricsState {
    fn new() -> Self {
        Self {
            active_streams: AtomicUsize::new(0),
            peak_active_streams: AtomicUsize::new(0),
            request_count: AtomicU64::new(0),
            stream_reset_count: AtomicU64::new(0),
            stream_error_count: AtomicU64::new(0),
            stream_limit_violation_count: AtomicU64::new(0),
            body_limit_violation_count: AtomicU64::new(0),
            grpc_request_count: AtomicU64::new(0),
            grpc_status_counts: Mutex::new(BTreeMap::new()),
            hardening_rejection_count: AtomicU64::new(0),
            slow_client_trigger_count: AtomicU64::new(0),
            anomaly_counts: Mutex::new(BTreeMap::new()),
            slow_client_counts: Mutex::new(BTreeMap::new()),
            response_status_counts: Mutex::new(BTreeMap::new()),
        }
    }

    fn snapshot(&self) -> Http2ConnectionMetrics {
        let grpc_status_counts =
            self.grpc_status_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        let response_status_counts = self
            .response_status_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let anomaly_counts =
            self.anomaly_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        let slow_client_counts =
            self.slow_client_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        Http2ConnectionMetrics {
            active_streams: self.active_streams.load(Ordering::SeqCst),
            peak_active_streams: self.peak_active_streams.load(Ordering::SeqCst),
            request_count: self.request_count.load(Ordering::SeqCst),
            stream_reset_count: self.stream_reset_count.load(Ordering::SeqCst),
            stream_error_count: self.stream_error_count.load(Ordering::SeqCst),
            stream_limit_violation_count: self.stream_limit_violation_count.load(Ordering::SeqCst),
            body_limit_violation_count: self.body_limit_violation_count.load(Ordering::SeqCst),
            grpc_request_count: self.grpc_request_count.load(Ordering::SeqCst),
            grpc_status_counts,
            hardening_rejection_count: self.hardening_rejection_count.load(Ordering::SeqCst),
            slow_client_trigger_count: self.slow_client_trigger_count.load(Ordering::SeqCst),
            anomaly_counts,
            slow_client_counts,
            response_status_counts,
        }
    }

    fn increment_request_count(&self) {
        self.request_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_active_streams(&self) {
        let current = self.active_streams.fetch_add(1, Ordering::SeqCst) + 1;
        let mut observed_peak = self.peak_active_streams.load(Ordering::SeqCst);
        while current > observed_peak {
            match self.peak_active_streams.compare_exchange(
                observed_peak,
                current,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => observed_peak = actual,
            }
        }
    }

    fn decrement_active_streams(&self) {
        let _ = self.active_streams.fetch_sub(1, Ordering::SeqCst);
    }

    fn increment_stream_reset_count(&self) {
        self.stream_reset_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_stream_error_count(&self) {
        self.stream_error_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_stream_limit_violation_count(&self) {
        self.stream_limit_violation_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_body_limit_violation_count(&self) {
        self.body_limit_violation_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_grpc_request_count(&self) {
        self.grpc_request_count.fetch_add(1, Ordering::SeqCst);
    }

    fn record_grpc_status(&self, status: u16) {
        let mut counts =
            self.grpc_status_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(status).or_insert(0) += 1;
    }

    fn increment_hardening_rejection_count(&self) {
        self.hardening_rejection_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_slow_client_trigger_count(&self) {
        self.slow_client_trigger_count.fetch_add(1, Ordering::SeqCst);
    }

    fn record_anomaly(&self, category: ProtocolAnomalyCategory) {
        let mut counts =
            self.anomaly_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(category).or_insert(0) += 1;
    }

    fn record_slow_client(&self, stage: SlowClientStage) {
        let mut counts =
            self.slow_client_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(stage).or_insert(0) += 1;
    }

    fn record_response_status(&self, status: u16) {
        let mut counts =
            self.response_status_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(status).or_insert(0) += 1;
    }
}

#[derive(Debug, Clone)]
struct UpstreamClientHandle {
    target: lb_net_core::UpstreamTarget,
    upstream_addr: SocketAddr,
    connect_duration: Duration,
    send_request: Arc<AsyncMutex<SendRequest<Bytes>>>,
    connected_at: Arc<Mutex<Instant>>,
    last_used_at: Arc<Mutex<Instant>>,
    completed_streams: Arc<Mutex<u64>>,
}

impl UpstreamClientHandle {
    fn mark_used(&self, at: Instant) {
        *self.last_used_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = at;
    }

    fn idle_expired(&self, now: Instant, idle_timeout: Duration) -> bool {
        now.saturating_duration_since(
            *self.last_used_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()),
        ) >= idle_timeout
    }

    fn age_expired(&self, now: Instant, max_age: Duration) -> bool {
        now.saturating_duration_since(
            *self.connected_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()),
        ) >= max_age
    }

    fn reuse_expired(&self, now: Instant, reuse_timeout: Duration) -> bool {
        self.idle_expired(now, reuse_timeout) || self.age_expired(now, reuse_timeout)
    }

    fn had_completed_streams(&self) -> bool {
        *self.completed_streams.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) > 0
    }

    fn note_completed_stream(&self) {
        *self.completed_streams.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
    }
}

#[derive(Debug, Clone, Default)]
struct UpstreamClientRegistry {
    clients: Arc<AsyncMutex<BTreeMap<String, UpstreamClientHandle>>>,
    last_active: Arc<AsyncMutex<Option<UpstreamClientHandle>>>,
}

#[derive(Debug)]
enum UpstreamClientConnectError {
    ConnectTimeout { target: SocketAddr },
    Connect { target: SocketAddr, source: std::io::Error },
    Handshake(h2::Error),
}

impl UpstreamClientRegistry {
    async fn ensure_client(
        &self,
        target: &lb_net_core::UpstreamTarget,
        timeouts: &lb_net_core::ConnectionTimeouts,
    ) -> Result<(UpstreamClientHandle, bool), UpstreamClientConnectError> {
        let key = upstream_client_key(target);
        let now = Instant::now();
        let cached_client = self.clients.lock().await.get(&key).cloned();
        if let Some(client) = cached_client {
            if client.reuse_expired(now, timeouts.idle_timeout) {
                self.remove_client(target).await;
            } else {
                let had_completed_streams = client.had_completed_streams();
                client.mark_used(now);
                self.record_active(&client).await;
                return Ok((client, had_completed_streams));
            }
        }

        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(&key) {
            if client.reuse_expired(now, timeouts.idle_timeout) {
                clients.remove(&key);
            } else {
                let client = client.clone();
                let had_completed_streams = client.had_completed_streams();
                client.mark_used(now);
                drop(clients);
                self.record_active(&client).await;
                return Ok((client, had_completed_streams));
            }
        }

        let connect_started = Instant::now();
        let upstream_stream =
            time::timeout(timeouts.connect_timeout, TcpStream::connect(target.address))
                .await
                .map_err(|_| UpstreamClientConnectError::ConnectTimeout {
                    target: target.address,
                })?
                .map_err(|source| UpstreamClientConnectError::Connect {
                    target: target.address,
                    source,
                })?;
        let connect_duration = connect_started.elapsed();
        let upstream_addr = upstream_stream
            .peer_addr()
            .map_err(|source| UpstreamClientConnectError::Connect {
                target: target.address,
                source,
            })?;

        let upstream_builder = client::Builder::new();
        let (send_request, upstream_connection) = upstream_builder
            .handshake(upstream_stream)
            .await
            .map_err(UpstreamClientConnectError::Handshake)?;
        tokio::spawn(async move {
            let _ = upstream_connection.await;
        });

        let connected_at = Instant::now();
        let client = UpstreamClientHandle {
            target: target.clone(),
            upstream_addr,
            connect_duration,
            send_request: Arc::new(AsyncMutex::new(send_request)),
            connected_at: Arc::new(Mutex::new(connected_at)),
            last_used_at: Arc::new(Mutex::new(connected_at)),
            completed_streams: Arc::new(Mutex::new(0)),
        };
        clients.insert(key, client.clone());
        drop(clients);
        self.record_active(&client).await;
        Ok((client, false))
    }

    async fn remove_client(&self, target: &lb_net_core::UpstreamTarget) {
        self.clients.lock().await.remove(&upstream_client_key(target));
    }

    async fn record_active(&self, client: &UpstreamClientHandle) {
        *self.last_active.lock().await = Some(client.clone());
    }

    async fn active_summary(&self) -> Option<UpstreamClientHandle> {
        self.last_active.lock().await.clone()
    }
}

fn upstream_client_key(target: &lb_net_core::UpstreamTarget) -> String {
    format!("{}@{}", target.name, target.address)
}

/// Proxies an HTTP/2 connection with bounded concurrent streams.
pub async fn proxy_http2_connection(
    downstream: TcpStream,
    config: &Http2ProxyConfig,
) -> Result<Http2ConnectionReport, Http2ProxyError> {
    let downstream_addr = downstream
        .peer_addr()
        .map_err(|source| Http2ProxyError::Connect { target: config.upstream.address, source })?;

    proxy_http2_connection_with_downstream_addr(downstream, downstream_addr, config).await
}

/// Proxies an HTTP/2 connection with bounded concurrent streams over an arbitrary downstream stream.
pub async fn proxy_http2_connection_with_downstream_addr<S>(
    downstream: S,
    downstream_addr: SocketAddr,
    config: &Http2ProxyConfig,
) -> Result<Http2ConnectionReport, Http2ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{

    let downstream_builder = server::Builder::new();
    let mut downstream_connection = downstream_builder
        .handshake(downstream)
        .await
        .map_err(Http2ProxyError::DownstreamHandshake)?;

    let upstream_clients = UpstreamClientRegistry::default();
    if config.route_upstreams.is_empty() && config.route_backend_pools.is_empty() {
        upstream_clients
            .ensure_client(&config.upstream, &config.timeouts)
            .await
            .map(|_| ())
            .map_err(map_upstream_client_connect_error)?;
    }

    let metrics = Arc::new(MetricsState::new());
    let semaphore = Arc::new(Semaphore::new(config.limits.max_concurrent_streams));
    let shared_config = Arc::new(config.clone());
    let mut stream_tasks = JoinSet::new();

    while let Some(result) = downstream_connection.accept().await {
        let (request, respond) = match result {
            Ok(stream) => stream,
            Err(error) => {
                let had_traffic = metrics.request_count.load(Ordering::SeqCst) > 0;
                let no_active_streams = metrics.active_streams.load(Ordering::SeqCst) == 0;
                if had_traffic && no_active_streams {
                    break;
                }
                return Err(Http2ProxyError::DownstreamConnection(error));
            }
        };
        let metrics = Arc::clone(&metrics);
        let semaphore = Arc::clone(&semaphore);
        let config = Arc::clone(&shared_config);
        let upstream_clients = upstream_clients.clone();

        stream_tasks.spawn(async move {
            handle_http2_stream(
                request,
                respond,
                downstream_addr,
                upstream_clients,
                metrics,
                semaphore,
                config,
            )
            .await;
        });
    }

    while let Some(result) = stream_tasks.join_next().await {
        result.map_err(Http2ProxyError::StreamTask)?;
    }

    let active_upstream = upstream_clients.active_summary().await;
    Ok(Http2ConnectionReport {
        downstream_addr,
        upstream_addr: active_upstream
            .as_ref()
            .map(|client| client.upstream_addr)
            .unwrap_or(config.upstream.address),
        upstream_name: active_upstream
            .as_ref()
            .map(|client| client.target.name.clone())
            .unwrap_or_else(|| config.upstream.name.clone()),
        connect_duration: active_upstream
            .as_ref()
            .map(|client| client.connect_duration)
            .unwrap_or(Duration::ZERO),
        metrics: metrics.snapshot(),
    })
}

fn map_upstream_client_connect_error(error: UpstreamClientConnectError) -> Http2ProxyError {
    match error {
        UpstreamClientConnectError::ConnectTimeout { target } => {
            Http2ProxyError::ConnectTimeout { target }
        }
        UpstreamClientConnectError::Connect { target, source } => {
            Http2ProxyError::Connect { target, source }
        }
        UpstreamClientConnectError::Handshake(source) => Http2ProxyError::UpstreamHandshake(source),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use http::{HeaderMap, HeaderValue, StatusCode};
    use ipnet::IpNet;

    use super::{
        anonymous_source_blocked, error_is_upstream_passive_failure, header_value,
        record_query_probe, record_unmatched_route, resolve_effective_client_ip,
        resolve_stream_upstream, route_enumeration_source_blocked, select_http2_route_upstream,
        selection_context_for_request, should_skip_http2_header, stable_request_hash,
        Http2ProxyConfig, Http2ProxyError, Http2RouteUpstream, MetricsState,
        RequestUpstreamResolution, StreamForwardError, StreamIdlePhase,
    };
    use crate::{
        AnonymousSourceFilterPolicy, ProtocolAnomalyCategory, RouteEnumerationProtectionPolicy,
        SlowClientStage, SourceAggregation, TrustedClientIpPolicy,
    };

    fn localhost_socket(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn http2_errors_expose_anomaly_and_sources() {
        let connect = Http2ProxyError::Connect {
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            source: io::Error::other("connect failed"),
        };
        let handshake = Http2ProxyError::DownstreamHandshake(h2::Error::from(h2::Reason::PROTOCOL_ERROR));

        assert!(connect.to_string().contains("failed to connect HTTP/2 upstream"));
        assert!(std::error::Error::source(&connect).is_some());
        assert_eq!(
            handshake.anomaly_category(),
            Some(ProtocolAnomalyCategory::MalformedPreface)
        );
    }

    #[test]
    fn metrics_state_snapshot_accumulates_all_counters() {
        let metrics = MetricsState::new();
        metrics.increment_request_count();
        metrics.increment_active_streams();
        metrics.increment_active_streams();
        metrics.decrement_active_streams();
        metrics.increment_stream_reset_count();
        metrics.increment_stream_error_count();
        metrics.increment_stream_limit_violation_count();
        metrics.increment_body_limit_violation_count();
        metrics.increment_grpc_request_count();
        metrics.record_grpc_status(0);
        metrics.increment_hardening_rejection_count();
        metrics.increment_slow_client_trigger_count();
        metrics.record_anomaly(ProtocolAnomalyCategory::BodySizeLimitExceeded);
        metrics.record_slow_client(SlowClientStage::RequestBody);
        metrics.record_response_status(200);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.active_streams, 1);
        assert_eq!(snapshot.peak_active_streams, 2);
        assert_eq!(snapshot.request_count, 1);
        assert_eq!(snapshot.stream_reset_count, 1);
        assert_eq!(snapshot.stream_error_count, 1);
        assert_eq!(snapshot.stream_limit_violation_count, 1);
        assert_eq!(snapshot.body_limit_violation_count, 1);
        assert_eq!(snapshot.grpc_request_count, 1);
        assert_eq!(snapshot.grpc_status_counts.get(&0), Some(&1));
        assert_eq!(snapshot.hardening_rejection_count, 1);
        assert_eq!(snapshot.slow_client_trigger_count, 1);
        assert_eq!(
            snapshot.anomaly_counts.get(&ProtocolAnomalyCategory::BodySizeLimitExceeded),
            Some(&1)
        );
        assert_eq!(snapshot.slow_client_counts.get(&SlowClientStage::RequestBody), Some(&1));
        assert_eq!(snapshot.response_status_counts.get(&200), Some(&1));
    }

    #[test]
    fn selection_context_trims_hints_and_uses_stable_hash() {
        let mut headers = HeaderMap::new();
        headers.insert("x-lb-locality", HeaderValue::from_static(" edge-west "));
        headers.insert("x-lb-zone", HeaderValue::from_static(" zone-west "));
        headers.insert("x-empty", HeaderValue::from_static("   "));

        let context = selection_context_for_request("/api?q=1", &headers);

        assert_eq!(context.preferred_locality.as_deref(), Some("edge-west"));
        assert_eq!(context.preferred_zone.as_deref(), Some("zone-west"));
        assert_eq!(context.request_hash, stable_request_hash(b"/api?q=1"));
        assert_eq!(header_value(&headers, "x-empty"), None);
    }

    #[test]
    fn route_upstream_selection_rotates_and_resolves_fallbacks() {
        let upstream_a = lb_net_core::UpstreamTarget::new("a", localhost_socket(9001));
        let upstream_b = lb_net_core::UpstreamTarget::new("b", localhost_socket(9002));
        let fallback = lb_net_core::UpstreamTarget::new("fallback", localhost_socket(9000));
        let mut config = Http2ProxyConfig::new(fallback.clone()).with_route_upstreams([
            Http2RouteUpstream {
                route_label: String::from("api"),
                upstream: upstream_a.clone(),
            },
            Http2RouteUpstream {
                route_label: String::from("api"),
                upstream: upstream_b.clone(),
            },
        ]);
        config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

        let route = lb_proto_http::match_route_request("/api", None, &config.routes)
            .expect("route should match");
        let selected_one = match resolve_stream_upstream(&config, Some(&route), &Default::default()) {
            RequestUpstreamResolution::Selected(selected) => selected.target,
            RequestUpstreamResolution::Reject(status) => panic!("unexpected reject: {status}"),
        };
        let selected_two = match resolve_stream_upstream(&config, Some(&route), &Default::default()) {
            RequestUpstreamResolution::Selected(selected) => selected.target,
            RequestUpstreamResolution::Reject(status) => panic!("unexpected reject: {status}"),
        };
        let selected_three = select_http2_route_upstream(
            &config,
            "api",
            config.route_upstreams.get("api").expect("route upstreams"),
        );

        assert_eq!(selected_one.address, upstream_a.address);
        assert_eq!(selected_two.address, upstream_b.address);
        assert_eq!(selected_three.address, upstream_a.address);

        let matched_none = match resolve_stream_upstream(&config, None, &Default::default()) {
            RequestUpstreamResolution::Selected(selected) => selected.target,
            RequestUpstreamResolution::Reject(status) => panic!("unexpected reject: {status}"),
        };
        assert_eq!(matched_none.address, fallback.address);

        let rejecting = Http2ProxyConfig::new(fallback).with_route_upstreams([Http2RouteUpstream {
            route_label: String::from("api"),
            upstream: upstream_a,
        }]).rejecting_unmatched_routes();
        assert!(matches!(
            resolve_stream_upstream(&rejecting, None, &Default::default()),
            RequestUpstreamResolution::Reject(StatusCode::FORBIDDEN)
        ));
    }

    #[test]
    fn source_filter_and_enumeration_helpers_block_sources() {
        let filtered = Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new(
            "upstream",
            localhost_socket(9000),
        ))
        .with_anonymous_source_filter(AnonymousSourceFilterPolicy {
            enabled: true,
            deny_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("cidr")],
            deny_vpn: false,
            deny_proxy: false,
            deny_socks: false,
            deny_tor: false,
            vpn_cidrs: Vec::new(),
            proxy_cidrs: Vec::new(),
            socks_cidrs: Vec::new(),
            tor_exit_cidrs: Vec::new(),
        });
        assert!(anonymous_source_blocked(&filtered, IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let enumerating = Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new(
            "upstream",
            localhost_socket(9000),
        ))
        .with_route_enumeration_protection(RouteEnumerationProtectionPolicy {
            source_aggregation: SourceAggregation::ExactIp,
            evaluation_window: Duration::from_secs(60),
            max_unmatched_route_events: 0,
            max_distinct_query_signatures_per_route: 0,
            base_ban_duration: Duration::from_secs(5),
            max_ban_duration: Duration::from_secs(30),
            max_tracked_sources: 32,
        });
        let source = localhost_socket(40000);

        assert!(record_unmatched_route(&enumerating, source));
        assert!(route_enumeration_source_blocked(&enumerating, source));
        assert!(record_query_probe(&enumerating, source, Some("example.test"), "/api?debug=1"));
    }

    #[test]
    fn trusted_client_ip_and_header_filtering_helpers_match_runtime_policy() {
        let config = Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new(
            "upstream",
            localhost_socket(9000),
        ))
        .with_trusted_client_ip(TrustedClientIpPolicy {
            enabled: true,
            trusted_proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("cidr")],
        });
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));

        let effective = resolve_effective_client_ip(&config, localhost_socket(8080), &headers)
            .expect("trusted forwarded client ip should resolve");
        assert_eq!(effective, "198.51.100.7".parse::<IpAddr>().expect("ip"));

        assert!(should_skip_http2_header(&http::header::HOST, &HeaderValue::from_static("example.test")));
        assert!(should_skip_http2_header(&http::header::TE, &HeaderValue::from_static("gzip")));
        assert!(!should_skip_http2_header(&http::header::TE, &HeaderValue::from_static("trailers")));
    }

    #[test]
    fn passive_failure_classifier_stays_narrow() {
        assert!(error_is_upstream_passive_failure(&StreamForwardError::UpstreamReady));
        assert!(error_is_upstream_passive_failure(&StreamForwardError::UpstreamRequest));
        assert!(error_is_upstream_passive_failure(&StreamForwardError::UpstreamResponse));
        assert!(error_is_upstream_passive_failure(&StreamForwardError::IdleTimeout(
            StreamIdlePhase::UpstreamResponse,
        )));
        assert!(!error_is_upstream_passive_failure(&StreamForwardError::UpstreamGracefulDrain));
        assert!(!error_is_upstream_passive_failure(&StreamForwardError::InvalidRequest));
        assert!(!error_is_upstream_passive_failure(&StreamForwardError::RequestBodyLimitExceeded));
    }
}

async fn handle_http2_stream(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    downstream_addr: SocketAddr,
    upstream_clients: UpstreamClientRegistry,
    metrics: Arc<MetricsState>,
    semaphore: Arc<Semaphore>,
    config: Arc<Http2ProxyConfig>,
) {
    let Ok(permit) = semaphore.try_acquire_owned() else {
        metrics.increment_stream_limit_violation_count();
        metrics.record_anomaly(ProtocolAnomalyCategory::StreamConcurrencyLimitExceeded);
        metrics.increment_stream_reset_count();
        respond.send_reset(Reason::REFUSED_STREAM);
        return;
    };

    metrics.increment_request_count();
    metrics.increment_active_streams();
    let stream_result = proxy_one_http2_stream(
        request,
        &mut respond,
        downstream_addr,
        upstream_clients,
        &metrics,
        &config,
    )
    .await;

    if matches!(stream_result, Err(StreamForwardError::ResponseBody)) {
        metrics.increment_stream_reset_count();
    }
    if let Err(error) = stream_result {
        if matches!(error, StreamForwardError::InvalidRequest) {
            metrics.increment_hardening_rejection_count();
            metrics.record_anomaly(ProtocolAnomalyCategory::MalformedMessage);
        }
        if let StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody) = error {
            metrics.increment_slow_client_trigger_count();
            metrics.record_slow_client(SlowClientStage::RequestBody);
        }
        if !matches!(error, StreamForwardError::RequestBodyLimitExceeded) {
            metrics.increment_stream_error_count();
        }
    }

    drop(permit);
    metrics.decrement_active_streams();
}

#[derive(Debug, Clone, Copy)]
enum StreamForwardError {
    InvalidRequest,
    IdleTimeout(StreamIdlePhase),
    UpstreamGracefulDrain,
    UpstreamReady,
    UpstreamRequest,
    UpstreamResponse,
    SendResponse,
    RequestBody,
    ResponseBody,
    RequestBodyLimitExceeded,
    ResponseBodyLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamIdlePhase {
    RequestBody,
    UpstreamResponse,
    ResponseBody,
}

#[derive(Clone, Copy)]
enum StreamBodyDirection {
    Request,
    Response,
}

async fn proxy_one_http2_stream(
    request: Request<RecvStream>,
    respond: &mut SendResponse<Bytes>,
    downstream_addr: SocketAddr,
    upstream_clients: UpstreamClientRegistry,
    metrics: &MetricsState,
    config: &Http2ProxyConfig,
) -> Result<(), StreamForwardError> {
    let effective_client_ip =
        match resolve_effective_client_ip(config, downstream_addr, request.headers()) {
            Ok(ip) => ip,
            Err(_) => {
                send_local_response(respond, StatusCode::BAD_REQUEST)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.increment_hardening_rejection_count();
                metrics.record_anomaly(ProtocolAnomalyCategory::MalformedMessage);
                metrics.record_response_status(StatusCode::BAD_REQUEST.as_u16());
                return Ok(());
            }
        };
    let effective_downstream_addr = SocketAddr::new(effective_client_ip, downstream_addr.port());

    if anonymous_source_blocked(config, effective_client_ip) {
        send_local_response(respond, StatusCode::FORBIDDEN)
            .map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(StatusCode::FORBIDDEN.as_u16());
        return Ok(());
    }

    if route_enumeration_source_blocked(config, effective_downstream_addr) {
        send_local_response(respond, StatusCode::FORBIDDEN)
            .map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(StatusCode::FORBIDDEN.as_u16());
        return Ok(());
    }

    let request_headers = header_map_to_http_headers(request.headers());
    let is_grpc = lb_proto_http::is_grpc_request(
        request.method().as_str(),
        lb_proto_http::SupportedHttpVersion::Http2,
        &request_headers,
    );
    if is_grpc {
        metrics.increment_grpc_request_count();
    }

    let authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| request.headers().get(http::header::HOST).and_then(|value| value.to_str().ok()));
    let route_match = lb_proto_http::match_route_request(
        request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        authority,
        &config.routes,
    );
    let selection_context = selection_context_for_request(
        request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        request.headers(),
    );
    if route_match.is_some()
        && record_query_probe(
            config,
            effective_downstream_addr,
            authority,
            request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        )
    {
        send_local_response(respond, StatusCode::FORBIDDEN)
            .map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(StatusCode::FORBIDDEN.as_u16());
        return Ok(());
    }

    let selected_upstream = match resolve_stream_upstream(
        config,
        route_match.as_ref(),
        &selection_context,
    ) {
        RequestUpstreamResolution::Selected(upstream) => upstream,
        RequestUpstreamResolution::Reject(status) => {
            let _blocked = status == StatusCode::FORBIDDEN
                && record_unmatched_route(config, effective_downstream_addr);
            send_local_response(respond, status).map_err(|_| StreamForwardError::SendResponse)?;
            metrics.record_response_status(status.as_u16());
            return Ok(());
        }
    };

    let request_end_stream = request.body().is_end_stream();
    let safe_stale_reuse_retry =
        request_end_stream && request_is_safe_stale_reuse_retry_candidate(&request);
    let retryable_upstream_request = if safe_stale_reuse_retry {
        Some(
            prepare_upstream_request_template(
                &request,
                effective_client_ip,
                selected_upstream.target.address,
            )
            .map_err(|error| {
                let _ = send_local_response(respond, StatusCode::BAD_GATEWAY);
                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                error
            })?,
        )
    } else {
        None
    };
    let (upstream_client, had_prior_successful_stream, retried_stale_client, response_future, mut upstream_send_stream) = {
        let mut retried_stale_client = false;
        loop {
            let (upstream_client, had_prior_successful_stream) = match upstream_clients
                .ensure_client(&selected_upstream.target, &config.timeouts)
                .await
            {
                Ok(client) => client,
                Err(UpstreamClientConnectError::ConnectTimeout { .. }) => {
                    send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                        .map_err(|_| StreamForwardError::SendResponse)?;
                    metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                    record_passive_health_result(
                        &selected_upstream,
                        &Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)),
                    );
                    return Err(StreamForwardError::IdleTimeout(
                        StreamIdlePhase::UpstreamResponse,
                    ));
                }
                Err(_) => {
                    send_local_response(respond, StatusCode::BAD_GATEWAY)
                        .map_err(|_| StreamForwardError::SendResponse)?;
                    metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                    record_passive_health_result(
                        &selected_upstream,
                        &Err(StreamForwardError::UpstreamRequest),
                    );
                    return Err(StreamForwardError::UpstreamRequest);
                }
            };

            let upstream_request = if let Some(upstream_request) = retryable_upstream_request.clone() {
                upstream_request.into_request()?
            } else {
                match build_upstream_request(
                    &request,
                    effective_client_ip,
                    selected_upstream.target.address,
                ) {
                    Ok(upstream_request) => upstream_request,
                    Err(error) => {
                        send_local_response(respond, StatusCode::BAD_GATEWAY)
                            .map_err(|_| StreamForwardError::SendResponse)?;
                        metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                        return Err(error);
                    }
                }
            };
            let retry_stale_reuse =
                had_prior_successful_stream && safe_stale_reuse_retry && !retried_stale_client;

            let mut send_request = upstream_client.send_request.lock().await;
            if let Err(error) = poll_fn(|cx| send_request.poll_ready(cx)).await {
                drop(send_request);
                upstream_clients.remove_client(&selected_upstream.target).await;
                if retry_stale_reuse && http2_stale_reuse_retryable_error(&error) {
                    retried_stale_client = true;
                    continue;
                }
                send_local_response(respond, StatusCode::BAD_GATEWAY)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                let classified_error = classify_http2_upstream_error(&error, StreamForwardError::UpstreamReady);
                record_passive_health_result(&selected_upstream, &Err(classified_error));
                return Err(classified_error);
            }

            match send_request.send_request(upstream_request, request_end_stream) {
                Ok((response_future, upstream_send_stream)) => {
                    drop(send_request);
                    break (
                        upstream_client,
                        had_prior_successful_stream,
                        retried_stale_client,
                        response_future,
                        upstream_send_stream,
                    );
                }
                Err(error) => {
                    drop(send_request);
                    upstream_clients.remove_client(&selected_upstream.target).await;
                    if retry_stale_reuse && http2_stale_reuse_retryable_error(&error) {
                        retried_stale_client = true;
                        continue;
                    }
                    send_local_response(respond, StatusCode::BAD_GATEWAY)
                        .map_err(|_| StreamForwardError::SendResponse)?;
                    metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                    let classified_error =
                        classify_http2_upstream_error(&error, StreamForwardError::UpstreamRequest);
                    record_passive_health_result(&selected_upstream, &Err(classified_error));
                    return Err(classified_error);
                }
            }
        }
    };

    if !request_end_stream {
        match relay_recv_body_to_send_stream(
            request.into_body(),
            &mut upstream_send_stream,
            config.limits.max_body_bytes,
            config.timeouts.idle_timeout,
            StreamBodyDirection::Request,
        )
        .await
        {
            Ok(_) => {}
            Err(StreamForwardError::RequestBodyLimitExceeded) => {
                metrics.increment_body_limit_violation_count();
                metrics.record_anomaly(ProtocolAnomalyCategory::BodySizeLimitExceeded);
                upstream_send_stream.send_reset(Reason::CANCEL);
                send_local_response(respond, StatusCode::PAYLOAD_TOO_LARGE)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::PAYLOAD_TOO_LARGE.as_u16());
                return Ok(());
            }
            Err(error) => {
                upstream_send_stream.send_reset(Reason::INTERNAL_ERROR);
                let status = if matches!(
                    error,
                    StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
                ) {
                    StatusCode::REQUEST_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                };
                send_local_response(respond, status)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(status.as_u16());
                return Err(error);
            }
        }
    }

    drop(upstream_send_stream);

    let response = match time::timeout(config.timeouts.idle_timeout, response_future).await {
        Err(_) => {
            upstream_clients.remove_client(&selected_upstream.target).await;
            send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                .map_err(|_| StreamForwardError::SendResponse)?;
            metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
            record_passive_health_result(
                &selected_upstream,
                &Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)),
            );
            return Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse));
        }
        Ok(response) => response,
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            upstream_clients.remove_client(&selected_upstream.target).await;
            if had_prior_successful_stream
                && safe_stale_reuse_retry
                && !retried_stale_client
                && http2_stale_reuse_retryable_error(&error)
            {
                let (retry_upstream_client, _) = match upstream_clients
                    .ensure_client(&selected_upstream.target, &config.timeouts)
                    .await
                {
                    Ok(client) => client,
                    Err(UpstreamClientConnectError::ConnectTimeout { .. }) => {
                        send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                            .map_err(|_| StreamForwardError::SendResponse)?;
                        metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                        record_passive_health_result(
                            &selected_upstream,
                            &Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)),
                        );
                        return Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse));
                    }
                    Err(_) => {
                        send_local_response(respond, StatusCode::BAD_GATEWAY)
                            .map_err(|_| StreamForwardError::SendResponse)?;
                        metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                        let classified_error = classify_http2_upstream_error(
                            &error,
                            StreamForwardError::UpstreamResponse,
                        );
                        record_passive_health_result(&selected_upstream, &Err(classified_error));
                        return Err(classified_error);
                    }
                };

                let retry_request = retryable_upstream_request
                    .clone()
                    .expect("safe stale-reuse retry should prebuild a retryable HTTP/2 request")
                    .into_request()?;

                let retry_response = {
                    let mut retry_send_request = retry_upstream_client.send_request.lock().await;
                    if poll_fn(|cx| retry_send_request.poll_ready(cx)).await.is_err() {
                        drop(retry_send_request);
                        upstream_clients.remove_client(&selected_upstream.target).await;
                        send_local_response(respond, StatusCode::BAD_GATEWAY)
                            .map_err(|_| StreamForwardError::SendResponse)?;
                        metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                        let classified_error = classify_http2_upstream_error(
                            &error,
                            StreamForwardError::UpstreamReady,
                        );
                        record_passive_health_result(&selected_upstream, &Err(classified_error));
                        return Err(classified_error);
                    }

                    let (retry_response_future, retry_upstream_send_stream) =
                        match retry_send_request.send_request(retry_request, true) {
                            Ok(result) => result,
                            Err(error) => {
                                drop(retry_send_request);
                                upstream_clients.remove_client(&selected_upstream.target).await;
                                send_local_response(respond, StatusCode::BAD_GATEWAY)
                                    .map_err(|_| StreamForwardError::SendResponse)?;
                                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                                let classified_error = classify_http2_upstream_error(
                                    &error,
                                    StreamForwardError::UpstreamRequest,
                                );
                                record_passive_health_result(&selected_upstream, &Err(classified_error));
                                return Err(classified_error);
                            }
                        };
                    drop(retry_send_request);
                    drop(retry_upstream_send_stream);

                    match time::timeout(config.timeouts.idle_timeout, retry_response_future).await {
                        Err(_) => {
                            upstream_clients.remove_client(&selected_upstream.target).await;
                            send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                                .map_err(|_| StreamForwardError::SendResponse)?;
                            metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                            record_passive_health_result(
                                &selected_upstream,
                                &Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)),
                            );
                            return Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse));
                        }
                        Ok(Ok(response)) => response,
                        Ok(Err(error)) => {
                            upstream_clients.remove_client(&selected_upstream.target).await;
                            send_local_response(respond, StatusCode::BAD_GATEWAY)
                                .map_err(|_| StreamForwardError::SendResponse)?;
                            metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                            let classified_error = classify_http2_upstream_error(
                                &error,
                                StreamForwardError::UpstreamResponse,
                            );
                            record_passive_health_result(&selected_upstream, &Err(classified_error));
                            return Err(classified_error);
                        }
                    }
                };

                retry_upstream_client.mark_used(Instant::now());
                retry_response
            } else {
                let _ = error;
                send_local_response(respond, StatusCode::BAD_GATEWAY)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                record_passive_health_result(&selected_upstream, &Err(StreamForwardError::UpstreamResponse));
                return Err(StreamForwardError::UpstreamResponse);
            }
        }
    };
    let response_status = response.status();
    let response_end_stream = response.body().is_end_stream();
    let response_headers = response.headers().clone();
    let downstream_response = build_downstream_response(&response)?;
    let mut downstream_send_stream = respond
        .send_response(downstream_response, response_end_stream)
        .map_err(|_| StreamForwardError::SendResponse)?;
    metrics.record_response_status(response_status.as_u16());

    if !response_end_stream {
        let response_trailers = relay_recv_body_to_send_stream(
            response.into_body(),
            &mut downstream_send_stream,
            config.limits.max_body_bytes,
            config.timeouts.idle_timeout,
            StreamBodyDirection::Response,
        )
        .await;
        match response_trailers {
            Ok(trailers) => {
                if is_grpc {
                    if let Some(grpc_status) = grpc_status_from_header_map(&response_headers)
                        .or_else(|| trailers.as_ref().and_then(grpc_status_from_header_map))
                    {
                        metrics.record_grpc_status(grpc_status);
                    }
                }
            }
            Err(StreamForwardError::ResponseBodyLimitExceeded) => {
                metrics.increment_body_limit_violation_count();
                metrics.record_anomaly(ProtocolAnomalyCategory::BodySizeLimitExceeded);
                downstream_send_stream.send_reset(Reason::ENHANCE_YOUR_CALM);
                metrics.increment_stream_reset_count();
            }
            Err(error) => {
                downstream_send_stream.send_reset(Reason::INTERNAL_ERROR);
                metrics.increment_stream_reset_count();
                return Err(error);
            }
        }
    } else if is_grpc {
        if let Some(grpc_status) = grpc_status_from_header_map(&response_headers) {
            metrics.record_grpc_status(grpc_status);
        }
    }

    upstream_client.mark_used(Instant::now());
    upstream_client.note_completed_stream();
    record_passive_health_result(&selected_upstream, &Ok(response_status.as_u16()));

    Ok(())
}

enum RequestUpstreamResolution {
    Selected(SelectedUpstream),
    Reject(StatusCode),
}

struct SelectedUpstream {
    target: lb_net_core::UpstreamTarget,
    route_backend: Option<crate::SelectedRouteBackend>,
}

fn resolve_stream_upstream(
    config: &Http2ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
    selection_context: &crate::SelectionContext,
) -> RequestUpstreamResolution {
    if config.route_upstreams.is_empty() && config.route_backend_pools.is_empty() {
        return RequestUpstreamResolution::Selected(SelectedUpstream {
            target: config.upstream.clone(),
            route_backend: None,
        });
    }

    let Some(route) = route else {
        return if config.reject_unmatched_routes {
            RequestUpstreamResolution::Reject(StatusCode::FORBIDDEN)
        } else {
            RequestUpstreamResolution::Selected(SelectedUpstream {
                target: config.upstream.clone(),
                route_backend: None,
            })
        };
    };

    if let Some(pool) = config.route_backend_pools.get(&route.label) {
        return match pool.select_backend_with_context(selection_context) {
            Ok(route_backend) => RequestUpstreamResolution::Selected(SelectedUpstream {
                target: route_backend.upstream().clone(),
                route_backend: Some(route_backend),
            }),
            Err(_) => RequestUpstreamResolution::Reject(StatusCode::BAD_GATEWAY),
        };
    }

    match config.route_upstreams.get(&route.label) {
        Some(upstreams) if !upstreams.is_empty() => {
            RequestUpstreamResolution::Selected(SelectedUpstream {
                target: select_http2_route_upstream(config, &route.label, upstreams),
                route_backend: None,
            })
        }
        _ => RequestUpstreamResolution::Reject(StatusCode::BAD_GATEWAY),
    }
}

fn stable_request_hash(input: &[u8]) -> u64 {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    hash.write(input);
    hash.finish()
}

fn selection_context_for_request(
    path_and_query: &str,
    headers: &http::HeaderMap,
) -> crate::SelectionContext {
    crate::SelectionContext {
        preferred_locality: header_value(headers, "x-lb-locality").map(String::from),
        preferred_zone: header_value(headers, "x-lb-zone").map(String::from),
        request_hash: stable_request_hash(path_and_query.as_bytes()),
    }
}

fn header_value<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok()).map(str::trim).filter(|value| !value.is_empty())
}

fn select_http2_route_upstream(
    config: &Http2ProxyConfig,
    route_label: &str,
    upstreams: &[lb_net_core::UpstreamTarget],
) -> lb_net_core::UpstreamTarget {
    if upstreams.len() == 1 {
        return upstreams[0].clone();
    }

    let mut cursors = config
        .route_upstream_cursors
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cursor = cursors.entry(route_label.to_string()).or_insert(0);
    let index = *cursor % upstreams.len();
    *cursor = (*cursor + 1) % upstreams.len();
    upstreams[index].clone()
}

fn route_enumeration_source_blocked(
    config: &Http2ProxyConfig,
    downstream_addr: SocketAddr,
) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.is_blocked(downstream_addr))
}

fn record_unmatched_route(config: &Http2ProxyConfig, downstream_addr: SocketAddr) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.record_unmatched_route(downstream_addr))
}

fn record_query_probe(
    config: &Http2ProxyConfig,
    downstream_addr: SocketAddr,
    authority: Option<&str>,
    target: &str,
) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.record_query_probe(downstream_addr, authority, target))
}

fn resolve_effective_client_ip(
    config: &Http2ProxyConfig,
    downstream_addr: SocketAddr,
    headers: &http::HeaderMap,
) -> Result<IpAddr, crate::TrustedClientIpError> {
    config.trusted_client_ip.as_ref().map_or(Ok(downstream_addr.ip()), |policy| {
        policy.resolve_from_http2_headers(downstream_addr.ip(), headers)
    })
}

fn anonymous_source_blocked(config: &Http2ProxyConfig, client_ip: IpAddr) -> bool {
    config.anonymous_source_filter.as_ref().is_some_and(|filter| {
        filter.classify_and_record(client_ip).is_some()
    })
}

fn record_passive_health_result(
    selected_upstream: &SelectedUpstream,
    result: &Result<u16, StreamForwardError>,
) {
    let Some(route_backend) = selected_upstream.route_backend.as_ref() else {
        return;
    };

    let feedback_result = match result {
        Ok(status) if *status < 500 => route_backend.note_passive_success(),
        Err(error) if error_is_upstream_passive_failure(error) => route_backend.note_passive_failure(),
        _ => return,
    };
    let _ = feedback_result;
}

fn error_is_upstream_passive_failure(error: &StreamForwardError) -> bool {
    matches!(
        error,
        StreamForwardError::UpstreamReady
            | StreamForwardError::UpstreamRequest
            | StreamForwardError::UpstreamResponse
            | StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)
    )
}

async fn relay_recv_body_to_send_stream(
    mut recv_stream: RecvStream,
    send_stream: &mut SendStream<Bytes>,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: StreamBodyDirection,
) -> Result<Option<http::HeaderMap>, StreamForwardError> {
    let mut transferred = 0_u64;
    while let Some(chunk) =
        time::timeout(idle_timeout, recv_stream.data()).await.map_err(|_| match direction {
            StreamBodyDirection::Request => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
            }
            StreamBodyDirection::Response => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
            }
        })?
    {
        let chunk = chunk.map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        recv_stream.flow_control().release_capacity(chunk.len()).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        transferred = transferred.saturating_add(chunk.len() as u64);
        if transferred > max_body_bytes {
            return Err(match direction {
                StreamBodyDirection::Request => StreamForwardError::RequestBodyLimitExceeded,
                StreamBodyDirection::Response => StreamForwardError::ResponseBodyLimitExceeded,
            });
        }
        send_bytes_chunked(send_stream, chunk, false, direction).await?;
    }

    if let Some(trailers) = time::timeout(idle_timeout, recv_stream.trailers())
        .await
        .map_err(|_| match direction {
            StreamBodyDirection::Request => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
            }
            StreamBodyDirection::Response => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
            }
        })?
        .map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?
    {
        let trailers_for_metrics = trailers.clone();
        send_stream.send_trailers(trailers).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        return Ok(Some(trailers_for_metrics));
    } else {
        send_bytes_chunked(send_stream, Bytes::new(), true, direction).await?;
    }

    Ok(None)
}

async fn send_bytes_chunked(
    send_stream: &mut SendStream<Bytes>,
    mut bytes: Bytes,
    end_stream: bool,
    direction: StreamBodyDirection,
) -> Result<(), StreamForwardError> {
    if bytes.is_empty() {
        return send_stream.send_data(bytes, end_stream).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        });
    }

    const MAX_FRAME_CHUNK: usize = 16 * 1024;
    while bytes.has_remaining() {
        let next_len = bytes.remaining().min(MAX_FRAME_CHUNK);
        let capacity = loop {
            send_stream.reserve_capacity(next_len);
            let capacity = poll_fn(|cx| match send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity)),
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                    Poll::Ready(Err(match direction {
                        StreamBodyDirection::Request => StreamForwardError::RequestBody,
                        StreamBodyDirection::Response => StreamForwardError::ResponseBody,
                    }))
                }
                Poll::Pending => Poll::Pending,
            })
            .await?;
            if capacity != 0 {
                break capacity;
            }
            tokio::task::yield_now().await;
        };
        let to_send = bytes.remaining().min(next_len).min(capacity);
        let chunk = bytes.split_to(to_send);
        let is_last = end_stream && !bytes.has_remaining();
        send_stream.send_data(chunk, is_last).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
    }

    Ok(())
}

fn build_upstream_request(
    request: &Request<RecvStream>,
    effective_client_ip: IpAddr,
    upstream_addr: SocketAddr,
) -> Result<Request<()>, StreamForwardError> {
    prepare_upstream_request_template(request, effective_client_ip, upstream_addr)?.into_request()
}

#[derive(Clone)]
struct UpstreamRequestTemplate {
    method: http::Method,
    uri: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl UpstreamRequestTemplate {
    fn into_request(self) -> Result<Request<()>, StreamForwardError> {
        let mut builder =
            Request::builder().method(self.method).uri(self.uri).version(http::Version::HTTP_2);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        builder.body(()).map_err(|_| StreamForwardError::InvalidRequest)
    }
}

fn prepare_upstream_request_template(
    request: &Request<RecvStream>,
    effective_client_ip: IpAddr,
    upstream_addr: SocketAddr,
) -> Result<UpstreamRequestTemplate, StreamForwardError> {
    let mut headers = Vec::new();
    for (name, value) in request.headers() {
        if should_skip_http2_header(name, value) {
            continue;
        }
        headers.push((name.clone(), value.clone()));
    }
    headers.push((
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&effective_client_ip.to_string())
            .map_err(|_| StreamForwardError::InvalidRequest)?,
    ));
    Ok(UpstreamRequestTemplate {
        method: request.method().clone(),
        uri: normalize_request_uri(request.uri(), upstream_addr)?,
        headers,
    })
}

fn request_is_safe_stale_reuse_retry_candidate(request: &Request<RecvStream>) -> bool {
    request.body().is_end_stream()
        && matches!(request.method().as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

fn http2_stale_reuse_retryable_error(error: &h2::Error) -> bool {
    error.is_io() || error.is_go_away()
}

fn classify_http2_upstream_error(
    error: &h2::Error,
    fallback: StreamForwardError,
) -> StreamForwardError {
    if error.is_go_away() && error.reason() == Some(Reason::NO_ERROR) {
        StreamForwardError::UpstreamGracefulDrain
    } else {
        fallback
    }
}


fn build_downstream_response(
    response: &Response<RecvStream>,
) -> Result<Response<()>, StreamForwardError> {
    let mut builder = Response::builder().status(response.status()).version(http::Version::HTTP_2);
    for (name, value) in response.headers() {
        if should_skip_http2_header(name, value) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder.body(()).map_err(|_| StreamForwardError::InvalidRequest)
}

fn normalize_request_uri(uri: &Uri, upstream_addr: SocketAddr) -> Result<Uri, StreamForwardError> {
    let target = uri.path_and_query().map(|value| value.as_str()).unwrap_or("/");
    format!("http://{upstream_addr}{target}")
        .parse::<Uri>()
        .map_err(|_| StreamForwardError::InvalidRequest)
}

fn should_skip_http2_header(name: &HeaderName, value: &HeaderValue) -> bool {
    if name == http::header::CONNECTION
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::PROXY_AUTHENTICATE
        || name == http::header::PROXY_AUTHORIZATION
        || name == http::header::UPGRADE
        || name == http::header::HOST
        || name == http::header::TE && value != "trailers"
        || name == HeaderName::from_static("proxy-connection")
        || name == HeaderName::from_static("keep-alive")
        || name == HeaderName::from_static("x-forwarded-for")
    {
        return true;
    }

    false
}

fn send_local_response(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
) -> Result<(), h2::Error> {
    let response = Response::builder()
        .status(status)
        .version(http::Version::HTTP_2)
        .body(())
        .map_err(|_| h2::Error::from(h2::Reason::INTERNAL_ERROR))?;
    respond.send_response(response, true).map(|_| ())
}

fn header_map_to_http_headers(headers: &http::HeaderMap) -> Vec<lb_proto_http::HttpHeader> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| lb_proto_http::HttpHeader {
                name: name.as_str().to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

fn grpc_status_from_header_map(headers: &http::HeaderMap) -> Option<u16> {
    headers
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u16>().ok())
}
