use std::collections::BTreeMap;
use std::fmt;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::{ProtocolAnomalyCategory, SlowClientStage};
use bytes::{Buf, Bytes};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{client, server, Reason, RecvStream, SendStream};
use http::header::{HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Uri};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time;

/// Runtime configuration for a bounded HTTP/2 proxy connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2ProxyConfig {
    /// Static upstream target used for forwarding streams.
    pub upstream: lb_net_core::UpstreamTarget,
    /// Connection timeout model reused from shared network primitives.
    pub timeouts: lb_net_core::ConnectionTimeouts,
    /// HTTP/2 concurrency and body limits.
    pub limits: lb_proto_http::Http2Limits,
    /// Shared route-prefix rules compatible with HTTP/1.1 routing placeholders.
    pub routes: Vec<lb_proto_http::RoutePrefixRule>,
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
        }
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

/// Proxies an HTTP/2 connection with bounded concurrent streams.
pub async fn proxy_http2_connection(
    downstream: TcpStream,
    config: &Http2ProxyConfig,
) -> Result<Http2ConnectionReport, Http2ProxyError> {
    let downstream_addr = downstream
        .peer_addr()
        .map_err(|source| Http2ProxyError::Connect { target: config.upstream.address, source })?;

    let connect_started = Instant::now();
    let upstream_stream =
        time::timeout(config.timeouts.connect_timeout, TcpStream::connect(config.upstream.address))
            .await
            .map_err(|_| Http2ProxyError::ConnectTimeout { target: config.upstream.address })?
            .map_err(|source| Http2ProxyError::Connect {
                target: config.upstream.address,
                source,
            })?;
    let connect_duration = connect_started.elapsed();
    let upstream_addr = upstream_stream
        .peer_addr()
        .map_err(|source| Http2ProxyError::Connect { target: config.upstream.address, source })?;

    let downstream_builder = server::Builder::new();
    let mut downstream_connection = downstream_builder
        .handshake(downstream)
        .await
        .map_err(Http2ProxyError::DownstreamHandshake)?;

    let upstream_builder = client::Builder::new();
    let (send_request, upstream_connection) = upstream_builder
        .handshake(upstream_stream)
        .await
        .map_err(Http2ProxyError::UpstreamHandshake)?;
    let send_request = Arc::new(AsyncMutex::new(send_request));
    tokio::spawn(async move {
        let _ = upstream_connection.await;
    });

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
        let send_request = Arc::clone(&send_request);
        let metrics = Arc::clone(&metrics);
        let semaphore = Arc::clone(&semaphore);
        let config = Arc::clone(&shared_config);

        stream_tasks.spawn(async move {
            handle_http2_stream(
                request,
                respond,
                downstream_addr,
                send_request,
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

    Ok(Http2ConnectionReport {
        downstream_addr,
        upstream_addr,
        upstream_name: config.upstream.name.clone(),
        connect_duration,
        metrics: metrics.snapshot(),
    })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{Http2ProxyError, MetricsState};
    use crate::{ProtocolAnomalyCategory, SlowClientStage};

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
}

async fn handle_http2_stream(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    downstream_addr: SocketAddr,
    send_request: Arc<AsyncMutex<SendRequest<Bytes>>>,
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
        send_request,
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

#[derive(Debug)]
enum StreamForwardError {
    InvalidRequest,
    IdleTimeout(StreamIdlePhase),
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
    send_request: Arc<AsyncMutex<SendRequest<Bytes>>>,
    metrics: &MetricsState,
    config: &Http2ProxyConfig,
) -> Result<(), StreamForwardError> {
    let request_headers = header_map_to_http_headers(request.headers());
    let is_grpc = lb_proto_http::is_grpc_request(
        request.method().as_str(),
        lb_proto_http::SupportedHttpVersion::Http2,
        &request_headers,
    );
    if is_grpc {
        metrics.increment_grpc_request_count();
    }

    let _route_match = lb_proto_http::match_route_prefix(
        request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        &config.routes,
    );

    let request_end_stream = request.body().is_end_stream();
    let upstream_request =
        match build_upstream_request(&request, downstream_addr, config.upstream.address) {
            Ok(upstream_request) => upstream_request,
            Err(error) => {
                send_local_response(respond, StatusCode::BAD_GATEWAY)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                return Err(error);
            }
        };

    let (response_future, mut upstream_send_stream) = {
        let mut send_request = send_request.lock().await;
        poll_fn(|cx| send_request.poll_ready(cx))
            .await
            .map_err(|_| StreamForwardError::UpstreamReady)?;
        match send_request.send_request(upstream_request, request_end_stream) {
            Ok(result) => result,
            Err(_) => {
                send_local_response(respond, StatusCode::BAD_GATEWAY)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                return Err(StreamForwardError::UpstreamRequest);
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

    let response = match time::timeout(config.timeouts.idle_timeout, response_future).await {
        Err(_) => {
            send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                .map_err(|_| StreamForwardError::SendResponse)?;
            metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
            return Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse));
        }
        Ok(response) => response,
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            send_local_response(respond, StatusCode::BAD_GATEWAY)
                .map_err(|_| StreamForwardError::SendResponse)?;
            metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
            let _ = error;
            return Err(StreamForwardError::UpstreamResponse);
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

    Ok(())
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
    downstream_addr: SocketAddr,
    upstream_addr: SocketAddr,
) -> Result<Request<()>, StreamForwardError> {
    let mut builder = Request::builder()
        .method(request.method().clone())
        .uri(normalize_request_uri(request.uri(), upstream_addr)?)
        .version(http::Version::HTTP_2);

    for (name, value) in request.headers() {
        if should_skip_http2_header(name, value) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder.header(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&downstream_addr.ip().to_string())
            .map_err(|_| StreamForwardError::InvalidRequest)?,
    );
    builder.body(()).map_err(|_| StreamForwardError::InvalidRequest)
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
