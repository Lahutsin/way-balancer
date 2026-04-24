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
    /// Count of shadow requests launched asynchronously.
    pub mirror_dispatch_count: u64,
    /// Count of requests not mirrored because the mirror policy was not selected or unsupported.
    pub mirror_skip_count: u64,
    /// Count of mirror attempts that failed before dispatch could start.
    pub mirror_dispatch_failure_count: u64,
    /// Count of requests delayed by destination-local fault injection.
    pub fault_injection_delay_count: u64,
    /// Count of requests aborted locally by destination-local fault injection.
    pub fault_injection_abort_count: u64,
    /// Count of gRPC requests observed on the connection.
    pub grpc_request_count: u64,
    /// Count of gRPC requests by canonical service name.
    pub grpc_service_counts: BTreeMap<String, u64>,
    /// Count of gRPC requests by canonical `<service>/<method>` identity.
    pub grpc_method_counts: BTreeMap<String, u64>,
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
    /// Snapshot of route-backend selection metrics when route backend pools are configured.
    pub route_selection_metrics: Option<crate::UpstreamSelectionMetrics>,
    /// Decision-trace events emitted while processing streams on this connection.
    pub decision_trace_events: Vec<lb_observability::TelemetryEvent>,
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
