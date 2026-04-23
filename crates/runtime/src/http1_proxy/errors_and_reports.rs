#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Http1ConnectionMetrics {
    /// Count of successfully proxied requests on the connection.
    pub request_count: u64,
    /// Count of malformed downstream request failures.
    pub malformed_request_count: u64,
    /// Count of request or response body limit violations.
    pub body_limit_violation_count: u64,
    /// Count of requests served from a fresh cache entry.
    pub cache_hit_count: u64,
    /// Count of cacheable requests that missed the cache.
    pub cache_miss_count: u64,
    /// Count of responses inserted into the cache.
    pub cache_fill_count: u64,
    /// Count of requests or responses bypassing cache participation.
    pub cache_bypass_count: u64,
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
    /// Count of responses by status code.
    pub response_status_counts: BTreeMap<u16, u64>,
}

/// Summary of a completed HTTP/1.1 proxied connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1ConnectionReport {
    /// Downstream peer address.
    pub downstream_addr: SocketAddr,
    /// Upstream peer address.
    pub upstream_addr: SocketAddr,
    /// Upstream display name.
    pub upstream_name: String,
    /// Time spent connecting to the upstream.
    pub connect_duration: Duration,
    /// Aggregate counters for the proxied connection.
    pub metrics: Http1ConnectionMetrics,
    /// Snapshot of route-backend selection metrics when route backend pools are configured.
    pub route_selection_metrics: Option<crate::UpstreamSelectionMetrics>,
}

/// Buffered response returned by one-shot HTTP/1 upstream dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1SingleRequestResponse {
    /// Parsed response head after normalization and transforms.
    pub head: lb_proto_http::Http1ResponseHead,
    /// Buffered response body.
    pub body: Vec<u8>,
}

/// Errors returned by the HTTP/1.1 proxy runtime.
#[derive(Debug)]
pub enum Http1ProxyError {
    /// Upstream connect exceeded the configured timeout.
    ConnectTimeout { target: SocketAddr },
    /// Upstream connect failed with an I/O error.
    Connect { target: SocketAddr, source: std::io::Error },
    /// Downstream request parsing failed.
    ParseRequest(lb_proto_http::Http1ParseError),
    /// Upstream response parsing failed.
    ParseResponse(lb_proto_http::Http1ParseError),
    /// Request or response body exceeded the configured limit.
    BodyLimitExceeded(&'static str),
    /// Idle timeout expired while waiting for HTTP traffic.
    IdleTimeout(&'static str),
    /// I/O failure while forwarding request bytes upstream.
    RequestIo(std::io::Error),
    /// I/O failure while forwarding response bytes downstream.
    ResponseIo(std::io::Error),
}

impl fmt::Display for Http1ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectTimeout { target } => {
                write!(formatter, "timed out connecting HTTP/1.1 upstream {target}")
            }
            Self::Connect { target, source } => {
                write!(formatter, "failed to connect HTTP/1.1 upstream {target}: {source}")
            }
            Self::ParseRequest(source) => {
                write!(formatter, "downstream HTTP/1.1 request failed: {source}")
            }
            Self::ParseResponse(source) => {
                write!(formatter, "upstream HTTP/1.1 response failed: {source}")
            }
            Self::BodyLimitExceeded(direction) => {
                write!(formatter, "HTTP/1.1 body limit exceeded for {direction}")
            }
            Self::IdleTimeout(stage) => {
                write!(formatter, "HTTP/1.1 idle timeout exceeded for {stage}")
            }
            Self::RequestIo(source) => {
                write!(formatter, "HTTP/1.1 upstream write failed: {source}")
            }
            Self::ResponseIo(source) => {
                write!(formatter, "HTTP/1.1 downstream write failed: {source}")
            }
        }
    }
}

impl std::error::Error for Http1ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect { source, .. } => Some(source),
            Self::ParseRequest(source) => Some(source),
            Self::ParseResponse(source) => Some(source),
            Self::RequestIo(source) => Some(source),
            Self::ResponseIo(source) => Some(source),
            _ => None,
        }
    }
}

impl Http1ProxyError {
    #[must_use]
    pub fn anomaly_category(&self) -> Option<ProtocolAnomalyCategory> {
        match self {
            Self::ParseRequest(source) => classify_http1_request_parse_error(source),
            Self::BodyLimitExceeded("request body") => {
                Some(ProtocolAnomalyCategory::BodySizeLimitExceeded)
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn slow_client_stage(&self) -> Option<SlowClientStage> {
        match self {
            Self::IdleTimeout("request head") => Some(SlowClientStage::RequestHead),
            Self::IdleTimeout("request body") => Some(SlowClientStage::RequestBody),
            _ => None,
        }
    }
}
