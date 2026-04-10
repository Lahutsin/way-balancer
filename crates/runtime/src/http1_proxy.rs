use std::collections::BTreeMap;
use std::fmt;
use std::hash::Hasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{
    AnonymousSourceFilterPolicy, AnonymousSourceFilterState, build_http_cache_key_material,
    HttpCacheEntry, HttpCacheHeader, HttpCacheKey,
    HttpCacheMetadata, HttpCacheRequest, HttpCacheRequestOutcome,
    HttpCacheRevalidationResult, HttpCacheStore, ProtocolAnomalyCategory,
    RouteEnumerationProtectionPolicy, RouteEnumerationProtectionState, RuntimeTelemetry,
    SlowClientStage, TrustedClientIpPolicy,
};
use http::{HeaderName, HeaderValue, StatusCode};
use httpdate::parse_http_date;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

/// Runtime configuration for a bounded HTTP/1.1 proxy session.
#[derive(Debug, Clone)]
pub struct Http1ProxyConfig {
    /// Static upstream target used for request forwarding.
    pub upstream: lb_net_core::UpstreamTarget,
    /// Connection timeout model reused from the shared network primitives.
    pub timeouts: lb_net_core::ConnectionTimeouts,
    /// HTTP/1.1 parser and relay limits.
    pub limits: lb_proto_http::Http1Limits,
    /// Placeholder route rules for future routing extensions.
    pub routes: Vec<lb_proto_http::RoutePrefixRule>,
    /// Optional route-to-upstream pools keyed by route label.
    pub route_upstreams: BTreeMap<String, Vec<lb_net_core::UpstreamTarget>>,
    /// Optional health-aware route backend pools keyed by route label.
    pub route_backend_pools: BTreeMap<String, crate::RouteBackendPool>,
    /// Deterministic round-robin cursors for route upstream pools.
    route_upstream_cursors: Arc<Mutex<BTreeMap<String, usize>>>,
    /// Whether requests with no matching route should be rejected locally.
    pub reject_unmatched_routes: bool,
    /// Optional CIDR-based anonymous source filter.
    pub anonymous_source_filter: Option<Arc<AnonymousSourceFilterState>>,
    /// Optional progressive ban guard for route and query enumeration by source.
    pub route_enumeration_protection: Option<Arc<RouteEnumerationProtectionState>>,
    /// Optional trusted-proxy model used to determine the effective client IP.
    pub trusted_client_ip: Option<TrustedClientIpPolicy>,
    /// Optional response-cache runtime for GET/HEAD traffic.
    pub response_cache: Option<Http1ResponseCacheConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1RouteUpstream {
    pub route_label: String,
    pub upstream: lb_net_core::UpstreamTarget,
}

/// Response cache runtime configuration for HTTP/1 proxying.
#[derive(Debug, Clone)]
pub struct Http1ResponseCacheConfig {
    /// Typed cache policy controlling lookup and fill behavior.
    pub policy: lb_config_model::HttpCachePolicyConfig,
    /// Shared bounded store used by the proxy.
    pub store: Arc<HttpCacheStore>,
    /// Optional cache telemetry handle and scope.
    pub telemetry: Option<HttpCacheTelemetryConfig>,
}

#[derive(Debug, Clone)]
pub struct HttpCacheTelemetryConfig {
    pub scope: String,
    pub telemetry: Arc<RuntimeTelemetry>,
}

impl Http1ResponseCacheConfig {
    /// Creates a reusable HTTP/1 response-cache runtime.
    #[must_use]
    pub fn new(
        policy: lb_config_model::HttpCachePolicyConfig,
        store: Arc<HttpCacheStore>,
    ) -> Self {
        Self { policy, store, telemetry: None }
    }

    #[must_use]
    pub fn with_telemetry(
        mut self,
        scope: impl Into<String>,
        telemetry: Arc<RuntimeTelemetry>,
    ) -> Self {
        self.telemetry = Some(HttpCacheTelemetryConfig {
            scope: scope.into(),
            telemetry,
        });
        self
    }
}

impl Http1ProxyConfig {
    /// Creates a baseline HTTP/1.1 config for a static upstream.
    #[must_use]
    pub fn new(upstream: lb_net_core::UpstreamTarget) -> Self {
        Self {
            upstream,
            timeouts: lb_net_core::ConnectionTimeouts::default(),
            limits: lb_proto_http::Http1Limits::default(),
            routes: Vec::new(),
            route_upstreams: BTreeMap::new(),
            route_backend_pools: BTreeMap::new(),
            route_upstream_cursors: Arc::new(Mutex::new(BTreeMap::new())),
            reject_unmatched_routes: false,
            anonymous_source_filter: None,
            route_enumeration_protection: None,
            trusted_client_ip: None,
            response_cache: None,
        }
    }

    #[must_use]
    pub fn with_route_upstreams(
        mut self,
        route_upstreams: impl IntoIterator<Item = Http1RouteUpstream>,
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

    /// Attaches an HTTP response-cache runtime to the proxy.
    #[must_use]
    pub fn with_response_cache(mut self, response_cache: Http1ResponseCacheConfig) -> Self {
        self.response_cache = Some(response_cache);
        self
    }
}

/// Observable counters for an HTTP/1.1 proxy connection.
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

/// Proxies one or more sequential HTTP/1.1 requests over a downstream TCP connection.
pub async fn proxy_http1_connection(
    downstream: TcpStream,
    config: &Http1ProxyConfig,
) -> Result<Http1ConnectionReport, Http1ProxyError> {
    let downstream_addr = downstream.peer_addr().map_err(Http1ProxyError::RequestIo)?;
    proxy_http1_connection_with_downstream_addr(downstream, downstream_addr, config).await
}

/// Proxies one or more sequential HTTP/1.1 requests over an arbitrary downstream stream.
pub async fn proxy_http1_connection_with_downstream_addr<S>(
    mut downstream: S,
    downstream_addr: SocketAddr,
    config: &Http1ProxyConfig,
) -> Result<Http1ConnectionReport, Http1ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = None;
    let mut active_upstream: Option<lb_net_core::UpstreamTarget> = None;
    let mut last_upstream_activity = None;
    let mut upstream_connected_at = None;
    let mut connect_duration = Duration::ZERO;
    let mut upstream_addr = config.upstream.address;

    let mut downstream_buffer = Vec::new();
    let mut upstream_buffer = Vec::new();
    let mut metrics = Http1ConnectionMetrics::default();

    loop {
        let request = time::timeout(
            config.timeouts.idle_timeout,
            lb_proto_http::read_request_head(
                &mut downstream,
                &mut downstream_buffer,
                &config.limits,
                &config.routes,
            ),
        )
        .await
        .map_err(|_| Http1ProxyError::IdleTimeout("request head"))?
        .map_err(Http1ProxyError::ParseRequest)?;

        let Some(request) = request else {
            break;
        };

        let effective_client_ip = match resolve_effective_client_ip(config, downstream_addr, &request)
        {
            Ok(ip) => ip,
            Err(_) => {
                write_local_response(
                    &mut downstream,
                    false,
                    StatusCode::BAD_REQUEST,
                    "invalid forwarding headers\n",
                )
                .await
                .map_err(Http1ProxyError::ResponseIo)?;
                metrics.request_count += 1;
                *metrics.response_status_counts.entry(StatusCode::BAD_REQUEST.as_u16()).or_insert(0) += 1;
                break;
            }
        };
        let effective_downstream_addr =
            SocketAddr::new(effective_client_ip, downstream_addr.port());

        if anonymous_source_blocked(config, effective_client_ip) {
            write_local_response(
                &mut downstream,
                false,
                StatusCode::FORBIDDEN,
                "anonymous source blocked\n",
            )
            .await
            .map_err(Http1ProxyError::ResponseIo)?;
            metrics.request_count += 1;
            *metrics.response_status_counts.entry(StatusCode::FORBIDDEN.as_u16()).or_insert(0) += 1;
            break;
        }

        if route_enumeration_source_blocked(config, effective_downstream_addr) {
            write_local_response(
                &mut downstream,
                false,
                StatusCode::FORBIDDEN,
                "source temporarily blocked\n",
            )
            .await
            .map_err(Http1ProxyError::ResponseIo)?;
            metrics.request_count += 1;
            *metrics.response_status_counts.entry(StatusCode::FORBIDDEN.as_u16()).or_insert(0) += 1;
            break;
        }

        if request.route.is_some()
            && record_query_probe(
                config,
                effective_downstream_addr,
                request_authority(&request),
                &request.target,
            )
        {
            write_local_response(
                &mut downstream,
                false,
                StatusCode::FORBIDDEN,
                "source temporarily blocked\n",
            )
            .await
            .map_err(Http1ProxyError::ResponseIo)?;
            metrics.request_count += 1;
            *metrics.response_status_counts.entry(StatusCode::FORBIDDEN.as_u16()).or_insert(0) += 1;
            break;
        }

        let selected_upstream = match resolve_request_upstream(config, &request) {
            RequestUpstreamResolution::Selected(upstream) => upstream,
            RequestUpstreamResolution::Reject(status, reason) => {
                let blocked = status == StatusCode::FORBIDDEN
                    && record_unmatched_route(config, effective_downstream_addr);
                let response_reason = if blocked {
                    "source temporarily blocked\n"
                } else {
                    reason
                };
                write_local_response(&mut downstream, request.keep_alive && !blocked, status, response_reason)
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                metrics.request_count += 1;
                *metrics.response_status_counts.entry(status.as_u16()).or_insert(0) += 1;
                if blocked || !request.keep_alive {
                    break;
                }
                continue;
            }
        };

        let now = config
            .response_cache
            .as_ref()
            .map_or(Duration::ZERO, |response_cache| response_cache.store.now());
        if let Some(cache_result) = resolve_cache_request(config.response_cache.as_ref(), &request, now) {
            match cache_result {
                CacheRequestOutcome::CacheHit { entry, outcome, reason } => {
                    write_cached_response(&mut downstream, &request.method, request.keep_alive, &entry)
                        .await
                        .map_err(Http1ProxyError::ResponseIo)?;
                    metrics.request_count += 1;
                    metrics.cache_hit_count += 1;
                    record_cache_request_telemetry(
                        config.response_cache.as_ref(),
                        outcome,
                        reason,
                        &format!("served cached response with status {}", entry.metadata.status.as_u16()),
                    );
                    *metrics
                        .response_status_counts
                        .entry(entry.metadata.status.as_u16())
                        .or_insert(0) += 1;
                    if !request.keep_alive {
                        break;
                    }
                    continue;
                }
                CacheRequestOutcome::Fetch {
                    key,
                    stale_fallback,
                    revalidation_entry,
                    reason,
                } => {
                    metrics.cache_miss_count += 1;
                    record_cache_request_telemetry(
                        config.response_cache.as_ref(),
                        HttpCacheRequestOutcome::Miss,
                        reason,
                        "cache lookup required origin fetch",
                    );
                    let result = process_uncached_request(
                        &mut upstream,
                        &mut active_upstream,
                        &mut last_upstream_activity,
                        &mut upstream_connected_at,
                        &mut upstream_addr,
                        &mut connect_duration,
                        &mut downstream,
                        &mut downstream_buffer,
                        &mut upstream_buffer,
                        effective_client_ip,
                        config,
                        &selected_upstream.target,
                        &request,
                        key,
                        stale_fallback.as_ref(),
                        revalidation_entry.as_ref(),
                        &mut metrics,
                        now,
                    )
                    .await;
                    record_passive_health_result(&selected_upstream, &result);
                    match result {
                        Ok(_) => {}
                        Err(error)
                            if stale_fallback.is_some()
                                && error_allows_stale_if_error(&error) => {
                                let stale_entry = stale_fallback.unwrap_or_else(|| unreachable!());
                                let _ = upstream.take();
                                write_cached_response(
                                    &mut downstream,
                                    &request.method,
                                    request.keep_alive,
                                    &stale_entry,
                                )
                                .await
                                .map_err(Http1ProxyError::ResponseIo)?;
                                metrics.request_count += 1;
                                metrics.cache_hit_count += 1;
                                record_cache_request_telemetry(
                                    config.response_cache.as_ref(),
                                    HttpCacheRequestOutcome::StaleHit,
                                    "stale_if_error",
                                    "served stale cached response after upstream failure",
                                );
                                *metrics
                                    .response_status_counts
                                    .entry(stale_entry.metadata.status.as_u16())
                                    .or_insert(0) += 1;
                            }
                        Err(error) => return Err(error),
                    }
                }
                CacheRequestOutcome::Bypass(reason) => {
                    metrics.cache_bypass_count += 1;
                    record_cache_request_telemetry(
                        config.response_cache.as_ref(),
                        HttpCacheRequestOutcome::Bypass,
                        reason,
                        "request bypassed shared cache",
                    );
                    let result = process_uncached_request(
                        &mut upstream,
                        &mut active_upstream,
                        &mut last_upstream_activity,
                        &mut upstream_connected_at,
                        &mut upstream_addr,
                        &mut connect_duration,
                        &mut downstream,
                        &mut downstream_buffer,
                        &mut upstream_buffer,
                        effective_client_ip,
                        config,
                        &selected_upstream.target,
                        &request,
                        None,
                        None,
                        None,
                        &mut metrics,
                        now,
                    )
                    .await;
                    record_passive_health_result(&selected_upstream, &result);
                    result?;
                }
            }
        } else {
            let result = process_uncached_request(
                &mut upstream,
                &mut active_upstream,
                &mut last_upstream_activity,
                &mut upstream_connected_at,
                &mut upstream_addr,
                &mut connect_duration,
                &mut downstream,
                &mut downstream_buffer,
                &mut upstream_buffer,
                effective_client_ip,
                config,
                &selected_upstream.target,
                &request,
                None,
                None,
                None,
                &mut metrics,
                now,
            )
            .await;
            record_passive_health_result(&selected_upstream, &result);
            result?;
        }
        if !request.keep_alive {
            break;
        }
    }

    Ok(Http1ConnectionReport {
        downstream_addr,
        upstream_addr,
        upstream_name: active_upstream
            .as_ref()
            .map(|upstream| upstream.name.clone())
            .unwrap_or_else(|| config.upstream.name.clone()),
        connect_duration,
        metrics,
    })
}

enum RequestUpstreamResolution {
    Selected(SelectedUpstream),
    Reject(StatusCode, &'static str),
}

struct SelectedUpstream {
    target: lb_net_core::UpstreamTarget,
    route_backend: Option<crate::SelectedRouteBackend>,
}

fn resolve_request_upstream(
    config: &Http1ProxyConfig,
    request: &lb_proto_http::Http1RequestHead,
) -> RequestUpstreamResolution {
    if config.route_upstreams.is_empty() && config.route_backend_pools.is_empty() {
        return RequestUpstreamResolution::Selected(SelectedUpstream {
            target: config.upstream.clone(),
            route_backend: None,
        });
    }

    let Some(route) = &request.route else {
        return if config.reject_unmatched_routes {
            RequestUpstreamResolution::Reject(StatusCode::FORBIDDEN, "route not allowed\n")
        } else {
            RequestUpstreamResolution::Selected(SelectedUpstream {
                target: config.upstream.clone(),
                route_backend: None,
            })
        };
    };

    if let Some(pool) = config.route_backend_pools.get(&route.label) {
        return match pool.select_backend_with_context(&selection_context_for_request(request)) {
            Ok(route_backend) => RequestUpstreamResolution::Selected(SelectedUpstream {
                target: route_backend.upstream().clone(),
                route_backend: Some(route_backend),
            }),
            Err(_) => RequestUpstreamResolution::Reject(
                StatusCode::BAD_GATEWAY,
                "route backend unavailable\n",
            ),
        };
    }

    match config.route_upstreams.get(&route.label) {
        Some(upstreams) if !upstreams.is_empty() => {
            RequestUpstreamResolution::Selected(SelectedUpstream {
                target: select_route_upstream(config, &route.label, upstreams),
                route_backend: None,
            })
        }
        _ => RequestUpstreamResolution::Reject(
            StatusCode::BAD_GATEWAY,
            "route backend unavailable\n",
        ),
    }
}

fn stable_request_hash(input: &[u8]) -> u64 {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    hash.write(input);
    hash.finish()
}

fn select_route_upstream(
    config: &Http1ProxyConfig,
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

fn request_authority(request: &lb_proto_http::Http1RequestHead) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.as_str())
}

fn selection_context_for_request(
    request: &lb_proto_http::Http1RequestHead,
) -> crate::SelectionContext {
    crate::SelectionContext {
        preferred_locality: request_header_value(request, "x-lb-locality").map(String::from),
        preferred_zone: request_header_value(request, "x-lb-zone").map(String::from),
        request_hash: stable_request_hash(request.target.as_bytes()),
    }
}

fn request_header_value<'a>(
    request: &'a lb_proto_http::Http1RequestHead,
    name: &str,
) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.trim())
        .filter(|value| !value.is_empty())
}

fn resolve_effective_client_ip(
    config: &Http1ProxyConfig,
    downstream_addr: SocketAddr,
    request: &lb_proto_http::Http1RequestHead,
) -> Result<IpAddr, crate::TrustedClientIpError> {
    config.trusted_client_ip.as_ref().map_or(Ok(downstream_addr.ip()), |policy| {
        policy.resolve_from_http1_headers(downstream_addr.ip(), &request.headers)
    })
}

fn route_enumeration_source_blocked(
    config: &Http1ProxyConfig,
    downstream_addr: SocketAddr,
) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.is_blocked(downstream_addr))
}

fn record_unmatched_route(config: &Http1ProxyConfig, downstream_addr: SocketAddr) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.record_unmatched_route(downstream_addr))
}

fn record_query_probe(
    config: &Http1ProxyConfig,
    downstream_addr: SocketAddr,
    authority: Option<&str>,
    target: &str,
) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.record_query_probe(downstream_addr, authority, target))
}

fn anonymous_source_blocked(config: &Http1ProxyConfig, client_ip: IpAddr) -> bool {
    config.anonymous_source_filter.as_ref().is_some_and(|filter| {
        filter.classify_and_record(client_ip).is_some()
    })
}

fn record_passive_health_result(
    selected_upstream: &SelectedUpstream,
    result: &Result<u16, Http1ProxyError>,
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

fn error_is_upstream_passive_failure(error: &Http1ProxyError) -> bool {
    matches!(
        error,
        Http1ProxyError::ConnectTimeout { .. }
            | Http1ProxyError::Connect { .. }
            | Http1ProxyError::RequestIo(_)
            | Http1ProxyError::ParseResponse(_)
            | Http1ProxyError::IdleTimeout("response head")
    )
}

enum CacheRequestOutcome {
    CacheHit {
        entry: HttpCacheEntry,
        outcome: HttpCacheRequestOutcome,
        reason: &'static str,
    },
    Fetch {
        key: Option<HttpCacheKey>,
        stale_fallback: Option<HttpCacheEntry>,
        revalidation_entry: Option<HttpCacheEntry>,
        reason: &'static str,
    },
    Bypass(&'static str),
}

fn resolve_cache_request(
    response_cache: Option<&Http1ResponseCacheConfig>,
    request: &lb_proto_http::Http1RequestHead,
    now: Duration,
) -> Option<CacheRequestOutcome> {
    let response_cache = response_cache?;
    if !request_method_is_cache_lookup_eligible(&response_cache.policy, &request.method)
    {
        return Some(CacheRequestOutcome::Bypass("method_ineligible"));
    }
    if !matches!(request.body_kind, lb_proto_http::BodyKind::None) {
        return Some(CacheRequestOutcome::Bypass("request_body"));
    }

    let key_material = match build_http_cache_key_material(
        &response_cache.policy,
        &HttpCacheRequest {
            method: &request.method,
            target: &request.target,
            headers: &request.headers,
        },
        &response_cache.policy.vary_headers,
    ) {
        Ok(Some(material)) => material,
        Ok(None) => {
            let reason = if request
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("cookie"))
            {
                "request_cookie"
            } else if request
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("authorization"))
            {
                "request_authorization"
            } else {
                "policy_bypass"
            };
            return Some(CacheRequestOutcome::Bypass(reason));
        }
        Err(_) => return Some(CacheRequestOutcome::Bypass("key_build_error")),
    };
    let storage_key = match key_material.storage_key() {
        Ok(key) => key,
        Err(_) => return Some(CacheRequestOutcome::Bypass("key_storage_error")),
    };

    match response_cache.store.lookup(now, &storage_key) {
        Some(lookup) if matches!(lookup.freshness, crate::HttpCacheFreshness::Fresh) => {
            Some(CacheRequestOutcome::CacheHit {
                entry: lookup.entry,
                outcome: HttpCacheRequestOutcome::Hit,
                reason: "fresh",
            })
        }
        Some(lookup)
            if matches!(lookup.freshness, crate::HttpCacheFreshness::StaleWhileRevalidate)
                && !should_revalidate_entry(&response_cache.policy, &lookup.entry) => {
            Some(CacheRequestOutcome::CacheHit {
                entry: lookup.entry,
                outcome: HttpCacheRequestOutcome::StaleHit,
                reason: "stale_while_revalidate",
            })
        }
        Some(lookup) if should_revalidate_entry(&response_cache.policy, &lookup.entry) => {
            Some(CacheRequestOutcome::Fetch {
                key: Some(storage_key),
                stale_fallback: Some(lookup.entry.clone()),
                revalidation_entry: Some(lookup.entry),
                reason: "revalidation",
            })
        }
        Some(lookup) if matches!(lookup.freshness, crate::HttpCacheFreshness::StaleIfError) => {
            Some(CacheRequestOutcome::Fetch {
                key: Some(storage_key),
                stale_fallback: Some(lookup.entry),
                revalidation_entry: None,
                reason: "stale_if_error_revalidation",
            })
        }
        _ => Some(CacheRequestOutcome::Fetch {
            key: Some(storage_key),
            stale_fallback: None,
            revalidation_entry: None,
            reason: "miss",
        }),
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_uncached_request<S>(
    upstream: &mut Option<TcpStream>,
    active_upstream: &mut Option<lb_net_core::UpstreamTarget>,
    last_upstream_activity: &mut Option<Instant>,
    upstream_connected_at: &mut Option<Instant>,
    upstream_addr: &mut SocketAddr,
    connect_duration: &mut Duration,
    downstream: &mut S,
    downstream_buffer: &mut Vec<u8>,
    upstream_buffer: &mut Vec<u8>,
    effective_client_ip: IpAddr,
    config: &Http1ProxyConfig,
    selected_upstream: &lb_net_core::UpstreamTarget,
    request: &lb_proto_http::Http1RequestHead,
    cache_lookup_key: Option<HttpCacheKey>,
    stale_fallback: Option<&HttpCacheEntry>,
    revalidation_entry: Option<&HttpCacheEntry>,
    metrics: &mut Http1ConnectionMetrics,
    now: Duration,
) -> Result<u16, Http1ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut retried_stale_reuse = false;
    let mut close_upstream = false;
    loop {
        let reused_existing_connection = ensure_upstream_connection(
            upstream,
            active_upstream,
            last_upstream_activity,
            upstream_connected_at,
            upstream_addr,
            connect_duration,
            selected_upstream,
            &config.timeouts,
        )
        .await?;
        let retry_stale_reuse = reused_existing_connection
            && !retried_stale_reuse
            && request_is_safe_stale_reuse_retry_candidate(request);

        {
            let Some(upstream_stream) = upstream.as_mut() else {
                break Err(Http1ProxyError::ConnectTimeout { target: selected_upstream.address });
            };

            let normalized_request_headers = lb_proto_http::normalize_request_headers(
                &request.headers,
                effective_client_ip,
                request.keep_alive,
                &request.body_kind,
            );
            let normalized_request_headers = append_conditional_revalidation_headers(
                normalized_request_headers,
                revalidation_entry,
            );
            let request_head = lb_proto_http::encode_request_head(
                &request.method,
                &request.target,
                request.version,
                &normalized_request_headers,
            );
            if let Err(source) = upstream_stream.write_all(&request_head).await {
                drop_upstream_connection(upstream, last_upstream_activity, upstream_connected_at);
                if retry_stale_reuse {
                    retried_stale_reuse = true;
                    continue;
                }
                break Err(Http1ProxyError::RequestIo(source));
            }
            relay_body(
                downstream,
                downstream_buffer,
                upstream_stream,
                &request.body_kind,
                config.limits.max_body_bytes,
                config.timeouts.idle_timeout,
                RelayDirection::Request,
            )
            .await?;

            let response = match time::timeout(
                config.timeouts.idle_timeout,
                lb_proto_http::read_response_head(
                    upstream_stream,
                    upstream_buffer,
                    &config.limits,
                    &request.method,
                ),
            )
            .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(source)) => {
                    let error = Http1ProxyError::ParseResponse(source);
                    drop_upstream_connection(upstream, last_upstream_activity, upstream_connected_at);
                    if retry_stale_reuse && http1_stale_reuse_retryable_response_error(&error) {
                        retried_stale_reuse = true;
                        continue;
                    }
                    break Err(error);
                }
                Err(_) => {
                    drop_upstream_connection(upstream, last_upstream_activity, upstream_connected_at);
                    break Err(Http1ProxyError::IdleTimeout("response head"));
                }
            };

            let normalized_response_headers = lb_proto_http::normalize_response_headers(
                &response.headers,
                response.keep_alive,
                &response.body_kind,
            );
            let upstream_response_status = response.status;
            let use_stale_if_error_response = stale_fallback.is_some()
                && is_stale_if_error_response_status(response.status);
            let use_not_modified_revalidation = response.status == 304 && revalidation_entry.is_some();
            if use_not_modified_revalidation {
                if let Some(stale_entry) = revalidation_entry {
                    let refreshed_entry = refresh_revalidated_entry(
                        config.response_cache.as_ref().map(|response_cache| &response_cache.policy),
                        stale_entry,
                        &normalized_response_headers,
                        now,
                    )
                    .unwrap_or_else(|| stale_entry.clone());
                    if let Some(response_cache) = config.response_cache.as_ref() {
                        if let Some(cache_lookup_key) = cache_lookup_key.clone() {
                            if response_cache
                                .store
                                .insert(now, cache_lookup_key, refreshed_entry.clone())
                                .is_ok()
                            {
                                metrics.cache_fill_count += 1;
                                record_cache_revalidation_telemetry(
                                    Some(response_cache),
                                    HttpCacheRevalidationResult::NotModified,
                                    "origin returned 304 Not Modified",
                                );
                            }
                        }
                    }
                    write_cached_response(
                        downstream,
                        &request.method,
                        request.keep_alive,
                        &refreshed_entry,
                    )
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                    metrics.request_count += 1;
                    *metrics
                        .response_status_counts
                        .entry(refreshed_entry.metadata.status.as_u16())
                        .or_insert(0) += 1;
                    close_upstream = !response.keep_alive;
                    if close_upstream {
                        drop_upstream_connection(
                            upstream,
                            last_upstream_activity,
                            upstream_connected_at,
                        );
                    } else {
                        *last_upstream_activity = Some(Instant::now());
                    }
                    break Ok(upstream_response_status);
                }
            } else if use_stale_if_error_response {
                if let Some(stale_entry) = stale_fallback {
                    write_cached_response(downstream, &request.method, request.keep_alive, stale_entry)
                        .await
                        .map_err(Http1ProxyError::ResponseIo)?;
                    metrics.request_count += 1;
                    metrics.cache_hit_count += 1;
                    record_cache_request_telemetry(
                        config.response_cache.as_ref(),
                        HttpCacheRequestOutcome::StaleHit,
                        "stale_if_error_response",
                        "served stale cached response after upstream error status",
                    );
                    *metrics
                        .response_status_counts
                        .entry(stale_entry.metadata.status.as_u16())
                        .or_insert(0) += 1;
                    close_upstream = true;
                    if close_upstream {
                        drop_upstream_connection(
                            upstream,
                            last_upstream_activity,
                            upstream_connected_at,
                        );
                    }
                    break Ok(upstream_response_status);
                }
            } else {
                let response_head = lb_proto_http::encode_response_head(
                    response.version,
                    response.status,
                    &response.reason,
                    &normalized_response_headers,
                );
                downstream
                    .write_all(&response_head)
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;

                let mut filled_cache = false;
                if let Some(response_cache) = config.response_cache.as_ref() {
                    if let Some(cache_lookup_key) = cache_lookup_key {
                        if let Some(entry) = build_cacheable_response_entry(
                            response_cache,
                            request,
                            &response,
                            &normalized_response_headers,
                            upstream_stream,
                            upstream_buffer,
                            downstream,
                            config,
                            now,
                        )
                        .await?
                        {
                            if response_cache.store.insert(now, cache_lookup_key, entry).is_ok() {
                                metrics.cache_fill_count += 1;
                                record_cache_request_telemetry(
                                    Some(response_cache),
                                    HttpCacheRequestOutcome::Fill,
                                    if revalidation_entry.is_some() {
                                        "revalidation_replace"
                                    } else {
                                        "origin_response"
                                    },
                                    "stored response in shared cache",
                                );
                                if revalidation_entry.is_some() {
                                    record_cache_revalidation_telemetry(
                                        Some(response_cache),
                                        HttpCacheRevalidationResult::Replaced,
                                        "origin returned replacement response for revalidation",
                                    );
                                }
                                filled_cache = true;
                            } else {
                                metrics.cache_bypass_count += 1;
                                record_cache_request_telemetry(
                                    Some(response_cache),
                                    HttpCacheRequestOutcome::Bypass,
                                    "store_reject",
                                    "cache store rejected response insertion",
                                );
                            }
                        }
                    }
                }
                if !filled_cache {
                    relay_body(
                        upstream_stream,
                        upstream_buffer,
                        downstream,
                        &response.body_kind,
                        config.limits.max_body_bytes,
                        config.timeouts.idle_timeout,
                        RelayDirection::Response,
                    )
                    .await?;
                }

                metrics.request_count += 1;
                *metrics.response_status_counts.entry(response.status).or_insert(0) += 1;
                if !response.keep_alive {
                    close_upstream = true;
                }
                if close_upstream {
                    drop_upstream_connection(
                        upstream,
                        last_upstream_activity,
                        upstream_connected_at,
                    );
                } else {
                    *last_upstream_activity = Some(Instant::now());
                }
                break Ok(upstream_response_status);
            }
        }
    }
}

async fn ensure_upstream_connection(
    upstream: &mut Option<TcpStream>,
    active_upstream: &mut Option<lb_net_core::UpstreamTarget>,
    last_upstream_activity: &mut Option<Instant>,
    upstream_connected_at: &mut Option<Instant>,
    upstream_addr: &mut SocketAddr,
    connect_duration: &mut Duration,
    target: &lb_net_core::UpstreamTarget,
    timeouts: &lb_net_core::ConnectionTimeouts,
) -> Result<bool, Http1ProxyError> {
    let now = Instant::now();
    if upstream.is_some()
        && active_upstream
            .as_ref()
            .is_some_and(|active| active.address == target.address && active.name == target.name)
    {
        if !upstream_connection_reuse_expired(
            now,
            *last_upstream_activity,
            *upstream_connected_at,
            timeouts.idle_timeout,
        ) {
            return Ok(true);
        }

        drop_upstream_connection(upstream, last_upstream_activity, upstream_connected_at);
    }

    let _ = upstream.take();
    let connect_started = Instant::now();
    let stream = time::timeout(timeouts.connect_timeout, TcpStream::connect(target.address))
        .await
        .map_err(|_| Http1ProxyError::ConnectTimeout { target: target.address })?
        .map_err(|source| Http1ProxyError::Connect { target: target.address, source })?;
    *connect_duration = connect_started.elapsed();
    *upstream_addr = stream
        .peer_addr()
        .map_err(|source| Http1ProxyError::Connect { target: target.address, source })?;
    *active_upstream = Some(target.clone());
    let connected_at = Instant::now();
    *last_upstream_activity = Some(connected_at);
    *upstream_connected_at = Some(connected_at);
    *upstream = Some(stream);
    Ok(false)
}

fn upstream_connection_reuse_expired(
    now: Instant,
    last_upstream_activity: Option<Instant>,
    upstream_connected_at: Option<Instant>,
    reuse_timeout: Duration,
) -> bool {
    last_upstream_activity.is_none_or(|last_used_at| {
        now.saturating_duration_since(last_used_at) >= reuse_timeout
    }) || upstream_connected_at.is_none_or(|connected_at| {
        now.saturating_duration_since(connected_at) >= reuse_timeout
    })
}

fn drop_upstream_connection(
    upstream: &mut Option<TcpStream>,
    last_upstream_activity: &mut Option<Instant>,
    upstream_connected_at: &mut Option<Instant>,
) {
    *last_upstream_activity = None;
    *upstream_connected_at = None;
    let _ = upstream.take();
}

fn request_is_safe_stale_reuse_retry_candidate(request: &lb_proto_http::Http1RequestHead) -> bool {
    matches!(request.body_kind, lb_proto_http::BodyKind::None)
        && matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

fn http1_stale_reuse_retryable_response_error(error: &Http1ProxyError) -> bool {
    match error {
        Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::IncompleteHead) => true,
        Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::Io(source)) => {
            matches!(
                source.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            )
        }
        _ => false,
    }
}

async fn write_local_response<W>(
    downstream: &mut W,
    keep_alive: bool,
    status: StatusCode,
    body: &'static str,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    let mut headers = vec![lb_proto_http::HttpHeader {
        name: String::from("content-type"),
        value: String::from("text/plain; charset=utf-8"),
    }];
    if !keep_alive {
        headers.push(lb_proto_http::HttpHeader {
            name: String::from("connection"),
            value: String::from("close"),
        });
    }
    headers.push(lb_proto_http::HttpHeader {
        name: String::from("content-length"),
        value: body.len().to_string(),
    });
    let response_head = lb_proto_http::encode_response_head(
        lb_proto_http::SupportedHttpVersion::Http1,
        status.as_u16(),
        "",
        &headers,
    );
    downstream.write_all(&response_head).await?;
    downstream.write_all(body.as_bytes()).await?;
    Ok(())
}

async fn write_cached_response<W>(
    downstream: &mut W,
    request_method: &str,
    keep_alive: bool,
    entry: &HttpCacheEntry,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    let mut headers = entry
        .headers
        .iter()
        .map(|header| lb_proto_http::HttpHeader {
            name: header.name.as_str().to_string(),
            value: header
                .value
                .to_str()
                .map_or_else(|_| String::new(), std::string::ToString::to_string),
        })
        .collect::<Vec<_>>();
    if !keep_alive {
        headers.push(lb_proto_http::HttpHeader {
            name: String::from("connection"),
            value: String::from("close"),
        });
    }
    let response_head = lb_proto_http::encode_response_head(
        lb_proto_http::SupportedHttpVersion::Http1,
        entry.metadata.status.as_u16(),
        "",
        &headers,
    );
    downstream.write_all(&response_head).await?;
    if !request_method.eq_ignore_ascii_case("HEAD") {
        downstream.write_all(&entry.body).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn build_cacheable_response_entry<W>(
    response_cache: &Http1ResponseCacheConfig,
    request: &lb_proto_http::Http1RequestHead,
    response: &lb_proto_http::Http1ResponseHead,
    normalized_response_headers: &[lb_proto_http::HttpHeader],
    upstream: &mut TcpStream,
    upstream_buffer: &mut Vec<u8>,
    downstream: &mut W,
    config: &Http1ProxyConfig,
    now: Duration,
) -> Result<Option<HttpCacheEntry>, Http1ProxyError>
where
    W: AsyncWrite + Unpin,
{
    if !request.method.eq_ignore_ascii_case("GET")
        || !response_is_cacheable(&response_cache.policy, response, normalized_response_headers)
    {
        return Ok(None);
    }

    let status = StatusCode::from_u16(response.status).map_err(|_| {
        parse_side_error(
            RelayDirection::Response,
            lb_proto_http::Http1ParseError::Invalid("invalid status code"),
        )
    })?;
    let metadata = match derive_cache_metadata(
        &response_cache.policy,
        normalized_response_headers,
        status,
        now,
    ) {
        Some(metadata) => metadata,
        None => return Ok(None),
    };

    let body = match response.body_kind {
        lb_proto_http::BodyKind::None => bytes::Bytes::new(),
        lb_proto_http::BodyKind::ContentLength(length) => {
            if length > response_cache.policy.max_object_bytes {
                return Ok(None);
            }
            relay_content_length_collect(
                upstream,
                upstream_buffer,
                downstream,
                length,
                config.timeouts.idle_timeout,
                RelayDirection::Response,
            )
            .await?
        }
        lb_proto_http::BodyKind::Chunked => return Ok(None),
    };

    let headers = match to_cache_headers(normalized_response_headers) {
        Some(headers) => headers,
        None => return Ok(None),
    };

    Ok(Some(HttpCacheEntry {
        metadata,
        headers,
        body,
    }))
}

fn request_method_is_cache_lookup_eligible(
    policy: &lb_config_model::HttpCachePolicyConfig,
    method: &str,
) -> bool {
    policy.methods.iter().any(|configured_method| match configured_method {
        lb_config_model::HttpCacheMethodConfig::Get => method.eq_ignore_ascii_case("GET"),
        lb_config_model::HttpCacheMethodConfig::Head => method.eq_ignore_ascii_case("HEAD"),
    })
}

fn response_is_cacheable(
    policy: &lb_config_model::HttpCachePolicyConfig,
    response: &lb_proto_http::Http1ResponseHead,
    headers: &[lb_proto_http::HttpHeader],
) -> bool {
    if !policy.cacheable_status_codes.contains(&response.status) {
        return false;
    }
    if !policy.allow_set_cookie_storage
        && headers.iter().any(|header| header.name.eq_ignore_ascii_case("set-cookie"))
    {
        return false;
    }
    if response_has_unsafe_vary(headers) {
        return false;
    }
    true
}

fn response_has_unsafe_vary(headers: &[lb_proto_http::HttpHeader]) -> bool {
    for header in headers.iter().filter(|header| header.name.eq_ignore_ascii_case("vary")) {
        for value in header.value.split(',').map(str::trim) {
            if value.is_empty() || value == "*" || is_disallowed_cache_vary_header(value) {
                return true;
            }
        }
    }
    false
}

fn is_disallowed_cache_vary_header(header: &str) -> bool {
    matches!(
        header.to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-proto"
    )
}

fn derive_cache_metadata(
    policy: &lb_config_model::HttpCachePolicyConfig,
    headers: &[lb_proto_http::HttpHeader],
    status: StatusCode,
    now: Duration,
) -> Option<HttpCacheMetadata> {
    let freshness = if policy.honor_cache_control {
        derive_freshness_windows_from_origin(policy, headers)?
    } else {
        CacheFreshnessWindows {
            fresh_for: Duration::from_secs(policy.default_ttl_secs),
            stale_while_revalidate_for: duration_if_non_zero(policy.stale_while_revalidate_secs),
            stale_if_error_for: duration_if_non_zero(policy.stale_if_error_secs),
        }
    };

    if freshness.fresh_for.is_zero()
        && freshness.stale_while_revalidate_for.is_none()
        && freshness.stale_if_error_for.is_none()
    {
        return None;
    }

    let fresh_until = now + freshness.fresh_for;
    Some(HttpCacheMetadata {
        status,
        stored_at: now,
        fresh_until,
        stale_while_revalidate_until: freshness
            .stale_while_revalidate_for
            .map(|window| fresh_until + window),
        stale_if_error_until: freshness
            .stale_if_error_for
            .map(|window| fresh_until + window),
        etag: response_header_value(headers, "etag"),
        last_modified: response_header_value(headers, "last-modified"),
    })
}

fn should_revalidate_entry(
    policy: &lb_config_model::HttpCachePolicyConfig,
    entry: &HttpCacheEntry,
) -> bool {
    policy.revalidation_enabled
        && (entry.metadata.etag.is_some() || entry.metadata.last_modified.is_some())
}

fn append_conditional_revalidation_headers(
    mut headers: Vec<lb_proto_http::HttpHeader>,
    revalidation_entry: Option<&HttpCacheEntry>,
) -> Vec<lb_proto_http::HttpHeader> {
    let Some(revalidation_entry) = revalidation_entry else {
        return headers;
    };
    if let Some(etag) = &revalidation_entry.metadata.etag {
        if let Ok(etag) = etag.to_str() {
            headers.push(lb_proto_http::HttpHeader {
                name: String::from("if-none-match"),
                value: String::from(etag),
            });
        }
    }
    if let Some(last_modified) = &revalidation_entry.metadata.last_modified {
        if let Ok(last_modified) = last_modified.to_str() {
            headers.push(lb_proto_http::HttpHeader {
                name: String::from("if-modified-since"),
                value: String::from(last_modified),
            });
        }
    }
    headers
}

fn refresh_revalidated_entry(
    policy: Option<&lb_config_model::HttpCachePolicyConfig>,
    stale_entry: &HttpCacheEntry,
    response_headers: &[lb_proto_http::HttpHeader],
    now: Duration,
) -> Option<HttpCacheEntry> {
    let policy = policy?;
    let mut refreshed = stale_entry.clone();
    let metadata = derive_cache_metadata(policy, response_headers, stale_entry.metadata.status, now)?;
    refreshed.metadata = HttpCacheMetadata {
        etag: metadata.etag.or_else(|| stale_entry.metadata.etag.clone()),
        last_modified: metadata
            .last_modified
            .or_else(|| stale_entry.metadata.last_modified.clone()),
        ..metadata
    };
    Some(refreshed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheFreshnessWindows {
    fresh_for: Duration,
    stale_while_revalidate_for: Option<Duration>,
    stale_if_error_for: Option<Duration>,
}

fn derive_freshness_windows_from_origin(
    policy: &lb_config_model::HttpCachePolicyConfig,
    headers: &[lb_proto_http::HttpHeader],
) -> Option<CacheFreshnessWindows> {
    let directives = parse_cache_control(headers)?;
    if directives.no_store || directives.private || directives.no_cache || has_pragma_no_cache(headers) {
        return None;
    }

    let age_secs = match header_value(headers, "age") {
        Some(value) => value.parse::<u64>().ok()?,
        None => 0,
    };

    let freshness_secs = if let Some(max_age) = directives.shared_max_age.or(directives.max_age) {
        max_age.saturating_sub(age_secs)
    } else if let Some(expires_header) = header_value(headers, "expires") {
        let expires_at = parse_http_date(expires_header).ok()?;
        if let Some(date_header) = header_value(headers, "date") {
            let origin_date = parse_http_date(date_header).ok()?;
            expires_at
                .duration_since(origin_date)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(age_secs)
        } else {
            policy.default_ttl_secs
        }
    } else {
        policy.default_ttl_secs
    };

    let fresh_for = Duration::from_secs(freshness_secs.min(policy.max_ttl_secs));
    let stale_while_revalidate_for = duration_if_non_zero(
        directives
            .stale_while_revalidate
            .unwrap_or(policy.stale_while_revalidate_secs)
            .min(policy.stale_while_revalidate_secs),
    );
    let stale_if_error_for = duration_if_non_zero(
        directives
            .stale_if_error
            .unwrap_or(policy.stale_if_error_secs)
            .min(policy.stale_if_error_secs),
    );

    Some(CacheFreshnessWindows {
        fresh_for,
        stale_while_revalidate_for,
        stale_if_error_for,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ParsedCacheControl {
    no_store: bool,
    private: bool,
    no_cache: bool,
    max_age: Option<u64>,
    shared_max_age: Option<u64>,
    stale_while_revalidate: Option<u64>,
    stale_if_error: Option<u64>,
}

fn parse_cache_control(headers: &[lb_proto_http::HttpHeader]) -> Option<ParsedCacheControl> {
    let mut parsed = ParsedCacheControl::default();
    for value in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("cache-control"))
        .map(|header| header.value.as_str())
    {
        for directive in value.split(',').map(str::trim).filter(|value| !value.is_empty()) {
            let (name, parameter) = directive
                .split_once('=')
                .map_or((directive, None), |(name, value)| (name.trim(), Some(value.trim())));
            if name.eq_ignore_ascii_case("no-store") {
                parsed.no_store = true;
            } else if name.eq_ignore_ascii_case("private") {
                parsed.private = true;
            } else if name.eq_ignore_ascii_case("no-cache") {
                parsed.no_cache = true;
            } else if name.eq_ignore_ascii_case("max-age") {
                parsed.max_age = Some(parse_cache_delta(parameter?)?);
            } else if name.eq_ignore_ascii_case("s-maxage") {
                parsed.shared_max_age = Some(parse_cache_delta(parameter?)?);
            } else if name.eq_ignore_ascii_case("stale-while-revalidate") {
                parsed.stale_while_revalidate = Some(parse_cache_delta(parameter?)?);
            } else if name.eq_ignore_ascii_case("stale-if-error") {
                parsed.stale_if_error = Some(parse_cache_delta(parameter?)?);
            }
        }
    }
    Some(parsed)
}

fn parse_cache_delta(value: &str) -> Option<u64> {
    let value = value.trim_matches('"');
    value.parse::<u64>().ok()
}

fn header_value<'a>(headers: &'a [lb_proto_http::HttpHeader], name: &str) -> Option<&'a str> {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.trim());
    let first = values.next()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn has_pragma_no_cache(headers: &[lb_proto_http::HttpHeader]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("pragma") && header.value.eq_ignore_ascii_case("no-cache")
    })
}

fn duration_if_non_zero(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn record_cache_request_telemetry(
    response_cache: Option<&Http1ResponseCacheConfig>,
    outcome: HttpCacheRequestOutcome,
    reason: &str,
    detail: &str,
) {
    if let Some(telemetry) = response_cache.and_then(|response_cache| response_cache.telemetry.as_ref()) {
        let _ = telemetry
            .telemetry
            .record_http_cache_request(&telemetry.scope, outcome, reason, detail);
    }
}

fn record_cache_revalidation_telemetry(
    response_cache: Option<&Http1ResponseCacheConfig>,
    result: HttpCacheRevalidationResult,
    detail: &str,
) {
    if let Some(telemetry) = response_cache.and_then(|response_cache| response_cache.telemetry.as_ref()) {
        let _ = telemetry
            .telemetry
            .record_http_cache_revalidation(&telemetry.scope, result, detail);
    }
}

fn is_stale_if_error_response_status(status: u16) -> bool {
    (500..=599).contains(&status)
}

fn error_allows_stale_if_error(error: &Http1ProxyError) -> bool {
    matches!(
        error,
        Http1ProxyError::ConnectTimeout { .. }
            | Http1ProxyError::Connect { .. }
            | Http1ProxyError::ParseResponse(_)
            | Http1ProxyError::RequestIo(_)
            | Http1ProxyError::IdleTimeout("request body")
            | Http1ProxyError::IdleTimeout("response head")
    )
}

fn response_header_value(
    headers: &[lb_proto_http::HttpHeader],
    name: &str,
) -> Option<HeaderValue> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .and_then(|header| HeaderValue::from_str(&header.value).ok())
}

fn to_cache_headers(headers: &[lb_proto_http::HttpHeader]) -> Option<Vec<HttpCacheHeader>> {
    headers
        .iter()
        .map(|header| {
            Some(HttpCacheHeader::new(
                HeaderName::from_bytes(header.name.as_bytes()).ok()?,
                HeaderValue::from_str(&header.value).ok()?,
            ))
        })
        .collect()
}

#[derive(Clone, Copy)]
enum RelayDirection {
    Request,
    Response,
}

async fn relay_body<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    body_kind: &lb_proto_http::BodyKind,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body_kind {
        lb_proto_http::BodyKind::None => Ok(()),
        lb_proto_http::BodyKind::ContentLength(length) => {
            if *length > max_body_bytes {
                return Err(body_limit_error(direction));
            }
            relay_content_length(reader, read_buffer, writer, *length, idle_timeout, direction)
                .await
        }
        lb_proto_http::BodyKind::Chunked => {
            relay_chunked(reader, read_buffer, writer, max_body_bytes, idle_timeout, direction)
                .await
        }
    }
}

async fn relay_content_length<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    length: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = usize::try_from(length).unwrap_or(usize::MAX);

    if !read_buffer.is_empty() {
        let buffered = remaining.min(read_buffer.len());
        writer
            .write_all(&read_buffer[..buffered])
            .await
            .map_err(|source| io_error(direction, source))?;
        read_buffer.drain(..buffered);
        remaining = remaining.saturating_sub(buffered);
    }

    let mut chunk = [0_u8; 8192];
    while remaining != 0 {
        let to_read = remaining.min(chunk.len());
        let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk[..to_read]))
            .await
            .map_err(|_| idle_error(direction))?
            .map_err(|source| io_error(direction, source))?;
        if bytes_read == 0 {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::IncompleteHead,
            ));
        }

        writer
            .write_all(&chunk[..bytes_read])
            .await
            .map_err(|source| io_error(direction, source))?;
        remaining = remaining.saturating_sub(bytes_read);
    }

    Ok(())
}

async fn relay_content_length_collect<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    length: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<bytes::Bytes, Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = usize::try_from(length).unwrap_or(usize::MAX);
    let mut collected = Vec::with_capacity(remaining.min(8192));

    if !read_buffer.is_empty() {
        let buffered = remaining.min(read_buffer.len());
        writer
            .write_all(&read_buffer[..buffered])
            .await
            .map_err(|source| io_error(direction, source))?;
        collected.extend_from_slice(&read_buffer[..buffered]);
        read_buffer.drain(..buffered);
        remaining = remaining.saturating_sub(buffered);
    }

    let mut chunk = [0_u8; 8192];
    while remaining != 0 {
        let to_read = remaining.min(chunk.len());
        let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk[..to_read]))
            .await
            .map_err(|_| idle_error(direction))?
            .map_err(|source| io_error(direction, source))?;
        if bytes_read == 0 {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::IncompleteHead,
            ));
        }

        writer
            .write_all(&chunk[..bytes_read])
            .await
            .map_err(|source| io_error(direction, source))?;
        collected.extend_from_slice(&chunk[..bytes_read]);
        remaining = remaining.saturating_sub(bytes_read);
    }

    Ok(bytes::Bytes::from(collected))
}

async fn relay_chunked<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total_body_bytes = 0_u64;

    loop {
        let line = read_crlf_line(reader, read_buffer, idle_timeout, direction).await?;
        writer.write_all(&line).await.map_err(|source| io_error(direction, source))?;

        let line_text =
            std::str::from_utf8(&line[..line.len().saturating_sub(2)]).map_err(|_| {
                parse_side_error(
                    direction,
                    lb_proto_http::Http1ParseError::Invalid("invalid chunk size line"),
                )
            })?;
        let chunk_size_text = line_text.split(';').next().unwrap_or_default().trim();
        let chunk_size = u64::from_str_radix(chunk_size_text, 16).map_err(|_| {
            parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::Invalid("invalid chunk size"),
            )
        })?;

        total_body_bytes = total_body_bytes.saturating_add(chunk_size);
        if total_body_bytes > max_body_bytes {
            return Err(body_limit_error(direction));
        }

        let chunk_plus_crlf = usize::try_from(chunk_size).unwrap_or(usize::MAX).saturating_add(2);
        relay_exact_bytes(reader, read_buffer, writer, chunk_plus_crlf, idle_timeout, direction)
            .await?;

        if chunk_size == 0 {
            loop {
                let trailer_line =
                    read_crlf_line(reader, read_buffer, idle_timeout, direction).await?;
                writer
                    .write_all(&trailer_line)
                    .await
                    .map_err(|source| io_error(direction, source))?;
                if trailer_line == b"\r\n" {
                    return Ok(());
                }
            }
        }
    }
}

async fn relay_exact_bytes<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    length: usize,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = length;
    while remaining != 0 {
        if !read_buffer.is_empty() {
            let buffered = remaining.min(read_buffer.len());
            writer
                .write_all(&read_buffer[..buffered])
                .await
                .map_err(|source| io_error(direction, source))?;
            read_buffer.drain(..buffered);
            remaining = remaining.saturating_sub(buffered);
            continue;
        }

        let mut chunk = vec![0_u8; remaining.min(8192)];
        let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk))
            .await
            .map_err(|_| idle_error(direction))?
            .map_err(|source| io_error(direction, source))?;
        if bytes_read == 0 {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::IncompleteHead,
            ));
        }

        writer
            .write_all(&chunk[..bytes_read])
            .await
            .map_err(|source| io_error(direction, source))?;
        remaining = remaining.saturating_sub(bytes_read);
    }

    Ok(())
}

async fn read_crlf_line<R>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<Vec<u8>, Http1ProxyError>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(position) = read_buffer.windows(2).position(|window| window == b"\r\n") {
            let line = read_buffer.drain(..position + 2).collect();
            return Ok(line);
        }

        let mut chunk = [0_u8; 1024];
        let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk))
            .await
            .map_err(|_| idle_error(direction))?
            .map_err(|source| io_error(direction, source))?;
        if bytes_read == 0 {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::IncompleteHead,
            ));
        }
        read_buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn idle_error(direction: RelayDirection) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::IdleTimeout("request body"),
        RelayDirection::Response => Http1ProxyError::IdleTimeout("response body"),
    }
}

fn body_limit_error(direction: RelayDirection) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::BodyLimitExceeded("request body"),
        RelayDirection::Response => Http1ProxyError::BodyLimitExceeded("response body"),
    }
}

fn io_error(direction: RelayDirection, source: std::io::Error) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::RequestIo(source),
        RelayDirection::Response => Http1ProxyError::ResponseIo(source),
    }
}

fn parse_side_error(
    direction: RelayDirection,
    source: lb_proto_http::Http1ParseError,
) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::ParseRequest(source),
        RelayDirection::Response => Http1ProxyError::ParseResponse(source),
    }
}

fn classify_http1_request_parse_error(
    error: &lb_proto_http::Http1ParseError,
) -> Option<ProtocolAnomalyCategory> {
    match error {
        lb_proto_http::Http1ParseError::HeadTooLarge => {
            Some(ProtocolAnomalyCategory::HeadSizeLimitExceeded)
        }
        lb_proto_http::Http1ParseError::TooManyHeaders => {
            Some(ProtocolAnomalyCategory::HeaderCountLimitExceeded)
        }
        lb_proto_http::Http1ParseError::Invalid(message)
            if message.contains("ambiguous content-length")
                || message.contains("missing required host header")
                || message.contains("multiple host headers") =>
        {
            Some(ProtocolAnomalyCategory::AmbiguousFraming)
        }
        lb_proto_http::Http1ParseError::Invalid(_)
        | lb_proto_http::Http1ParseError::IncompleteHead => {
            Some(ProtocolAnomalyCategory::MalformedMessage)
        }
        lb_proto_http::Http1ParseError::Io(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::{
        body_limit_error, classify_http1_request_parse_error, idle_error, io_error,
        parse_side_error, read_crlf_line, relay_body, relay_chunked, relay_content_length,
        relay_content_length_collect, relay_exact_bytes, ensure_upstream_connection,
        Http1ProxyError, RelayDirection,
    };
    use crate::{ProtocolAnomalyCategory, SlowClientStage};

    #[test]
    fn request_parse_errors_map_to_stable_anomaly_categories() {
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::HeadTooLarge),
            Some(ProtocolAnomalyCategory::HeadSizeLimitExceeded)
        );
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::TooManyHeaders),
            Some(ProtocolAnomalyCategory::HeaderCountLimitExceeded)
        );
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::Invalid(
                "multiple host headers",
            )),
            Some(ProtocolAnomalyCategory::AmbiguousFraming)
        );
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::IncompleteHead),
            Some(ProtocolAnomalyCategory::MalformedMessage)
        );
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::Io(
                io::Error::other("io"),
            )),
            None
        );
    }

    #[test]
    fn error_helpers_preserve_direction_and_source() {
        let request_idle = idle_error(RelayDirection::Request);
        let response_limit = body_limit_error(RelayDirection::Response);
        let request_io = io_error(RelayDirection::Request, io::Error::other("write failed"));
        let response_parse = parse_side_error(
            RelayDirection::Response,
            lb_proto_http::Http1ParseError::IncompleteHead,
        );
        let connect_timeout = Http1ProxyError::ConnectTimeout {
            target: "127.0.0.1:8080".parse().expect("socket addr"),
        };
        let connect = Http1ProxyError::Connect {
            target: "127.0.0.1:8080".parse().expect("socket addr"),
            source: io::Error::other("connect failed"),
        };
        let parse_request = Http1ProxyError::ParseRequest(lb_proto_http::Http1ParseError::HeadTooLarge);
        let parse_response = Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::IncompleteHead);
        let response_io = Http1ProxyError::ResponseIo(io::Error::other("response failed"));

        assert_eq!(request_idle.slow_client_stage(), Some(SlowClientStage::RequestBody));
        assert_eq!(response_limit.anomaly_category(), None);
        assert!(connect_timeout.to_string().contains("timed out connecting HTTP/1.1 upstream"));
        assert!(connect.to_string().contains("failed to connect HTTP/1.1 upstream"));
        assert_eq!(
            parse_request.anomaly_category(),
            Some(ProtocolAnomalyCategory::HeadSizeLimitExceeded)
        );
        assert_eq!(parse_response.anomaly_category(), None);
        assert!(request_io.to_string().contains("upstream write failed"));
        assert!(std::error::Error::source(&request_io).is_some());
        assert!(std::error::Error::source(&connect).is_some());
        assert!(std::error::Error::source(&parse_request).is_some());
        assert!(std::error::Error::source(&response_io).is_some());
        assert!(matches!(response_parse, Http1ProxyError::ParseResponse(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_body_none_and_body_limit_paths_are_explicit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut reader_peer) = tokio::io::duplex(64);
        let (mut writer_peer, mut writer) = tokio::io::duplex(64);
        reader_peer.write_all(b"abc").await?;

        relay_body(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            &lb_proto_http::BodyKind::None,
            10,
            Duration::from_millis(10),
            RelayDirection::Request,
        )
        .await?;

        let body_limit = relay_body(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            &lb_proto_http::BodyKind::ContentLength(11),
            10,
            Duration::from_millis(10),
            RelayDirection::Request,
        )
        .await
        .expect_err("oversized body should fail");

        assert_eq!(
            body_limit.anomaly_category(),
            Some(ProtocolAnomalyCategory::BodySizeLimitExceeded)
        );

        drop(writer);
        let mut sink = Vec::new();
        writer_peer.read_to_end(&mut sink).await?;
        assert!(sink.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_content_length_flushes_buffered_bytes_and_detects_truncation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut sink_reader, mut writer) = tokio::io::duplex(64);
        let mut buffered = b"ab".to_vec();
        feeder.write_all(b"cd").await?;
        feeder.shutdown().await?;

        relay_content_length(
            &mut reader,
            &mut buffered,
            &mut writer,
            4,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await?;

        drop(writer);
        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;
        assert_eq!(output, b"abcd");

        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut _sink_reader, mut writer) = tokio::io::duplex(64);
        feeder.write_all(b"x").await?;
        feeder.shutdown().await?;
        let truncation = relay_content_length(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            2,
            Duration::from_millis(50),
            RelayDirection::Response,
        )
        .await
        .expect_err("truncated body should fail");

        assert!(matches!(truncation, Http1ProxyError::ParseResponse(_)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_content_length_collect_writes_and_returns_body(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut sink_reader, mut writer) = tokio::io::duplex(64);
        feeder.write_all(b"payload").await?;
        feeder.shutdown().await?;

        let collected = relay_content_length_collect(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            7,
            Duration::from_millis(50),
            RelayDirection::Response,
        )
        .await?;

        drop(writer);
        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;
        assert_eq!(output, b"payload");
        assert_eq!(collected, bytes::Bytes::from_static(b"payload"));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_exact_bytes_and_read_crlf_line_cover_buffer_and_eof_paths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut sink_reader, mut writer) = tokio::io::duplex(64);
        let mut buffered = b"ab".to_vec();
        feeder.write_all(b"cd").await?;
        feeder.shutdown().await?;

        relay_exact_bytes(
            &mut reader,
            &mut buffered,
            &mut writer,
            4,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await?;

        drop(writer);
        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;
        assert_eq!(output, b"abcd");

        let mut line_buffer = b"size\r\nrest".to_vec();
        let (mut reader, _feeder) = tokio::io::duplex(64);
        let line = read_crlf_line(
            &mut reader,
            &mut line_buffer,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await?;
        assert_eq!(line, b"size\r\n");

        let (mut reader, mut feeder) = tokio::io::duplex(64);
        feeder.write_all(b"unterminated").await?;
        feeder.shutdown().await?;
        let eof = read_crlf_line(
            &mut reader,
            &mut Vec::new(),
            Duration::from_millis(50),
            RelayDirection::Response,
        )
        .await
        .expect_err("missing CRLF should fail");
        assert!(matches!(eof, Http1ProxyError::ParseResponse(_)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_chunked_handles_success_and_invalid_chunk_sizes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(256);
        let (mut sink_reader, mut writer) = tokio::io::duplex(256);
        feeder.write_all(b"4\r\ntest\r\n0\r\nheader: ok\r\n\r\n").await?;
        feeder.shutdown().await?;

        relay_chunked(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            10,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await?;

        drop(writer);
        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;
        assert_eq!(output, b"4\r\ntest\r\n0\r\nheader: ok\r\n\r\n");

        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut _sink_reader, mut writer) = tokio::io::duplex(64);
        feeder.write_all(b"zz\r\n").await?;
        feeder.shutdown().await?;

        let invalid = relay_chunked(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            10,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await
        .expect_err("invalid chunk sizes should fail");
        assert!(matches!(invalid, Http1ProxyError::ParseRequest(_)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ensure_upstream_connection_reconnects_after_idle_timeout(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = oneshot::channel();

        tokio::spawn(async move {
            let mut accepted_peer_addrs = Vec::new();
            let mut held_streams = Vec::new();
            for _ in 0..2 {
                let Ok((stream, peer_addr)) = listener.accept().await else {
                    break;
                };
                accepted_peer_addrs.push(peer_addr);
                held_streams.push(stream);
            }
            let _ = accepted_tx.send(accepted_peer_addrs);
            let _held_streams = held_streams;
        });

        let target = lb_net_core::UpstreamTarget::new("unit-http1-upstream", target_addr);
        let timeouts = lb_net_core::ConnectionTimeouts {
            connect_timeout: Duration::from_millis(100),
            preface_timeout: Duration::from_millis(50),
            idle_timeout: Duration::from_millis(25),
        };
        let mut upstream = None;
        let mut active_upstream = None;
        let mut last_upstream_activity = None;
        let mut upstream_connected_at = None;
        let mut upstream_addr = target_addr;
        let mut connect_duration = Duration::ZERO;

        ensure_upstream_connection(
            &mut upstream,
            &mut active_upstream,
            &mut last_upstream_activity,
            &mut upstream_connected_at,
            &mut upstream_addr,
            &mut connect_duration,
            &target,
            &timeouts,
        )
        .await?;

        let first_local_addr = upstream
            .as_ref()
            .expect("first upstream connection")
            .local_addr()?;
        last_upstream_activity = Some(
            Instant::now()
                .checked_sub(Duration::from_millis(50))
                .expect("valid instant subtraction"),
        );

        ensure_upstream_connection(
            &mut upstream,
            &mut active_upstream,
            &mut last_upstream_activity,
            &mut upstream_connected_at,
            &mut upstream_addr,
            &mut connect_duration,
            &target,
            &timeouts,
        )
        .await?;

        let second_local_addr = upstream
            .as_ref()
            .expect("second upstream connection")
            .local_addr()?;
        assert_ne!(first_local_addr, second_local_addr);

        drop(upstream.take());
        let accepted_peer_addrs = accepted_rx.await?;
        assert_eq!(accepted_peer_addrs.len(), 2);
        assert_eq!(accepted_peer_addrs[0], first_local_addr);
        assert_eq!(accepted_peer_addrs[1], second_local_addr);

        Ok(())
    }
}
