#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;
use lb_net_core::canonicalize_ip;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Returns the crate identifier for HTTP protocol abstractions.
pub const CRATE_ID: &str = "lb-proto-http";

/// Minimal protocol surface placeholder for future HTTP pipeline work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedHttpVersion {
    /// HTTP/1.1 foundation.
    Http1,
    /// HTTP/2 foundation.
    Http2,
}

/// Request/response parsing and relay limits for HTTP/1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1Limits {
    /// Maximum bytes allowed for a start line and headers block.
    pub max_head_bytes: usize,
    /// Maximum number of headers accepted per message.
    pub max_header_count: usize,
    /// Maximum total body bytes accepted per message.
    pub max_body_bytes: u64,
}

impl Default for Http1Limits {
    fn default() -> Self {
        Self { max_head_bytes: 16 * 1024, max_header_count: 64, max_body_bytes: 8 * 1024 * 1024 }
    }
}

/// Stream and body limits for HTTP/2 forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Limits {
    /// Maximum number of concurrently proxied streams on one connection.
    pub max_concurrent_streams: usize,
    /// Maximum total body bytes accepted per stream.
    pub max_body_bytes: u64,
}

impl Default for Http2Limits {
    fn default() -> Self {
        Self { max_concurrent_streams: 128, max_body_bytes: 8 * 1024 * 1024 }
    }
}

/// Placeholder route prefix rule for future routing extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePrefixRule {
    /// Human-readable route label.
    pub label: String,
    /// Path prefix matched against request targets.
    pub prefix: String,
    /// Optional normalized hostnames matched against Host or :authority.
    pub hostnames: Vec<String>,
    /// Optional normalized HTTP methods matched against the request method.
    pub methods: Vec<String>,
    /// Optional request-header matchers.
    pub header_matches: Vec<RouteHeaderMatch>,
    /// Optional query-parameter matchers.
    pub query_matches: Vec<RouteQueryMatch>,
    /// Optional normalized content types matched against the request content type.
    pub content_types: Vec<String>,
    /// Optional normalized gRPC service names matched against the canonical gRPC path service.
    pub grpc_services: Vec<String>,
    /// Optional normalized gRPC method names matched against the canonical gRPC path method.
    pub grpc_methods: Vec<String>,
    /// Optional source CIDRs matched against the effective client IP.
    pub source_cidrs: Vec<IpNet>,
}

/// Supported route-header matcher shapes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteHeaderMatch {
    Exact { name: String, value: String },
    Present { name: String },
    Absent { name: String },
}

/// Supported route-query matcher shapes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteQueryMatch {
    Exact { name: String, value: String },
    Present { name: String },
    Absent { name: String },
}

impl RoutePrefixRule {
    /// Builds a prefix rule for basic route matching.
    #[must_use]
    pub fn new(label: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            prefix: prefix.into(),
            hostnames: Vec::new(),
            methods: Vec::new(),
            header_matches: Vec::new(),
            query_matches: Vec::new(),
            content_types: Vec::new(),
            grpc_services: Vec::new(),
            grpc_methods: Vec::new(),
            source_cidrs: Vec::new(),
        }
    }

    /// Restricts a prefix rule to the provided normalized hostnames.
    #[must_use]
    pub fn with_hostnames(mut self, hostnames: Vec<String>) -> Self {
        self.hostnames = hostnames;
        self
    }

    /// Restricts a prefix rule to the provided normalized HTTP methods.
    #[must_use]
    pub fn with_methods(mut self, methods: Vec<String>) -> Self {
        self.methods = methods.into_iter().map(|method| method.trim().to_ascii_uppercase()).collect();
        self
    }

    #[must_use]
    pub fn with_header_matches(mut self, header_matches: Vec<RouteHeaderMatch>) -> Self {
        self.header_matches = header_matches;
        self
    }

    #[must_use]
    pub fn with_query_matches(mut self, query_matches: Vec<RouteQueryMatch>) -> Self {
        self.query_matches = query_matches;
        self
    }

    #[must_use]
    pub fn with_content_types(mut self, content_types: Vec<String>) -> Self {
        self.content_types = content_types;
        self
    }

    #[must_use]
    pub fn with_grpc_services(mut self, grpc_services: Vec<String>) -> Self {
        self.grpc_services = grpc_services;
        self
    }

    #[must_use]
    pub fn with_grpc_methods(mut self, grpc_methods: Vec<String>) -> Self {
        self.grpc_methods = grpc_methods;
        self
    }

    #[must_use]
    pub fn with_source_cidrs(mut self, source_cidrs: Vec<IpNet>) -> Self {
        self.source_cidrs = source_cidrs;
        self
    }

    fn specificity_key(&self) -> (usize, bool, bool, usize, usize, bool, usize, usize, bool) {
        (
            self.prefix.len(),
            !self.hostnames.is_empty(),
            !self.methods.is_empty(),
            self.header_matches.len(),
            self.query_matches.len(),
            !self.content_types.is_empty(),
            self.grpc_services.len(),
            self.grpc_methods.len(),
            !self.source_cidrs.is_empty(),
        )
    }
}

/// Normalizes an HTTP method for matching and validation.
#[must_use]
pub fn normalize_http_method(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() || !normalized.chars().all(is_http_token_char) {
        return None;
    }
    Some(normalized.to_ascii_uppercase())
}

#[must_use]
pub fn normalize_grpc_service_match(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty()
        || normalized.contains('/')
        || normalized.chars().any(|character| character.is_ascii_whitespace())
    {
        return None;
    }

    normalized
        .split('.')
        .all(is_valid_grpc_identifier)
        .then(|| normalized.to_string())
}

#[must_use]
pub fn normalize_grpc_method_match(value: &str) -> Option<String> {
    let normalized = value.trim();
    is_valid_grpc_identifier(normalized).then(|| normalized.to_string())
}

fn is_valid_grpc_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };

    (first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Normalizes an HTTP header name for matching and validation.
#[must_use]
pub fn normalize_http_header_name(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() || !normalized.chars().all(is_http_token_char) {
        return None;
    }
    Some(normalized.to_ascii_lowercase())
}

/// Canonicalizes a query-parameter name used by route matchers.
pub fn canonicalize_query_match_name(value: &str) -> Result<String, RequestTargetError> {
    let normalized = canonicalize_percent_encoded(value)?;
    if normalized.is_empty() || normalized.contains('&') || normalized.contains('=') {
        return Err(RequestTargetError::InvalidQuery);
    }
    Ok(normalized)
}

/// Canonicalizes a query-parameter value used by route matchers.
pub fn canonicalize_query_match_value(value: &str) -> Result<String, RequestTargetError> {
    if value.contains('&') {
        return Err(RequestTargetError::InvalidQuery);
    }
    canonicalize_percent_encoded(value)
}

/// Normalizes a content-type media type used for matching and validation.
#[must_use]
pub fn normalize_content_type_match(value: &str) -> Option<String> {
    let media_type = value.split(';').next()?.trim().to_ascii_lowercase();
    let (type_name, subtype_name) = media_type.split_once('/')?;
    if type_name.is_empty()
        || subtype_name.is_empty()
        || !type_name.chars().all(is_http_token_char)
        || !subtype_name.chars().all(is_http_token_char)
    {
        return None;
    }
    Some(media_type)
}

/// Canonical route-matching inputs shared across HTTP versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatchInput {
    pub target: String,
    pub host: Option<String>,
    pub method: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub source_ip: Option<IpAddr>,
}

/// Canonical route-classification inputs derived from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRouteMatchInput {
    pub path: String,
    pub authority: Option<String>,
    pub method: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub query_pairs: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub grpc_service: Option<String>,
    pub grpc_method: Option<String>,
    pub source_ip: Option<IpAddr>,
}

/// Canonicalizes route-matching inputs once so callers can reuse them.
pub fn canonicalize_route_match_input(
    input: &RouteMatchInput,
) -> Result<CanonicalRouteMatchInput, RequestTargetError> {
    let canonical_target = canonicalize_request_target(&input.target)?;
    let grpc_path = extract_grpc_path_components(&canonical_target.path);
    Ok(CanonicalRouteMatchInput {
        path: canonical_target.path,
        authority: input
            .host
            .as_deref()
            .and_then(|value| canonicalize_host(value).ok())
            .or(canonical_target.authority),
        method: input.method.as_deref().and_then(normalize_http_method),
        headers: input.headers.clone(),
        query_pairs: canonical_target.query_pairs,
        content_type: extract_content_type_match(&input.headers),
        grpc_service: grpc_path.as_ref().map(|(service, _)| service.clone()),
        grpc_method: grpc_path.as_ref().map(|(_, method)| method.clone()),
        source_ip: input.source_ip,
    })
}

/// Resolved route placeholder for a request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch {
    /// Matched route label.
    pub label: String,
    /// Matched path prefix.
    pub prefix: String,
}

/// A normalized HTTP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    /// Header name as emitted on the wire.
    pub name: String,
    /// Header value.
    pub value: String,
}

/// Canonical request-target parts used for cache key construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRequestTarget {
    /// Optional authority extracted from absolute-form request targets.
    pub authority: Option<String>,
    /// Canonical path component.
    pub path: String,
    /// Canonical query pairs sorted for deterministic cache key construction.
    pub query_pairs: Vec<(String, String)>,
}

impl CanonicalRequestTarget {
    /// Serializes the canonical query pairs to stable text.
    #[must_use]
    pub fn canonical_query(&self) -> String {
        self.query_pairs
            .iter()
            .map(
                |(name, value)| {
                    if value.is_empty() {
                        name.clone()
                    } else {
                        format!("{name}={value}")
                    }
                },
            )
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// Stable canonicalization errors for request targets and host key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTargetError {
    /// Request target was empty or used an unsupported form.
    UnsupportedForm,
    /// Absolute-form target declared an empty authority.
    EmptyAuthority,
    /// Fragments are not valid in origin request targets.
    FragmentNotAllowed,
    /// Percent-encoding was malformed.
    InvalidPercentEncoding,
    /// Query shape was ambiguous or malformed.
    InvalidQuery,
    /// Host authority contained invalid whitespace or separators.
    InvalidAuthority,
}

/// Message body framing detected from HTTP/1.1 headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyKind {
    /// No message body is expected.
    None,
    /// A fixed-size body follows.
    ContentLength(u64),
    /// Chunked transfer encoding is used.
    Chunked,
}

/// Parsed HTTP/1.1 request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1RequestHead {
    /// Request method.
    pub method: String,
    /// Request target.
    pub target: String,
    /// HTTP version.
    pub version: SupportedHttpVersion,
    /// Normalized request headers in receive order.
    pub headers: Vec<HttpHeader>,
    /// Request body framing.
    pub body_kind: BodyKind,
    /// Whether the downstream requested keep-alive semantics.
    pub keep_alive: bool,
    /// Placeholder route match for future extensibility.
    pub route: Option<RouteMatch>,
}

/// Parsed HTTP/1.1 response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1ResponseHead {
    /// HTTP version.
    pub version: SupportedHttpVersion,
    /// Numeric status code.
    pub status: u16,
    /// Optional reason phrase.
    pub reason: String,
    /// Normalized response headers in receive order.
    pub headers: Vec<HttpHeader>,
    /// Response body framing.
    pub body_kind: BodyKind,
    /// Whether the upstream requested keep-alive semantics.
    pub keep_alive: bool,
}

/// Stable parsing errors for bounded HTTP/1.1 handling.
#[derive(Debug)]
pub enum Http1ParseError {
    /// I/O failure while reading a head block.
    Io(std::io::Error),
    /// EOF occurred after a partial head was buffered.
    IncompleteHead,
    /// The head block exceeded the configured bound.
    HeadTooLarge,
    /// Too many headers were present for the configured limit.
    TooManyHeaders,
    /// A malformed or unsupported construct was encountered.
    Invalid(&'static str),
}

/// Explicit L7 hardening failures for ambiguous or unsafe HTTP semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolHardeningError {
    /// `content-length` and `transfer-encoding` were both present.
    AmbiguousMessageLength,
    /// Request carried an unsupported `transfer-encoding` chain.
    UnsupportedTransferEncoding,
    /// HTTP/1.1 requests must carry exactly one `host` header.
    MissingHost,
    /// Multiple `host` headers were present.
    MultipleHostHeaders,
}

impl fmt::Display for ProtocolHardeningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousMessageLength => {
                formatter.write_str("ambiguous content-length and transfer-encoding")
            }
            Self::UnsupportedTransferEncoding => {
                formatter.write_str("unsupported transfer-encoding chain")
            }
            Self::MissingHost => formatter.write_str("missing required host header"),
            Self::MultipleHostHeaders => {
                formatter.write_str("multiple host headers are not allowed")
            }
        }
    }
}

impl std::error::Error for ProtocolHardeningError {}

impl fmt::Display for RequestTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedForm => formatter.write_str("unsupported HTTP request-target form"),
            Self::EmptyAuthority => {
                formatter.write_str("absolute-form request-target must include authority")
            }
            Self::FragmentNotAllowed => {
                formatter.write_str("request-target fragments are not allowed")
            }
            Self::InvalidPercentEncoding => {
                formatter.write_str("request-target contains invalid percent-encoding")
            }
            Self::InvalidQuery => {
                formatter.write_str("request-target contains an invalid query shape")
            }
            Self::InvalidAuthority => formatter.write_str("request-target authority is invalid"),
        }
    }
}

impl std::error::Error for RequestTargetError {}

impl fmt::Display for Http1ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "HTTP/1.1 I/O failure: {source}"),
            Self::IncompleteHead => formatter.write_str("incomplete HTTP/1.1 head"),
            Self::HeadTooLarge => formatter.write_str("HTTP/1.1 head exceeded configured limit"),
            Self::TooManyHeaders => {
                formatter.write_str("HTTP/1.1 message exceeded header count limit")
            }
            Self::Invalid(message) => write!(formatter, "invalid HTTP/1.1 message: {message}"),
        }
    }
}

impl std::error::Error for Http1ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            _ => None,
        }
    }
}

/// Reads and parses a bounded HTTP/1.1 request head.
pub async fn read_request_head<R>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    limits: &Http1Limits,
    routes: &[RoutePrefixRule],
) -> Result<Option<Http1RequestHead>, Http1ParseError>
where
    R: AsyncRead + Unpin,
{
    let Some(head_end) = fill_until_head_end(reader, buffer, limits).await? else {
        return Ok(None);
    };

    let mut header_slots = vec![httparse::EMPTY_HEADER; limits.max_header_count];
    let mut request = httparse::Request::new(&mut header_slots);
    let status = request.parse(&buffer[..head_end]).map_err(map_httparse_error)?;
    let consumed = match status {
        httparse::Status::Complete(consumed) => consumed,
        httparse::Status::Partial => return Err(Http1ParseError::IncompleteHead),
    };

    let method =
        request.method.ok_or(Http1ParseError::Invalid("missing request method"))?.to_string();
    let target =
        request.path.ok_or(Http1ParseError::Invalid("missing request target"))?.to_string();
    let version = parse_version(request.version)?;
    let headers = owned_headers(request.headers)?;
    validate_http1_request_hardening(&headers)
        .map_err(|error| Http1ParseError::Invalid(hardening_message(error)))?;
    let body_kind = detect_request_body_kind(&headers)?;
    let keep_alive = detect_keep_alive(&headers, version);
    let route = match_route(&target, extract_host_header(&headers), Some(&method), routes);
    buffer.drain(..consumed);

    Ok(Some(Http1RequestHead { method, target, version, headers, body_kind, keep_alive, route }))
}

/// Reads and parses a bounded HTTP/1.1 response head.
pub async fn read_response_head<R>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    limits: &Http1Limits,
    request_method: &str,
) -> Result<Http1ResponseHead, Http1ParseError>
where
    R: AsyncRead + Unpin,
{
    let head_end = fill_until_head_end(reader, buffer, limits)
        .await?
        .ok_or(Http1ParseError::IncompleteHead)?;

    let mut header_slots = vec![httparse::EMPTY_HEADER; limits.max_header_count];
    let mut response = httparse::Response::new(&mut header_slots);
    let status = response.parse(&buffer[..head_end]).map_err(map_httparse_error)?;
    let consumed = match status {
        httparse::Status::Complete(consumed) => consumed,
        httparse::Status::Partial => return Err(Http1ParseError::IncompleteHead),
    };

    let version = parse_version(response.version)?;
    let status = response.code.ok_or(Http1ParseError::Invalid("missing status code"))?;
    let headers = owned_headers(response.headers)?;
    let body_kind = detect_response_body_kind(&headers, status, request_method)?;
    let keep_alive = detect_keep_alive(&headers, version);
    let reason = response.reason.unwrap_or("").to_string();
    buffer.drain(..consumed);

    Ok(Http1ResponseHead { version, status, reason, headers, body_kind, keep_alive })
}

/// Normalizes request headers for safe forwarding behavior.
#[must_use]
pub fn normalize_request_headers(
    headers: &[HttpHeader],
    client_ip: IpAddr,
    keep_alive: bool,
    body_kind: &BodyKind,
) -> Vec<HttpHeader> {
    let mut normalized = filter_headers(headers, body_kind, false);
    normalized
        .push(HttpHeader { name: String::from("x-forwarded-for"), value: client_ip.to_string() });

    if !keep_alive {
        normalized
            .push(HttpHeader { name: String::from("connection"), value: String::from("close") });
    }

    normalized
}

/// Normalizes response headers for safe forwarding behavior.
#[must_use]
pub fn normalize_response_headers(
    headers: &[HttpHeader],
    keep_alive: bool,
    body_kind: &BodyKind,
) -> Vec<HttpHeader> {
    let mut normalized = filter_headers(headers, body_kind, true);
    if !keep_alive {
        normalized
            .push(HttpHeader { name: String::from("connection"), value: String::from("close") });
    }
    normalized
}

/// Serializes a request head to wire bytes.
#[must_use]
pub fn encode_request_head(
    method: &str,
    target: &str,
    version: SupportedHttpVersion,
    headers: &[HttpHeader],
) -> Vec<u8> {
    let version_text = version_text(version);
    let mut bytes = format!("{method} {target} {version_text}\r\n").into_bytes();
    append_headers(&mut bytes, headers);
    bytes
}

/// Serializes a response head to wire bytes.
#[must_use]
pub fn encode_response_head(
    version: SupportedHttpVersion,
    status: u16,
    reason: &str,
    headers: &[HttpHeader],
) -> Vec<u8> {
    let version_text = version_text(version);
    let reason = if reason.is_empty() { default_reason(status) } else { reason };
    let mut bytes = format!("{version_text} {status} {reason}\r\n").into_bytes();
    append_headers(&mut bytes, headers);
    bytes
}

fn append_headers(bytes: &mut Vec<u8>, headers: &[HttpHeader]) {
    for header in headers {
        bytes.extend_from_slice(header.name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(header.value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
}

async fn fill_until_head_end<R>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    limits: &Http1Limits,
) -> Result<Option<usize>, Http1ParseError>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(position) = find_head_end(buffer) {
            return Ok(Some(position));
        }

        if buffer.len() >= limits.max_head_bytes {
            return Err(Http1ParseError::HeadTooLarge);
        }

        let read_limit = limits.max_head_bytes.saturating_sub(buffer.len()).min(1024);
        let mut chunk = vec![0_u8; read_limit];
        let bytes_read = reader.read(&mut chunk).await.map_err(Http1ParseError::Io)?;
        if bytes_read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(Http1ParseError::IncompleteHead);
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n").map(|index| index + 4)
}

fn parse_version(version: Option<u8>) -> Result<SupportedHttpVersion, Http1ParseError> {
    match version {
        Some(1) => Ok(SupportedHttpVersion::Http1),
        Some(_) => Err(Http1ParseError::Invalid("unsupported HTTP version")),
        None => Err(Http1ParseError::Invalid("missing HTTP version")),
    }
}

fn owned_headers(headers: &[httparse::Header<'_>]) -> Result<Vec<HttpHeader>, Http1ParseError> {
    headers
        .iter()
        .map(|header| {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| Http1ParseError::Invalid("header value is not valid ASCII/UTF-8"))?;
            Ok(HttpHeader {
                name: header.name.to_ascii_lowercase(),
                value: value.trim().to_string(),
            })
        })
        .collect()
}

fn detect_request_body_kind(headers: &[HttpHeader]) -> Result<BodyKind, Http1ParseError> {
    detect_body_kind(headers, false, None)
}

fn detect_response_body_kind(
    headers: &[HttpHeader],
    status: u16,
    request_method: &str,
) -> Result<BodyKind, Http1ParseError> {
    if request_method.eq_ignore_ascii_case("HEAD") || matches!(status, 100..=199 | 204 | 304) {
        return Ok(BodyKind::None);
    }

    detect_body_kind(headers, true, Some(status))
}

fn detect_body_kind(
    headers: &[HttpHeader],
    _is_response: bool,
    _status: Option<u16>,
) -> Result<BodyKind, Http1ParseError> {
    if header_value_contains_token(headers, "transfer-encoding", "chunked") {
        return Ok(BodyKind::Chunked);
    }

    let content_lengths: Vec<&str> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .map(|header| header.value.as_str())
        .collect();
    if content_lengths.is_empty() {
        return Ok(BodyKind::None);
    }

    let first = content_lengths[0].trim();
    for candidate in &content_lengths[1..] {
        if candidate.trim() != first {
            return Err(Http1ParseError::Invalid("conflicting content-length headers"));
        }
    }

    let content_length = first
        .parse::<u64>()
        .map_err(|_| Http1ParseError::Invalid("invalid content-length header"))?;
    if content_length == 0 {
        return Ok(BodyKind::None);
    }

    Ok(BodyKind::ContentLength(content_length))
}

fn detect_keep_alive(headers: &[HttpHeader], version: SupportedHttpVersion) -> bool {
    match version {
        SupportedHttpVersion::Http1 => !header_value_contains_token(headers, "connection", "close"),
        SupportedHttpVersion::Http2 => true,
    }
}

/// Matches a target path against shared route-prefix rules.
#[must_use]
pub fn match_route_prefix(target: &str, rules: &[RoutePrefixRule]) -> Option<RouteMatch> {
    match_route(target, None, None, rules)
}

/// Matches a target path and optional host against shared route-prefix rules.
#[must_use]
pub fn match_route_request(
    target: &str,
    host: Option<&str>,
    rules: &[RoutePrefixRule],
) -> Option<RouteMatch> {
    match_route(target, host, None, rules)
}

/// Matches a target path, optional host, and optional method against shared route-prefix rules.
#[must_use]
pub fn match_route_request_with_method(
    target: &str,
    host: Option<&str>,
    method: Option<&str>,
    rules: &[RoutePrefixRule],
) -> Option<RouteMatch> {
    match_route(target, host, method, rules)
}

/// Matches a request against shared route-prefix rules using all supported canonical criteria.
#[must_use]
pub fn match_route_request_with_context(
    input: &RouteMatchInput,
    rules: &[RoutePrefixRule],
) -> Option<RouteMatch> {
    let canonical_input = canonicalize_route_match_input(input).ok()?;
    match_canonical_route(&canonical_input, rules)
}

/// Returns whether the request should be treated as a gRPC request.
#[must_use]
pub fn is_grpc_request(
    method: &str,
    version: SupportedHttpVersion,
    headers: &[HttpHeader],
) -> bool {
    version == SupportedHttpVersion::Http2
        && method.eq_ignore_ascii_case("POST")
        && headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type") && is_grpc_content_type(&header.value)
        })
}

/// Returns whether a content-type value represents gRPC traffic.
#[must_use]
pub fn is_grpc_content_type(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized == "application/grpc"
        || normalized.starts_with("application/grpc+")
        || normalized.starts_with("application/grpc;")
}

#[must_use]
pub fn extract_grpc_path_components(path: &str) -> Option<(String, String)> {
    let trimmed = path.strip_prefix('/')?;
    let (service, method) = trimmed.split_once('/')?;
    if method.contains('/') {
        return None;
    }

    Some((
        normalize_grpc_service_match(service)?,
        normalize_grpc_method_match(method)?,
    ))
}

/// Enforces explicit HTTP/1.1 hardening rules for ambiguous framing and host handling.
pub fn validate_http1_request_hardening(
    headers: &[HttpHeader],
) -> Result<(), ProtocolHardeningError> {
    let host_count =
        headers.iter().filter(|header| header.name.eq_ignore_ascii_case("host")).count();
    if host_count == 0 {
        return Err(ProtocolHardeningError::MissingHost);
    }
    if host_count > 1 {
        return Err(ProtocolHardeningError::MultipleHostHeaders);
    }

    if headers.iter().any(|header| header.name.eq_ignore_ascii_case("content-length"))
        && headers.iter().any(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(ProtocolHardeningError::AmbiguousMessageLength);
    }

    let transfer_encoding_tokens: Vec<&str> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();
    if !transfer_encoding_tokens.is_empty()
        && transfer_encoding_tokens.iter().any(|token| !token.eq_ignore_ascii_case("chunked"))
    {
        return Err(ProtocolHardeningError::UnsupportedTransferEncoding);
    }

    Ok(())
}

/// Returns the single normalized host header value when present.
#[must_use]
pub fn extract_host_header(headers: &[HttpHeader]) -> Option<&str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.as_str())
}

/// Canonicalizes a host/authority value for cache key material.
pub fn canonicalize_host(value: &str) -> Result<String, RequestTargetError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.contains('/')
        || normalized.contains('@')
        || normalized.contains(',')
        || normalized.chars().any(|character| character.is_ascii_whitespace())
    {
        return Err(RequestTargetError::InvalidAuthority);
    }
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    if normalized.is_empty() {
        return Err(RequestTargetError::InvalidAuthority);
    }
    Ok(normalized.to_string())
}

/// Canonicalizes an origin-form or absolute-form request target.
pub fn canonicalize_request_target(
    target: &str,
) -> Result<CanonicalRequestTarget, RequestTargetError> {
    let target = target.trim();
    if target.is_empty() || target == "*" {
        return Err(RequestTargetError::UnsupportedForm);
    }
    if target.contains('#') {
        return Err(RequestTargetError::FragmentNotAllowed);
    }

    let (authority, path_and_query) = if let Some(scheme_end) = target.find("://") {
        let scheme = &target[..scheme_end];
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(RequestTargetError::UnsupportedForm);
        }
        let remainder = &target[scheme_end + 3..];
        let split_index = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let authority = &remainder[..split_index];
        if authority.trim().is_empty() {
            return Err(RequestTargetError::EmptyAuthority);
        }
        let tail = &remainder[split_index..];
        (
            Some(canonicalize_host(authority)?),
            if tail.is_empty() {
                "/"
            } else if tail.starts_with('?') {
                ""
            } else {
                tail
            },
        )
    } else if target.starts_with('/') {
        (None, target)
    } else {
        return Err(RequestTargetError::UnsupportedForm);
    };

    let (path, query) = split_path_and_query(path_and_query);
    Ok(CanonicalRequestTarget {
        authority,
        path: canonicalize_percent_encoded(path)?,
        query_pairs: canonicalize_query_pairs(query)?,
    })
}

fn match_route(
    target: &str,
    host: Option<&str>,
    method: Option<&str>,
    rules: &[RoutePrefixRule],
) -> Option<RouteMatch> {
    match_route_request_with_context(
        &RouteMatchInput {
            target: target.to_string(),
            host: host.map(String::from),
            method: method.map(String::from),
            headers: Vec::new(),
            source_ip: None,
        },
        rules,
    )
}

fn match_canonical_route(
    input: &CanonicalRouteMatchInput,
    rules: &[RoutePrefixRule],
) -> Option<RouteMatch> {
    let mut best_match: Option<&RoutePrefixRule> = None;
    for rule in rules.iter().filter(|rule| route_rule_matches(rule, input)) {
        let should_replace = best_match
            .map(|matched| rule.specificity_key() > matched.specificity_key())
            .unwrap_or(true);
        if should_replace {
            best_match = Some(rule);
        }
    }

    best_match.map(|rule| RouteMatch { label: rule.label.clone(), prefix: rule.prefix.clone() })
}

fn route_rule_matches(rule: &RoutePrefixRule, input: &CanonicalRouteMatchInput) -> bool {
    input.path.starts_with(&rule.prefix)
        && (rule.hostnames.is_empty()
            || input
                .authority
                .as_deref()
                .is_some_and(|value| rule.hostnames.iter().any(|hostname| hostname == value)))
        && (rule.methods.is_empty()
            || input
                .method
                .as_deref()
                .is_some_and(|value| rule.methods.iter().any(|method| method == value)))
        && rule.header_matches.iter().all(|matcher| header_match_satisfied(matcher, &input.headers))
        && rule.query_matches.iter().all(|matcher| query_match_satisfied(matcher, &input.query_pairs))
        && (rule.content_types.is_empty()
            || input
                .content_type
                .as_deref()
                .is_some_and(|value| {
                    rule.content_types.iter().any(|content_type| {
                        content_type == value
                            || (content_type == "application/grpc" && is_grpc_content_type(value))
                    })
                }))
        && (rule.grpc_services.is_empty()
            || input
                .grpc_service
                .as_deref()
                .is_some_and(|value| rule.grpc_services.iter().any(|service| service == value)))
        && (rule.grpc_methods.is_empty()
            || input
                .grpc_method
                .as_deref()
                .is_some_and(|value| rule.grpc_methods.iter().any(|method| method == value)))
        && (rule.source_cidrs.is_empty()
            || input
                .source_ip
                .map(canonicalize_ip)
                .is_some_and(|ip| rule.source_cidrs.iter().any(|cidr| cidr.contains(&ip))))
}

fn header_match_satisfied(matcher: &RouteHeaderMatch, headers: &[HttpHeader]) -> bool {
    match matcher {
        RouteHeaderMatch::Exact { name, value } => headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case(name) && header.value.trim() == value
        }),
        RouteHeaderMatch::Present { name } => {
            headers.iter().any(|header| header.name.eq_ignore_ascii_case(name))
        }
        RouteHeaderMatch::Absent { name } => {
            !headers.iter().any(|header| header.name.eq_ignore_ascii_case(name))
        }
    }
}

fn query_match_satisfied(matcher: &RouteQueryMatch, query_pairs: &[(String, String)]) -> bool {
    match matcher {
        RouteQueryMatch::Exact { name, value } => {
            query_pairs.iter().any(|(query_name, query_value)| query_name == name && query_value == value)
        }
        RouteQueryMatch::Present { name } => query_pairs.iter().any(|(query_name, _)| query_name == name),
        RouteQueryMatch::Absent { name } => !query_pairs.iter().any(|(query_name, _)| query_name == name),
    }
}

fn extract_content_type_match(headers: &[HttpHeader]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .and_then(|header| normalize_content_type_match(&header.value))
}

fn split_path_and_query(path_and_query: &str) -> (&str, &str) {
    if path_and_query.is_empty() {
        return ("/", "");
    }
    match path_and_query.split_once('?') {
        Some((path, query)) => (if path.is_empty() { "/" } else { path }, query),
        None => (path_and_query, ""),
    }
}

fn is_http_token_char(character: char) -> bool {
    matches!(
        character,
        '!' | '#'
            | '$'
            | '%'
            | '&'
            | '\''
            | '*'
            | '+'
            | '-'
            | '.'
            | '^'
            | '_'
            | '`'
            | '|'
            | '~'
    ) || character.is_ascii_alphanumeric()
}

fn canonicalize_query_pairs(query: &str) -> Result<Vec<(String, String)>, RequestTargetError> {
    if query.is_empty() {
        return Ok(Vec::new());
    }

    let mut pairs = Vec::new();
    for raw_pair in query.split('&') {
        if raw_pair.is_empty() {
            return Err(RequestTargetError::InvalidQuery);
        }
        let (name, value) = raw_pair.split_once('=').unwrap_or((raw_pair, ""));
        pairs.push((canonicalize_percent_encoded(name)?, canonicalize_percent_encoded(value)?));
    }
    pairs.sort();
    Ok(pairs)
}

fn canonicalize_percent_encoded(value: &str) -> Result<String, RequestTargetError> {
    let mut normalized = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(RequestTargetError::InvalidPercentEncoding);
            }
            normalized.push('%');
            normalized.push((bytes[index + 1] as char).to_ascii_uppercase());
            normalized.push((bytes[index + 2] as char).to_ascii_uppercase());
            index += 3;
            continue;
        }
        normalized.push(bytes[index] as char);
        index += 1;
    }
    Ok(normalized)
}

fn filter_headers(
    headers: &[HttpHeader],
    body_kind: &BodyKind,
    is_response: bool,
) -> Vec<HttpHeader> {
    let connection_tokens = connection_tokens(headers);
    headers
        .iter()
        .filter(|header| {
            let name = header.name.as_str();
            if name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("proxy-connection")
                || name.eq_ignore_ascii_case("keep-alive")
                || name.eq_ignore_ascii_case("upgrade")
                || name.eq_ignore_ascii_case("proxy-authenticate")
                || name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case("te")
                || name.eq_ignore_ascii_case("trailer")
                || name.eq_ignore_ascii_case("x-forwarded-for")
                || name.eq_ignore_ascii_case("x-forwarded-proto")
                || connection_tokens.iter().any(|token| token.eq_ignore_ascii_case(name))
            {
                return false;
            }

            if name.eq_ignore_ascii_case("transfer-encoding") {
                return matches!(body_kind, BodyKind::Chunked);
            }

            if name.eq_ignore_ascii_case("content-length") {
                return matches!(body_kind, BodyKind::ContentLength(_));
            }

            if is_response && name.eq_ignore_ascii_case("server") {
                return true;
            }

            true
        })
        .cloned()
        .collect()
}

fn connection_tokens(headers: &[HttpHeader]) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn header_value_contains_token(headers: &[HttpHeader], header_name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(header_name))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .any(|candidate| candidate.eq_ignore_ascii_case(token))
}

fn map_httparse_error(error: httparse::Error) -> Http1ParseError {
    match error {
        httparse::Error::TooManyHeaders => Http1ParseError::TooManyHeaders,
        httparse::Error::Version
        | httparse::Error::Status
        | httparse::Error::Token
        | httparse::Error::NewLine
        | httparse::Error::HeaderName
        | httparse::Error::HeaderValue => Http1ParseError::Invalid("malformed HTTP/1.1 head"),
    }
}

const fn hardening_message(error: ProtocolHardeningError) -> &'static str {
    match error {
        ProtocolHardeningError::AmbiguousMessageLength => {
            "ambiguous content-length and transfer-encoding"
        }
        ProtocolHardeningError::UnsupportedTransferEncoding => {
            "unsupported transfer-encoding chain"
        }
        ProtocolHardeningError::MissingHost => "missing required host header",
        ProtocolHardeningError::MultipleHostHeaders => "multiple host headers are not allowed",
    }
}

fn version_text(version: SupportedHttpVersion) -> &'static str {
    match version {
        SupportedHttpVersion::Http1 => "HTTP/1.1",
        SupportedHttpVersion::Http2 => "HTTP/2",
    }
}

fn default_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonicalize_host, canonicalize_request_target, encode_request_head, is_grpc_content_type,
        is_grpc_request, match_route_prefix, match_route_request, match_route_request_with_context,
        match_route_request_with_method, normalize_content_type_match, normalize_http_header_name,
        normalize_http_method, normalize_request_headers, validate_http1_request_hardening,
        BodyKind, Http1Limits, Http2Limits, HttpHeader, ProtocolHardeningError,
        RequestTargetError, RouteHeaderMatch, RouteMatchInput, RoutePrefixRule, RouteQueryMatch,
        SupportedHttpVersion, canonicalize_query_match_name, canonicalize_query_match_value,
    };

    #[test]
    fn route_prefix_matching_uses_path_prefix() {
        let routes = vec![RoutePrefixRule::new("api", "/api")];

        let matched = match_route_prefix("/api/v1/items?limit=1", &routes);

        assert_eq!(matched.map(|route| route.label), Some(String::from("api")));
    }

    #[test]
    fn route_matching_can_filter_by_host() {
        let routes =
            vec![RoutePrefixRule::new("api", "/api")
                .with_hostnames(vec![String::from("example.com")])];

        let matched = match_route_request("/api/v1/items?limit=1", Some("Example.COM"), &routes);
        let rejected = match_route_request("/api/v1/items?limit=1", Some("other.example"), &routes);

        assert_eq!(matched.map(|route| route.label), Some(String::from("api")));
        assert_eq!(rejected, None);
    }

    #[test]
    fn route_matching_can_filter_by_method() {
        let routes = vec![RoutePrefixRule::new("writes", "/api")
            .with_methods(vec![String::from("post")])];

        let matched = match_route_request_with_method("/api/v1/items", None, Some("POST"), &routes);
        let rejected =
            match_route_request_with_method("/api/v1/items", None, Some("GET"), &routes);

        assert_eq!(matched.map(|route| route.label), Some(String::from("writes")));
        assert_eq!(rejected, None);
    }

    #[test]
    fn route_matching_prefers_most_specific_prefix() {
        let routes =
            vec![RoutePrefixRule::new("catch-all", "/"), RoutePrefixRule::new("api", "/api")];

        let matched = match_route_prefix("/api/v1/items?limit=1", &routes);

        assert_eq!(matched.map(|route| route.label), Some(String::from("api")));
    }

    #[test]
    fn route_matching_prefers_host_specific_rule_for_equal_prefix() {
        let routes = vec![
            RoutePrefixRule::new("generic-api", "/api"),
            RoutePrefixRule::new("tenant-api", "/api")
                .with_hostnames(vec![String::from("example.com")]),
        ];

        let matched = match_route_request("/api/v1/items", Some("example.com"), &routes);

        assert_eq!(matched.map(|route| route.label), Some(String::from("tenant-api")));
    }

    #[test]
    fn route_matching_prefers_method_specific_rule_for_equal_prefix() {
        let routes = vec![
            RoutePrefixRule::new("generic-api", "/api"),
            RoutePrefixRule::new("writes", "/api").with_methods(vec![String::from("POST")]),
        ];

        let matched = match_route_request_with_method("/api/v1/items", None, Some("POST"), &routes);

        assert_eq!(matched.map(|route| route.label), Some(String::from("writes")));
    }

    #[test]
    fn normalize_http_method_rejects_invalid_tokens() {
        assert_eq!(normalize_http_method("get"), Some(String::from("GET")));
        assert_eq!(normalize_http_method(""), None);
        assert_eq!(normalize_http_method("bad token"), None);
    }

    #[test]
    fn normalize_http_header_name_rejects_invalid_tokens() {
        assert_eq!(normalize_http_header_name("X-Test"), Some(String::from("x-test")));
        assert_eq!(normalize_http_header_name("bad header"), None);
    }

    #[test]
    fn canonicalize_query_match_components_validate_shape() {
        assert_eq!(canonicalize_query_match_name("auth"), Ok(String::from("auth")));
        assert_eq!(canonicalize_query_match_value("user%2Falpha"), Ok(String::from("user%2Falpha")));
        assert!(canonicalize_query_match_name("").is_err());
        assert!(canonicalize_query_match_name("a=b").is_err());
    }

    #[test]
    fn normalize_content_type_match_extracts_media_type() {
        assert_eq!(
            normalize_content_type_match("Application/JSON; charset=utf-8"),
            Some(String::from("application/json"))
        );
        assert_eq!(normalize_content_type_match("broken"), None);
    }

    #[test]
    fn route_matching_uses_absolute_form_authority_and_path() {
        let routes =
            vec![RoutePrefixRule::new("api", "/api")
                .with_hostnames(vec![String::from("example.com")])];

        let matched = match_route_request("http://Example.com/api?q=1", None, &routes);

        assert_eq!(matched.map(|route| route.label), Some(String::from("api")));
    }

    #[test]
    fn route_matching_can_filter_by_headers_query_content_type_and_source() {
        let route = RoutePrefixRule::new("api", "/api")
            .with_header_matches(vec![RouteHeaderMatch::Exact {
                name: String::from("x-tenant"),
                value: String::from("beta"),
            }])
            .with_query_matches(vec![RouteQueryMatch::Exact {
                name: String::from("auth"),
                value: String::from("user"),
            }])
            .with_content_types(vec![String::from("application/json")])
            .with_source_cidrs(vec!["198.51.100.0/24".parse().expect("cidr")]);

        let matched = match_route_request_with_context(
            &RouteMatchInput {
                target: String::from("/api?auth=user"),
                host: Some(String::from("example.com")),
                method: Some(String::from("POST")),
                headers: vec![
                    HttpHeader { name: String::from("x-tenant"), value: String::from("beta") },
                    HttpHeader {
                        name: String::from("content-type"),
                        value: String::from("application/json; charset=utf-8"),
                    },
                ],
                source_ip: Some("198.51.100.7".parse().expect("ip")),
            },
            &[route],
        );

        assert_eq!(matched.map(|route| route.label), Some(String::from("api")));
    }

    #[test]
    fn route_matching_rejects_missing_header_query_or_source_constraints() {
        let route = RoutePrefixRule::new("api", "/api")
            .with_header_matches(vec![RouteHeaderMatch::Present { name: String::from("x-tenant") }])
            .with_query_matches(vec![RouteQueryMatch::Present { name: String::from("auth") }])
            .with_source_cidrs(vec!["198.51.100.0/24".parse().expect("cidr")]);

        let rejected = match_route_request_with_context(
            &RouteMatchInput {
                target: String::from("/api"),
                host: None,
                method: Some(String::from("GET")),
                headers: Vec::new(),
                source_ip: Some("203.0.113.7".parse().expect("ip")),
            },
            &[route],
        );

        assert_eq!(rejected, None);
    }

    #[test]
    fn route_matching_accepts_ipv4_mapped_ipv6_for_ipv4_source_cidrs() {
        let route = RoutePrefixRule::new("api", "/api")
            .with_source_cidrs(vec!["198.51.100.0/24".parse().expect("cidr")]);

        let matched = match_route_request_with_context(
            &RouteMatchInput {
                target: String::from("/api"),
                host: None,
                method: Some(String::from("GET")),
                headers: Vec::new(),
                source_ip: Some("::ffff:198.51.100.7".parse().expect("mapped ip")),
            },
            &[route],
        );

        assert_eq!(matched.map(|route| route.label), Some(String::from("api")));
    }

    #[test]
    fn request_normalization_strips_hop_by_hop_headers() -> Result<(), Box<dyn std::error::Error>> {
        let headers = vec![
            HttpHeader { name: String::from("host"), value: String::from("example.com") },
            HttpHeader {
                name: String::from("connection"),
                value: String::from("keep-alive, x-extra"),
            },
            HttpHeader { name: String::from("x-extra"), value: String::from("remove-me") },
        ];
        let normalized =
            normalize_request_headers(&headers, "127.0.0.1".parse()?, true, &BodyKind::None);

        assert_eq!(normalized.len(), 2);
        assert!(normalized.iter().any(|header| header.name == "host"));
        assert!(normalized.iter().any(|header| header.name == "x-forwarded-for"));
        Ok(())
    }

    #[test]
    fn request_normalization_strips_framing_and_forwarding_override_headers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let headers = vec![
            HttpHeader { name: String::from("host"), value: String::from("example.com") },
            HttpHeader { name: String::from("transfer-encoding"), value: String::from("chunked") },
            HttpHeader { name: String::from("te"), value: String::from("trailers") },
            HttpHeader { name: String::from("trailer"), value: String::from("x-checksum") },
            HttpHeader {
                name: String::from("x-forwarded-for"),
                value: String::from("198.51.100.7"),
            },
        ];
        let normalized =
            normalize_request_headers(&headers, "127.0.0.1".parse()?, true, &BodyKind::Chunked);

        assert!(normalized.iter().any(|header| header.name == "host"));
        assert_eq!(
            normalized
                .iter()
                .filter(|header| header.name == "transfer-encoding")
                .map(|header| header.value.as_str())
                .collect::<Vec<_>>(),
            vec!["chunked"]
        );
        assert!(!normalized.iter().any(|header| header.name == "te"));
        assert!(!normalized.iter().any(|header| header.name == "trailer"));
        assert_eq!(
            normalized
                .iter()
                .filter(|header| header.name == "x-forwarded-for")
                .map(|header| header.value.as_str())
                .collect::<Vec<_>>(),
            vec!["127.0.0.1"]
        );
        Ok(())
    }

    #[test]
    fn request_head_encoding_is_http11() {
        let bytes = encode_request_head("GET", "/", SupportedHttpVersion::Http1, &[]);

        assert_eq!(bytes, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn default_limits_are_bounded() {
        let limits = Http1Limits::default();

        assert!(limits.max_head_bytes >= 4096);
        assert!(limits.max_header_count >= 16);
        assert!(limits.max_body_bytes >= 1024);
    }

    #[test]
    fn default_http2_limits_are_bounded() {
        let limits = Http2Limits::default();

        assert!(limits.max_concurrent_streams >= 16);
        assert!(limits.max_body_bytes >= 1024);
    }

    #[test]
    fn hardening_rejects_ambiguous_message_framing() {
        let headers = vec![
            HttpHeader { name: String::from("host"), value: String::from("example.test") },
            HttpHeader { name: String::from("content-length"), value: String::from("5") },
            HttpHeader { name: String::from("transfer-encoding"), value: String::from("chunked") },
        ];

        let result = validate_http1_request_hardening(&headers);

        assert_eq!(result, Err(ProtocolHardeningError::AmbiguousMessageLength));
    }

    #[test]
    fn hardening_rejects_unsupported_transfer_encoding_chain() {
        let headers = vec![
            HttpHeader { name: String::from("host"), value: String::from("example.test") },
            HttpHeader {
                name: String::from("transfer-encoding"),
                value: String::from("gzip, chunked"),
            },
        ];

        let result = validate_http1_request_hardening(&headers);

        assert_eq!(result, Err(ProtocolHardeningError::UnsupportedTransferEncoding));
    }

    #[test]
    fn hardening_allows_chunked_transfer_encoding_chain_only() {
        let headers = vec![
            HttpHeader { name: String::from("host"), value: String::from("example.test") },
            HttpHeader { name: String::from("transfer-encoding"), value: String::from("chunked") },
        ];

        let result = validate_http1_request_hardening(&headers);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn grpc_detection_requires_http2_post_and_grpc_content_type() {
        let headers = vec![HttpHeader {
            name: String::from("content-type"),
            value: String::from("application/grpc+proto"),
        }];

        assert!(is_grpc_request("POST", SupportedHttpVersion::Http2, &headers));
        assert!(is_grpc_content_type("application/grpc; charset=utf-8"));
    }

    #[test]
    fn grpc_route_matching_uses_service_and_method_filters() {
        let route = RoutePrefixRule::new("grpc", "/")
            .with_methods(vec![String::from("POST")])
            .with_content_types(vec![String::from("application/grpc")])
            .with_grpc_services(vec![String::from("grpc.payments.v1.Payments")])
            .with_grpc_methods(vec![String::from("Capture")]);

        let matched = match_route_request_with_context(
            &RouteMatchInput {
                target: String::from("/grpc.payments.v1.Payments/Capture"),
                host: None,
                method: Some(String::from("POST")),
                headers: vec![HttpHeader {
                    name: String::from("content-type"),
                    value: String::from("application/grpc+proto"),
                }],
                source_ip: None,
            },
            &[route],
        );

        assert_eq!(matched.map(|value| value.label), Some(String::from("grpc")));
    }

    #[test]
    fn request_target_canonicalization_sorts_query_and_normalizes_percent_encoding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let canonical = canonicalize_request_target("/items?b=%2f&a=2&a=1")?;

        assert_eq!(canonical.path, "/items");
        assert_eq!(canonical.canonical_query(), "a=1&a=2&b=%2F");
        Ok(())
    }

    #[test]
    fn absolute_form_request_target_extracts_authority() -> Result<(), Box<dyn std::error::Error>> {
        let canonical = canonicalize_request_target("http://Example.TEST/api?q=1")?;

        assert_eq!(canonical.authority.as_deref(), Some("example.test"));
        assert_eq!(canonical.path, "/api");
        assert_eq!(canonical.canonical_query(), "q=1");
        Ok(())
    }

    #[test]
    fn canonicalization_rejects_ambiguous_shapes() {
        assert_eq!(
            canonicalize_request_target("/items?x=1&&y=2"),
            Err(RequestTargetError::InvalidQuery)
        );
        assert_eq!(
            canonicalize_request_target("/items?x=%zz"),
            Err(RequestTargetError::InvalidPercentEncoding)
        );
        assert_eq!(canonicalize_host("bad/host"), Err(RequestTargetError::InvalidAuthority));
        assert_eq!(canonicalize_host("bad host"), Err(RequestTargetError::InvalidAuthority));
    }
}
