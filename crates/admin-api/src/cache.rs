use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    HttpCacheInvalidationDeliveryMode, HttpCachePeerConfig, HttpCachePeerTransport,
    InvalidHttpCachePeerConfig,
};

const MAX_SCOPE_LEN: usize = lb_runtime::HTTP_CACHE_INVALIDATION_MAX_SCOPE_LEN;
const MAX_ACTOR_LEN: usize = 128;
const MAX_REASON_LEN: usize = 256;
const MAX_PATH_PREFIX_LEN: usize = lb_runtime::HTTP_CACHE_INVALIDATION_MAX_PATH_PREFIX_LEN;
const MAX_HISTORY: usize = 64;

static NEXT_INVALIDATION_EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpCachePurgeTarget {
    ExactKey(lb_runtime::HttpCacheKey),
    PathPrefix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCachePurgeRequest {
    pub target: HttpCachePurgeTarget,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpCachePurgeActionKind {
    ExactKey,
    PathPrefix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpCachePurgeResultKind {
    Purged,
    NoMatch,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCachePurgeHistoryEntry {
    pub action: HttpCachePurgeActionKind,
    pub result: HttpCachePurgeResultKind,
    pub scope: String,
    pub actor: Option<String>,
    pub reason: Option<String>,
    pub purged_entries: usize,
    pub fanout_transport: Option<String>,
    pub fanout_subscriber_count: usize,
    pub fanout_delivery_success_count: usize,
    pub fanout_delivery_failure_count: usize,
    pub fanout_duplicate_count: usize,
    pub fanout_failed_targets: Vec<String>,
    pub degraded: bool,
    pub occurred_at_unix_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HttpCacheAdminMetrics {
    pub successful_purge_count: u64,
    pub no_match_purge_count: u64,
    pub rejected_purge_count: u64,
    pub purged_entry_count: u64,
    pub degraded_fanout_count: u64,
    pub audit_event_count: u64,
    pub history_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCachePurgeResponse {
    pub action: HttpCachePurgeActionKind,
    pub result: HttpCachePurgeResultKind,
    pub scope: String,
    pub purged_entries: usize,
    pub fanout_transport: Option<String>,
    pub fanout_subscriber_count: usize,
    pub fanout_delivery_success_count: usize,
    pub fanout_delivery_failure_count: usize,
    pub fanout_duplicate_count: usize,
    pub fanout_failed_targets: Vec<String>,
    pub degraded: bool,
    pub invalidation_event_id: Option<String>,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone)]
struct DistributedInvalidationConfig {
    node_id: String,
    transport: Arc<dyn lb_runtime::HttpCacheInvalidationTransport>,
    delivery_mode: HttpCacheInvalidationDeliveryMode,
}

impl std::fmt::Debug for DistributedInvalidationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DistributedInvalidationConfig")
            .field("node_id", &self.node_id)
            .field("transport", &self.transport.name())
            .field("delivery_mode", &self.delivery_mode)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidHttpCachePurgeRequest {
    EmptyScope,
    ScopeTooLong,
    EmptyRequestedBy,
    RequestedByTooLong,
    EmptyReason,
    ReasonTooLong,
    EmptyPathPrefix,
    PathPrefixTooLong,
    PathPrefixMustStartWithSlash,
    PathPrefixMustNotContainQuery,
}

impl std::fmt::Display for InvalidHttpCachePurgeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyScope => formatter.write_str("cache scope must not be empty"),
            Self::ScopeTooLong => formatter.write_str("cache scope exceeds max length"),
            Self::EmptyRequestedBy => formatter.write_str("requested_by must not be empty"),
            Self::RequestedByTooLong => formatter.write_str("requested_by exceeds max length"),
            Self::EmptyReason => formatter.write_str("reason must not be empty"),
            Self::ReasonTooLong => formatter.write_str("reason exceeds max length"),
            Self::EmptyPathPrefix => formatter.write_str("path prefix must not be empty"),
            Self::PathPrefixTooLong => formatter.write_str("path prefix exceeds max length"),
            Self::PathPrefixMustStartWithSlash => {
                formatter.write_str("path prefix must start with '/'")
            }
            Self::PathPrefixMustNotContainQuery => {
                formatter.write_str("path prefix must not include query or fragment delimiters")
            }
        }
    }
}

impl std::error::Error for InvalidHttpCachePurgeRequest {}

#[derive(Debug)]
pub enum HttpCachePurgeError {
    InvalidRequest(InvalidHttpCachePurgeRequest),
    InvalidPeerConfig(InvalidHttpCachePeerConfig),
    PurgeDisabled,
    Invalidation(lb_runtime::HttpCacheInvalidationTransportError),
    Internal(SystemTimeError),
}

impl std::fmt::Display for HttpCachePurgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(error) => {
                write!(formatter, "invalid cache purge request: {error}")
            }
            Self::InvalidPeerConfig(error) => {
                write!(formatter, "invalid cache peer config: {error}")
            }
            Self::PurgeDisabled => {
                formatter.write_str("cache purge API is disabled for this cache")
            }
            Self::Invalidation(error) => {
                write!(formatter, "cache distributed invalidation failed: {error}")
            }
            Self::Internal(error) => {
                write!(formatter, "cache purge operation failed internally: {error}")
            }
        }
    }
}

impl std::error::Error for HttpCachePurgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRequest(error) => Some(error),
            Self::InvalidPeerConfig(error) => Some(error),
            Self::Invalidation(error) => Some(error),
            Self::Internal(error) => Some(error),
            Self::PurgeDisabled => None,
        }
    }
}

#[derive(Debug)]
pub struct SystemTimeError(std::time::SystemTimeError);

impl std::fmt::Display for SystemTimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "failed to read system time: {}", self.0)
    }
}

impl std::error::Error for SystemTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug)]
pub struct HttpCacheAdminService {
    scope: String,
    purge_enabled: bool,
    store: Arc<lb_runtime::HttpCacheStore>,
    distributed_invalidation: Option<DistributedInvalidationConfig>,
    history: Vec<HttpCachePurgeHistoryEntry>,
    metrics: HttpCacheAdminMetrics,
}

impl HttpCacheAdminService {
    #[must_use]
    pub fn new(
        scope: impl Into<String>,
        purge_enabled: bool,
        store: Arc<lb_runtime::HttpCacheStore>,
    ) -> Self {
        Self {
            scope: scope.into(),
            purge_enabled,
            store,
            distributed_invalidation: None,
            history: Vec::new(),
            metrics: HttpCacheAdminMetrics::default(),
        }
    }

    #[must_use]
    pub fn with_invalidation_bus(
        mut self,
        node_id: impl Into<String>,
        bus: Arc<lb_runtime::HttpCacheInvalidationBus>,
    ) -> Self {
        self.distributed_invalidation = Some(DistributedInvalidationConfig {
            node_id: node_id.into(),
            transport: Arc::new(lb_runtime::HttpCacheInvalidationBusTransport::new(bus)),
            delivery_mode: HttpCacheInvalidationDeliveryMode::BestEffort,
        });
        self
    }

    #[must_use]
    pub fn with_invalidation_transport(
        mut self,
        node_id: impl Into<String>,
        transport: Arc<dyn lb_runtime::HttpCacheInvalidationTransport>,
        delivery_mode: HttpCacheInvalidationDeliveryMode,
    ) -> Self {
        self.distributed_invalidation = Some(DistributedInvalidationConfig {
            node_id: node_id.into(),
            transport,
            delivery_mode,
        });
        self
    }

    pub fn with_http_peer_transport(
        self,
        node_id: impl Into<String>,
        peers: impl IntoIterator<Item = HttpCachePeerConfig>,
    ) -> Result<Self, HttpCachePurgeError> {
        let transport =
            HttpCachePeerTransport::new(peers).map_err(HttpCachePurgeError::InvalidPeerConfig)?;
        Ok(self.with_invalidation_transport(
            node_id,
            Arc::new(transport),
            HttpCacheInvalidationDeliveryMode::BestEffort,
        ))
    }

    pub fn purge(
        &mut self,
        request: HttpCachePurgeRequest,
        telemetry: Option<&lb_runtime::RuntimeTelemetry>,
    ) -> Result<HttpCachePurgeResponse, HttpCachePurgeError> {
        validate_scope(&self.scope).map_err(HttpCachePurgeError::InvalidRequest)?;
        validate_actor_reason(request.requested_by.as_deref(), request.reason.as_deref())
            .map_err(HttpCachePurgeError::InvalidRequest)?;
        let occurred_at_unix_ms = current_unix_ms().map_err(HttpCachePurgeError::Internal)?;
        let (action, detail_target) = target_descriptor(&request.target);

        if !self.purge_enabled {
            self.metrics.rejected_purge_count = self.metrics.rejected_purge_count.saturating_add(1);
            self.push_history(HttpCachePurgeHistoryEntry {
                action,
                result: HttpCachePurgeResultKind::Rejected,
                scope: self.scope.clone(),
                actor: request.requested_by,
                reason: request.reason,
                purged_entries: 0,
                fanout_transport: None,
                fanout_subscriber_count: 0,
                fanout_delivery_success_count: 0,
                fanout_delivery_failure_count: 0,
                fanout_duplicate_count: 0,
                fanout_failed_targets: Vec::new(),
                degraded: false,
                occurred_at_unix_ms,
                detail: String::from("cache purge API is disabled"),
            });
            record_purge_telemetry(telemetry, &self.scope, "rejected", 0);
            return Err(HttpCachePurgeError::PurgeDisabled);
        }

        let (
            purged_entries,
            fanout_transport,
            fanout_subscriber_count,
            fanout_delivery_success_count,
            fanout_delivery_failure_count,
            fanout_duplicate_count,
            fanout_failed_targets,
            invalidation_event_id,
        ) = if let Some(distributed) = &self.distributed_invalidation {
            let event = lb_runtime::HttpCacheInvalidationEvent::new(
                next_invalidation_event_id(&distributed.node_id, occurred_at_unix_ms),
                self.scope.clone(),
                distributed.node_id.clone(),
                purge_target_to_invalidation_target(&request.target)
                    .map_err(HttpCachePurgeError::InvalidRequest)?,
                occurred_at_unix_ms,
            )
            .map_err(map_event_validation_error)?;
            let local_apply =
                self.store.apply_invalidation_event(&event).map_err(map_event_validation_error)?;
            let publish = distributed.transport.publish(&event).map_err(map_transport_error)?;
            let local_purged_entries = match local_apply {
                lb_runtime::HttpCacheInvalidationApplyResult::Applied { purged_entries } => {
                    purged_entries
                }
                lb_runtime::HttpCacheInvalidationApplyResult::Duplicate => 0,
            };
            (
                local_purged_entries + publish.purged_entries,
                Some(String::from(distributed.transport.name())),
                publish.subscriber_count,
                publish.delivery_success_count,
                publish.delivery_failure_count,
                publish.duplicate_count,
                publish.failed_targets,
                Some(event.event_id),
            )
        } else {
            let purged_entries = match &request.target {
                HttpCachePurgeTarget::ExactKey(key) => {
                    usize::from(self.store.remove(key).is_some())
                }
                HttpCachePurgeTarget::PathPrefix(prefix) => {
                    validate_path_prefix(prefix).map_err(HttpCachePurgeError::InvalidRequest)?;
                    self.store.purge_path_prefix(prefix)
                }
            };
            (purged_entries, None, 0, 0, 0, 0, Vec::new(), None)
        };
        let degraded = fanout_delivery_failure_count > 0;
        let result = if purged_entries == 0 {
            self.metrics.no_match_purge_count = self.metrics.no_match_purge_count.saturating_add(1);
            HttpCachePurgeResultKind::NoMatch
        } else {
            self.metrics.successful_purge_count =
                self.metrics.successful_purge_count.saturating_add(1);
            self.metrics.purged_entry_count =
                self.metrics.purged_entry_count.saturating_add(purged_entries as u64);
            HttpCachePurgeResultKind::Purged
        };
        if degraded {
            self.metrics.degraded_fanout_count =
                self.metrics.degraded_fanout_count.saturating_add(1);
        }

        record_purge_telemetry(
            telemetry,
            &self.scope,
            match result {
                HttpCachePurgeResultKind::Purged => "purged",
                HttpCachePurgeResultKind::NoMatch => "no_match",
                HttpCachePurgeResultKind::Rejected => "rejected",
            },
            purged_entries,
        );
        record_delivery_telemetry(
            telemetry,
            &self.scope,
            fanout_transport.as_deref(),
            fanout_delivery_success_count,
            fanout_duplicate_count,
            fanout_delivery_failure_count,
        );
        self.push_history(HttpCachePurgeHistoryEntry {
            action,
            result,
            scope: self.scope.clone(),
            actor: request.requested_by,
            reason: request.reason,
            purged_entries,
            fanout_transport: fanout_transport.clone(),
            fanout_subscriber_count,
            fanout_delivery_success_count,
            fanout_delivery_failure_count,
            fanout_duplicate_count,
            fanout_failed_targets: fanout_failed_targets.clone(),
            degraded,
            occurred_at_unix_ms,
            detail: format!(
                "purged {purged_entries} entries for {detail_target}; fanout transport={}, success={}, duplicate={}, failed={}",
                fanout_transport.as_deref().unwrap_or("local_only"),
                fanout_delivery_success_count,
                fanout_duplicate_count,
                fanout_delivery_failure_count,
            ),
        });

        Ok(HttpCachePurgeResponse {
            action,
            result,
            scope: self.scope.clone(),
            purged_entries,
            fanout_transport,
            fanout_subscriber_count,
            fanout_delivery_success_count,
            fanout_delivery_failure_count,
            fanout_duplicate_count,
            fanout_failed_targets,
            degraded,
            invalidation_event_id,
            occurred_at_unix_ms,
        })
    }

    #[must_use]
    pub fn metrics(&self) -> HttpCacheAdminMetrics {
        self.metrics
    }

    #[must_use]
    pub fn history(&self) -> &[HttpCachePurgeHistoryEntry] {
        &self.history
    }

    fn push_history(&mut self, entry: HttpCachePurgeHistoryEntry) {
        if self.history.len() == MAX_HISTORY {
            let _ = self.history.remove(0);
        }
        self.history.push(entry);
        self.metrics.audit_event_count = self.metrics.audit_event_count.saturating_add(1);
        self.metrics.history_size = self.history.len();
    }
}

fn validate_scope(scope: &str) -> Result<(), InvalidHttpCachePurgeRequest> {
    if scope.trim().is_empty() {
        return Err(InvalidHttpCachePurgeRequest::EmptyScope);
    }
    if scope.len() > MAX_SCOPE_LEN {
        return Err(InvalidHttpCachePurgeRequest::ScopeTooLong);
    }
    Ok(())
}

fn validate_actor_reason(
    requested_by: Option<&str>,
    reason: Option<&str>,
) -> Result<(), InvalidHttpCachePurgeRequest> {
    if let Some(requested_by) = requested_by {
        if requested_by.trim().is_empty() {
            return Err(InvalidHttpCachePurgeRequest::EmptyRequestedBy);
        }
        if requested_by.len() > MAX_ACTOR_LEN {
            return Err(InvalidHttpCachePurgeRequest::RequestedByTooLong);
        }
    }
    if let Some(reason) = reason {
        if reason.trim().is_empty() {
            return Err(InvalidHttpCachePurgeRequest::EmptyReason);
        }
        if reason.len() > MAX_REASON_LEN {
            return Err(InvalidHttpCachePurgeRequest::ReasonTooLong);
        }
    }
    Ok(())
}

fn validate_path_prefix(prefix: &str) -> Result<(), InvalidHttpCachePurgeRequest> {
    if prefix.trim().is_empty() {
        return Err(InvalidHttpCachePurgeRequest::EmptyPathPrefix);
    }
    if prefix.len() > MAX_PATH_PREFIX_LEN {
        return Err(InvalidHttpCachePurgeRequest::PathPrefixTooLong);
    }
    if !prefix.starts_with('/') {
        return Err(InvalidHttpCachePurgeRequest::PathPrefixMustStartWithSlash);
    }
    if prefix.contains('?') || prefix.contains('#') {
        return Err(InvalidHttpCachePurgeRequest::PathPrefixMustNotContainQuery);
    }
    Ok(())
}

fn purge_target_to_invalidation_target(
    target: &HttpCachePurgeTarget,
) -> Result<lb_runtime::HttpCacheInvalidationTarget, InvalidHttpCachePurgeRequest> {
    match target {
        HttpCachePurgeTarget::ExactKey(key) => {
            Ok(lb_runtime::HttpCacheInvalidationTarget::ExactKey(key.clone()))
        }
        HttpCachePurgeTarget::PathPrefix(prefix) => {
            validate_path_prefix(prefix)?;
            Ok(lb_runtime::HttpCacheInvalidationTarget::PathPrefix(prefix.clone()))
        }
    }
}

fn map_event_validation_error(
    error: lb_runtime::HttpCacheInvalidationError,
) -> HttpCachePurgeError {
    match error {
        lb_runtime::HttpCacheInvalidationError::EmptyScope => {
            HttpCachePurgeError::InvalidRequest(InvalidHttpCachePurgeRequest::EmptyScope)
        }
        lb_runtime::HttpCacheInvalidationError::ScopeTooLong => {
            HttpCachePurgeError::InvalidRequest(InvalidHttpCachePurgeRequest::ScopeTooLong)
        }
        other => HttpCachePurgeError::Invalidation(
            lb_runtime::HttpCacheInvalidationTransportError::InvalidEvent(other),
        ),
    }
}

fn map_transport_error(
    error: lb_runtime::HttpCacheInvalidationTransportError,
) -> HttpCachePurgeError {
    match error {
        lb_runtime::HttpCacheInvalidationTransportError::InvalidEvent(
            lb_runtime::HttpCacheInvalidationError::EmptyScope,
        ) => HttpCachePurgeError::InvalidRequest(InvalidHttpCachePurgeRequest::EmptyScope),
        lb_runtime::HttpCacheInvalidationTransportError::InvalidEvent(
            lb_runtime::HttpCacheInvalidationError::ScopeTooLong,
        ) => HttpCachePurgeError::InvalidRequest(InvalidHttpCachePurgeRequest::ScopeTooLong),
        other => HttpCachePurgeError::Invalidation(other),
    }
}

fn record_purge_telemetry(
    telemetry: Option<&lb_runtime::RuntimeTelemetry>,
    scope: &str,
    result: &str,
    purged_entries: usize,
) {
    if let Some(telemetry) = telemetry {
        let _ = telemetry.record_http_cache_purge(scope, result, purged_entries);
    }
}

fn record_delivery_telemetry(
    telemetry: Option<&lb_runtime::RuntimeTelemetry>,
    scope: &str,
    transport: Option<&str>,
    success_count: usize,
    duplicate_count: usize,
    failure_count: usize,
) {
    let Some(telemetry) = telemetry else {
        return;
    };
    let Some(transport) = transport else {
        return;
    };
    if success_count > 0 {
        let _ = telemetry.record_http_cache_invalidation_delivery(
            scope,
            transport,
            "success",
            success_count,
        );
    }
    if duplicate_count > 0 {
        let _ = telemetry.record_http_cache_invalidation_delivery(
            scope,
            transport,
            "duplicate",
            duplicate_count,
        );
    }
    if failure_count > 0 {
        let _ = telemetry.record_http_cache_invalidation_delivery(
            scope,
            transport,
            "failed",
            failure_count,
        );
    }
}

fn target_descriptor(target: &HttpCachePurgeTarget) -> (HttpCachePurgeActionKind, String) {
    match target {
        HttpCachePurgeTarget::ExactKey(key) => (
            HttpCachePurgeActionKind::ExactKey,
            format!("exact key {} bytes", key.as_bytes().len()),
        ),
        HttpCachePurgeTarget::PathPrefix(prefix) => {
            (HttpCachePurgeActionKind::PathPrefix, format!("path prefix {prefix}"))
        }
    }
}

fn current_unix_ms() -> Result<u64, SystemTimeError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(SystemTimeError)?;
    Ok(duration.as_millis().min(u128::from(u64::MAX)) as u64)
}

fn next_invalidation_event_id(node_id: &str, occurred_at_unix_ms: u64) -> String {
    let sequence = NEXT_INVALIDATION_EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}-{}", node_id, std::process::id(), occurred_at_unix_ms, sequence)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderValue, StatusCode};

    use crate::{
        sign_http_cache_peer_request, HttpCachePeerConfig, HttpCachePeerInvalidationResponse,
        HttpCachePeerInvalidationResult,
    };

    use super::{
        HttpCacheAdminService, HttpCachePurgeRequest, HttpCachePurgeResultKind,
        HttpCachePurgeTarget,
    };

    enum MockPeerMode {
        Apply,
        Duplicate,
        Fail(u16),
    }

    fn entry() -> lb_runtime::HttpCacheEntry {
        lb_runtime::HttpCacheEntry {
            metadata: lb_runtime::HttpCacheMetadata {
                status: StatusCode::OK,
                stored_at: Duration::from_secs(1),
                fresh_until: Duration::from_secs(60),
                stale_while_revalidate_until: Some(Duration::from_secs(90)),
                stale_if_error_until: Some(Duration::from_secs(120)),
                etag: Some(HeaderValue::from_static("\"v1\"")),
                last_modified: None,
            },
            headers: Vec::new(),
            body: Bytes::from_static(b"cached"),
        }
    }

    fn spawn_mock_peer_server(
        scope: &'static str,
        store: Arc<lb_runtime::HttpCacheStore>,
        actor: &'static str,
        secret: &'static str,
        mode: MockPeerMode,
    ) -> Result<(String, thread::JoinHandle<()>), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let handle = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            let header_end = loop {
                let read = stream.read(&mut buffer).expect("read peer request");
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let Ok(head) = std::str::from_utf8(&request[..header_end]) else {
                return;
            };
            let content_length = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.parse::<usize>().ok())
                .expect("content length header");
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).expect("read peer request body");
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let Ok(request_text) = String::from_utf8(request) else {
                return;
            };
            let Some((head, body)) = request_text.split_once("\r\n\r\n") else {
                return;
            };
            let mut lines = head.lines();
            let request_line = lines.next().unwrap_or_default();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default();
            let target = parts.next().unwrap_or_default();

            let mut actor_header = String::new();
            let mut timestamp_header = String::new();
            let mut nonce_header = String::new();
            let mut signature_header = String::new();
            for line in lines {
                if let Some(value) = line.strip_prefix("X-LB-Admin-Actor: ") {
                    actor_header = value.to_string();
                }
                if let Some(value) = line.strip_prefix("X-LB-Admin-Timestamp: ") {
                    timestamp_header = value.to_string();
                }
                if let Some(value) = line.strip_prefix("X-LB-Admin-Nonce: ") {
                    nonce_header = value.to_string();
                }
                if let Some(value) = line.strip_prefix("X-LB-Admin-Signature: ") {
                    signature_header = value.to_string();
                }
            }
            assert_eq!(method, "POST");
            assert_eq!(target, "/cache/invalidate");
            assert_eq!(actor_header, actor);
            let timestamp = timestamp_header.parse::<u64>().expect("timestamp header");
            let expected_signature = sign_http_cache_peer_request(
                secret,
                actor,
                method,
                target,
                timestamp,
                &nonce_header,
            );
            assert_eq!(signature_header, expected_signature);

            let event: lb_runtime::HttpCacheInvalidationEvent =
                serde_json::from_str(body).expect("event body JSON");
            let (status_code, response) = match mode {
                MockPeerMode::Apply => {
                    let apply =
                        store.apply_invalidation_event(&event).expect("apply event must succeed");
                    let (result, purged_entries) = match apply {
                        lb_runtime::HttpCacheInvalidationApplyResult::Applied {
                            purged_entries,
                        } => (HttpCachePeerInvalidationResult::Applied, purged_entries),
                        lb_runtime::HttpCacheInvalidationApplyResult::Duplicate => {
                            (HttpCachePeerInvalidationResult::Duplicate, 0)
                        }
                    };
                    (
                        200,
                        HttpCachePeerInvalidationResponse {
                            result,
                            event_id: event.event_id.clone(),
                            scope: scope.to_string(),
                            purged_entries,
                            occurred_at_unix_ms: event.occurred_at_unix_ms,
                        },
                    )
                }
                MockPeerMode::Duplicate => {
                    store.apply_invalidation_event(&event).expect("first apply must succeed");
                    let duplicate =
                        store.apply_invalidation_event(&event).expect("second apply must succeed");
                    let purged_entries = match duplicate {
                        lb_runtime::HttpCacheInvalidationApplyResult::Applied {
                            purged_entries,
                        } => purged_entries,
                        lb_runtime::HttpCacheInvalidationApplyResult::Duplicate => 0,
                    };
                    (
                        200,
                        HttpCachePeerInvalidationResponse {
                            result: HttpCachePeerInvalidationResult::Duplicate,
                            event_id: event.event_id.clone(),
                            scope: scope.to_string(),
                            purged_entries,
                            occurred_at_unix_ms: event.occurred_at_unix_ms,
                        },
                    )
                }
                MockPeerMode::Fail(status_code) => (
                    status_code,
                    HttpCachePeerInvalidationResponse {
                        result: HttpCachePeerInvalidationResult::Applied,
                        event_id: event.event_id.clone(),
                        scope: scope.to_string(),
                        purged_entries: 0,
                        occurred_at_unix_ms: event.occurred_at_unix_ms,
                    },
                ),
            };

            let body = serde_json::to_vec(&response).expect("response body JSON");
            let status_text = if status_code == 200 { "OK" } else { "Service Unavailable" };
            let response = format!(
                "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
        });
        Ok((format!("http://{address}"), handle))
    }

    #[test]
    fn exact_key_purge_removes_targeted_object() -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 4,
            max_bytes: 1024,
            max_object_bytes: 512,
        })?);
        let key = lb_runtime::HttpCacheKey::new("path=/api/items\nhost=example.test")?;
        store.insert(Duration::from_secs(1), key.clone(), entry())?;
        let mut service = HttpCacheAdminService::new("public-http", true, Arc::clone(&store));
        let telemetry = lb_runtime::RuntimeTelemetry::new()?;

        let response = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::ExactKey(key.clone()),
                requested_by: Some(String::from("admin-a")),
                reason: Some(String::from("exact invalidation")),
            },
            Some(&telemetry),
        )?;

        assert_eq!(response.result, HttpCachePurgeResultKind::Purged);
        assert_eq!(response.purged_entries, 1);
        assert_eq!(response.fanout_delivery_success_count, 0);
        assert_eq!(response.fanout_delivery_failure_count, 0);
        assert!(!response.degraded);
        assert_eq!(response.fanout_subscriber_count, 0);
        assert_eq!(response.invalidation_event_id, None);
        assert!(store.lookup(Duration::from_secs(1), &key).is_none());
        assert_eq!(service.metrics().successful_purge_count, 1);
        assert_eq!(service.metrics().purged_entry_count, 1);
        assert!(telemetry
            .export_metrics()
            .contains("runtime_http_cache_purged_entries_total{scope=\"public-http\"} 1"));
        Ok(())
    }

    #[test]
    fn path_prefix_purge_removes_matching_keys_only() -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let image_key = lb_runtime::HttpCacheKey::new("path=/images/logo.png\nhost=example.test")?;
        let api_key = lb_runtime::HttpCacheKey::new("path=/api/items\nhost=example.test")?;
        store.insert(Duration::from_secs(1), image_key.clone(), entry())?;
        store.insert(Duration::from_secs(1), api_key.clone(), entry())?;
        let mut service = HttpCacheAdminService::new("public-http", true, Arc::clone(&store));

        let response = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::PathPrefix(String::from("/images")),
                requested_by: Some(String::from("admin-a")),
                reason: Some(String::from("flush static assets")),
            },
            None,
        )?;

        assert_eq!(response.result, HttpCachePurgeResultKind::Purged);
        assert_eq!(response.purged_entries, 1);
        assert!(!response.degraded);
        assert_eq!(response.fanout_subscriber_count, 0);
        assert!(store.lookup(Duration::from_secs(1), &image_key).is_none());
        assert!(store.lookup(Duration::from_secs(1), &api_key).is_some());
        assert_eq!(service.history().len(), 1);
        Ok(())
    }

    #[test]
    fn disabled_purge_is_rejected_and_audited() -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 4,
            max_bytes: 1024,
            max_object_bytes: 512,
        })?);
        let mut service = HttpCacheAdminService::new("public-http", false, store);

        let error = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::PathPrefix(String::from("/api")),
                requested_by: Some(String::from("admin-a")),
                reason: Some(String::from("should fail")),
            },
            None,
        );

        assert!(matches!(error, Err(super::HttpCachePurgeError::PurgeDisabled)));
        assert_eq!(service.metrics().rejected_purge_count, 1);
        assert_eq!(service.metrics().audit_event_count, 1);
        assert_eq!(service.history()[0].result, HttpCachePurgeResultKind::Rejected);
        Ok(())
    }

    #[test]
    fn distributed_invalidation_fans_out_to_peer_nodes() -> Result<(), Box<dyn std::error::Error>> {
        let first = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let second = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let key = lb_runtime::HttpCacheKey::new("path=/images/logo.png\nhost=example.test")?;
        first.insert(Duration::from_secs(1), key.clone(), entry())?;
        second.insert(Duration::from_secs(1), key.clone(), entry())?;

        let bus = Arc::new(lb_runtime::HttpCacheInvalidationBus::new());
        bus.register(Arc::new(lb_runtime::HttpCacheStoreInvalidationSubscriber::new(
            "public-http",
            Arc::clone(&second),
        )));
        let mut service = HttpCacheAdminService::new("public-http", true, Arc::clone(&first))
            .with_invalidation_bus("node-a", Arc::clone(&bus));

        let response = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::ExactKey(key.clone()),
                requested_by: Some(String::from("admin-a")),
                reason: Some(String::from("cluster invalidation")),
            },
            None,
        )?;

        assert_eq!(response.result, HttpCachePurgeResultKind::Purged);
        assert_eq!(response.purged_entries, 2);
        assert_eq!(response.fanout_transport.as_deref(), Some("in_memory_bus"));
        assert_eq!(response.fanout_subscriber_count, 1);
        assert_eq!(response.fanout_delivery_success_count, 1);
        assert_eq!(response.fanout_delivery_failure_count, 0);
        assert_eq!(response.fanout_duplicate_count, 0);
        assert!(!response.degraded);
        assert!(response.invalidation_event_id.is_some());
        assert!(first.lookup(Duration::from_secs(1), &key).is_none());
        assert!(second.lookup(Duration::from_secs(1), &key).is_none());
        Ok(())
    }

    #[test]
    fn distributed_invalidation_event_ids_are_unique_across_repeated_purges(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let first_key = lb_runtime::HttpCacheKey::new("path=/assets/a.png\nhost=example.test")?;
        let second_key = lb_runtime::HttpCacheKey::new("path=/assets/b.png\nhost=example.test")?;
        store.insert(Duration::from_secs(1), first_key.clone(), entry())?;
        store.insert(Duration::from_secs(1), second_key.clone(), entry())?;

        let bus = Arc::new(lb_runtime::HttpCacheInvalidationBus::new());
        let mut service = HttpCacheAdminService::new("public-http", true, Arc::clone(&store))
            .with_invalidation_bus("node-a", Arc::clone(&bus));

        let first = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::ExactKey(first_key),
                requested_by: Some(String::from("admin-a")),
                reason: Some(String::from("purge-first")),
            },
            None,
        )?;
        let second = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::ExactKey(second_key),
                requested_by: Some(String::from("admin-a")),
                reason: Some(String::from("purge-second")),
            },
            None,
        )?;

        assert_ne!(first.invalidation_event_id, second.invalidation_event_id);
        assert!(first.invalidation_event_id.is_some());
        assert!(second.invalidation_event_id.is_some());
        Ok(())
    }

    #[test]
    fn http_peer_transport_fans_out_to_multiple_nodes() -> Result<(), Box<dyn std::error::Error>> {
        std::env::set_var("LB_CACHE_PEER_SECRET", "peer-shared-secret");
        let first = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let second = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let third = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let key = lb_runtime::HttpCacheKey::new("path=/images/logo.png\nhost=example.test")?;
        first.insert(Duration::from_secs(1), key.clone(), entry())?;
        second.insert(Duration::from_secs(1), key.clone(), entry())?;
        third.insert(Duration::from_secs(1), key.clone(), entry())?;

        let (second_origin, second_thread) = spawn_mock_peer_server(
            "public-http",
            Arc::clone(&second),
            "cache-peer-a",
            "peer-shared-secret",
            MockPeerMode::Apply,
        )?;
        let (third_origin, third_thread) = spawn_mock_peer_server(
            "public-http",
            Arc::clone(&third),
            "cache-peer-a",
            "peer-shared-secret",
            MockPeerMode::Apply,
        )?;

        let telemetry = lb_runtime::RuntimeTelemetry::new()?;
        let mut service = HttpCacheAdminService::new("public-http", true, Arc::clone(&first))
            .with_http_peer_transport(
                "node-a",
                [
                    HttpCachePeerConfig::new(
                        "node-b",
                        second_origin,
                        "cache-peer-a",
                        "LB_CACHE_PEER_SECRET",
                    ),
                    HttpCachePeerConfig::new(
                        "node-c",
                        third_origin,
                        "cache-peer-a",
                        "LB_CACHE_PEER_SECRET",
                    ),
                ],
            )?;

        let response = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::ExactKey(key.clone()),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("fanout over http peers")),
            },
            Some(&telemetry),
        )?;

        second_thread.join().map_err(|_| "second peer thread panicked")?;
        third_thread.join().map_err(|_| "third peer thread panicked")?;

        assert_eq!(response.result, HttpCachePurgeResultKind::Purged);
        assert_eq!(response.purged_entries, 3);
        assert_eq!(response.fanout_transport.as_deref(), Some("http_peer"));
        assert_eq!(response.fanout_subscriber_count, 2);
        assert_eq!(response.fanout_delivery_success_count, 2);
        assert_eq!(response.fanout_delivery_failure_count, 0);
        assert_eq!(response.fanout_duplicate_count, 0);
        assert!(response.fanout_failed_targets.is_empty());
        assert!(!response.degraded);
        assert!(first.lookup(Duration::from_secs(1), &key).is_none());
        assert!(second.lookup(Duration::from_secs(1), &key).is_none());
        assert!(third.lookup(Duration::from_secs(1), &key).is_none());

        let metrics = telemetry.export_metrics();
        assert!(metrics.contains(
            "runtime_http_cache_invalidation_peer_deliveries_total{scope=\"public-http\",result=\"success\",reason=\"http_peer\"} 2"
        ));
        Ok(())
    }

    #[test]
    fn http_peer_transport_reports_degraded_fanout_without_blocking_local_purge(
    ) -> Result<(), Box<dyn std::error::Error>> {
        std::env::set_var("LB_CACHE_PEER_SECRET", "peer-shared-secret");
        let first = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let second = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let third = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let key = lb_runtime::HttpCacheKey::new("path=/assets/app.js\nhost=example.test")?;
        first.insert(Duration::from_secs(1), key.clone(), entry())?;
        second.insert(Duration::from_secs(1), key.clone(), entry())?;
        third.insert(Duration::from_secs(1), key.clone(), entry())?;

        let (second_origin, second_thread) = spawn_mock_peer_server(
            "public-http",
            Arc::clone(&second),
            "cache-peer-a",
            "peer-shared-secret",
            MockPeerMode::Apply,
        )?;
        let (third_origin, third_thread) = spawn_mock_peer_server(
            "public-http",
            Arc::clone(&third),
            "cache-peer-a",
            "peer-shared-secret",
            MockPeerMode::Fail(503),
        )?;

        let telemetry = lb_runtime::RuntimeTelemetry::new()?;
        let mut service = HttpCacheAdminService::new("public-http", true, Arc::clone(&first))
            .with_http_peer_transport(
                "node-a",
                [
                    HttpCachePeerConfig::new(
                        "node-b",
                        second_origin,
                        "cache-peer-a",
                        "LB_CACHE_PEER_SECRET",
                    ),
                    HttpCachePeerConfig::new(
                        "node-c",
                        third_origin,
                        "cache-peer-a",
                        "LB_CACHE_PEER_SECRET",
                    ),
                ],
            )?;

        let response = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::ExactKey(key.clone()),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("degraded fanout")),
            },
            Some(&telemetry),
        )?;

        second_thread.join().map_err(|_| "second peer thread panicked")?;
        third_thread.join().map_err(|_| "third peer thread panicked")?;

        assert_eq!(response.result, HttpCachePurgeResultKind::Purged);
        assert_eq!(response.purged_entries, 2);
        assert_eq!(response.fanout_subscriber_count, 2);
        assert_eq!(response.fanout_delivery_success_count, 1);
        assert_eq!(response.fanout_delivery_failure_count, 1);
        assert!(response.degraded);
        assert_eq!(service.metrics().degraded_fanout_count, 1);
        assert_eq!(response.fanout_failed_targets.len(), 1);
        assert!(response.fanout_failed_targets[0].starts_with("node-c:"));
        assert!(first.lookup(Duration::from_secs(1), &key).is_none());
        assert!(second.lookup(Duration::from_secs(1), &key).is_none());
        assert!(third.lookup(Duration::from_secs(1), &key).is_some());

        let metrics = telemetry.export_metrics();
        assert!(metrics.contains(
            "runtime_http_cache_invalidation_peer_deliveries_total{scope=\"public-http\",result=\"success\",reason=\"http_peer\"} 1"
        ));
        assert!(metrics.contains(
            "runtime_http_cache_invalidation_peer_deliveries_total{scope=\"public-http\",result=\"failed\",reason=\"http_peer\"} 1"
        ));
        Ok(())
    }

    #[test]
    fn http_peer_transport_counts_duplicate_peer_delivery() -> Result<(), Box<dyn std::error::Error>>
    {
        std::env::set_var("LB_CACHE_PEER_SECRET", "peer-shared-secret");
        let first = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let second = Arc::new(lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
            max_entries: 8,
            max_bytes: 2048,
            max_object_bytes: 512,
        })?);
        let key = lb_runtime::HttpCacheKey::new("path=/docs/index.html\nhost=example.test")?;
        first.insert(Duration::from_secs(1), key.clone(), entry())?;
        second.insert(Duration::from_secs(1), key.clone(), entry())?;

        let (second_origin, second_thread) = spawn_mock_peer_server(
            "public-http",
            Arc::clone(&second),
            "cache-peer-a",
            "peer-shared-secret",
            MockPeerMode::Duplicate,
        )?;

        let telemetry = lb_runtime::RuntimeTelemetry::new()?;
        let mut service = HttpCacheAdminService::new("public-http", true, Arc::clone(&first))
            .with_http_peer_transport(
                "node-a",
                [HttpCachePeerConfig::new(
                    "node-b",
                    second_origin,
                    "cache-peer-a",
                    "LB_CACHE_PEER_SECRET",
                )],
            )?;

        let response = service.purge(
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::ExactKey(key.clone()),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("duplicate replay check")),
            },
            Some(&telemetry),
        )?;

        second_thread.join().map_err(|_| "peer thread panicked")?;

        assert_eq!(response.result, HttpCachePurgeResultKind::Purged);
        assert_eq!(response.purged_entries, 1);
        assert_eq!(response.fanout_subscriber_count, 1);
        assert_eq!(response.fanout_delivery_success_count, 1);
        assert_eq!(response.fanout_duplicate_count, 1);
        assert_eq!(response.fanout_delivery_failure_count, 0);
        assert!(!response.degraded);
        assert!(first.lookup(Duration::from_secs(1), &key).is_none());
        assert!(second.lookup(Duration::from_secs(1), &key).is_none());

        let metrics = telemetry.export_metrics();
        assert!(metrics.contains(
            "runtime_http_cache_invalidation_peer_deliveries_total{scope=\"public-http\",result=\"duplicate\",reason=\"http_peer\"} 1"
        ));
        Ok(())
    }
}
