use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_INVALIDATION_PATH: &str = "/cache/invalidate";
const DEFAULT_MAX_FAILURE_DETAILS: usize = 8;
const MAX_CACHE_PEER_NODE_ID_LEN: usize = lb_runtime::HTTP_CACHE_INVALIDATION_MAX_ISSUER_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerOriginScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPeerOrigin {
    authority: String,
    socket_addr: SocketAddr,
    scheme: PeerOriginScheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpCachePeerRetryPolicy {
    pub max_attempts: usize,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for HttpCachePeerRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(25),
            max_backoff: Duration::from_millis(250),
        }
    }
}

impl HttpCachePeerRetryPolicy {
    #[must_use]
    pub fn normalized(self) -> Self {
        Self {
            max_attempts: self.max_attempts.max(1),
            initial_backoff: self.initial_backoff,
            max_backoff: self.max_backoff.max(self.initial_backoff),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpCacheInvalidationDeliveryMode {
    #[default]
    BestEffort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCachePeerConfig {
    pub node_id: String,
    pub origin: String,
    pub actor: String,
    pub secret_env: String,
    pub tls_ca_cert_env: Option<String>,
    pub invalidation_path: String,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
}

impl HttpCachePeerConfig {
    #[must_use]
    pub fn new(
        node_id: impl Into<String>,
        origin: impl Into<String>,
        actor: impl Into<String>,
        secret_env: impl Into<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            origin: origin.into(),
            actor: actor.into(),
            secret_env: secret_env.into(),
            tls_ca_cert_env: None,
            invalidation_path: String::from(DEFAULT_INVALIDATION_PATH),
            connect_timeout: Duration::from_millis(500),
            response_timeout: Duration::from_millis(1000),
        }
    }

    #[must_use]
    pub fn with_tls_ca_cert_env(mut self, tls_ca_cert_env: impl Into<String>) -> Self {
        self.tls_ca_cert_env = Some(tls_ca_cert_env.into());
        self
    }

    #[must_use]
    pub fn with_invalidation_path(mut self, invalidation_path: impl Into<String>) -> Self {
        self.invalidation_path = invalidation_path.into();
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    #[must_use]
    pub fn with_response_timeout(mut self, response_timeout: Duration) -> Self {
        self.response_timeout = response_timeout;
        self
    }

    pub fn validate(&self) -> Result<(), InvalidHttpCachePeerConfig> {
        if self.node_id.trim().is_empty() {
            return Err(InvalidHttpCachePeerConfig::EmptyNodeId);
        }
        if self.node_id.len() > MAX_CACHE_PEER_NODE_ID_LEN {
            return Err(InvalidHttpCachePeerConfig::NodeIdTooLong);
        }
        if self.origin.trim().is_empty() {
            return Err(InvalidHttpCachePeerConfig::EmptyOrigin);
        }
        let parsed_origin = parse_peer_origin(&self.origin)
            .map_err(|_| InvalidHttpCachePeerConfig::InvalidOrigin)?;
        if !parsed_origin.socket_addr.ip().is_loopback() {
            return Err(match parsed_origin.scheme {
                PeerOriginScheme::Http => InvalidHttpCachePeerConfig::InsecureHttpOrigin,
                PeerOriginScheme::Https => InvalidHttpCachePeerConfig::InsecureHttpsOrigin,
            });
        }
        if matches!(parsed_origin.scheme, PeerOriginScheme::Https) && self.tls_ca_cert_env.is_none()
        {
            return Err(InvalidHttpCachePeerConfig::MissingTlsCaCertEnv);
        }
        if self.tls_ca_cert_env.as_deref().is_some_and(|value| value.trim().is_empty()) {
            return Err(InvalidHttpCachePeerConfig::EmptyTlsCaCertEnv);
        }
        if self.actor.contains(['\r', '\n', '\0'])
            || self.invalidation_path.contains(['\r', '\n', '\0'])
        {
            return Err(InvalidHttpCachePeerConfig::InvalidOrigin);
        }
        if self.actor.trim().is_empty() {
            return Err(InvalidHttpCachePeerConfig::EmptyActor);
        }
        if self.secret_env.trim().is_empty() {
            return Err(InvalidHttpCachePeerConfig::EmptySecretEnv);
        }
        if self.invalidation_path.trim().is_empty() {
            return Err(InvalidHttpCachePeerConfig::EmptyInvalidationPath);
        }
        if !self.invalidation_path.starts_with('/') {
            return Err(InvalidHttpCachePeerConfig::InvalidInvalidationPath);
        }
        if self.invalidation_path.contains('?') || self.invalidation_path.contains('#') {
            return Err(InvalidHttpCachePeerConfig::InvalidInvalidationPath);
        }
        if self.connect_timeout.is_zero() {
            return Err(InvalidHttpCachePeerConfig::ZeroConnectTimeout);
        }
        if self.response_timeout.is_zero() {
            return Err(InvalidHttpCachePeerConfig::ZeroResponseTimeout);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidHttpCachePeerConfig {
    EmptyNodeId,
    NodeIdTooLong,
    EmptyOrigin,
    InvalidOrigin,
    InsecureHttpOrigin,
    InsecureHttpsOrigin,
    EmptyActor,
    EmptySecretEnv,
    MissingTlsCaCertEnv,
    EmptyTlsCaCertEnv,
    EmptyInvalidationPath,
    InvalidInvalidationPath,
    ZeroConnectTimeout,
    ZeroResponseTimeout,
}

impl fmt::Display for InvalidHttpCachePeerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNodeId => formatter.write_str("cache peer node_id must not be empty"),
            Self::NodeIdTooLong => formatter.write_str("cache peer node_id exceeds max length"),
            Self::EmptyOrigin => formatter.write_str("cache peer origin must not be empty"),
            Self::InvalidOrigin => {
                formatter.write_str(
                    "cache peer origin must be an authority-only http://host:port or https://host:port origin",
                )
            }
            Self::InsecureHttpOrigin => formatter.write_str(
                "cache peer http origins must target loopback; use https:// for remote peers",
            ),
            Self::InsecureHttpsOrigin => formatter
                .write_str("cache peer https origins must target loopback"),
            Self::EmptyActor => formatter.write_str("cache peer actor must not be empty"),
            Self::EmptySecretEnv => formatter.write_str("cache peer secret_env must not be empty"),
            Self::MissingTlsCaCertEnv => formatter.write_str(
                "cache peer https origins must declare tls_ca_cert_env",
            ),
            Self::EmptyTlsCaCertEnv => formatter.write_str(
                "cache peer tls_ca_cert_env must not be empty when configured",
            ),
            Self::EmptyInvalidationPath => {
                formatter.write_str("cache peer invalidation path must not be empty")
            }
            Self::InvalidInvalidationPath => formatter.write_str(
                "cache peer invalidation path must start with '/' and contain no query or fragment",
            ),
            Self::ZeroConnectTimeout => {
                formatter.write_str("cache peer connect timeout must be greater than zero")
            }
            Self::ZeroResponseTimeout => {
                formatter.write_str("cache peer response timeout must be greater than zero")
            }
        }
    }
}

impl std::error::Error for InvalidHttpCachePeerConfig {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpCachePeerInvalidationResult {
    Applied,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCachePeerInvalidationResponse {
    pub result: HttpCachePeerInvalidationResult,
    pub event_id: String,
    pub scope: String,
    pub purged_entries: usize,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpCachePeerDeliveryResult {
    Applied,
    Duplicate,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCachePeerDeliveryRecord {
    pub node_id: String,
    pub result: HttpCachePeerDeliveryResult,
    pub attempts: usize,
    pub purged_entries: usize,
    pub latency_ms: u64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCachePeerFanoutReport {
    pub event_id: String,
    pub scope: String,
    pub degraded: bool,
    pub partition_detected: bool,
    pub delivery_success_count: usize,
    pub delivery_failure_count: usize,
    pub duplicate_count: usize,
    pub subscriber_count: usize,
    pub max_attempts: usize,
    pub peer_results: Vec<HttpCachePeerDeliveryRecord>,
}

#[derive(Debug, Clone)]
pub struct HttpCachePeerTransport {
    peers: Vec<HttpCachePeerConfig>,
    max_failure_details: usize,
    retry_policy: HttpCachePeerRetryPolicy,
    last_report: Arc<Mutex<Option<HttpCachePeerFanoutReport>>>,
}

impl HttpCachePeerTransport {
    pub fn new(
        peers: impl IntoIterator<Item = HttpCachePeerConfig>,
    ) -> Result<Self, InvalidHttpCachePeerConfig> {
        let peers = peers.into_iter().collect::<Vec<_>>();
        for peer in &peers {
            peer.validate()?;
        }
        Ok(Self {
            peers,
            max_failure_details: DEFAULT_MAX_FAILURE_DETAILS,
            retry_policy: HttpCachePeerRetryPolicy::default(),
            last_report: Arc::new(Mutex::new(None)),
        })
    }

    #[must_use]
    pub fn with_max_failure_details(mut self, max_failure_details: usize) -> Self {
        self.max_failure_details = max_failure_details.max(1);
        self
    }

    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: HttpCachePeerRetryPolicy) -> Self {
        self.retry_policy = retry_policy.normalized();
        self
    }

    #[must_use]
    pub fn retry_policy(&self) -> HttpCachePeerRetryPolicy {
        self.retry_policy
    }

    #[must_use]
    pub fn last_report(&self) -> Option<HttpCachePeerFanoutReport> {
        self.last_report.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }
}

impl lb_runtime::HttpCacheInvalidationTransport for HttpCachePeerTransport {
    fn name(&self) -> &str {
        "http_peer"
    }

    fn publish(
        &self,
        event: &lb_runtime::HttpCacheInvalidationEvent,
    ) -> Result<
        lb_runtime::HttpCacheInvalidationPublishResult,
        lb_runtime::HttpCacheInvalidationTransportError,
    > {
        event.validate().map_err(lb_runtime::HttpCacheInvalidationTransportError::InvalidEvent)?;

        let mut result = lb_runtime::HttpCacheInvalidationPublishResult::default();
        let mut peer_results = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            result.subscriber_count += 1;
            let started = std::time::Instant::now();
            let mut attempts = 0;
            let outcome = loop {
                attempts += 1;
                match publish_to_peer(peer, event) {
                    Ok(response) => break Ok(response),
                    Err(error) => {
                        if attempts >= self.retry_policy.max_attempts {
                            break Err(error);
                        }
                        let shift = u32::try_from(attempts.saturating_sub(1)).unwrap_or(u32::MAX);
                        let multiplier = 1_u32.checked_shl(shift.min(20)).unwrap_or(u32::MAX);
                        let backoff = self
                            .retry_policy
                            .initial_backoff
                            .checked_mul(multiplier)
                            .unwrap_or(self.retry_policy.max_backoff)
                            .min(self.retry_policy.max_backoff);
                        if !backoff.is_zero() {
                            std::thread::sleep(backoff);
                        }
                    }
                }
            };
            let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match outcome {
                Ok(HttpCachePeerInvalidationResponse {
                    result: HttpCachePeerInvalidationResult::Applied,
                    purged_entries,
                    ..
                }) => {
                    result.applied_count += 1;
                    result.delivery_success_count += 1;
                    result.purged_entries += purged_entries;
                    peer_results.push(HttpCachePeerDeliveryRecord {
                        node_id: peer.node_id.clone(),
                        result: HttpCachePeerDeliveryResult::Applied,
                        attempts,
                        purged_entries,
                        latency_ms,
                        detail: None,
                    });
                }
                Ok(HttpCachePeerInvalidationResponse {
                    result: HttpCachePeerInvalidationResult::Duplicate,
                    ..
                }) => {
                    result.duplicate_count += 1;
                    result.delivery_success_count += 1;
                    peer_results.push(HttpCachePeerDeliveryRecord {
                        node_id: peer.node_id.clone(),
                        result: HttpCachePeerDeliveryResult::Duplicate,
                        attempts,
                        purged_entries: 0,
                        latency_ms,
                        detail: None,
                    });
                }
                Err(error) => {
                    result.delivery_failure_count += 1;
                    if result.failed_targets.len() < self.max_failure_details {
                        result.failed_targets.push(format!("{}:{error}", peer.node_id));
                    }
                    peer_results.push(HttpCachePeerDeliveryRecord {
                        node_id: peer.node_id.clone(),
                        result: HttpCachePeerDeliveryResult::Failed,
                        attempts,
                        purged_entries: 0,
                        latency_ms,
                        detail: Some(error),
                    });
                }
            }
        }

        *self.last_report.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(HttpCachePeerFanoutReport {
                event_id: event.event_id.clone(),
                scope: event.scope.clone(),
                degraded: result.delivery_failure_count > 0,
                partition_detected: result.delivery_failure_count > 0,
                delivery_success_count: result.delivery_success_count,
                delivery_failure_count: result.delivery_failure_count,
                duplicate_count: result.duplicate_count,
                subscriber_count: result.subscriber_count,
                max_attempts: self.retry_policy.max_attempts,
                peer_results,
            });

        Ok(result)
    }
}

fn publish_to_peer(
    peer: &HttpCachePeerConfig,
    event: &lb_runtime::HttpCacheInvalidationEvent,
) -> Result<HttpCachePeerInvalidationResponse, String> {
    let origin = parse_peer_origin(&peer.origin)?;
    let secret = std::env::var(&peer.secret_env)
        .map_err(|_| format!("secret env {} is not configured", peer.secret_env))?;
    if secret.is_empty() {
        return Err(format!("secret env {} is empty", peer.secret_env));
    }

    let body = serde_json::to_vec(event).map_err(|error| format!("encode event: {error}"))?;
    let timestamp = current_unix_secs().map_err(|error| error.to_string())?;
    let nonce = format!("fanout-{}-{timestamp}", event.event_id);
    let signature = sign_http_cache_peer_request(
        &secret,
        &peer.actor,
        "POST",
        &peer.invalidation_path,
        timestamp,
        &nonce,
        &body,
    );

    let request = format!(
        concat!(
            "POST {path} HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "Content-Type: application/json\r\n",
            "X-LB-Admin-Actor: {actor}\r\n",
            "X-LB-Admin-Timestamp: {timestamp}\r\n",
            "X-LB-Admin-Nonce: {nonce}\r\n",
            "X-LB-Admin-Signature: {signature}\r\n",
            "Connection: close\r\n",
            "Content-Length: {length}\r\n\r\n"
        ),
        path = peer.invalidation_path,
        host = origin.authority,
        actor = peer.actor,
        timestamp = timestamp,
        nonce = nonce,
        signature = signature,
        length = body.len(),
    );
    let mut request_bytes = request.into_bytes();
    request_bytes.extend_from_slice(&body);

    match origin.scheme {
        PeerOriginScheme::Http => publish_to_http_peer(peer, origin.socket_addr, &request_bytes),
        PeerOriginScheme::Https => publish_to_https_peer(peer, &origin, &request_bytes),
    }
}

fn publish_to_http_peer(
    peer: &HttpCachePeerConfig,
    socket_addr: SocketAddr,
    request_bytes: &[u8],
) -> Result<HttpCachePeerInvalidationResponse, String> {
    let mut stream = TcpStream::connect_timeout(&socket_addr, peer.connect_timeout)
        .map_err(|error| format!("connect {}: {error}", peer.node_id))?;
    stream
        .set_read_timeout(Some(peer.response_timeout))
        .map_err(|error| format!("set read timeout {}: {error}", peer.node_id))?;
    stream
        .set_write_timeout(Some(peer.response_timeout))
        .map_err(|error| format!("set write timeout {}: {error}", peer.node_id))?;
    stream
        .write_all(request_bytes)
        .map_err(|error| format!("write request {}: {error}", peer.node_id))?;

    let response = read_peer_response(&mut stream, &peer.node_id)?;
    parse_peer_response(&response).map_err(|error| format!("{} response: {error}", peer.node_id))
}

fn publish_to_https_peer(
    peer: &HttpCachePeerConfig,
    origin: &ParsedPeerOrigin,
    request_bytes: &[u8],
) -> Result<HttpCachePeerInvalidationResponse, String> {
    let tls_ca_cert_env = peer
        .tls_ca_cert_env
        .as_deref()
        .ok_or_else(|| format!("peer {} is missing tls_ca_cert_env", peer.node_id))?;
    let ca_pem = std::env::var(tls_ca_cert_env)
        .map_err(|_| format!("tls ca env {} is not configured", tls_ca_cert_env))?;
    if ca_pem.trim().is_empty() {
        return Err(format!("tls ca env {} is empty", tls_ca_cert_env));
    }
    let mut root_store = RootCertStore::empty();
    for certificate in lb_proto_tls::load_certificates_from_pem(&ca_pem)
        .map_err(|error| format!("load CA certificates from {tls_ca_cert_env}: {error}"))?
    {
        root_store
            .add(CertificateDer::from(certificate))
            .map_err(|error| format!("load CA certificate from {tls_ca_cert_env}: {error}"))?;
    }

    let client_config =
        ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    let server_name = ServerName::IpAddress(origin.socket_addr.ip().into());

    let stream = TcpStream::connect_timeout(&origin.socket_addr, peer.connect_timeout)
        .map_err(|error| format!("connect {}: {error}", peer.node_id))?;
    stream
        .set_read_timeout(Some(peer.response_timeout))
        .map_err(|error| format!("set read timeout {}: {error}", peer.node_id))?;
    stream
        .set_write_timeout(Some(peer.response_timeout))
        .map_err(|error| format!("set write timeout {}: {error}", peer.node_id))?;

    let connection = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|error| format!("tls {}: {error}", peer.node_id))?;
    let mut tls_stream = StreamOwned::new(connection, stream);
    tls_stream
        .write_all(request_bytes)
        .map_err(|error| format!("write https request {}: {error}", peer.node_id))?;

    let response = read_peer_response(&mut tls_stream, &peer.node_id)?;
    parse_peer_response(&response).map_err(|error| format!("{} response: {error}", peer.node_id))
}

fn read_peer_response(stream: &mut impl Read, node_id: &str) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error)
                if !response.is_empty()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                    ) =>
            {
                break;
            }
            Err(error) => return Err(format!("read response {node_id}: {error}")),
        }
    }
    Ok(response)
}
fn parse_peer_origin(origin: &str) -> Result<ParsedPeerOrigin, String> {
    let (scheme, authority) = if let Some(authority) = origin.strip_prefix("http://") {
        (PeerOriginScheme::Http, authority)
    } else if let Some(authority) = origin.strip_prefix("https://") {
        (PeerOriginScheme::Https, authority)
    } else {
        return Err(String::from("origin must start with http:// or https://"));
    };
    if authority.is_empty() || authority.contains('/') {
        return Err(String::from("origin must be an authority-only HTTP origin"));
    }
    let socket_addr = authority
        .parse::<std::net::SocketAddr>()
        .map_err(|_| String::from("origin authority must be a socket address"))?;
    Ok(ParsedPeerOrigin { authority: authority.to_string(), socket_addr, scheme })
}

fn parse_peer_response(bytes: &[u8]) -> Result<HttpCachePeerInvalidationResponse, String> {
    let response = String::from_utf8(bytes.to_vec()).map_err(|error| error.to_string())?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| String::from("missing HTTP response separator"))?;
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(|| String::from("missing status line"))?;
    let mut parts = status_line.split_whitespace();
    let _http_version = parts.next().ok_or_else(|| String::from("missing HTTP version"))?;
    let status_code = parts
        .next()
        .ok_or_else(|| String::from("missing HTTP status code"))?
        .parse::<u16>()
        .map_err(|_| String::from("invalid HTTP status code"))?;
    if status_code != 200 {
        return Err(format!("unexpected status {status_code}"));
    }
    serde_json::from_str(body).map_err(|error| format!("invalid JSON body: {error}"))
}

fn current_unix_secs() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn sign_http_cache_peer_request(
    secret: &str,
    actor: &str,
    method: &str,
    target: &str,
    timestamp: u64,
    nonce: &str,
    body: &[u8],
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

    let payload = format!(
        "{actor}\n{method}\n{target}\n{timestamp}\n{nonce}\n{}\n",
        request_body_digest(body)
    );
    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    inner.update(payload.as_bytes());
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}

fn request_body_digest(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use lb_runtime::{
        HttpCacheInvalidationEvent, HttpCacheInvalidationTarget, HttpCacheInvalidationTransport,
    };

    use super::{
        HttpCachePeerConfig, HttpCachePeerDeliveryResult, HttpCachePeerRetryPolicy,
        HttpCachePeerTransport, InvalidHttpCachePeerConfig,
    };

    fn spawn_peer_server(
        responses: Vec<&'static str>,
        attempts: Arc<AtomicUsize>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept connection");
                attempts.fetch_add(1, Ordering::SeqCst);
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                stream.write_all(response.as_bytes()).expect("write response");
                stream.flush().expect("flush response");
                stream.shutdown(Shutdown::Write).expect("shutdown write half");
            }
        });
        Ok(format!("http://{addr}"))
    }

    fn publish_event(
        transport: &HttpCachePeerTransport,
        event_id: &str,
    ) -> Result<lb_runtime::HttpCacheInvalidationPublishResult, Box<dyn std::error::Error>> {
        let event = HttpCacheInvalidationEvent::new(
            event_id,
            "shared-cache",
            "operator",
            HttpCacheInvalidationTarget::PathPrefix(String::from("/assets")),
            100,
        )?;
        Ok(transport.publish(&event)?)
    }

    #[test]
    fn peer_transport_retries_then_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let attempts = Arc::new(AtomicUsize::new(0));
        let applied_body = "{\"result\":\"applied\",\"event_id\":\"evt-1\",\"scope\":\"shared-cache\",\"purged_entries\":3,\"occurred_at_unix_ms\":100}";
        let origin = spawn_peer_server(
            vec![
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
                Box::leak(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        applied_body.len(),
                        applied_body,
                    )
                    .into_boxed_str(),
                ),
            ],
            attempts.clone(),
        )?;
        std::env::set_var("LB_CACHE_TEST_SECRET", "peer-secret");
        let transport = HttpCachePeerTransport::new([HttpCachePeerConfig::new(
            "node-b",
            origin,
            "peer-a",
            "LB_CACHE_TEST_SECRET",
        )])?
        .with_retry_policy(HttpCachePeerRetryPolicy {
            max_attempts: 2,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        });

        let result = publish_event(&transport, "evt-1")?;

        assert_eq!(result.delivery_success_count, 1);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        let report = transport.last_report().expect("last report");
        assert!(!report.degraded);
        assert_eq!(report.peer_results[0].result, HttpCachePeerDeliveryResult::Applied);
        assert_eq!(report.peer_results[0].attempts, 2);
        Ok(())
    }

    #[test]
    fn peer_transport_reports_partition_when_peer_is_unreachable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        std::env::set_var("LB_CACHE_TEST_SECRET_UNREACHABLE", "peer-secret");
        let transport = HttpCachePeerTransport::new([HttpCachePeerConfig::new(
            "node-z",
            "http://127.0.0.1:9",
            "peer-a",
            "LB_CACHE_TEST_SECRET_UNREACHABLE",
        )])?
        .with_retry_policy(HttpCachePeerRetryPolicy {
            max_attempts: 2,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        });

        let result = publish_event(&transport, "evt-2")?;

        assert_eq!(result.delivery_failure_count, 1);
        let report = transport.last_report().expect("last report");
        assert!(report.degraded);
        assert!(report.partition_detected);
        assert_eq!(report.peer_results[0].result, HttpCachePeerDeliveryResult::Failed);
        assert_eq!(report.peer_results[0].attempts, 2);
        Ok(())
    }

    #[test]
    fn peer_transport_reports_duplicate_delivery() -> Result<(), Box<dyn std::error::Error>> {
        let attempts = Arc::new(AtomicUsize::new(0));
        let duplicate_body = "{\"result\":\"duplicate\",\"event_id\":\"evt-3\",\"scope\":\"shared-cache\",\"purged_entries\":0,\"occurred_at_unix_ms\":100}";
        let origin = spawn_peer_server(
            vec![Box::leak(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    duplicate_body.len(),
                    duplicate_body,
                )
                .into_boxed_str(),
            )],
            attempts,
        )?;
        std::env::set_var("LB_CACHE_TEST_SECRET_DUPLICATE", "peer-secret");
        let transport = HttpCachePeerTransport::new([HttpCachePeerConfig::new(
            "node-b",
            origin,
            "peer-a",
            "LB_CACHE_TEST_SECRET_DUPLICATE",
        )])?
        .with_retry_policy(HttpCachePeerRetryPolicy {
            max_attempts: 1,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        });

        let result = publish_event(&transport, "evt-3")?;

        assert_eq!(result.delivery_success_count, 1, "unexpected publish result: {:?}", result);
        let report = transport.last_report().expect("last report");
        assert_eq!(
            report.peer_results[0].result,
            HttpCachePeerDeliveryResult::Duplicate,
            "unexpected fanout report: {:?}",
            report
        );
        assert_eq!(report.duplicate_count, 1, "unexpected fanout report: {:?}", report);
        Ok(())
    }

    #[test]
    fn peer_config_rejects_remote_plaintext_origin() {
        let result = HttpCachePeerTransport::new([HttpCachePeerConfig::new(
            "node-b",
            "http://198.51.100.10:8443",
            "peer-a",
            "LB_CACHE_TEST_SECRET",
        )]);

        assert!(matches!(result, Err(InvalidHttpCachePeerConfig::InsecureHttpOrigin)));
    }

    #[test]
    fn peer_config_requires_tls_ca_env_for_https_origins() {
        let result = HttpCachePeerTransport::new([HttpCachePeerConfig::new(
            "node-b",
            "https://127.0.0.1:8443",
            "peer-a",
            "LB_CACHE_TEST_SECRET",
        )]);

        assert!(matches!(result, Err(InvalidHttpCachePeerConfig::MissingTlsCaCertEnv)));
    }

    #[test]
    fn peer_config_rejects_remote_https_origin_even_with_tls_ca() {
        let result = HttpCachePeerTransport::new([
            HttpCachePeerConfig::new(
                "node-b",
                "https://198.51.100.10:8443",
                "peer-a",
                "LB_CACHE_TEST_SECRET",
            )
            .with_tls_ca_cert_env("LB_CACHE_TEST_CA"),
        ]);

        assert!(matches!(
            result,
            Err(InvalidHttpCachePeerConfig::InsecureHttpsOrigin)
        ));
    }

    #[test]
    fn peer_config_rejects_actor_with_crlf_suffix() {
        let result = HttpCachePeerTransport::new([HttpCachePeerConfig::new(
            "node-b",
            "http://127.0.0.1:8443",
            "peer-a\r\n",
            "LB_CACHE_TEST_SECRET",
        )]);

        assert!(matches!(result, Err(InvalidHttpCachePeerConfig::InvalidOrigin)));
    }
}
