use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_INVALIDATION_PATH: &str = "/cache/invalidate";
const DEFAULT_MAX_FAILURE_DETAILS: usize = 8;

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
            invalidation_path: String::from(DEFAULT_INVALIDATION_PATH),
            connect_timeout: Duration::from_millis(500),
            response_timeout: Duration::from_millis(1000),
        }
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
        if self.origin.trim().is_empty() {
            return Err(InvalidHttpCachePeerConfig::EmptyOrigin);
        }
        if parse_http_origin(&self.origin).is_err() {
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
    EmptyOrigin,
    InvalidOrigin,
    EmptyActor,
    EmptySecretEnv,
    EmptyInvalidationPath,
    InvalidInvalidationPath,
    ZeroConnectTimeout,
    ZeroResponseTimeout,
}

impl fmt::Display for InvalidHttpCachePeerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNodeId => formatter.write_str("cache peer node_id must not be empty"),
            Self::EmptyOrigin => formatter.write_str("cache peer origin must not be empty"),
            Self::InvalidOrigin => {
                formatter.write_str("cache peer origin must be an http://host:port origin")
            }
            Self::EmptyActor => formatter.write_str("cache peer actor must not be empty"),
            Self::EmptySecretEnv => formatter.write_str("cache peer secret_env must not be empty"),
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

#[derive(Debug, Clone)]
pub struct HttpCachePeerTransport {
    peers: Vec<HttpCachePeerConfig>,
    max_failure_details: usize,
}

impl HttpCachePeerTransport {
    pub fn new(
        peers: impl IntoIterator<Item = HttpCachePeerConfig>,
    ) -> Result<Self, InvalidHttpCachePeerConfig> {
        let peers = peers.into_iter().collect::<Vec<_>>();
        for peer in &peers {
            peer.validate()?;
        }
        Ok(Self { peers, max_failure_details: DEFAULT_MAX_FAILURE_DETAILS })
    }

    #[must_use]
    pub fn with_max_failure_details(mut self, max_failure_details: usize) -> Self {
        self.max_failure_details = max_failure_details.max(1);
        self
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
        for peer in &self.peers {
            result.subscriber_count += 1;
            match publish_to_peer(peer, event) {
                Ok(HttpCachePeerInvalidationResponse {
                    result: HttpCachePeerInvalidationResult::Applied,
                    purged_entries,
                    ..
                }) => {
                    result.applied_count += 1;
                    result.delivery_success_count += 1;
                    result.purged_entries += purged_entries;
                }
                Ok(HttpCachePeerInvalidationResponse {
                    result: HttpCachePeerInvalidationResult::Duplicate,
                    ..
                }) => {
                    result.duplicate_count += 1;
                    result.delivery_success_count += 1;
                }
                Err(error) => {
                    result.delivery_failure_count += 1;
                    if result.failed_targets.len() < self.max_failure_details {
                        result.failed_targets.push(format!("{}:{error}", peer.node_id));
                    }
                }
            }
        }

        Ok(result)
    }
}

fn publish_to_peer(
    peer: &HttpCachePeerConfig,
    event: &lb_runtime::HttpCacheInvalidationEvent,
) -> Result<HttpCachePeerInvalidationResponse, String> {
    let (authority, socket_addr) = parse_http_origin(&peer.origin)?;
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
    );

    let mut stream = TcpStream::connect_timeout(&socket_addr, peer.connect_timeout)
        .map_err(|error| format!("connect {}: {error}", peer.node_id))?;
    stream
        .set_read_timeout(Some(peer.response_timeout))
        .map_err(|error| format!("set read timeout {}: {error}", peer.node_id))?;
    stream
        .set_write_timeout(Some(peer.response_timeout))
        .map_err(|error| format!("set write timeout {}: {error}", peer.node_id))?;

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
        host = authority,
        actor = peer.actor,
        timestamp = timestamp,
        nonce = nonce,
        signature = signature,
        length = body.len(),
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .map_err(|error| format!("write request {}: {error}", peer.node_id))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("read response {}: {error}", peer.node_id))?;

    parse_peer_response(&response).map_err(|error| format!("{} response: {error}", peer.node_id))
}

fn parse_http_origin(origin: &str) -> Result<(String, std::net::SocketAddr), String> {
    let authority = origin
        .strip_prefix("http://")
        .ok_or_else(|| String::from("origin must start with http://"))?;
    if authority.is_empty() || authority.contains('/') {
        return Err(String::from("origin must be an authority-only http origin"));
    }
    let socket_addr = authority
        .parse::<std::net::SocketAddr>()
        .map_err(|_| String::from("origin authority must be a socket address"))?;
    Ok((authority.to_string(), socket_addr))
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
    digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}
