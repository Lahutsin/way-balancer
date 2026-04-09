use serde::{Deserialize, Serialize};

/// Declarative default set for workspace resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspaceDefaultsConfig {
    /// Default listener settings applied when resource fields are omitted.
    pub listener: ListenerDefaultsConfig,
    /// Default HTTP protocol limits.
    pub http: HttpDefaultsConfig,
}

/// Declarative defaults for listener resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerDefaultsConfig {
    /// Default maximum admitted downstream connections.
    pub max_connections: usize,
    /// Default socket backlog.
    pub backlog: u32,
    /// Default downstream idle timeout in milliseconds.
    pub idle_timeout_ms: u64,
    /// Default graceful drain timeout in milliseconds.
    pub drain_timeout_ms: u64,
    /// Whether unspecified binds are permitted by default.
    pub allow_unspecified_bind: bool,
}

impl Default for ListenerDefaultsConfig {
    fn default() -> Self {
        let network_defaults = lb_net_core::NetworkDefaults::default();

        Self {
            max_connections: 128,
            backlog: network_defaults.backlog,
            idle_timeout_ms: network_defaults.idle_timeout_secs.saturating_mul(1_000),
            drain_timeout_ms: 5_000,
            allow_unspecified_bind: false,
        }
    }
}

/// Declarative defaults for HTTP protocol limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct HttpDefaultsConfig {
    /// Shared HTTP/1.1 limits.
    pub http1: Http1DefaultsConfig,
    /// Shared HTTP/2 limits.
    pub http2: Http2DefaultsConfig,
}

impl HttpDefaultsConfig {
    /// Compiles the declarative HTTP/1.1 defaults into the protocol model.
    #[must_use]
    pub fn http1_limits(&self) -> lb_proto_http::Http1Limits {
        lb_proto_http::Http1Limits {
            max_head_bytes: self.http1.max_head_bytes,
            max_header_count: self.http1.max_header_count,
            max_body_bytes: self.http1.max_body_bytes,
        }
    }

    /// Compiles the declarative HTTP/2 defaults into the protocol model.
    #[must_use]
    pub fn http2_limits(&self) -> lb_proto_http::Http2Limits {
        lb_proto_http::Http2Limits {
            max_concurrent_streams: self.http2.max_concurrent_streams,
            max_body_bytes: self.http2.max_body_bytes,
        }
    }
}

/// Declarative defaults for HTTP/1.1 parsing and relay limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http1DefaultsConfig {
    /// Maximum request or response head bytes.
    pub max_head_bytes: usize,
    /// Maximum number of headers.
    pub max_header_count: usize,
    /// Maximum message body bytes.
    pub max_body_bytes: u64,
}

impl Default for Http1DefaultsConfig {
    fn default() -> Self {
        let defaults = lb_proto_http::Http1Limits::default();

        Self {
            max_head_bytes: defaults.max_head_bytes,
            max_header_count: defaults.max_header_count,
            max_body_bytes: defaults.max_body_bytes,
        }
    }
}

/// Declarative defaults for HTTP/2 relay limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http2DefaultsConfig {
    /// Maximum concurrent proxied streams.
    pub max_concurrent_streams: usize,
    /// Maximum body bytes per stream.
    pub max_body_bytes: u64,
}

impl Default for Http2DefaultsConfig {
    fn default() -> Self {
        let defaults = lb_proto_http::Http2Limits::default();

        Self {
            max_concurrent_streams: defaults.max_concurrent_streams,
            max_body_bytes: defaults.max_body_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WorkspaceDefaultsConfig;

    #[test]
    fn defaults_align_with_foundation_runtime_values() {
        let defaults = WorkspaceDefaultsConfig::default();

        assert_eq!(defaults.listener.max_connections, 128);
        assert_eq!(defaults.listener.backlog, 1024);
        assert_eq!(defaults.http.http1.max_header_count, 64);
        assert_eq!(defaults.http.http2.max_concurrent_streams, 128);
    }

    #[test]
    fn declarative_http_defaults_compile_into_protocol_limits() {
        let defaults = WorkspaceDefaultsConfig::default();

        let http1 = defaults.http.http1_limits();
        let http2 = defaults.http.http2_limits();

        assert_eq!(http1.max_head_bytes, defaults.http.http1.max_head_bytes);
        assert_eq!(http1.max_body_bytes, defaults.http.http1.max_body_bytes);
        assert_eq!(http2.max_concurrent_streams, defaults.http.http2.max_concurrent_streams);
        assert_eq!(http2.max_body_bytes, defaults.http.http2.max_body_bytes);
    }
}
