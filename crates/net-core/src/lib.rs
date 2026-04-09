#![forbid(unsafe_code)]

mod upstream;

pub use upstream::{
    EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName, UpstreamClusterState,
    UpstreamEndpoint, UpstreamEndpointId, UpstreamModelError,
};

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Returns the crate identifier for the shared networking layer.
pub const CRATE_ID: &str = "lb-net-core";

/// Shared network defaults used by future listeners and upstream sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkDefaults {
    /// Default backlog for listener configuration placeholders.
    pub backlog: u32,
    /// Default idle timeout in seconds.
    pub idle_timeout_secs: u64,
}

impl Default for NetworkDefaults {
    fn default() -> Self {
        Self { backlog: 1024, idle_timeout_secs: 30 }
    }
}

/// Distinguishes externally reachable and privileged listener surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerClass {
    /// Public traffic listener.
    Public,
    /// Privileged listener for local admin or diagnostics traffic.
    Admin,
}

/// File-backed TLS material for listeners that terminate TLS locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsListenerConfig {
    /// PEM certificate chain path.
    pub cert_path: String,
    /// PEM private key path.
    pub key_path: String,
}

impl TlsListenerConfig {
    fn validate(&self) -> Result<(), ListenerConfigError> {
        if self.cert_path.trim().is_empty() {
            return Err(ListenerConfigError::EmptyTlsCertificatePath);
        }

        if self.key_path.trim().is_empty() {
            return Err(ListenerConfigError::EmptyTlsPrivateKeyPath);
        }

        Ok(())
    }
}

/// Listener configuration used by the runtime skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerConfig {
    /// Human-readable listener name.
    pub name: String,
    /// Listener surface classification.
    pub class: ListenerClass,
    /// Socket address to bind.
    pub bind_address: SocketAddr,
    /// Maximum number of admitted concurrent connections.
    pub max_connections: usize,
    /// Listener backlog placeholder.
    pub backlog: u32,
    /// Idle timeout applied to admitted placeholder connections.
    pub idle_timeout: Duration,
    /// Maximum drain duration during shutdown.
    pub drain_timeout: Duration,
    /// Whether unspecified addresses such as `0.0.0.0` are allowed.
    pub allow_unspecified_bind: bool,
    /// Optional TLS termination material for HTTPS listeners.
    pub tls_termination: Option<TlsListenerConfig>,
}

impl ListenerConfig {
    /// Creates a safe localhost-only foundation listener configuration.
    #[must_use]
    pub fn foundation_local(name: impl Into<String>, class: ListenerClass) -> Self {
        let defaults = NetworkDefaults::default();

        Self {
            name: name.into(),
            class,
            bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            max_connections: 128,
            backlog: defaults.backlog,
            idle_timeout: Duration::from_secs(defaults.idle_timeout_secs),
            drain_timeout: Duration::from_secs(5),
            allow_unspecified_bind: false,
            tls_termination: None,
        }
    }

    /// Validates listener configuration safety and runtime invariants.
    pub fn validate(&self) -> Result<(), ListenerConfigError> {
        if self.name.trim().is_empty() {
            return Err(ListenerConfigError::EmptyName);
        }

        if self.max_connections == 0 {
            return Err(ListenerConfigError::ZeroMaxConnections);
        }

        if self.backlog == 0 {
            return Err(ListenerConfigError::ZeroBacklog);
        }

        if self.bind_address.ip().is_unspecified() && !self.allow_unspecified_bind {
            return Err(ListenerConfigError::UnspecifiedBindRequiresOptIn(self.bind_address));
        }

        if let Some(tls_termination) = &self.tls_termination {
            tls_termination.validate()?;
        }

        Ok(())
    }
}

/// Listener configuration validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerConfigError {
    /// Listener name cannot be empty.
    EmptyName,
    /// Connection admission must be bounded by a positive number.
    ZeroMaxConnections,
    /// Backlog must be non-zero.
    ZeroBacklog,
    /// Unspecified bind addresses require explicit opt-in.
    UnspecifiedBindRequiresOptIn(SocketAddr),
    /// TLS termination requires a non-empty certificate path.
    EmptyTlsCertificatePath,
    /// TLS termination requires a non-empty private key path.
    EmptyTlsPrivateKeyPath,
}

impl fmt::Display for ListenerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => formatter.write_str("listener name must not be empty"),
            Self::ZeroMaxConnections => {
                formatter.write_str("listener max_connections must be greater than zero")
            }
            Self::ZeroBacklog => formatter.write_str("listener backlog must be greater than zero"),
            Self::UnspecifiedBindRequiresOptIn(address) => write!(
                formatter,
                "unspecified bind address {address} requires allow_unspecified_bind=true"
            ),
            Self::EmptyTlsCertificatePath => {
                formatter.write_str("listener TLS certificate path must not be empty")
            }
            Self::EmptyTlsPrivateKeyPath => {
                formatter.write_str("listener TLS private key path must not be empty")
            }
        }
    }
}

impl std::error::Error for ListenerConfigError {}

/// Static upstream target used by the initial L4 proxy path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    /// Human-readable upstream name.
    pub name: String,
    /// Upstream TCP address.
    pub address: SocketAddr,
}

impl UpstreamTarget {
    /// Creates an upstream target.
    #[must_use]
    pub fn new(name: impl Into<String>, address: SocketAddr) -> Self {
        Self { name: name.into(), address }
    }
}

/// Timeout model for TCP proxy sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionTimeouts {
    /// Upper bound for upstream connect.
    pub connect_timeout: Duration,
    /// Upper bound for downstream classification preface.
    pub preface_timeout: Duration,
    /// Per-direction idle timeout during proxying.
    pub idle_timeout: Duration,
}

impl Default for ConnectionTimeouts {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            preface_timeout: Duration::from_millis(250),
            idle_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{ListenerClass, ListenerConfig, ListenerConfigError, TlsListenerConfig};

    #[test]
    fn foundation_local_uses_safe_defaults() {
        let config = ListenerConfig::foundation_local("public", ListenerClass::Public);

        assert_eq!(config.bind_address.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(!config.allow_unspecified_bind);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_unspecified_bind_without_opt_in() {
        let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
        config.bind_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);

        let result = config.validate();

        assert_eq!(
            result,
            Err(ListenerConfigError::UnspecifiedBindRequiresOptIn(config.bind_address,))
        );
    }

    #[test]
    fn validate_rejects_empty_tls_material_paths() {
        let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
        config.tls_termination = Some(TlsListenerConfig {
            cert_path: String::new(),
            key_path: String::from("certs/server.key"),
        });

        assert_eq!(config.validate(), Err(ListenerConfigError::EmptyTlsCertificatePath));

        config.tls_termination = Some(TlsListenerConfig {
            cert_path: String::from("certs/server.pem"),
            key_path: String::new(),
        });

        assert_eq!(config.validate(), Err(ListenerConfigError::EmptyTlsPrivateKeyPath));
    }
}
