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

/// Canonicalizes IPv4-mapped IPv6 addresses back to plain IPv4.
#[must_use]
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ipv6)),
    }
}

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

/// Proxy Protocol handling mode for accepted listener connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolMode {
    /// Do not expect a Proxy Protocol preface.
    #[default]
    Disabled,
    /// Require and parse HAProxy Proxy Protocol v1.
    V1,
    /// Require and parse HAProxy Proxy Protocol v2.
    V2,
}

/// Socket-family mode used when binding a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ListenerBindMode {
    /// Bind a single-stack listener using the concrete address family of bind_address.
    #[default]
    SingleStack,
    /// Bind one IPv6 socket intended to also accept IPv4 traffic where supported.
    DualStack,
    /// Bind an IPv6-only socket explicitly.
    Ipv6Only,
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
    /// Address-family behavior for the bound socket.
    pub bind_mode: ListenerBindMode,
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
    /// Proxy Protocol handling mode for accepted downstream connections.
    pub proxy_protocol: ProxyProtocolMode,
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
            bind_mode: ListenerBindMode::SingleStack,
            max_connections: 128,
            backlog: defaults.backlog,
            idle_timeout: Duration::from_secs(defaults.idle_timeout_secs),
            drain_timeout: Duration::from_secs(5),
            allow_unspecified_bind: false,
            proxy_protocol: ProxyProtocolMode::Disabled,
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

        match self.bind_mode {
            ListenerBindMode::SingleStack => {}
            ListenerBindMode::DualStack => {
                if !self.bind_address.is_ipv6() {
                    return Err(ListenerConfigError::DualStackRequiresIpv6Bind(self.bind_address));
                }
                if !self.bind_address.ip().is_unspecified() {
                    return Err(ListenerConfigError::DualStackRequiresIpv6Wildcard(
                        self.bind_address,
                    ));
                }
            }
            ListenerBindMode::Ipv6Only => {
                if !self.bind_address.is_ipv6() {
                    return Err(ListenerConfigError::Ipv6OnlyRequiresIpv6Bind(self.bind_address));
                }
            }
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
    /// Dual-stack listeners must bind an IPv6 socket.
    DualStackRequiresIpv6Bind(SocketAddr),
    /// Dual-stack listeners currently require the IPv6 wildcard address.
    DualStackRequiresIpv6Wildcard(SocketAddr),
    /// IPv6-only listeners must bind an IPv6 socket.
    Ipv6OnlyRequiresIpv6Bind(SocketAddr),
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
            Self::DualStackRequiresIpv6Bind(address) => write!(
                formatter,
                "dual_stack listener bind address {address} must use an IPv6 socket"
            ),
            Self::DualStackRequiresIpv6Wildcard(address) => write!(
                formatter,
                "dual_stack listener bind address {address} must use the IPv6 wildcard address [::]:port"
            ),
            Self::Ipv6OnlyRequiresIpv6Bind(address) => write!(
                formatter,
                "ipv6_only listener bind address {address} must use an IPv6 socket"
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

/// Explicit application transport protocol for an upstream target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTransport {
    Http1,
    Http2,
    Http3,
}

impl Default for UpstreamTransport {
    fn default() -> Self {
        Self::Http1
    }
}

/// Static upstream target used by the initial L4 proxy path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    /// Human-readable upstream name.
    pub name: String,
    /// Upstream TCP address.
    pub address: SocketAddr,
    /// Explicit upstream application transport.
    pub transport: UpstreamTransport,
}

impl UpstreamTarget {
    /// Creates an upstream target.
    #[must_use]
    pub fn new(name: impl Into<String>, address: SocketAddr) -> Self {
        Self {
            name: name.into(),
            address,
            transport: UpstreamTransport::Http1,
        }
    }

    /// Creates an upstream target with explicit transport selection.
    #[must_use]
    pub fn with_transport(
        name: impl Into<String>,
        address: SocketAddr,
        transport: UpstreamTransport,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            transport,
        }
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

    use super::{
        canonicalize_ip, ListenerBindMode, ListenerClass, ListenerConfig, ListenerConfigError,
        ProxyProtocolMode, TlsListenerConfig,
    };

    #[test]
    fn canonicalize_ip_flattens_ipv4_mapped_ipv6() {
        let mapped = "::ffff:192.0.2.10".parse::<IpAddr>().expect("mapped ip");

        assert_eq!(canonicalize_ip(mapped), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn foundation_local_uses_safe_defaults() {
        let config = ListenerConfig::foundation_local("public", ListenerClass::Public);

        assert_eq!(config.bind_address.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(!config.allow_unspecified_bind);
        assert_eq!(config.proxy_protocol, ProxyProtocolMode::Disabled);
        assert_eq!(config.bind_mode, ListenerBindMode::SingleStack);
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

    #[test]
    fn validate_rejects_dual_stack_on_ipv4_socket() {
        let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
        config.bind_mode = ListenerBindMode::DualStack;

        assert_eq!(
            config.validate(),
            Err(ListenerConfigError::DualStackRequiresIpv6Bind(config.bind_address))
        );
    }

    #[test]
    fn validate_rejects_dual_stack_on_specific_ipv6_socket() {
        let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
        config.bind_address = "[::1]:8080".parse().expect("ipv6 loopback address");
        config.bind_mode = ListenerBindMode::DualStack;

        assert_eq!(
            config.validate(),
            Err(ListenerConfigError::DualStackRequiresIpv6Wildcard(config.bind_address))
        );
    }

    #[test]
    fn validate_accepts_ipv6_only_listener() {
        let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
        config.bind_address = "[::1]:8080".parse().expect("ipv6 loopback address");
        config.bind_mode = ListenerBindMode::Ipv6Only;

        assert!(config.validate().is_ok());
    }
}
