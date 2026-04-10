use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{PolicyBindingConfig, WorkspaceConfigError, WorkspaceDefaultsConfig};

/// Declarative listener resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerResourceConfig {
    /// Stable listener name.
    pub name: String,
    /// Public or admin listener surface.
    #[serde(default)]
    pub class: ListenerClassConfig,
    /// Bound socket address.
    pub bind_address: SocketAddr,
    /// Listener protocol mode.
    #[serde(default)]
    pub protocol: ListenerProtocolConfig,
    /// Optional local TLS termination material for HTTPS listeners.
    #[serde(default)]
    pub tls_termination: Option<ListenerTlsTerminationConfig>,
    /// Explicit opt-in for unspecified bind addresses.
    #[serde(default)]
    pub allow_unspecified_bind: bool,
    /// Resource-specific max connections override.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Resource-specific backlog override.
    #[serde(default)]
    pub backlog: Option<u32>,
    /// Resource-specific idle timeout override in milliseconds.
    #[serde(default)]
    pub idle_timeout_ms: Option<u64>,
    /// Resource-specific drain timeout override in milliseconds.
    #[serde(default)]
    pub drain_timeout_ms: Option<u64>,
    /// Ordered route references evaluated for this listener.
    #[serde(default)]
    pub routes: Vec<String>,
    /// Attached named policy references.
    #[serde(default)]
    pub policies: PolicyBindingConfig,
    /// Admin-plane hardening policy for privileged listeners.
    #[serde(default, skip_serializing_if = "AdminListenerPolicyConfig::is_default")]
    pub admin: AdminListenerPolicyConfig,
}

impl ListenerResourceConfig {
    /// Creates a safe localhost-only foundation listener resource.
    #[must_use]
    pub fn foundation(name: impl Into<String>, class: ListenerClassConfig, port: u16) -> Self {
        Self {
            name: name.into(),
            class,
            bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            protocol: ListenerProtocolConfig::Tcp,
            tls_termination: None,
            allow_unspecified_bind: false,
            max_connections: None,
            backlog: None,
            idle_timeout_ms: None,
            drain_timeout_ms: None,
            routes: Vec::new(),
            policies: PolicyBindingConfig::default(),
            admin: AdminListenerPolicyConfig::default(),
        }
    }

    fn compile(
        &self,
        defaults: &WorkspaceDefaultsConfig,
    ) -> Result<lb_net_core::ListenerConfig, WorkspaceConfigError> {
        let listener_defaults = &defaults.listener;
        let compiled = lb_net_core::ListenerConfig {
            name: self.name.clone(),
            class: self.class.into(),
            bind_address: self.bind_address,
            max_connections: self.max_connections.unwrap_or(listener_defaults.max_connections),
            backlog: self.backlog.unwrap_or(listener_defaults.backlog),
            idle_timeout: Duration::from_millis(
                self.idle_timeout_ms.unwrap_or(listener_defaults.idle_timeout_ms),
            ),
            drain_timeout: Duration::from_millis(
                self.drain_timeout_ms.unwrap_or(listener_defaults.drain_timeout_ms),
            ),
            allow_unspecified_bind: self.allow_unspecified_bind
                || listener_defaults.allow_unspecified_bind,
            tls_termination: self.tls_termination.as_ref().map(|tls_termination| {
                lb_net_core::TlsListenerConfig {
                    cert_path: tls_termination.certificate_source.cert_path().to_owned(),
                    key_path: tls_termination.certificate_source.key_path().to_owned(),
                }
            }),
        };

        compiled.validate().map_err(WorkspaceConfigError::InvalidListenerConfig)?;
        Ok(compiled)
    }
}

/// Declarative admin-plane hardening policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminListenerPolicyConfig {
    /// Authentication and authorization model for admin requests.
    pub auth: AdminAuthPolicyConfig,
    /// Optional CIDR allow-list for admin-plane source addresses.
    pub allowed_source_cidrs: Vec<String>,
    /// Per-source request shaping for the admin plane.
    pub rate_limit: AdminRateLimitConfig,
    /// Audit retention controls for recent admin actions.
    pub audit: AdminAuditConfig,
}

impl Default for AdminListenerPolicyConfig {
    fn default() -> Self {
        Self {
            auth: AdminAuthPolicyConfig::default(),
            allowed_source_cidrs: Vec::new(),
            rate_limit: AdminRateLimitConfig::default(),
            audit: AdminAuditConfig::default(),
        }
    }
}

impl AdminListenerPolicyConfig {
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

/// Declarative admin-plane authn/authz model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AdminAuthPolicyConfig {
    /// Legacy shared bearer secret with explicit permissions.
    Bearer {
        #[serde(default = "default_admin_secret_env")]
        secret_env: String,
        #[serde(default = "default_admin_permissions")]
        permissions: Vec<AdminAuthorizationScopeConfig>,
    },
    /// Replay-resistant signed headers with per-operator permissions.
    SignedHeaders {
        operators: Vec<AdminOperatorConfig>,
        #[serde(default = "default_admin_clock_skew_secs")]
        max_clock_skew_secs: u64,
        #[serde(default = "default_admin_nonce_ttl_secs")]
        nonce_ttl_secs: u64,
    },
}

impl Default for AdminAuthPolicyConfig {
    fn default() -> Self {
        Self::Bearer {
            secret_env: default_admin_secret_env(),
            permissions: default_admin_permissions(),
        }
    }
}

/// Declarative admin operator for signed requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminOperatorConfig {
    /// Stable operator identifier carried in signed requests.
    pub id: String,
    /// Environment variable name used to resolve the shared signing secret.
    pub secret_env: String,
    /// Permissions granted to this operator.
    #[serde(default = "default_admin_permissions")]
    pub permissions: Vec<AdminAuthorizationScopeConfig>,
}

/// Declarative admin-plane permission scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuthorizationScopeConfig {
    Read,
    Audit,
    Write,
}

/// Declarative admin-plane per-source rate limiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminRateLimitConfig {
    /// Steady-state requests allowed per minute for each source.
    pub requests_per_minute: u32,
    /// Maximum short-term burst allowed for each source.
    pub burst: u32,
}

impl Default for AdminRateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 120,
            burst: 10,
        }
    }
}

/// Declarative admin-plane audit retention settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminAuditConfig {
    /// Number of recent audit events retained in-memory for inspection.
    pub max_retained_events: usize,
}

impl Default for AdminAuditConfig {
    fn default() -> Self {
        Self {
            max_retained_events: 64,
        }
    }
}

fn default_admin_secret_env() -> String {
    String::from("LB_CTL_ADMIN_SECRET")
}

fn default_admin_permissions() -> Vec<AdminAuthorizationScopeConfig> {
    vec![
        AdminAuthorizationScopeConfig::Read,
        AdminAuthorizationScopeConfig::Audit,
        AdminAuthorizationScopeConfig::Write,
    ]
}

const fn default_admin_clock_skew_secs() -> u64 {
    30
}

const fn default_admin_nonce_ttl_secs() -> u64 {
    120
}

/// Declarative local TLS termination for HTTPS listeners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerTlsTerminationConfig {
    /// Source of certificate material.
    pub certificate_source: ListenerCertificateSourceConfig,
    /// Additional SNI-targeted certificates layered on top of the default certificate.
    #[serde(default)]
    pub sni_certificates: Vec<ListenerTlsSniCertificateConfig>,
    /// TLS session resumption strategy for this listener.
    #[serde(default = "default_tls_session_resumption")]
    pub session_resumption: ListenerTlsSessionResumptionConfig,
    /// Minimum TLS version admitted by the listener.
    #[serde(default = "default_tls_minimum_version")]
    pub minimum_version: ListenerTlsMinimumVersionConfig,
    /// Ordered ALPN protocols advertised by the listener.
    #[serde(default = "default_tls_alpn_protocols")]
    pub alpn_protocols: Vec<ListenerAlpnProtocolConfig>,
}

fn default_tls_minimum_version() -> ListenerTlsMinimumVersionConfig {
    ListenerTlsMinimumVersionConfig::Tls12
}

fn default_tls_alpn_protocols() -> Vec<ListenerAlpnProtocolConfig> {
    vec![
        ListenerAlpnProtocolConfig::Http2,
        ListenerAlpnProtocolConfig::Http11,
    ]
}

fn default_tls_session_resumption() -> ListenerTlsSessionResumptionConfig {
    ListenerTlsSessionResumptionConfig::default()
}

/// Declarative TLS session resumption strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerTlsSessionResumptionConfig {
    /// Whether resumption is disabled, stateful, ticket-based, or both.
    pub mode: ListenerTlsSessionResumptionModeConfig,
    /// Stateful cache size when the selected mode uses in-memory session storage.
    pub session_cache_size: usize,
    /// Number of TLS 1.3 tickets sent when the selected mode issues tickets.
    pub tls13_ticket_count: usize,
}

impl Default for ListenerTlsSessionResumptionConfig {
    fn default() -> Self {
        Self {
            mode: ListenerTlsSessionResumptionModeConfig::Hybrid,
            session_cache_size: 256,
            tls13_ticket_count: 2,
        }
    }
}

/// Declarative session resumption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ListenerTlsSessionResumptionModeConfig {
    /// Disable stateful and ticket-based resumption.
    Disabled,
    /// Allow only in-memory stateful resumption.
    Stateful,
    /// Allow only ticket-based stateless resumption.
    Tickets,
    /// Allow both stateful and ticket-based resumption.
    #[default]
    Hybrid,
}

/// Declarative minimum TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ListenerTlsMinimumVersionConfig {
    /// Allow TLS 1.2 and TLS 1.3 handshakes.
    #[default]
    Tls12,
    /// Require TLS 1.3 handshakes.
    Tls13,
}

/// Declarative ALPN protocol advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerAlpnProtocolConfig {
    /// Advertise HTTP/2 via ALPN.
    Http2,
    /// Advertise HTTP/1.1 via ALPN.
    Http11,
}

impl ListenerAlpnProtocolConfig {
    #[must_use]
    pub fn wire_id(self) -> &'static [u8] {
        match self {
            Self::Http2 => b"h2",
            Self::Http11 => b"http/1.1",
        }
    }
}

/// Declarative SNI-targeted certificate mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerTlsSniCertificateConfig {
    /// Hostnames that should use this certificate during SNI resolution.
    pub server_names: Vec<String>,
    /// Source of certificate material for those hostnames.
    pub certificate_source: ListenerCertificateSourceConfig,
}

/// Declarative certificate material source for HTTPS listeners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ListenerCertificateSourceConfig {
    /// PEM certificate chain and PEM private key loaded from files.
    Files {
        cert_path: String,
        key_path: String,
        #[serde(default)]
        ocsp_path: Option<String>,
    },
}

impl ListenerCertificateSourceConfig {
    pub fn cert_path(&self) -> &str {
        match self {
            Self::Files { cert_path, .. } => cert_path,
        }
    }

    pub fn key_path(&self) -> &str {
        match self {
            Self::Files { key_path, .. } => key_path,
        }
    }

    pub fn ocsp_path(&self) -> Option<&str> {
        match self {
            Self::Files { ocsp_path, .. } => ocsp_path.as_deref(),
        }
    }
}

/// Declarative listener class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ListenerClassConfig {
    /// Public traffic listener.
    #[default]
    Public,
    /// Privileged admin listener.
    Admin,
}

impl From<ListenerClassConfig> for lb_net_core::ListenerClass {
    fn from(value: ListenerClassConfig) -> Self {
        match value {
            ListenerClassConfig::Public => Self::Public,
            ListenerClassConfig::Admin => Self::Admin,
        }
    }
}

/// Declarative listener protocol mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocolConfig {
    /// Transport-layer proxying.
    #[default]
    Tcp,
    /// HTTP/1.1 termination and forwarding.
    Http1,
    /// HTTPS termination and forwarding.
    Https,
    /// HTTP/2 or gRPC termination and forwarding.
    Http2,
    /// Future protocol auto-detection.
    Auto,
}

pub(crate) fn compile_listeners(
    listeners: &[ListenerResourceConfig],
    defaults: &WorkspaceDefaultsConfig,
) -> Result<Vec<lb_net_core::ListenerConfig>, WorkspaceConfigError> {
    let mut seen = BTreeSet::new();
    let mut compiled = Vec::with_capacity(listeners.len());

    for listener in listeners {
        if !seen.insert(listener.name.clone()) {
            return Err(WorkspaceConfigError::DuplicateListenerName(listener.name.clone()));
        }
        compiled.push(listener.compile(defaults)?);
    }

    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        AdminListenerPolicyConfig, compile_listeners, ListenerAlpnProtocolConfig,
        ListenerCertificateSourceConfig, ListenerClassConfig, ListenerResourceConfig,
        ListenerTlsMinimumVersionConfig, ListenerTlsSessionResumptionConfig,
        ListenerTlsSessionResumptionModeConfig, ListenerTlsSniCertificateConfig,
        ListenerTlsTerminationConfig,
    };
    use crate::{WorkspaceConfigError, WorkspaceDefaultsConfig};

    #[test]
    fn compile_listeners_rejects_duplicate_names() {
        let listeners = vec![
            ListenerResourceConfig::foundation("public", ListenerClassConfig::Public, 8080),
            ListenerResourceConfig::foundation("public", ListenerClassConfig::Admin, 9090),
        ];

        let result = compile_listeners(&listeners, &WorkspaceDefaultsConfig::default());

        assert_eq!(
            result,
            Err(WorkspaceConfigError::DuplicateListenerName(String::from("public")))
        );
    }

    #[test]
    fn listener_compile_applies_default_values() -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerResourceConfig {
            name: String::from("public"),
            class: ListenerClassConfig::Public,
            bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            protocol: super::ListenerProtocolConfig::Http1,
            tls_termination: None,
            allow_unspecified_bind: false,
            max_connections: None,
            backlog: None,
            idle_timeout_ms: None,
            drain_timeout_ms: None,
            routes: Vec::new(),
            policies: crate::PolicyBindingConfig::default(),
            admin: AdminListenerPolicyConfig::default(),
        };

        let compiled = compile_listeners(&[listener], &WorkspaceDefaultsConfig::default())?;

        assert_eq!(compiled[0].max_connections, 128);
        assert_eq!(compiled[0].backlog, 1024);
        Ok(())
    }

    #[test]
    fn https_listener_compile_preserves_tls_material() -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerResourceConfig {
            name: String::from("public-https"),
            class: ListenerClassConfig::Public,
            bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443),
            protocol: super::ListenerProtocolConfig::Https,
            tls_termination: Some(ListenerTlsTerminationConfig {
                certificate_source: ListenerCertificateSourceConfig::Files {
                    cert_path: String::from("certs/server.pem"),
                    key_path: String::from("certs/server.key"),
                    ocsp_path: Some(String::from("certs/server.ocsp")),
                },
                sni_certificates: vec![ListenerTlsSniCertificateConfig {
                    server_names: vec![String::from("tenant.example")],
                    certificate_source: ListenerCertificateSourceConfig::Files {
                        cert_path: String::from("certs/tenant.pem"),
                        key_path: String::from("certs/tenant.key"),
                        ocsp_path: None,
                    },
                }],
                session_resumption: ListenerTlsSessionResumptionConfig {
                    mode: ListenerTlsSessionResumptionModeConfig::Stateful,
                    session_cache_size: 64,
                    tls13_ticket_count: 0,
                },
                minimum_version: ListenerTlsMinimumVersionConfig::Tls13,
                alpn_protocols: vec![ListenerAlpnProtocolConfig::Http11],
            }),
            allow_unspecified_bind: false,
            max_connections: None,
            backlog: None,
            idle_timeout_ms: None,
            drain_timeout_ms: None,
            routes: vec![String::from("api")],
            policies: crate::PolicyBindingConfig::default(),
            admin: AdminListenerPolicyConfig::default(),
        };

        let compiled = compile_listeners(&[listener], &WorkspaceDefaultsConfig::default())?;

        assert_eq!(
            compiled[0].tls_termination.as_ref().map(|tls| tls.cert_path.as_str()),
            Some("certs/server.pem")
        );
        assert_eq!(
            compiled[0].tls_termination.as_ref().map(|tls| tls.key_path.as_str()),
            Some("certs/server.key")
        );
        Ok(())
    }

    #[test]
    fn tls_termination_defaults_preserve_modern_compatibility() {
        let config = ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: ListenerTlsSessionResumptionConfig::default(),
            minimum_version: ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![
                ListenerAlpnProtocolConfig::Http2,
                ListenerAlpnProtocolConfig::Http11,
            ],
        };

        assert_eq!(config.minimum_version, ListenerTlsMinimumVersionConfig::Tls12);
        assert_eq!(
            config.alpn_protocols,
            vec![
                ListenerAlpnProtocolConfig::Http2,
                ListenerAlpnProtocolConfig::Http11,
            ]
        );
        assert_eq!(
            config.session_resumption,
            ListenerTlsSessionResumptionConfig::default()
        );
    }
}
