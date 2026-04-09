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

/// Declarative local TLS termination for HTTPS listeners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerTlsTerminationConfig {
    /// Source of certificate material.
    pub certificate_source: ListenerCertificateSourceConfig,
}

/// Declarative certificate material source for HTTPS listeners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ListenerCertificateSourceConfig {
    /// PEM certificate chain and PEM private key loaded from files.
    Files { cert_path: String, key_path: String },
}

impl ListenerCertificateSourceConfig {
    pub(crate) fn cert_path(&self) -> &str {
        match self {
            Self::Files { cert_path, .. } => cert_path,
        }
    }

    pub(crate) fn key_path(&self) -> &str {
        match self {
            Self::Files { key_path, .. } => key_path,
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
        compile_listeners, ListenerCertificateSourceConfig, ListenerClassConfig,
        ListenerResourceConfig, ListenerTlsTerminationConfig,
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
                },
            }),
            allow_unspecified_bind: false,
            max_connections: None,
            backlog: None,
            idle_timeout_ms: None,
            drain_timeout_ms: None,
            routes: vec![String::from("api")],
            policies: crate::PolicyBindingConfig::default(),
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
}
