use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::PolicyBindingConfig;

/// Declarative cluster configuration compiled into strong internal types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamClusterConfig {
    /// Human-readable cluster name.
    pub name: String,
    /// Explicit application transport protocol for upstream requests.
    #[serde(default)]
    pub transport: UpstreamTransportConfig,
    /// Static endpoint definitions.
    pub endpoints: Vec<UpstreamEndpointConfig>,
    /// Optional dynamic endpoint discovery source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoverySourceConfig>,
    /// Declarative cluster traffic policy.
    #[serde(default)]
    pub traffic_policy: UpstreamTrafficPolicyConfig,
    /// Attached named policy references.
    #[serde(default)]
    pub policies: PolicyBindingConfig,
}

/// Declarative upstream application transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamTransportConfig {
    /// Proxy requests using an HTTP/1 upstream transport.
    #[default]
    Http1,
    /// Proxy requests using an HTTP/2 upstream transport.
    Http2,
    /// Proxy requests using an HTTP/3 upstream transport.
    Http3,
}

impl From<UpstreamTransportConfig> for lb_net_core::UpstreamTransport {
    fn from(value: UpstreamTransportConfig) -> Self {
        match value {
            UpstreamTransportConfig::Http1 => Self::Http1,
            UpstreamTransportConfig::Http2 => Self::Http2,
            UpstreamTransportConfig::Http3 => Self::Http3,
        }
    }
}

/// Declarative dynamic discovery source model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DiscoverySourceConfig {
    /// Resolve A/AAAA records for a fixed host and port.
    DnsAaaa {
        hostname: String,
        port: u16,
        #[serde(default)]
        min_refresh_secs: u64,
    },
    /// Resolve SRV records and map targets to endpoint addresses.
    DnsSrv {
        service: String,
        #[serde(default)]
        min_refresh_secs: u64,
    },
    /// Consume Kubernetes EndpointSlice updates for one Service.
    KubernetesEndpointSlice {
        namespace: String,
        service: String,
    },
    /// Consume Consul-like service catalog updates.
    ConsulLike {
        service: String,
        datacenter: Option<String>,
    },
}

/// Declarative cluster traffic policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamTrafficPolicyConfig {
    /// Selected balancing algorithm.
    pub algorithm: LoadBalancingAlgorithmConfig,
    /// Locality preference mode.
    pub locality: LocalityRoutingConfig,
    /// Explicit no-healthy fallback mode.
    pub no_healthy_fallback: NoHealthyFallbackConfig,
    /// Optional deterministic session-affinity policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affinity: Option<AffinityPolicyConfig>,
}

/// Declarative session-affinity policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AffinityPolicyConfig {
    /// Hash a request header value to a deterministic upstream endpoint.
    HeaderHash {
        /// Header name to hash.
        header_name: String,
        /// Behavior when the preferred endpoint is unavailable.
        #[serde(default)]
        fallback: AffinityFallbackConfig,
    },
    /// Hash a cookie value to a deterministic upstream endpoint.
    CookieHash {
        /// Cookie name to hash.
        cookie_name: String,
        /// Behavior when the preferred endpoint is unavailable.
        #[serde(default)]
        fallback: AffinityFallbackConfig,
    },
}

/// Declarative affinity fallback behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffinityFallbackConfig {
    /// Fall back to normal healthy endpoint selection.
    #[default]
    BalanceHealthy,
}

/// Declarative balancing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithmConfig {
    /// Deterministic round-robin.
    #[default]
    RoundRobin,
    /// Smooth weighted round-robin.
    WeightedRoundRobin,
    /// Deterministic power-of-two choices.
    PowerOfTwoChoices,
}

/// Declarative locality policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalityRoutingConfig {
    /// No locality preference.
    #[default]
    Disabled,
    /// Prefer locality.
    PreferLocality,
    /// Prefer zone.
    PreferZone,
    /// Prefer locality, then zone.
    PreferLocalityThenZone,
}

/// Declarative all-unhealthy fallback policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoHealthyFallbackConfig {
    /// Fail selection when no healthy endpoints remain.
    #[default]
    Fail,
    /// Permit unhealthy fallback as an explicit escape hatch.
    IncludeUnhealthy,
}

/// Declarative endpoint definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamEndpointConfig {
    /// Stable endpoint identifier.
    pub id: String,
    /// Endpoint socket address.
    pub address: SocketAddr,
    /// Explicit readiness placeholder.
    #[serde(default)]
    pub state: EndpointStateConfig,
    /// Optional zone hint.
    pub zone: Option<String>,
    /// Optional locality hint.
    pub locality: Option<String>,
    /// Static endpoint weight placeholder.
    pub weight: u16,
}

impl UpstreamEndpointConfig {
    /// Creates a minimal ready endpoint config.
    #[must_use]
    pub fn foundation(id: impl Into<String>, address: SocketAddr) -> Self {
        Self {
            id: id.into(),
            address,
            state: EndpointStateConfig::Ready,
            zone: None,
            locality: None,
            weight: 1,
        }
    }

    fn compile(&self) -> Result<lb_net_core::UpstreamEndpoint, WorkspaceConfigError> {
        let metadata = lb_net_core::EndpointMetadata {
            zone: self.zone.clone(),
            locality: self.locality.clone(),
            weight: self.weight,
        };
        lb_net_core::UpstreamEndpoint::new(
            lb_net_core::UpstreamEndpointId::new(self.id.clone())?,
            self.address,
            self.state.into(),
            metadata,
        )
        .map_err(WorkspaceConfigError::InvalidUpstreamModel)
    }
}

/// Declarative endpoint readiness state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointStateConfig {
    /// Endpoint can receive traffic.
    #[default]
    Ready,
    /// Endpoint drains in-flight traffic.
    Draining,
    /// Endpoint is explicitly unavailable.
    Unavailable,
}

impl From<EndpointStateConfig> for lb_net_core::EndpointState {
    fn from(value: EndpointStateConfig) -> Self {
        match value {
            EndpointStateConfig::Ready => Self::Ready,
            EndpointStateConfig::Draining => Self::Draining,
            EndpointStateConfig::Unavailable => Self::Unavailable,
        }
    }
}

/// Workspace configuration validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceConfigError {
    /// Listener names must be unique.
    DuplicateListenerName(String),
    /// Cluster names must be unique.
    DuplicateClusterName(String),
    /// Route names must be unique.
    DuplicateRouteName(String),
    /// Listener configuration failed strong validation.
    InvalidListenerConfig(lb_net_core::ListenerConfigError),
    /// Route names must not be empty.
    EmptyRouteName,
    /// Path-prefix routes must provide a non-empty prefix.
    EmptyRoutePrefix(String),
    /// Route hostname filters must be syntactically valid.
    InvalidRouteHostname(String),
    /// Route method filters must be syntactically valid.
    InvalidRouteMethod(String),
    /// Route header matchers are invalid.
    InvalidRouteHeader(String),
    /// Route query matchers are invalid.
    InvalidRouteQuery(String),
    /// Route content-type matchers are invalid.
    InvalidRouteContentType(String),
    /// Route gRPC service matchers are invalid.
    InvalidRouteGrpcService(String),
    /// Route gRPC method matchers are invalid.
    InvalidRouteGrpcMethod(String),
    /// Route source CIDR matchers are invalid.
    InvalidRouteSourceCidr(String),
    /// Strong upstream model validation failed.
    InvalidUpstreamModel(lb_net_core::UpstreamModelError),
}

impl fmt::Display for WorkspaceConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateListenerName(listener_name) => {
                write!(formatter, "duplicate listener name {listener_name}")
            }
            Self::DuplicateClusterName(cluster_name) => {
                write!(formatter, "duplicate upstream cluster name {cluster_name}")
            }
            Self::DuplicateRouteName(route_name) => {
                write!(formatter, "duplicate route name {route_name}")
            }
            Self::InvalidListenerConfig(error) => {
                write!(formatter, "invalid listener config: {error}")
            }
            Self::EmptyRouteName => formatter.write_str("route name must not be empty"),
            Self::EmptyRoutePrefix(route_name) => {
                write!(formatter, "route {route_name} must declare a non-empty path prefix")
            }
            Self::InvalidRouteHostname(route_name) => {
                write!(formatter, "route {route_name} must declare only valid hostnames")
            }
            Self::InvalidRouteMethod(route_name) => {
                write!(formatter, "route {route_name} must declare only valid HTTP methods")
            }
            Self::InvalidRouteHeader(route_name) => {
                write!(formatter, "route {route_name} must declare only valid header matchers")
            }
            Self::InvalidRouteQuery(route_name) => {
                write!(formatter, "route {route_name} must declare only valid query matchers")
            }
            Self::InvalidRouteContentType(route_name) => {
                write!(formatter, "route {route_name} must declare only valid content types")
            }
            Self::InvalidRouteGrpcService(route_name) => {
                write!(formatter, "route {route_name} must declare only valid gRPC service matchers")
            }
            Self::InvalidRouteGrpcMethod(route_name) => {
                write!(formatter, "route {route_name} must declare only valid gRPC method matchers")
            }
            Self::InvalidRouteSourceCidr(route_name) => {
                write!(formatter, "route {route_name} must declare only valid source CIDRs")
            }
            Self::InvalidUpstreamModel(error) => {
                write!(formatter, "invalid upstream model: {error}")
            }
        }
    }
}

impl std::error::Error for WorkspaceConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidListenerConfig(error) => Some(error),
            Self::InvalidUpstreamModel(error) => Some(error),
            Self::DuplicateListenerName(_)
            | Self::DuplicateClusterName(_)
            | Self::DuplicateRouteName(_)
            | Self::EmptyRouteName
            | Self::EmptyRoutePrefix(_)
            | Self::InvalidRouteHostname(_)
            | Self::InvalidRouteMethod(_)
            | Self::InvalidRouteHeader(_)
            | Self::InvalidRouteQuery(_)
            | Self::InvalidRouteContentType(_)
            | Self::InvalidRouteGrpcService(_)
            | Self::InvalidRouteGrpcMethod(_)
            | Self::InvalidRouteSourceCidr(_) => None,
        }
    }
}

impl From<lb_net_core::UpstreamModelError> for WorkspaceConfigError {
    fn from(value: lb_net_core::UpstreamModelError) -> Self {
        Self::InvalidUpstreamModel(value)
    }
}

pub(crate) fn compile_clusters(
    clusters: &[UpstreamClusterConfig],
) -> Result<Vec<lb_net_core::UpstreamCluster>, WorkspaceConfigError> {
    let mut seen = BTreeSet::new();
    let mut compiled = Vec::with_capacity(clusters.len());

    for cluster in clusters {
        let cluster_name = lb_net_core::UpstreamClusterName::new(cluster.name.clone())?;
        if !seen.insert(cluster_name.clone()) {
            return Err(WorkspaceConfigError::DuplicateClusterName(cluster.name.clone()));
        }

        let mut endpoints = Vec::with_capacity(cluster.endpoints.len());
        for endpoint in &cluster.endpoints {
            endpoints.push(endpoint.compile()?);
        }

        compiled.push(
            lb_net_core::UpstreamCluster::new(cluster_name, endpoints)
                .map_err(WorkspaceConfigError::InvalidUpstreamModel)?,
        );
    }

    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        compile_clusters, AffinityFallbackConfig, AffinityPolicyConfig, EndpointStateConfig,
        UpstreamClusterConfig, UpstreamEndpointConfig, UpstreamTrafficPolicyConfig,
        UpstreamTransportConfig,
        WorkspaceConfigError,
    };

    #[test]
    fn compile_clusters_rejects_duplicate_cluster_names() {
        let clusters = vec![
            UpstreamClusterConfig {
                name: String::from("payments"),
                transport: UpstreamTransportConfig::Http1,
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "a",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                )],
                discovery: None,
                traffic_policy: UpstreamTrafficPolicyConfig::default(),
                policies: crate::PolicyBindingConfig::default(),
            },
            UpstreamClusterConfig {
                name: String::from("payments"),
                transport: UpstreamTransportConfig::Http1,
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "b",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
                )],
                discovery: None,
                traffic_policy: UpstreamTrafficPolicyConfig::default(),
                policies: crate::PolicyBindingConfig::default(),
            },
        ];

        let result = compile_clusters(&clusters);

        assert_eq!(
            result,
            Err(WorkspaceConfigError::DuplicateClusterName(String::from("payments")))
        );
    }

    #[test]
    fn foundation_endpoint_and_cluster_compile_into_strong_models(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = UpstreamEndpointConfig::foundation(
            "payments-a",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        );
        let compiled_endpoint = endpoint.clone().compile()?;

        assert_eq!(compiled_endpoint.id().as_str(), "payments-a");
        assert_eq!(compiled_endpoint.state(), lb_net_core::EndpointState::Ready);

        let clusters = compile_clusters(&[UpstreamClusterConfig {
            name: String::from("payments"),
            transport: UpstreamTransportConfig::Http1,
            endpoints: vec![endpoint],
            discovery: None,
            traffic_policy: UpstreamTrafficPolicyConfig::default(),
            policies: crate::PolicyBindingConfig::default(),
        }])?;

        assert_eq!(clusters[0].name().as_str(), "payments");
        assert_eq!(clusters[0].endpoints().len(), 1);
        Ok(())
    }

    #[test]
    fn invalid_upstream_model_errors_surface_display_and_source() {
        let result = UpstreamEndpointConfig {
            id: String::new(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            state: EndpointStateConfig::Ready,
            zone: None,
            locality: None,
            weight: 0,
        }
        .compile();

        let error = result.err();
        assert!(error.is_some(), "invalid endpoint should fail strong model validation");
        let Some(error) = error else {
            return;
        };

        assert!(error.to_string().contains("invalid upstream model"));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn traffic_policy_parses_cookie_affinity() -> Result<(), Box<dyn std::error::Error>> {
        let policy = serde_json::from_str::<UpstreamTrafficPolicyConfig>(
            r#"{
                "algorithm": "round_robin",
                "locality": "disabled",
                "no_healthy_fallback": "fail",
                "affinity": {
                    "type": "cookie_hash",
                    "cookie_name": "session_id",
                    "fallback": "balance_healthy"
                }
            }"#,
        )?;

        assert_eq!(
            policy.affinity,
            Some(AffinityPolicyConfig::CookieHash {
                cookie_name: String::from("session_id"),
                fallback: AffinityFallbackConfig::BalanceHealthy,
            })
        );
        Ok(())
    }

    #[test]
    fn upstream_transport_parses_http3() -> Result<(), Box<dyn std::error::Error>> {
        let cluster = serde_json::from_str::<UpstreamClusterConfig>(
            r#"{
                "name": "edge-h3",
                "transport": "http3",
                "endpoints": [
                    {
                        "id": "a",
                        "address": "127.0.0.1:8443",
                        "weight": 1
                    }
                ]
            }"#,
        )?;

        assert_eq!(cluster.transport, UpstreamTransportConfig::Http3);
        Ok(())
    }
}
