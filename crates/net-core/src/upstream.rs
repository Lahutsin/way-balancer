use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;

const MAX_METADATA_VALUE_LEN: usize = 64;

/// Strong identifier for an upstream cluster.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpstreamClusterName(String);

impl UpstreamClusterName {
    /// Validates and creates a cluster name.
    pub fn new(value: impl Into<String>) -> Result<Self, UpstreamModelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(UpstreamModelError::EmptyClusterName);
        }
        Ok(Self(value))
    }

    /// Returns the cluster name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UpstreamClusterName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Strong identifier for an upstream endpoint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpstreamEndpointId(String);

impl UpstreamEndpointId {
    /// Validates and creates an endpoint identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, UpstreamModelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(UpstreamModelError::EmptyEndpointId);
        }
        Ok(Self(value))
    }

    /// Returns the endpoint identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UpstreamEndpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Bounded endpoint metadata used by routing and locality-aware features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointMetadata {
    /// Optional zone identifier.
    pub zone: Option<String>,
    /// Optional locality identifier.
    pub locality: Option<String>,
    /// Static endpoint weight placeholder for later balancing features.
    pub weight: u16,
}

impl Default for EndpointMetadata {
    fn default() -> Self {
        Self { zone: None, locality: None, weight: 1 }
    }
}

impl EndpointMetadata {
    /// Validates bounded metadata fields.
    pub fn validate(&self) -> Result<(), UpstreamModelError> {
        validate_metadata_field("zone", self.zone.as_deref())?;
        validate_metadata_field("locality", self.locality.as_deref())?;

        if self.weight == 0 {
            return Err(UpstreamModelError::ZeroEndpointWeight);
        }

        Ok(())
    }
}

/// Explicit endpoint readiness state for upstream selection decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    /// Endpoint can receive traffic.
    Ready,
    /// Endpoint is draining and should not receive new traffic.
    Draining,
    /// Endpoint is explicitly unavailable.
    Unavailable,
}

impl EndpointState {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Strong internal endpoint representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamEndpoint {
    id: UpstreamEndpointId,
    address: SocketAddr,
    state: EndpointState,
    metadata: EndpointMetadata,
}

impl UpstreamEndpoint {
    /// Creates and validates an upstream endpoint.
    pub fn new(
        id: UpstreamEndpointId,
        address: SocketAddr,
        state: EndpointState,
        metadata: EndpointMetadata,
    ) -> Result<Self, UpstreamModelError> {
        validate_endpoint_address(address)?;
        metadata.validate()?;

        Ok(Self { id, address, state, metadata })
    }

    /// Returns the endpoint identifier.
    #[must_use]
    pub fn id(&self) -> &UpstreamEndpointId {
        &self.id
    }

    /// Returns the upstream socket address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the explicit endpoint state.
    #[must_use]
    pub const fn state(&self) -> EndpointState {
        self.state
    }

    /// Returns the endpoint metadata.
    #[must_use]
    pub fn metadata(&self) -> &EndpointMetadata {
        &self.metadata
    }

    /// Creates a copy of the endpoint with a different explicit state.
    #[must_use]
    pub fn with_state(&self, state: EndpointState) -> Self {
        Self { id: self.id.clone(), address: self.address, state, metadata: self.metadata.clone() }
    }

    /// Re-validates an endpoint before registry insertion.
    pub fn validate(&self) -> Result<(), UpstreamModelError> {
        validate_endpoint_address(self.address)?;
        self.metadata.validate()
    }
}

/// Explicit aggregate cluster state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamClusterState {
    /// Cluster has no registered endpoints.
    Empty,
    /// Cluster has endpoints but none are ready for traffic.
    Unavailable { total_endpoints: usize },
    /// Cluster has one or more ready endpoints.
    Ready { total_endpoints: usize, ready_endpoints: usize },
}

/// Strong internal cluster model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamCluster {
    name: UpstreamClusterName,
    endpoints: Vec<UpstreamEndpoint>,
}

impl UpstreamCluster {
    /// Creates and validates a cluster from a bounded endpoint list.
    pub fn new(
        name: UpstreamClusterName,
        endpoints: Vec<UpstreamEndpoint>,
    ) -> Result<Self, UpstreamModelError> {
        validate_endpoint_uniqueness(&endpoints)?;
        Ok(Self { name, endpoints })
    }

    /// Returns the strong cluster name.
    #[must_use]
    pub fn name(&self) -> &UpstreamClusterName {
        &self.name
    }

    /// Returns the endpoint slice.
    #[must_use]
    pub fn endpoints(&self) -> &[UpstreamEndpoint] {
        &self.endpoints
    }

    /// Returns the explicit cluster state.
    #[must_use]
    pub fn state(&self) -> UpstreamClusterState {
        let total_endpoints = self.endpoints.len();
        if total_endpoints == 0 {
            return UpstreamClusterState::Empty;
        }

        let ready_endpoints =
            self.endpoints.iter().filter(|endpoint| endpoint.state.is_ready()).count();
        if ready_endpoints == 0 {
            UpstreamClusterState::Unavailable { total_endpoints }
        } else {
            UpstreamClusterState::Ready { total_endpoints, ready_endpoints }
        }
    }

    /// Adds a validated endpoint to the cluster.
    pub fn insert_endpoint(
        &mut self,
        endpoint: UpstreamEndpoint,
    ) -> Result<(), UpstreamModelError> {
        endpoint.validate()?;
        if self.endpoints.iter().any(|existing| existing.id == endpoint.id) {
            return Err(UpstreamModelError::DuplicateEndpointId(endpoint.id.to_string()));
        }
        self.endpoints.push(endpoint);
        Ok(())
    }

    /// Removes an endpoint from the cluster.
    #[must_use]
    pub fn remove_endpoint(
        &mut self,
        endpoint_id: &UpstreamEndpointId,
    ) -> Option<UpstreamEndpoint> {
        self.endpoints
            .iter()
            .position(|endpoint| endpoint.id() == endpoint_id)
            .map(|index| self.endpoints.remove(index))
    }

    /// Returns a cluster endpoint by identifier.
    #[must_use]
    pub fn endpoint(&self, endpoint_id: &UpstreamEndpointId) -> Option<&UpstreamEndpoint> {
        self.endpoints.iter().find(|endpoint| endpoint.id() == endpoint_id)
    }
}

/// Validation failures for the upstream model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamModelError {
    /// Cluster names must be non-empty.
    EmptyClusterName,
    /// Endpoint identifiers must be non-empty.
    EmptyEndpointId,
    /// Upstream addresses must not use port zero.
    ZeroPort(SocketAddr),
    /// Upstream addresses must not be unspecified.
    UnspecifiedAddress(SocketAddr),
    /// Metadata values are bounded.
    MetadataTooLong { field: &'static str, max_len: usize },
    /// Endpoint weights must be greater than zero.
    ZeroEndpointWeight,
    /// Cluster endpoint identifiers must be unique.
    DuplicateEndpointId(String),
}

impl fmt::Display for UpstreamModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyClusterName => {
                formatter.write_str("upstream cluster name must not be empty")
            }
            Self::EmptyEndpointId => formatter.write_str("upstream endpoint id must not be empty"),
            Self::ZeroPort(address) => {
                write!(formatter, "upstream endpoint address {address} must use a non-zero port")
            }
            Self::UnspecifiedAddress(address) => {
                write!(formatter, "upstream endpoint address {address} must not be unspecified")
            }
            Self::MetadataTooLong { field, max_len } => {
                write!(formatter, "endpoint metadata field {field} exceeds {max_len} characters")
            }
            Self::ZeroEndpointWeight => {
                formatter.write_str("endpoint weight must be greater than zero")
            }
            Self::DuplicateEndpointId(endpoint_id) => {
                write!(formatter, "duplicate upstream endpoint id {endpoint_id}")
            }
        }
    }
}

impl std::error::Error for UpstreamModelError {}

fn validate_endpoint_address(address: SocketAddr) -> Result<(), UpstreamModelError> {
    if address.port() == 0 {
        return Err(UpstreamModelError::ZeroPort(address));
    }
    if address.ip().is_unspecified() {
        return Err(UpstreamModelError::UnspecifiedAddress(address));
    }
    Ok(())
}

fn validate_metadata_field(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), UpstreamModelError> {
    if let Some(value) = value {
        if value.len() > MAX_METADATA_VALUE_LEN {
            return Err(UpstreamModelError::MetadataTooLong {
                field,
                max_len: MAX_METADATA_VALUE_LEN,
            });
        }
    }

    Ok(())
}

fn validate_endpoint_uniqueness(endpoints: &[UpstreamEndpoint]) -> Result<(), UpstreamModelError> {
    let mut seen = BTreeSet::new();
    for endpoint in endpoints {
        endpoint.validate()?;
        if !seen.insert(endpoint.id.clone()) {
            return Err(UpstreamModelError::DuplicateEndpointId(endpoint.id.to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName,
        UpstreamClusterState, UpstreamEndpoint, UpstreamEndpointId, UpstreamModelError,
    };

    fn endpoint(
        id: &str,
        address: SocketAddr,
        state: EndpointState,
    ) -> Result<UpstreamEndpoint, UpstreamModelError> {
        UpstreamEndpoint::new(
            UpstreamEndpointId::new(id)?,
            address,
            state,
            EndpointMetadata::default(),
        )
    }

    #[test]
    fn cluster_state_is_explicit_for_empty_and_unavailable_clusters(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let empty_cluster =
            UpstreamCluster::new(UpstreamClusterName::new("payments")?, Vec::new())?;
        assert_eq!(empty_cluster.state(), UpstreamClusterState::Empty);

        let unavailable_cluster = UpstreamCluster::new(
            UpstreamClusterName::new("payments")?,
            vec![
                endpoint(
                    "a",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                    EndpointState::Unavailable,
                )?,
                endpoint(
                    "b",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
                    EndpointState::Draining,
                )?,
            ],
        )?;

        assert_eq!(
            unavailable_cluster.state(),
            UpstreamClusterState::Unavailable { total_endpoints: 2 }
        );

        Ok(())
    }

    #[test]
    fn duplicate_endpoint_ids_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let result = UpstreamCluster::new(
            UpstreamClusterName::new("payments")?,
            vec![
                endpoint(
                    "a",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                    EndpointState::Ready,
                )?,
                endpoint(
                    "a",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
                    EndpointState::Ready,
                )?,
            ],
        );

        assert_eq!(result, Err(UpstreamModelError::DuplicateEndpointId(String::from("a"))));
        Ok(())
    }

    #[test]
    fn malformed_endpoint_definitions_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let result = UpstreamEndpoint::new(
            UpstreamEndpointId::new("a")?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            EndpointState::Ready,
            EndpointMetadata::default(),
        );

        assert_eq!(
            result,
            Err(UpstreamModelError::UnspecifiedAddress(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                8080,
            )))
        );
        Ok(())
    }
}
