use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Observable registry metrics snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EndpointRegistryMetrics {
    /// Number of clusters registered.
    pub cluster_count: u64,
    /// Total number of endpoints across all clusters.
    pub endpoint_count: u64,
    /// Number of explicitly unavailable or draining endpoints.
    pub unavailable_endpoint_count: u64,
    /// Number of invalid definitions rejected by the registry.
    pub invalid_definition_count: u64,
}

/// Errors produced by the in-memory endpoint registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointRegistryError {
    /// Cluster definitions must be unique.
    DuplicateCluster(lb_net_core::UpstreamClusterName),
    /// Endpoint definitions must be unique within a cluster.
    DuplicateEndpoint {
        cluster: lb_net_core::UpstreamClusterName,
        endpoint_id: lb_net_core::UpstreamEndpointId,
    },
    /// Requested cluster does not exist.
    ClusterNotFound(lb_net_core::UpstreamClusterName),
    /// Requested endpoint does not exist.
    EndpointNotFound {
        cluster: lb_net_core::UpstreamClusterName,
        endpoint_id: lb_net_core::UpstreamEndpointId,
    },
    /// Strong model validation rejected the definition.
    InvalidDefinition(lb_net_core::UpstreamModelError),
}

impl fmt::Display for EndpointRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCluster(cluster) => {
                write!(formatter, "duplicate cluster registration for {cluster}")
            }
            Self::DuplicateEndpoint { cluster, endpoint_id } => {
                write!(formatter, "duplicate endpoint {endpoint_id} for cluster {cluster}")
            }
            Self::ClusterNotFound(cluster) => write!(formatter, "cluster {cluster} was not found"),
            Self::EndpointNotFound { cluster, endpoint_id } => {
                write!(formatter, "endpoint {endpoint_id} was not found in cluster {cluster}")
            }
            Self::InvalidDefinition(error) => {
                write!(formatter, "invalid upstream definition: {error}")
            }
        }
    }
}

impl std::error::Error for EndpointRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidDefinition(error) => Some(error),
            _ => None,
        }
    }
}

/// In-memory registry for clusters and their endpoints.
#[derive(Debug, Default)]
pub struct EndpointRegistry {
    clusters: RwLock<BTreeMap<lb_net_core::UpstreamClusterName, lb_net_core::UpstreamCluster>>,
    invalid_definition_count: AtomicU64,
}

impl EndpointRegistry {
    /// Creates an empty endpoint registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new cluster into the registry.
    pub fn insert_cluster(
        &self,
        cluster: lb_net_core::UpstreamCluster,
    ) -> Result<(), EndpointRegistryError> {
        let mut clusters = self.clusters.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster_name = cluster.name().clone();
        if clusters.contains_key(&cluster_name) {
            self.increment_invalid_definition_count();
            return Err(EndpointRegistryError::DuplicateCluster(cluster_name));
        }

        clusters.insert(cluster_name, cluster);
        Ok(())
    }

    /// Removes a cluster from the registry.
    #[must_use]
    pub fn remove_cluster(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
    ) -> Option<lb_net_core::UpstreamCluster> {
        let mut clusters = self.clusters.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        clusters.remove(cluster_name)
    }

    /// Inserts an endpoint into an existing cluster.
    pub fn insert_endpoint(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint: lb_net_core::UpstreamEndpoint,
    ) -> Result<(), EndpointRegistryError> {
        let mut clusters = self.clusters.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(cluster) = clusters.get_mut(cluster_name) else {
            return Err(EndpointRegistryError::ClusterNotFound(cluster_name.clone()));
        };
        let endpoint_id = endpoint.id().clone();
        match cluster.insert_endpoint(endpoint) {
            Ok(()) => Ok(()),
            Err(lb_net_core::UpstreamModelError::DuplicateEndpointId(_)) => {
                self.increment_invalid_definition_count();
                Err(EndpointRegistryError::DuplicateEndpoint {
                    cluster: cluster_name.clone(),
                    endpoint_id,
                })
            }
            Err(error) => {
                self.increment_invalid_definition_count();
                Err(EndpointRegistryError::InvalidDefinition(error))
            }
        }
    }

    /// Removes an endpoint from a cluster.
    pub fn remove_endpoint(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<lb_net_core::UpstreamEndpoint, EndpointRegistryError> {
        let mut clusters = self.clusters.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(cluster) = clusters.get_mut(cluster_name) else {
            return Err(EndpointRegistryError::ClusterNotFound(cluster_name.clone()));
        };
        cluster.remove_endpoint(endpoint_id).ok_or_else(|| {
            EndpointRegistryError::EndpointNotFound {
                cluster: cluster_name.clone(),
                endpoint_id: endpoint_id.clone(),
            }
        })
    }

    /// Returns a cluster snapshot if present.
    #[must_use]
    pub fn cluster(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
    ) -> Option<lb_net_core::UpstreamCluster> {
        let clusters = self.clusters.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        clusters.get(cluster_name).cloned()
    }

    /// Returns the explicit state for a given cluster.
    pub fn cluster_state(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
    ) -> Result<lb_net_core::UpstreamClusterState, EndpointRegistryError> {
        let clusters = self.clusters.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster = clusters
            .get(cluster_name)
            .ok_or_else(|| EndpointRegistryError::ClusterNotFound(cluster_name.clone()))?;
        Ok(cluster.state())
    }

    /// Returns aggregate registry metrics.
    #[must_use]
    pub fn metrics(&self) -> EndpointRegistryMetrics {
        let clusters = self.clusters.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut endpoint_count = 0_u64;
        let mut unavailable_endpoint_count = 0_u64;

        for cluster in clusters.values() {
            endpoint_count += cluster.endpoints().len() as u64;
            unavailable_endpoint_count +=
                cluster.endpoints().iter().filter(|endpoint| !endpoint.state().is_ready()).count()
                    as u64;
        }

        EndpointRegistryMetrics {
            cluster_count: clusters.len() as u64,
            endpoint_count,
            unavailable_endpoint_count,
            invalid_definition_count: self.invalid_definition_count.load(Ordering::SeqCst),
        }
    }

    fn increment_invalid_definition_count(&self) {
        self.invalid_definition_count.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{EndpointRegistry, EndpointRegistryError};

    fn cluster_name(name: &str) -> Result<lb_net_core::UpstreamClusterName, Box<dyn std::error::Error>> {
        Ok(lb_net_core::UpstreamClusterName::new(String::from(name))?)
    }

    fn endpoint_id(id: &str) -> Result<lb_net_core::UpstreamEndpointId, Box<dyn std::error::Error>> {
        Ok(lb_net_core::UpstreamEndpointId::new(String::from(id))?)
    }

    fn endpoint(id: &str, port: u16) -> Result<lb_net_core::UpstreamEndpoint, Box<dyn std::error::Error>> {
        Ok(lb_net_core::UpstreamEndpoint::new(
            endpoint_id(id)?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            lb_net_core::EndpointState::Ready,
            lb_net_core::EndpointMetadata { zone: None, locality: None, weight: 1 },
        )?)
    }

    fn cluster(name: &str) -> Result<lb_net_core::UpstreamCluster, Box<dyn std::error::Error>> {
        Ok(lb_net_core::UpstreamCluster::new(cluster_name(name)?, vec![endpoint("a", 9000)?])?)
    }

    #[test]
    fn remove_and_lookup_missing_items_are_explicit() -> Result<(), Box<dyn std::error::Error>> {
        let registry = EndpointRegistry::new();
        let payments = cluster_name("payments")?;
        let missing = endpoint_id("missing")?;

        assert!(registry.remove_cluster(&payments).is_none());
        assert_eq!(registry.cluster(&payments), None);
        assert!(matches!(
            registry.cluster_state(&payments),
            Err(EndpointRegistryError::ClusterNotFound(name)) if name == payments
        ));
        assert!(matches!(
            registry.remove_endpoint(&payments, &missing),
            Err(EndpointRegistryError::ClusterNotFound(name)) if name == payments
        ));
        Ok(())
    }

    #[test]
    fn duplicate_cluster_and_endpoint_increment_invalid_definition_count(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = EndpointRegistry::new();
        let registered_cluster = cluster("payments")?;
        let payments = registered_cluster.name().clone();
        registry.insert_cluster(registered_cluster)?;

        assert!(matches!(
            registry.insert_cluster(cluster("payments")?),
            Err(EndpointRegistryError::DuplicateCluster(name)) if name == payments
        ));

        assert!(matches!(
            registry.insert_endpoint(&payments, endpoint("a", 9001)?),
            Err(EndpointRegistryError::DuplicateEndpoint { cluster, .. }) if cluster == payments
        ));

        assert_eq!(registry.metrics().invalid_definition_count, 2);
        Ok(())
    }
}
