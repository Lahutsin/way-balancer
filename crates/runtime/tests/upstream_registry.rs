use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use lb_net_core::{
    EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName, UpstreamClusterState,
    UpstreamEndpoint, UpstreamEndpointId,
};
use lb_runtime::{EndpointRegistry, EndpointRegistryError};

fn endpoint(
    id: &str,
    port: u16,
    state: EndpointState,
) -> Result<UpstreamEndpoint, Box<dyn std::error::Error>> {
    Ok(UpstreamEndpoint::new(
        UpstreamEndpointId::new(id)?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        state,
        EndpointMetadata::default(),
    )?)
}

#[test]
fn registry_lifecycle_tracks_cluster_and_endpoint_state() -> Result<(), Box<dyn std::error::Error>>
{
    let registry = EndpointRegistry::new();
    let cluster_name = UpstreamClusterName::new("payments")?;
    registry.insert_cluster(UpstreamCluster::new(cluster_name.clone(), Vec::new())?)?;

    assert_eq!(registry.cluster_state(&cluster_name)?, UpstreamClusterState::Empty);

    registry.insert_endpoint(&cluster_name, endpoint("a", 8080, EndpointState::Ready)?)?;

    assert_eq!(
        registry.cluster_state(&cluster_name)?,
        UpstreamClusterState::Ready { total_endpoints: 1, ready_endpoints: 1 }
    );

    let removed = registry.remove_endpoint(&cluster_name, &UpstreamEndpointId::new("a")?)?;
    assert_eq!(removed.id().as_str(), "a");
    assert_eq!(registry.cluster_state(&cluster_name)?, UpstreamClusterState::Empty);
    assert!(registry.remove_cluster(&cluster_name).is_some());
    assert!(registry.cluster(&cluster_name).is_none());

    Ok(())
}

#[test]
fn registry_reports_unavailable_clusters_explicitly() -> Result<(), Box<dyn std::error::Error>> {
    let registry = EndpointRegistry::new();
    let cluster_name = UpstreamClusterName::new("search")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![
            endpoint("a", 8080, EndpointState::Unavailable)?,
            endpoint("b", 8081, EndpointState::Draining)?,
        ],
    )?)?;

    assert_eq!(
        registry.cluster_state(&cluster_name)?,
        UpstreamClusterState::Unavailable { total_endpoints: 2 }
    );

    let metrics = registry.metrics();
    assert_eq!(metrics.cluster_count, 1);
    assert_eq!(metrics.endpoint_count, 2);
    assert_eq!(metrics.unavailable_endpoint_count, 2);

    Ok(())
}

#[test]
fn registry_rejects_duplicate_endpoint_ids() -> Result<(), Box<dyn std::error::Error>> {
    let registry = EndpointRegistry::new();
    let cluster_name = UpstreamClusterName::new("payments")?;
    registry.insert_cluster(UpstreamCluster::new(cluster_name.clone(), Vec::new())?)?;
    registry.insert_endpoint(&cluster_name, endpoint("a", 8080, EndpointState::Ready)?)?;

    let result =
        registry.insert_endpoint(&cluster_name, endpoint("a", 8081, EndpointState::Ready)?);

    assert_eq!(
        result,
        Err(EndpointRegistryError::DuplicateEndpoint {
            cluster: cluster_name,
            endpoint_id: UpstreamEndpointId::new("a")?,
        })
    );
    assert_eq!(registry.metrics().invalid_definition_count, 1);
    Ok(())
}
