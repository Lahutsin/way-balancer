use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use lb_net_core::{
    EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName, UpstreamClusterState,
    UpstreamEndpoint, UpstreamEndpointId,
};
use lb_runtime::{
    EndpointHealthPolicy, EndpointHealthStatus, UpstreamHealthError, UpstreamHealthRegistry,
};

fn endpoint(
    id: &str,
    port: u16,
    weight: u16,
) -> Result<UpstreamEndpoint, Box<dyn std::error::Error>> {
    Ok(UpstreamEndpoint::new(
        UpstreamEndpointId::new(id)?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        EndpointState::Ready,
        EndpointMetadata { zone: None, locality: None, weight },
    )?)
}

fn policy() -> EndpointHealthPolicy {
    EndpointHealthPolicy {
        degraded_failure_threshold: 1,
        unhealthy_failure_threshold: 2,
        ejection_failure_threshold: 3,
        recovery_success_threshold: 2,
        ejection_duration: Duration::from_secs(30),
        warmup_duration: Duration::from_secs(20),
    }
}

#[test]
fn active_failures_eject_and_recovery_enters_warmup() -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(policy());
    let cluster_name = UpstreamClusterName::new("payments")?;
    let endpoint_id = UpstreamEndpointId::new("a")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![endpoint(endpoint_id.as_str(), 8080, 10)?],
    )?)?;

    let initial = registry.endpoint_health(&cluster_name, &endpoint_id)?;
    assert_eq!(initial.status, EndpointHealthStatus::Warming);
    assert_eq!(initial.effective_weight, 1);

    registry.advance_time(Duration::from_secs(20));
    assert_eq!(
        registry.endpoint_health(&cluster_name, &endpoint_id)?.status,
        EndpointHealthStatus::Healthy
    );

    assert_eq!(
        registry.note_active_failure(&cluster_name, &endpoint_id)?.status,
        EndpointHealthStatus::Degraded
    );
    assert_eq!(
        registry.note_active_failure(&cluster_name, &endpoint_id)?.status,
        EndpointHealthStatus::Unhealthy
    );
    assert_eq!(
        registry.note_active_failure(&cluster_name, &endpoint_id)?.status,
        EndpointHealthStatus::Ejected
    );
    assert_eq!(
        registry.cluster_state(&cluster_name)?,
        UpstreamClusterState::Unavailable { total_endpoints: 1 }
    );

    registry.advance_time(Duration::from_secs(29));
    assert_eq!(
        registry.note_active_success(&cluster_name, &endpoint_id)?.status,
        EndpointHealthStatus::Ejected
    );

    registry.advance_time(Duration::from_secs(1));
    assert_eq!(
        registry.endpoint_health(&cluster_name, &endpoint_id)?.status,
        EndpointHealthStatus::Unhealthy
    );
    assert_eq!(
        registry.note_active_success(&cluster_name, &endpoint_id)?.status,
        EndpointHealthStatus::Unhealthy
    );
    let recovering = registry.note_active_success(&cluster_name, &endpoint_id)?;
    assert_eq!(recovering.status, EndpointHealthStatus::Warming);
    assert!(recovering.effective_weight < 10);

    registry.advance_time(Duration::from_secs(10));
    let midpoint = registry.endpoint_health(&cluster_name, &endpoint_id)?;
    assert_eq!(midpoint.status, EndpointHealthStatus::Warming);
    assert!((1..10).contains(&midpoint.effective_weight));

    registry.advance_time(Duration::from_secs(10));
    let healed = registry.endpoint_health(&cluster_name, &endpoint_id)?;
    assert_eq!(healed.status, EndpointHealthStatus::Healthy);
    assert_eq!(healed.effective_weight, 10);

    let metrics = registry.metrics();
    assert_eq!(metrics.active_failure_count, 3);
    assert_eq!(metrics.active_success_count, 3);
    assert_eq!(metrics.ejection_count, 1);

    Ok(())
}

#[test]
fn passive_failures_can_remove_endpoint_from_availability() -> Result<(), Box<dyn std::error::Error>>
{
    let registry = UpstreamHealthRegistry::new(policy());
    let cluster_name = UpstreamClusterName::new("search")?;
    let endpoint_id = UpstreamEndpointId::new("a")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![endpoint(endpoint_id.as_str(), 8080, 5)?],
    )?)?;
    registry.advance_time(Duration::from_secs(20));

    assert_eq!(
        registry.note_passive_failure(&cluster_name, &endpoint_id)?.status,
        EndpointHealthStatus::Degraded
    );
    assert_eq!(
        registry.cluster_state(&cluster_name)?,
        UpstreamClusterState::Ready { total_endpoints: 1, ready_endpoints: 1 }
    );

    let unavailable = registry.note_passive_failure(&cluster_name, &endpoint_id)?;
    assert_eq!(unavailable.status, EndpointHealthStatus::Unhealthy);
    assert_eq!(
        registry.cluster_state(&cluster_name)?,
        UpstreamClusterState::Unavailable { total_endpoints: 1 }
    );
    assert_eq!(registry.metrics().passive_failure_count, 2);

    Ok(())
}

#[test]
fn new_endpoint_starts_in_warmup_and_emits_events() -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(policy());
    let cluster_name = UpstreamClusterName::new("edge")?;
    let endpoint_id = UpstreamEndpointId::new("a")?;
    registry.insert_cluster(UpstreamCluster::new(cluster_name.clone(), Vec::new())?)?;
    registry.insert_endpoint(&cluster_name, endpoint(endpoint_id.as_str(), 8080, 12)?)?;

    let snapshot = registry.endpoint_health(&cluster_name, &endpoint_id)?;
    assert_eq!(snapshot.status, EndpointHealthStatus::Warming);
    assert_eq!(snapshot.effective_weight, 1);
    assert_eq!(
        registry.cluster_state(&cluster_name)?,
        UpstreamClusterState::Ready { total_endpoints: 1, ready_endpoints: 1 }
    );

    registry.advance_time(Duration::from_secs(5));
    let in_progress = registry.endpoint_health(&cluster_name, &endpoint_id)?;
    assert!(in_progress.effective_weight > 1);
    assert!(in_progress.effective_weight < 12);

    registry.advance_time(Duration::from_secs(15));
    let events = registry.recent_events();
    assert!(events
        .iter()
        .any(|event| event.kind == lb_observability::UpstreamHealthEventKind::WarmupStarted));
    assert!(events
        .iter()
        .any(|event| event.kind == lb_observability::UpstreamHealthEventKind::WarmupCompleted));

    Ok(())
}

#[test]
fn removed_cluster_rejects_stale_endpoint_health_reads(
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(policy());
    let cluster_name = UpstreamClusterName::new("removed")?;
    let endpoint_id = UpstreamEndpointId::new("a")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![endpoint(endpoint_id.as_str(), 8080, 1)?],
    )?)?;

    assert!(registry.remove_cluster(&cluster_name).is_some());
    assert!(matches!(
        registry.endpoint_health(&cluster_name, &endpoint_id),
        Err(UpstreamHealthError::Registry(lb_runtime::EndpointRegistryError::ClusterNotFound(
            name,
        ))) if name == cluster_name
    ));
    Ok(())
}
