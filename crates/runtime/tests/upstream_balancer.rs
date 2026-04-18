use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use lb_net_core::{
    EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName, UpstreamEndpoint,
    UpstreamEndpointId,
};
use lb_runtime::{
    AffinityFallbackPolicy, AffinityPolicy, EndpointHealthPolicy, EndpointHealthStatus,
    LoadBalancingAlgorithm, LocalityRoutingPolicy, NoHealthyFallback, SelectionContext,
    UpstreamBalancer, UpstreamHealthRegistry, UpstreamSelectionError, UpstreamSelectionPolicy,
};

fn endpoint(
    id: &str,
    port: u16,
    weight: u16,
    zone: Option<&str>,
    locality: Option<&str>,
) -> Result<UpstreamEndpoint, Box<dyn std::error::Error>> {
    Ok(UpstreamEndpoint::new(
        UpstreamEndpointId::new(id)?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        EndpointState::Ready,
        EndpointMetadata {
            zone: zone.map(str::to_string),
            locality: locality.map(str::to_string),
            weight,
        },
    )?)
}

fn health_policy() -> EndpointHealthPolicy {
    EndpointHealthPolicy {
        degraded_failure_threshold: 1,
        unhealthy_failure_threshold: 2,
        ejection_failure_threshold: 3,
        recovery_success_threshold: 1,
        ejection_duration: Duration::from_secs(30),
        warmup_duration: Duration::ZERO,
    }
}

#[test]
fn round_robin_selection_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(health_policy());
    let balancer = UpstreamBalancer::new();
    let cluster_name = UpstreamClusterName::new("payments")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![
            endpoint("a", 8080, 1, None, None)?,
            endpoint("b", 8081, 1, None, None)?,
            endpoint("c", 8082, 1, None, None)?,
        ],
    )?)?;

    let policy = UpstreamSelectionPolicy::default();
    let context = SelectionContext::default();
    let sequence = [
        balancer.select_endpoint(&registry, &cluster_name, &policy, &context)?,
        balancer.select_endpoint(&registry, &cluster_name, &policy, &context)?,
        balancer.select_endpoint(&registry, &cluster_name, &policy, &context)?,
        balancer.select_endpoint(&registry, &cluster_name, &policy, &context)?,
    ];

    assert_eq!(sequence[0].endpoint_id.as_str(), "a");
    assert_eq!(sequence[1].endpoint_id.as_str(), "b");
    assert_eq!(sequence[2].endpoint_id.as_str(), "c");
    assert_eq!(sequence[3].endpoint_id.as_str(), "a");
    assert_eq!(balancer.metrics().round_robin_selection_count, 4);

    Ok(())
}

#[test]
fn weighted_round_robin_respects_effective_weights() -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(health_policy());
    let balancer = UpstreamBalancer::new();
    let cluster_name = UpstreamClusterName::new("payments")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![endpoint("heavy", 8080, 5, None, None)?, endpoint("light", 8081, 1, None, None)?],
    )?)?;

    let policy = UpstreamSelectionPolicy {
        algorithm: LoadBalancingAlgorithm::WeightedRoundRobin,
        locality: LocalityRoutingPolicy::Disabled,
        no_healthy_fallback: NoHealthyFallback::Fail,
        affinity: None,
    };
    let context = SelectionContext::default();
    let mut counts = BTreeMap::new();
    for _ in 0..12 {
        let selected = balancer.select_endpoint(&registry, &cluster_name, &policy, &context)?;
        *counts.entry(selected.endpoint_id.to_string()).or_insert(0_u32) += 1;
    }

    assert_eq!(counts.get("heavy"), Some(&10));
    assert_eq!(counts.get("light"), Some(&2));
    assert_eq!(balancer.metrics().weighted_round_robin_selection_count, 12);

    Ok(())
}

#[test]
fn locality_preference_narrows_candidate_pool() -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(health_policy());
    let balancer = UpstreamBalancer::new();
    let cluster_name = UpstreamClusterName::new("edge")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![
            endpoint("remote", 8080, 1, Some("z2"), Some("l2"))?,
            endpoint("local", 8081, 1, Some("z1"), Some("l1"))?,
        ],
    )?)?;

    let policy = UpstreamSelectionPolicy {
        algorithm: LoadBalancingAlgorithm::RoundRobin,
        locality: LocalityRoutingPolicy::PreferLocalityThenZone,
        no_healthy_fallback: NoHealthyFallback::Fail,
        affinity: None,
    };
    let context = SelectionContext {
        preferred_locality: Some(String::from("l1")),
        preferred_zone: Some(String::from("z1")),
        affinity_key: None,
        request_hash: 7,
    };

    let selected = balancer.select_endpoint(&registry, &cluster_name, &policy, &context)?;

    assert_eq!(selected.endpoint_id.as_str(), "local");
    assert!(selected.locality_matched);
    assert_eq!(balancer.metrics().locality_preference_hit_count, 1);

    Ok(())
}

#[test]
fn affinity_selection_is_deterministic_for_same_key() -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(health_policy());
    let balancer = UpstreamBalancer::new();
    let cluster_name = UpstreamClusterName::new("sessions")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![endpoint("a", 8080, 1, None, None)?, endpoint("b", 8081, 1, None, None)?],
    )?)?;

    let policy = UpstreamSelectionPolicy {
        algorithm: LoadBalancingAlgorithm::RoundRobin,
        locality: LocalityRoutingPolicy::Disabled,
        no_healthy_fallback: NoHealthyFallback::Fail,
        affinity: Some(AffinityPolicy::HeaderHash {
            header_name: String::from("x-session"),
            fallback: AffinityFallbackPolicy::BalanceHealthy,
        }),
    };

    let first = balancer.select_endpoint(
        &registry,
        &cluster_name,
        &policy,
        &SelectionContext {
            affinity_key: Some(String::from("session-a")),
            request_hash: 7,
            ..SelectionContext::default()
        },
    )?;
    let second = balancer.select_endpoint(
        &registry,
        &cluster_name,
        &policy,
        &SelectionContext {
            affinity_key: Some(String::from("session-a")),
            request_hash: 11,
            ..SelectionContext::default()
        },
    )?;

    assert_eq!(first.endpoint_id, second.endpoint_id);
    assert_eq!(balancer.metrics().affinity_hit_count, 2);
    assert_eq!(balancer.metrics().affinity_fallback_count, 0);
    Ok(())
}

#[test]
fn affinity_falls_back_when_preferred_endpoint_is_unhealthy(
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(health_policy());
    let balancer = UpstreamBalancer::new();
    let cluster_name = UpstreamClusterName::new("sessions")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![endpoint("a", 8080, 1, None, None)?, endpoint("b", 8081, 1, None, None)?],
    )?)?;

    let policy = UpstreamSelectionPolicy {
        algorithm: LoadBalancingAlgorithm::RoundRobin,
        locality: LocalityRoutingPolicy::Disabled,
        no_healthy_fallback: NoHealthyFallback::Fail,
        affinity: Some(AffinityPolicy::HeaderHash {
            header_name: String::from("x-session"),
            fallback: AffinityFallbackPolicy::BalanceHealthy,
        }),
    };
    let context = SelectionContext {
        affinity_key: Some(String::from("session-a")),
        request_hash: 7,
        ..SelectionContext::default()
    };

    let preferred = balancer.select_endpoint(&registry, &cluster_name, &policy, &context)?;
    let _ = registry.note_active_failure(&cluster_name, &preferred.endpoint_id)?;
    let _ = registry.note_active_failure(&cluster_name, &preferred.endpoint_id)?;

    let selected = balancer.select_endpoint(&registry, &cluster_name, &policy, &context)?;

    assert_ne!(selected.endpoint_id, preferred.endpoint_id);
    assert_eq!(selected.health_status, EndpointHealthStatus::Healthy);
    assert_eq!(balancer.metrics().affinity_hit_count, 1);
    assert_eq!(balancer.metrics().affinity_fallback_count, 1);
    assert_eq!(balancer.metrics().round_robin_selection_count, 1);
    Ok(())
}

#[test]
fn all_unhealthy_fallback_is_explicit() -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(health_policy());
    let balancer = UpstreamBalancer::new();
    let cluster_name = UpstreamClusterName::new("search")?;
    let endpoint_id = UpstreamEndpointId::new("a")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![endpoint(endpoint_id.as_str(), 8080, 3, None, None)?],
    )?)?;
    let _ = registry.note_active_failure(&cluster_name, &endpoint_id)?;
    let _ = registry.note_active_failure(&cluster_name, &endpoint_id)?;

    let fail_policy = UpstreamSelectionPolicy::default();
    let context = SelectionContext::default();
    let result = balancer.select_endpoint(&registry, &cluster_name, &fail_policy, &context);
    assert_eq!(result, Err(UpstreamSelectionError::NoEligibleEndpoints(cluster_name.clone())));

    let fallback_policy = UpstreamSelectionPolicy {
        algorithm: LoadBalancingAlgorithm::RoundRobin,
        locality: LocalityRoutingPolicy::Disabled,
        no_healthy_fallback: NoHealthyFallback::IncludeUnhealthy,
        affinity: None,
    };
    let selected =
        balancer.select_endpoint(&registry, &cluster_name, &fallback_policy, &context)?;
    assert_eq!(selected.endpoint_id.as_str(), "a");
    assert_eq!(selected.health_status, EndpointHealthStatus::Unhealthy);
    assert_eq!(balancer.metrics().no_healthy_endpoint_count, 2);
    assert_eq!(balancer.metrics().unhealthy_fallback_selection_count, 1);

    Ok(())
}

#[test]
fn power_of_two_choices_prefers_stronger_candidate() -> Result<(), Box<dyn std::error::Error>> {
    let registry = UpstreamHealthRegistry::new(health_policy());
    let balancer = UpstreamBalancer::new();
    let cluster_name = UpstreamClusterName::new("api")?;
    registry.insert_cluster(UpstreamCluster::new(
        cluster_name.clone(),
        vec![
            endpoint("a", 8080, 1, None, None)?,
            endpoint("b", 8081, 10, None, None)?,
            endpoint("c", 8082, 2, None, None)?,
        ],
    )?)?;

    let policy = UpstreamSelectionPolicy {
        algorithm: LoadBalancingAlgorithm::PowerOfTwoChoices,
        locality: LocalityRoutingPolicy::Disabled,
        no_healthy_fallback: NoHealthyFallback::Fail,
        affinity: None,
    };

    let selected = balancer.select_endpoint(
        &registry,
        &cluster_name,
        &policy,
        &SelectionContext {
            preferred_locality: None,
            preferred_zone: None,
            affinity_key: None,
            request_hash: 42,
        },
    )?;

    assert_ne!(selected.endpoint_id.as_str(), "a");
    assert_eq!(balancer.metrics().power_of_two_selection_count, 1);
    Ok(())
}
