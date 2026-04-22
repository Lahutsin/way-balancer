use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::Hasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use crate::{
    EndpointHealthSnapshot, EndpointHealthStatus, UpstreamHealthError, UpstreamHealthRegistry,
};

/// Selection algorithm used for upstream endpoint choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingAlgorithm {
    /// Deterministic round-robin over eligible endpoints.
    RoundRobin,
    /// Smooth weighted round-robin using effective endpoint weights.
    WeightedRoundRobin,
    /// Deterministic power-of-two choices using a request hash.
    PowerOfTwoChoices,
}

/// Locality preference policy applied before algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalityRoutingPolicy {
    /// Ignore locality metadata during selection.
    Disabled,
    /// Prefer exact locality matches when available.
    PreferLocality,
    /// Prefer zone matches when available.
    PreferZone,
    /// Prefer locality first, then zone.
    PreferLocalityThenZone,
}

/// Explicit fallback semantics when no healthy endpoints are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoHealthyFallback {
    /// Fail selection instead of routing to unhealthy endpoints.
    Fail,
    /// Allow unhealthy endpoints but still exclude ejected ones.
    IncludeUnhealthy,
}

/// Explicit fallback semantics when the preferred affinity endpoint is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityFallbackPolicy {
    /// Fall back to normal healthy endpoint selection.
    BalanceHealthy,
}

/// Runtime affinity source and fallback configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AffinityPolicy {
    /// Hash a request header value to a deterministic endpoint.
    HeaderHash {
        /// Header name used to source the affinity key.
        header_name: String,
        /// Behavior when the preferred endpoint is unavailable.
        fallback: AffinityFallbackPolicy,
    },
    /// Hash a request cookie value to a deterministic endpoint.
    CookieHash {
        /// Cookie name used to source the affinity key.
        cookie_name: String,
        /// Behavior when the preferred endpoint is unavailable.
        fallback: AffinityFallbackPolicy,
    },
}

/// Runtime selection policy for a cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSelectionPolicy {
    /// Selected balancing algorithm.
    pub algorithm: LoadBalancingAlgorithm,
    /// Locality routing behavior.
    pub locality: LocalityRoutingPolicy,
    /// Explicit no-healthy fallback behavior.
    pub no_healthy_fallback: NoHealthyFallback,
    /// Optional deterministic affinity behavior.
    pub affinity: Option<AffinityPolicy>,
}

impl Default for UpstreamSelectionPolicy {
    fn default() -> Self {
        Self {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        }
    }
}

/// Selection-time hints supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectionContext {
    /// Preferred locality of the caller.
    pub preferred_locality: Option<String>,
    /// Preferred zone of the caller.
    pub preferred_zone: Option<String>,
    /// Optional deterministic affinity key supplied by the caller.
    pub affinity_key: Option<String>,
    /// Stable request hash used for deterministic selection.
    pub request_hash: u64,
}

/// Candidate endpoint exposed by the health registry for balancing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSelectionCandidate {
    /// Cluster identifier.
    pub cluster_name: lb_net_core::UpstreamClusterName,
    /// Endpoint identifier.
    pub endpoint_id: lb_net_core::UpstreamEndpointId,
    /// Endpoint address.
    pub address: std::net::SocketAddr,
    /// Bounded endpoint metadata.
    pub metadata: lb_net_core::EndpointMetadata,
    /// Dynamic health snapshot.
    pub health: EndpointHealthSnapshot,
}

/// Selected endpoint and decision metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedEndpoint {
    /// Cluster identifier.
    pub cluster_name: lb_net_core::UpstreamClusterName,
    /// Selected endpoint identifier.
    pub endpoint_id: lb_net_core::UpstreamEndpointId,
    /// Upstream address.
    pub address: std::net::SocketAddr,
    /// Effective weight used during selection.
    pub effective_weight: u16,
    /// Final health status used during selection.
    pub health_status: EndpointHealthStatus,
    /// Whether locality preference narrowed the candidate pool.
    pub locality_matched: bool,
}

/// Selection counters and hooks for observability.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpstreamSelectionMetrics {
    /// Number of round-robin selections.
    pub round_robin_selection_count: u64,
    /// Number of weighted round-robin selections.
    pub weighted_round_robin_selection_count: u64,
    /// Number of weighted route-destination selections.
    pub weighted_route_selection_count: u64,
    /// Number of power-of-two selections.
    pub power_of_two_selection_count: u64,
    /// Number of locality preference hits.
    pub locality_preference_hit_count: u64,
    /// Number of no-healthy situations encountered.
    pub no_healthy_endpoint_count: u64,
    /// Number of fallback selections performed against unhealthy endpoints.
    pub unhealthy_fallback_selection_count: u64,
    /// Number of selections satisfied directly by affinity.
    pub affinity_hit_count: u64,
    /// Number of affinity preferences that fell back to normal selection.
    pub affinity_fallback_count: u64,
    /// Number of successful route-level fallbacks to a later destination.
    pub route_destination_fallback_count: u64,
    /// Number of selections per route destination cluster.
    pub route_destination_selection_counts: BTreeMap<String, u64>,
}

/// Reusable route backend pool that applies selection policy over a health-aware cluster view.
#[derive(Debug, Clone)]
pub struct RouteBackendPool {
    inner: Arc<RouteBackendPoolInner>,
}

#[derive(Debug, Clone)]
enum RouteBackendPoolInner {
    Single {
        cluster_name: lb_net_core::UpstreamClusterName,
        registry: Arc<UpstreamHealthRegistry>,
        balancer: Arc<UpstreamBalancer>,
        selection_policy: UpstreamSelectionPolicy,
    },
    Weighted {
        destinations: Vec<WeightedRouteDestination>,
        state: Arc<Mutex<RouteDestinationWeightedState>>,
    },
}

/// Weighted route destination used for route-level traffic splitting across clusters.
#[derive(Debug, Clone)]
pub struct WeightedRouteDestination {
    /// Relative traffic weight for this route destination.
    pub weight: u16,
    /// Single-cluster backend pool for this destination.
    pub pool: RouteBackendPool,
}

#[derive(Debug, Default)]
struct RouteDestinationWeightedState {
    total_weight: i64,
    current_weights: BTreeMap<lb_net_core::UpstreamClusterName, i64>,
    weighted_route_selection_count: u64,
    route_destination_fallback_count: u64,
    route_destination_selection_counts: BTreeMap<lb_net_core::UpstreamClusterName, u64>,
}

/// Selected route backend plus a handle for passive health feedback.
#[derive(Debug, Clone)]
pub struct SelectedRouteBackend {
    pool: RouteBackendPool,
    endpoint_id: lb_net_core::UpstreamEndpointId,
    upstream: lb_net_core::UpstreamTarget,
}

/// Endpoint target exposed for active health probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProbeTarget {
    /// Endpoint identifier within the cluster.
    pub endpoint_id: lb_net_core::UpstreamEndpointId,
    /// Endpoint address to probe.
    pub address: std::net::SocketAddr,
    /// Current dynamic health snapshot.
    pub health: EndpointHealthSnapshot,
}

impl SelectedRouteBackend {
    #[must_use]
    pub fn upstream(&self) -> &lb_net_core::UpstreamTarget {
        &self.upstream
    }

    #[must_use]
    pub fn cluster_name(&self) -> &lb_net_core::UpstreamClusterName {
        self.pool.cluster_name()
    }

    #[must_use]
    pub fn into_upstream(self) -> lb_net_core::UpstreamTarget {
        self.upstream
    }

    pub fn note_passive_success(&self) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        self.pool.note_passive_success(&self.endpoint_id)
    }

    pub fn note_passive_failure(&self) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        self.pool.note_passive_failure(&self.endpoint_id)
    }
}

impl RouteBackendPool {
    /// Builds a health-aware route backend pool from a validated cluster model.
    pub fn from_cluster(
        cluster: lb_net_core::UpstreamCluster,
        health_policy: crate::EndpointHealthPolicy,
        selection_policy: UpstreamSelectionPolicy,
    ) -> Result<Self, UpstreamHealthError> {
        let cluster_name = cluster.name().clone();
        let registry = Arc::new(UpstreamHealthRegistry::new(health_policy));
        registry.insert_cluster(cluster)?;
        Ok(Self {
            inner: Arc::new(RouteBackendPoolInner::Single {
                cluster_name,
                registry,
                balancer: Arc::new(UpstreamBalancer::new()),
                selection_policy,
            }),
        })
    }

    /// Builds a weighted route backend pool from single-cluster destination pools.
    pub fn from_weighted_destinations(
        destinations: impl IntoIterator<Item = WeightedRouteDestination>,
    ) -> Result<Self, RouteBackendPoolBuildError> {
        let mut destinations = destinations.into_iter().collect::<Vec<_>>();
        if destinations.is_empty() {
            return Err(RouteBackendPoolBuildError::EmptyDestinations);
        }
        for destination in &destinations {
            if destination.weight == 0 {
                return Err(RouteBackendPoolBuildError::ZeroWeightDestination(
                    destination.pool.cluster_name().to_string(),
                ));
            }
            if !destination.pool.is_single_cluster() {
                return Err(RouteBackendPoolBuildError::NestedWeightedDestination);
            }
        }
        destinations.sort_by(|left, right| left.pool.cluster_name().cmp(right.pool.cluster_name()));
        Ok(Self {
            inner: Arc::new(RouteBackendPoolInner::Weighted {
                destinations,
                state: Arc::new(Mutex::new(RouteDestinationWeightedState::default())),
            }),
        })
    }

    /// Selects an upstream target for a request hash using the configured policy.
    pub fn select_upstream(
        &self,
        request_hash: u64,
    ) -> Result<lb_net_core::UpstreamTarget, UpstreamSelectionError> {
        self.select_backend(request_hash).map(SelectedRouteBackend::into_upstream)
    }

    /// Selects a route backend for a request hash using the configured policy.
    pub fn select_backend(
        &self,
        request_hash: u64,
    ) -> Result<SelectedRouteBackend, UpstreamSelectionError> {
        self.select_backend_with_context(&SelectionContext {
            request_hash,
            ..SelectionContext::default()
        })
    }

    /// Selects an upstream target using the configured policy and full selection context.
    pub fn select_upstream_with_context(
        &self,
        context: &SelectionContext,
    ) -> Result<lb_net_core::UpstreamTarget, UpstreamSelectionError> {
        self.select_backend_with_context(context).map(SelectedRouteBackend::into_upstream)
    }

    /// Selects a route backend using the configured policy and full selection context.
    pub fn select_backend_with_context(
        &self,
        context: &SelectionContext,
    ) -> Result<SelectedRouteBackend, UpstreamSelectionError> {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single {
                cluster_name,
                registry,
                balancer,
                selection_policy,
            } => {
                let selected =
                    balancer.select_endpoint(registry, cluster_name, selection_policy, context)?;
                let endpoint_id = selected.endpoint_id;
                Ok(SelectedRouteBackend {
                    pool: self.clone(),
                    upstream: lb_net_core::UpstreamTarget::new(
                        format!("{}:{}", cluster_name, endpoint_id),
                        selected.address,
                    ),
                    endpoint_id,
                })
            }
            RouteBackendPoolInner::Weighted { destinations, state } => {
                let selection_order = select_weighted_route_destination_order(destinations, state);
                let mut last_error = None;
                for (selection_rank, destination_index) in selection_order.into_iter().enumerate() {
                    match destinations[destination_index].pool.select_backend_with_context(context) {
                        Ok(selected) => {
                            let mut state = state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            state.weighted_route_selection_count =
                                state.weighted_route_selection_count.saturating_add(1);
                            if selection_rank > 0 {
                                state.route_destination_fallback_count = state
                                    .route_destination_fallback_count
                                    .saturating_add(1);
                            }
                            let counter = state
                                .route_destination_selection_counts
                                .entry(destinations[destination_index].pool.cluster_name().clone())
                                .or_insert(0);
                            *counter = counter.saturating_add(1);
                            return Ok(selected);
                        }
                        Err(UpstreamSelectionError::NoEligibleEndpoints(_)) => {
                            last_error = Some(UpstreamSelectionError::NoEligibleEndpoints(
                                destinations[destination_index].pool.cluster_name().clone(),
                            ));
                        }
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(last_error.unwrap_or_else(|| {
                    UpstreamSelectionError::NoEligibleEndpoints(self.cluster_name().clone())
                }))
            }
        }
    }

    pub fn note_passive_success(
        &self,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { cluster_name, registry, .. } => {
                registry.note_passive_success(cluster_name, endpoint_id)
            }
            RouteBackendPoolInner::Weighted { destinations, .. } => {
                note_endpoint_across_weighted_destinations(destinations, endpoint_id, |pool, endpoint_id| {
                    pool.note_passive_success(endpoint_id)
                })
            }
        }
    }

    pub fn note_passive_failure(
        &self,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { cluster_name, registry, .. } => {
                registry.note_passive_failure(cluster_name, endpoint_id)
            }
            RouteBackendPoolInner::Weighted { destinations, .. } => {
                note_endpoint_across_weighted_destinations(destinations, endpoint_id, |pool, endpoint_id| {
                    pool.note_passive_failure(endpoint_id)
                })
            }
        }
    }

    #[must_use]
    pub fn cluster_name(&self) -> &lb_net_core::UpstreamClusterName {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { cluster_name, .. } => cluster_name,
            RouteBackendPoolInner::Weighted { destinations, .. } => {
                destinations[0].pool.cluster_name()
            }
        }
    }

    #[must_use]
    pub fn cluster_names(&self) -> Vec<lb_net_core::UpstreamClusterName> {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { cluster_name, .. } => vec![cluster_name.clone()],
            RouteBackendPoolInner::Weighted { destinations, .. } => destinations
                .iter()
                .map(|destination| destination.pool.cluster_name().clone())
                .collect(),
        }
    }

    #[must_use]
    pub fn affinity_policy(&self) -> Option<&AffinityPolicy> {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { selection_policy, .. } => {
                selection_policy.affinity.as_ref()
            }
            RouteBackendPoolInner::Weighted { destinations, .. } => {
                let first = destinations.first()?.pool.affinity_policy()?;
                if destinations
                    .iter()
                    .skip(1)
                    .all(|destination| destination.pool.affinity_policy() == Some(first))
                {
                    Some(first)
                } else {
                    None
                }
            }
        }
    }

    pub fn active_probe_targets(&self) -> Result<Vec<ActiveProbeTarget>, UpstreamHealthError> {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { cluster_name, registry, .. } => {
                registry.selection_candidates(cluster_name, true).map(|candidates| {
                    candidates
                        .into_iter()
                        .map(|candidate| ActiveProbeTarget {
                            endpoint_id: candidate.endpoint_id,
                            address: candidate.address,
                            health: candidate.health,
                        })
                        .collect()
                })
            }
            RouteBackendPoolInner::Weighted { destinations, .. } => {
                let mut targets = Vec::new();
                for destination in destinations {
                    targets.extend(destination.pool.active_probe_targets()?);
                }
                Ok(targets)
            }
        }
    }

    pub fn note_active_success(
        &self,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { cluster_name, registry, .. } => {
                registry.note_active_success(cluster_name, endpoint_id)
            }
            RouteBackendPoolInner::Weighted { destinations, .. } => {
                note_endpoint_across_weighted_destinations(destinations, endpoint_id, |pool, endpoint_id| {
                    pool.note_active_success(endpoint_id)
                })
            }
        }
    }

    pub fn note_active_failure(
        &self,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { cluster_name, registry, .. } => {
                registry.note_active_failure(cluster_name, endpoint_id)
            }
            RouteBackendPoolInner::Weighted { destinations, .. } => {
                note_endpoint_across_weighted_destinations(destinations, endpoint_id, |pool, endpoint_id| {
                    pool.note_active_failure(endpoint_id)
                })
            }
        }
    }

    #[must_use]
    pub fn selection_metrics(&self) -> UpstreamSelectionMetrics {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { balancer, .. } => balancer.metrics(),
            RouteBackendPoolInner::Weighted { destinations, state } => {
                let mut aggregate =
                    destinations.iter().fold(UpstreamSelectionMetrics::default(), |mut aggregate, destination| {
                        let metrics = destination.pool.selection_metrics();
                        aggregate.round_robin_selection_count +=
                            metrics.round_robin_selection_count;
                        aggregate.weighted_round_robin_selection_count +=
                            metrics.weighted_round_robin_selection_count;
                        aggregate.weighted_route_selection_count +=
                            metrics.weighted_route_selection_count;
                        aggregate.power_of_two_selection_count +=
                            metrics.power_of_two_selection_count;
                        aggregate.locality_preference_hit_count +=
                            metrics.locality_preference_hit_count;
                        aggregate.no_healthy_endpoint_count += metrics.no_healthy_endpoint_count;
                        aggregate.unhealthy_fallback_selection_count +=
                            metrics.unhealthy_fallback_selection_count;
                        aggregate.affinity_hit_count += metrics.affinity_hit_count;
                        aggregate.affinity_fallback_count += metrics.affinity_fallback_count;
                        aggregate.route_destination_fallback_count +=
                            metrics.route_destination_fallback_count;
                        for (destination_name, count) in metrics.route_destination_selection_counts {
                            *aggregate
                                .route_destination_selection_counts
                                .entry(destination_name)
                                .or_default() += count;
                        }
                        aggregate
                    });
                let weighted_state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                aggregate.weighted_route_selection_count +=
                    weighted_state.weighted_route_selection_count;
                aggregate.route_destination_fallback_count +=
                    weighted_state.route_destination_fallback_count;
                for (cluster_name, count) in &weighted_state.route_destination_selection_counts {
                    *aggregate
                        .route_destination_selection_counts
                        .entry(cluster_name.to_string())
                        .or_default() += *count;
                }
                aggregate
            }
        }
    }

    pub fn advance_time(&self, elapsed: std::time::Duration) {
        match self.inner.as_ref() {
            RouteBackendPoolInner::Single { registry, .. } => registry.advance_time(elapsed),
            RouteBackendPoolInner::Weighted { destinations, .. } => {
                for destination in destinations {
                    destination.pool.advance_time(elapsed);
                }
            }
        }
    }

    fn is_single_cluster(&self) -> bool {
        matches!(self.inner.as_ref(), RouteBackendPoolInner::Single { .. })
    }
}

/// Errors returned while building route backend pools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteBackendPoolBuildError {
    EmptyDestinations,
    ZeroWeightDestination(String),
    NestedWeightedDestination,
}

impl fmt::Display for RouteBackendPoolBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDestinations => {
                write!(formatter, "weighted route pool must declare at least one destination")
            }
            Self::ZeroWeightDestination(cluster_name) => write!(
                formatter,
                "weighted route destination {cluster_name} must use a non-zero weight"
            ),
            Self::NestedWeightedDestination => write!(
                formatter,
                "weighted route pools may reference only single-cluster destination pools"
            ),
        }
    }
}

impl std::error::Error for RouteBackendPoolBuildError {}

fn select_weighted_route_destination_order(
    destinations: &[WeightedRouteDestination],
    state: &Arc<Mutex<RouteDestinationWeightedState>>,
) -> Vec<usize> {
    let mut state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    state.current_weights.retain(|cluster_name, _| {
        destinations
            .iter()
            .any(|destination| destination.pool.cluster_name() == cluster_name)
    });
    state.total_weight = destinations.iter().map(|destination| i64::from(destination.weight)).sum();

    for destination in destinations {
        let entry = state
            .current_weights
            .entry(destination.pool.cluster_name().clone())
            .or_insert(0);
        *entry += i64::from(destination.weight);
    }

    let Some(best_index) = best_weighted_route_destination_index(destinations, &state.current_weights)
    else {
        return Vec::new();
    };
    let total_weight = state.total_weight;
    if let Some(current) = state.current_weights.get_mut(destinations[best_index].pool.cluster_name()) {
        *current -= total_weight;
    }

    let mut order = vec![best_index];
    let mut fallback_weights = state.current_weights.clone();
    while order.len() < destinations.len() {
        let next = destinations
            .iter()
            .enumerate()
            .filter(|(index, _)| !order.contains(index))
            .max_by(|(left_index, left), (right_index, right)| {
                let left_weight = fallback_weights
                    .get(left.pool.cluster_name())
                    .copied()
                    .unwrap_or_default();
                let right_weight = fallback_weights
                    .get(right.pool.cluster_name())
                    .copied()
                    .unwrap_or_default();
                left_weight
                    .cmp(&right_weight)
                    .then_with(|| {
                        right
                            .pool
                            .cluster_name()
                            .cmp(left.pool.cluster_name())
                            .then_with(|| right_index.cmp(left_index))
                    })
            })
            .map(|(index, _)| index);
        let Some(next_index) = next else {
            break;
        };
        order.push(next_index);
        if let Some(current) = fallback_weights.get_mut(destinations[next_index].pool.cluster_name()) {
            *current -= state.total_weight;
        }
    }
    order
}

fn best_weighted_route_destination_index(
    destinations: &[WeightedRouteDestination],
    current_weights: &BTreeMap<lb_net_core::UpstreamClusterName, i64>,
) -> Option<usize> {
    let mut best: Option<(usize, i64)> = None;
    for (index, destination) in destinations.iter().enumerate() {
        let current = current_weights
            .get(destination.pool.cluster_name())
            .copied()
            .unwrap_or_default();
        match best {
            None => best = Some((index, current)),
            Some((best_index, best_weight)) => {
                if current > best_weight
                    || (current == best_weight
                        && destination.pool.cluster_name()
                            < destinations[best_index].pool.cluster_name())
                {
                    best = Some((index, current));
                }
            }
        }
    }
    best.map(|(index, _)| index)
}

fn note_endpoint_across_weighted_destinations<F>(
    destinations: &[WeightedRouteDestination],
    endpoint_id: &lb_net_core::UpstreamEndpointId,
    note: F,
) -> Result<EndpointHealthSnapshot, UpstreamHealthError>
where
    F: Fn(&RouteBackendPool, &lb_net_core::UpstreamEndpointId) -> Result<EndpointHealthSnapshot, UpstreamHealthError>,
{
    for destination in destinations {
        if destination
            .pool
            .active_probe_targets()?
            .iter()
            .any(|candidate| &candidate.endpoint_id == endpoint_id)
        {
            return note(&destination.pool, endpoint_id);
        }
    }
    Err(UpstreamHealthError::EndpointNotTracked {
        cluster: destinations[0].pool.cluster_name().clone(),
        endpoint_id: endpoint_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::{
        LoadBalancingAlgorithm, LocalityRoutingPolicy, NoHealthyFallback, RouteBackendPool,
        RouteBackendPoolBuildError, UpstreamSelectionPolicy, WeightedRouteDestination,
    };

    fn single_endpoint_pool(
        cluster_name: &str,
        endpoint_id: &str,
        port: u16,
        health_policy: crate::EndpointHealthPolicy,
    ) -> Result<RouteBackendPool, Box<dyn std::error::Error>> {
        Ok(RouteBackendPool::from_cluster(
            lb_net_core::UpstreamCluster::new(
                lb_net_core::UpstreamClusterName::new(cluster_name)?,
                vec![lb_net_core::UpstreamEndpoint::new(
                    lb_net_core::UpstreamEndpointId::new(endpoint_id)?,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    lb_net_core::EndpointState::Ready,
                    lb_net_core::EndpointMetadata {
                        zone: None,
                        locality: None,
                        weight: 1,
                    },
                )?],
            )?,
            health_policy,
            UpstreamSelectionPolicy {
                algorithm: LoadBalancingAlgorithm::RoundRobin,
                locality: LocalityRoutingPolicy::Disabled,
                no_healthy_fallback: NoHealthyFallback::Fail,
                affinity: None,
            },
        )?)
    }

    #[test]
    fn weighted_route_backend_pool_rejects_invalid_destination_sets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let single = single_endpoint_pool(
            "stable",
            "a",
            9000,
            crate::EndpointHealthPolicy::default(),
        )?;

        let empty = RouteBackendPool::from_weighted_destinations([]);
        assert!(matches!(
            empty,
            Err(RouteBackendPoolBuildError::EmptyDestinations)
        ));

        let zero_weight = RouteBackendPool::from_weighted_destinations([WeightedRouteDestination {
            weight: 0,
            pool: single,
        }]);
        assert!(matches!(
            zero_weight,
            Err(RouteBackendPoolBuildError::ZeroWeightDestination(_))
        ));
        Ok(())
    }

    #[test]
    fn weighted_route_backend_pool_distributes_traffic_by_weight(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable = single_endpoint_pool(
            "stable",
            "a",
            9000,
            crate::EndpointHealthPolicy::default(),
        )?;
        let canary = single_endpoint_pool(
            "canary",
            "b",
            9001,
            crate::EndpointHealthPolicy::default(),
        )?;
        let pool = RouteBackendPool::from_weighted_destinations([
            WeightedRouteDestination { weight: 90, pool: stable },
            WeightedRouteDestination { weight: 10, pool: canary },
        ])?;

        let mut stable_count = 0;
        let mut canary_count = 0;
        for _ in 0..10 {
            let selected = pool.select_backend(0)?;
            match selected.upstream().address.port() {
                9000 => stable_count += 1,
                9001 => canary_count += 1,
                other => panic!("unexpected selected port {other}"),
            }
        }

        assert_eq!(stable_count, 9);
        assert_eq!(canary_count, 1);
        Ok(())
    }

    #[test]
    fn weighted_route_backend_pool_falls_back_when_primary_destination_is_unhealthy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stable = single_endpoint_pool(
            "stable",
            "stable-a",
            9000,
            crate::EndpointHealthPolicy::default(),
        )?;
        let canary = single_endpoint_pool(
            "canary",
            "canary-a",
            9001,
            crate::EndpointHealthPolicy {
                degraded_failure_threshold: 1,
                unhealthy_failure_threshold: 1,
                ejection_failure_threshold: 1,
                recovery_success_threshold: 1,
                ejection_duration: Duration::from_secs(30),
                warmup_duration: Duration::ZERO,
            },
        )?;
        let canary_endpoint_id = canary.active_probe_targets()?[0].endpoint_id.clone();
        canary.note_active_failure(&canary_endpoint_id)?;

        let pool = RouteBackendPool::from_weighted_destinations([
            WeightedRouteDestination { weight: 100, pool: canary },
            WeightedRouteDestination { weight: 1, pool: stable },
        ])?;

        let selected = pool.select_backend(0)?;
        assert_eq!(selected.upstream().address.port(), 9000);
        Ok(())
    }
}

/// Errors returned during endpoint selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamSelectionError {
    /// Health registry failed to provide cluster state.
    Health(UpstreamHealthError),
    /// No eligible endpoints matched the selection policy.
    NoEligibleEndpoints(lb_net_core::UpstreamClusterName),
}

impl fmt::Display for UpstreamSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Health(error) => write!(formatter, "upstream selection health error: {error}"),
            Self::NoEligibleEndpoints(cluster) => {
                write!(formatter, "no eligible endpoints available for cluster {cluster}")
            }
        }
    }
}

impl std::error::Error for UpstreamSelectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Health(error) => Some(error),
            Self::NoEligibleEndpoints(_) => None,
        }
    }
}

impl From<UpstreamHealthError> for UpstreamSelectionError {
    fn from(value: UpstreamHealthError) -> Self {
        Self::Health(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClusterCursorKey {
    cluster_name: lb_net_core::UpstreamClusterName,
    unhealthy: bool,
}

#[derive(Debug, Default)]
struct WeightedState {
    total_weight: i64,
    current_weights: BTreeMap<lb_net_core::UpstreamEndpointId, i64>,
}

#[derive(Debug, Default)]
struct MetricsState {
    round_robin_selection_count: AtomicU64,
    weighted_round_robin_selection_count: AtomicU64,
    power_of_two_selection_count: AtomicU64,
    locality_preference_hit_count: AtomicU64,
    no_healthy_endpoint_count: AtomicU64,
    unhealthy_fallback_selection_count: AtomicU64,
    affinity_hit_count: AtomicU64,
    affinity_fallback_count: AtomicU64,
}

impl MetricsState {
    fn snapshot(&self) -> UpstreamSelectionMetrics {
        UpstreamSelectionMetrics {
            round_robin_selection_count: self.round_robin_selection_count.load(Ordering::SeqCst),
            weighted_round_robin_selection_count: self
                .weighted_round_robin_selection_count
                .load(Ordering::SeqCst),
            weighted_route_selection_count: 0,
            power_of_two_selection_count: self.power_of_two_selection_count.load(Ordering::SeqCst),
            locality_preference_hit_count: self
                .locality_preference_hit_count
                .load(Ordering::SeqCst),
            no_healthy_endpoint_count: self.no_healthy_endpoint_count.load(Ordering::SeqCst),
            unhealthy_fallback_selection_count: self
                .unhealthy_fallback_selection_count
                .load(Ordering::SeqCst),
            affinity_hit_count: self.affinity_hit_count.load(Ordering::SeqCst),
            affinity_fallback_count: self.affinity_fallback_count.load(Ordering::SeqCst),
            route_destination_fallback_count: 0,
            route_destination_selection_counts: BTreeMap::new(),
        }
    }
}

/// Deterministic selector over the health-aware upstream registry.
#[derive(Debug, Default)]
pub struct UpstreamBalancer {
    round_robin_cursors: Mutex<BTreeMap<ClusterCursorKey, usize>>,
    weighted_states: Mutex<BTreeMap<ClusterCursorKey, WeightedState>>,
    metrics: MetricsState,
}

impl UpstreamBalancer {
    /// Creates a new balancer with deterministic internal state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects an endpoint for the given cluster under the provided policy.
    pub fn select_endpoint(
        &self,
        registry: &UpstreamHealthRegistry,
        cluster_name: &lb_net_core::UpstreamClusterName,
        policy: &UpstreamSelectionPolicy,
        context: &SelectionContext,
    ) -> Result<SelectedEndpoint, UpstreamSelectionError> {
        let mut fallback_used = false;
        let mut candidates = registry.selection_candidates(cluster_name, false)?;
        if candidates.is_empty() {
            self.metrics.no_healthy_endpoint_count.fetch_add(1, Ordering::SeqCst);
            if matches!(policy.no_healthy_fallback, NoHealthyFallback::IncludeUnhealthy) {
                candidates = registry.selection_candidates(cluster_name, true)?;
                fallback_used = true;
            }
        }

        if candidates.is_empty() {
            return Err(UpstreamSelectionError::NoEligibleEndpoints(cluster_name.clone()));
        }

        let (candidates, locality_matched) = apply_locality_preference(candidates, policy, context);
        if locality_matched {
            self.metrics.locality_preference_hit_count.fetch_add(1, Ordering::SeqCst);
        }

        let selected = if let Some(selected) = self.try_select_affinity_candidate(
            registry,
            cluster_name,
            policy,
            context,
            &candidates,
        )? {
            selected
        } else {
            match policy.algorithm {
                LoadBalancingAlgorithm::RoundRobin => {
                    self.metrics.round_robin_selection_count.fetch_add(1, Ordering::SeqCst);
                    self.select_round_robin(cluster_name, &candidates, fallback_used)
                }
                LoadBalancingAlgorithm::WeightedRoundRobin => {
                    self.metrics
                        .weighted_round_robin_selection_count
                        .fetch_add(1, Ordering::SeqCst);
                    self.select_weighted_round_robin(cluster_name, &candidates, fallback_used)
                }
                LoadBalancingAlgorithm::PowerOfTwoChoices => {
                    self.metrics.power_of_two_selection_count.fetch_add(1, Ordering::SeqCst);
                    self.select_power_of_two(&candidates, context.request_hash)
                }
            }
        };

        if fallback_used {
            self.metrics.unhealthy_fallback_selection_count.fetch_add(1, Ordering::SeqCst);
        }

        Ok(SelectedEndpoint {
            cluster_name: selected.cluster_name,
            endpoint_id: selected.endpoint_id,
            address: selected.address,
            effective_weight: selected.health.effective_weight,
            health_status: selected.health.status,
            locality_matched,
        })
    }

    /// Returns current selection metrics.
    #[must_use]
    pub fn metrics(&self) -> UpstreamSelectionMetrics {
        self.metrics.snapshot()
    }

    fn select_round_robin(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        candidates: &[EndpointSelectionCandidate],
        fallback_used: bool,
    ) -> EndpointSelectionCandidate {
        let key = ClusterCursorKey { cluster_name: cluster_name.clone(), unhealthy: fallback_used };
        let mut cursors =
            self.round_robin_cursors.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let cursor = cursors.entry(key).or_insert(0);
        let index = *cursor % candidates.len();
        *cursor = (*cursor + 1) % candidates.len();
        candidates[index].clone()
    }

    fn select_weighted_round_robin(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        candidates: &[EndpointSelectionCandidate],
        fallback_used: bool,
    ) -> EndpointSelectionCandidate {
        let key = ClusterCursorKey { cluster_name: cluster_name.clone(), unhealthy: fallback_used };
        let mut states =
            self.weighted_states.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = states.entry(key).or_default();
        state.total_weight = candidates
            .iter()
            .map(|candidate| i64::from(candidate.health.effective_weight.max(1)))
            .sum();
        state.current_weights.retain(|endpoint_id, _| {
            candidates.iter().any(|candidate| &candidate.endpoint_id == endpoint_id)
        });

        let mut best: Option<(usize, i64)> = None;
        for (index, candidate) in candidates.iter().enumerate() {
            let entry = state.current_weights.entry(candidate.endpoint_id.clone()).or_insert(0);
            *entry += i64::from(candidate.health.effective_weight.max(1));
            let current = *entry;
            match best {
                None => best = Some((index, current)),
                Some((best_index, best_weight)) => {
                    if current > best_weight
                        || (current == best_weight
                            && candidates[index].endpoint_id < candidates[best_index].endpoint_id)
                    {
                        best = Some((index, current));
                    }
                }
            }
        }

        let (best_index, _) = best.unwrap_or((0, 0));
        if let Some(current) = state.current_weights.get_mut(&candidates[best_index].endpoint_id) {
            *current -= state.total_weight;
        }
        candidates[best_index].clone()
    }

    fn select_power_of_two(
        &self,
        candidates: &[EndpointSelectionCandidate],
        request_hash: u64,
    ) -> EndpointSelectionCandidate {
        if candidates.len() == 1 {
            return candidates[0].clone();
        }

        let first_index = mix64(request_hash) as usize % candidates.len();
        let second_index = mix64(request_hash ^ 0x9e37_79b9_7f4a_7c15) as usize % candidates.len();
        let second_index = if second_index == first_index {
            (second_index + 1) % candidates.len()
        } else {
            second_index
        };

        let first = &candidates[first_index];
        let second = &candidates[second_index];
        if compare_candidates(first, second) != CmpOrdering::Less {
            first.clone()
        } else {
            second.clone()
        }
    }

    fn try_select_affinity_candidate(
        &self,
        registry: &UpstreamHealthRegistry,
        cluster_name: &lb_net_core::UpstreamClusterName,
        policy: &UpstreamSelectionPolicy,
        context: &SelectionContext,
        eligible_candidates: &[EndpointSelectionCandidate],
    ) -> Result<Option<EndpointSelectionCandidate>, UpstreamSelectionError> {
        let Some(affinity_policy) = policy.affinity.as_ref() else {
            return Ok(None);
        };
        let Some(affinity_key) = context.affinity_key.as_deref() else {
            return Ok(None);
        };

        let affinity_candidates = registry.selection_candidates(cluster_name, true)?;
        let (affinity_candidates, _) =
            apply_locality_preference(affinity_candidates, policy, context);
        if affinity_candidates.is_empty() {
            return Ok(None);
        }

        let preferred = select_affinity_candidate(&affinity_candidates, affinity_key);
        if let Some(selected) = eligible_candidates
            .iter()
            .find(|candidate| candidate.endpoint_id == preferred.endpoint_id)
        {
            self.metrics.affinity_hit_count.fetch_add(1, Ordering::SeqCst);
            return Ok(Some(selected.clone()));
        }

        self.metrics.affinity_fallback_count.fetch_add(1, Ordering::SeqCst);
        match affinity_policy {
            AffinityPolicy::HeaderHash { fallback, .. }
            | AffinityPolicy::CookieHash { fallback, .. } => match fallback {
                AffinityFallbackPolicy::BalanceHealthy => Ok(None),
            },
        }
    }
}

fn select_affinity_candidate(
    candidates: &[EndpointSelectionCandidate],
    affinity_key: &str,
) -> EndpointSelectionCandidate {
    let mut best_index = 0_usize;
    let mut best_score = f64::NEG_INFINITY;

    for (index, candidate) in candidates.iter().enumerate() {
        let score = affinity_score(affinity_key, candidate);
        let ordering = score.total_cmp(&best_score);
        if ordering == CmpOrdering::Greater
            || (ordering == CmpOrdering::Equal
                && candidate.endpoint_id < candidates[best_index].endpoint_id)
        {
            best_index = index;
            best_score = score;
        }
    }

    candidates[best_index].clone()
}

fn affinity_score(affinity_key: &str, candidate: &EndpointSelectionCandidate) -> f64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(affinity_key.as_bytes());
    hasher.write_u8(0xff);
    hasher.write(candidate.endpoint_id.as_str().as_bytes());
    let hash = hasher.finish();
    let unit_interval = (hash as f64 + 1.0) / (u64::MAX as f64 + 2.0);
    let effective_weight = f64::from(candidate.health.effective_weight.max(1));
    effective_weight / (-unit_interval.ln())
}

fn apply_locality_preference(
    candidates: Vec<EndpointSelectionCandidate>,
    policy: &UpstreamSelectionPolicy,
    context: &SelectionContext,
) -> (Vec<EndpointSelectionCandidate>, bool) {
    match policy.locality {
        LocalityRoutingPolicy::Disabled => (candidates, false),
        LocalityRoutingPolicy::PreferLocality => {
            if let Some(locality) = context.preferred_locality.as_deref() {
                prefer_by_field(candidates, |candidate| {
                    candidate.metadata.locality.as_deref() == Some(locality)
                })
            } else {
                (candidates, false)
            }
        }
        LocalityRoutingPolicy::PreferZone => {
            if let Some(zone) = context.preferred_zone.as_deref() {
                prefer_by_field(candidates, |candidate| {
                    candidate.metadata.zone.as_deref() == Some(zone)
                })
            } else {
                (candidates, false)
            }
        }
        LocalityRoutingPolicy::PreferLocalityThenZone => {
            if let Some(locality) = context.preferred_locality.as_deref() {
                let (filtered, matched) = prefer_by_field(candidates.clone(), |candidate| {
                    candidate.metadata.locality.as_deref() == Some(locality)
                });
                if matched {
                    return (filtered, true);
                }
            }
            if let Some(zone) = context.preferred_zone.as_deref() {
                prefer_by_field(candidates, |candidate| {
                    candidate.metadata.zone.as_deref() == Some(zone)
                })
            } else {
                (candidates, false)
            }
        }
    }
}

fn prefer_by_field<F>(
    candidates: Vec<EndpointSelectionCandidate>,
    predicate: F,
) -> (Vec<EndpointSelectionCandidate>, bool)
where
    F: Fn(&EndpointSelectionCandidate) -> bool,
{
    let filtered: Vec<_> =
        candidates.iter().filter(|candidate| predicate(candidate)).cloned().collect();
    if filtered.is_empty() {
        (candidates, false)
    } else {
        (filtered, true)
    }
}

fn compare_candidates(
    left: &EndpointSelectionCandidate,
    right: &EndpointSelectionCandidate,
) -> CmpOrdering {
    let left_score = candidate_score(left);
    let right_score = candidate_score(right);
    left_score.cmp(&right_score).then_with(|| right.endpoint_id.cmp(&left.endpoint_id))
}

fn candidate_score(candidate: &EndpointSelectionCandidate) -> (u8, u16, u16) {
    (
        health_rank(candidate.health.status),
        candidate.health.effective_weight,
        candidate.metadata.weight,
    )
}

fn health_rank(status: EndpointHealthStatus) -> u8 {
    match status {
        EndpointHealthStatus::Healthy => 4,
        EndpointHealthStatus::Warming => 3,
        EndpointHealthStatus::Degraded => 2,
        EndpointHealthStatus::Unhealthy => 1,
        EndpointHealthStatus::Ejected => 0,
    }
}

fn mix64(value: u64) -> u64 {
    let mut value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
