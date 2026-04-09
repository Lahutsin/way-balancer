use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Runtime selection policy for a cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSelectionPolicy {
    /// Selected balancing algorithm.
    pub algorithm: LoadBalancingAlgorithm,
    /// Locality routing behavior.
    pub locality: LocalityRoutingPolicy,
    /// Explicit no-healthy fallback behavior.
    pub no_healthy_fallback: NoHealthyFallback,
}

impl Default for UpstreamSelectionPolicy {
    fn default() -> Self {
        Self {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
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
    /// Number of power-of-two selections.
    pub power_of_two_selection_count: u64,
    /// Number of locality preference hits.
    pub locality_preference_hit_count: u64,
    /// Number of no-healthy situations encountered.
    pub no_healthy_endpoint_count: u64,
    /// Number of fallback selections performed against unhealthy endpoints.
    pub unhealthy_fallback_selection_count: u64,
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
}

impl MetricsState {
    fn snapshot(&self) -> UpstreamSelectionMetrics {
        UpstreamSelectionMetrics {
            round_robin_selection_count: self.round_robin_selection_count.load(Ordering::SeqCst),
            weighted_round_robin_selection_count: self
                .weighted_round_robin_selection_count
                .load(Ordering::SeqCst),
            power_of_two_selection_count: self.power_of_two_selection_count.load(Ordering::SeqCst),
            locality_preference_hit_count: self
                .locality_preference_hit_count
                .load(Ordering::SeqCst),
            no_healthy_endpoint_count: self.no_healthy_endpoint_count.load(Ordering::SeqCst),
            unhealthy_fallback_selection_count: self
                .unhealthy_fallback_selection_count
                .load(Ordering::SeqCst),
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

        let selected = match policy.algorithm {
            LoadBalancingAlgorithm::RoundRobin => {
                self.metrics.round_robin_selection_count.fetch_add(1, Ordering::SeqCst);
                self.select_round_robin(cluster_name, &candidates, fallback_used)
            }
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                self.metrics.weighted_round_robin_selection_count.fetch_add(1, Ordering::SeqCst);
                self.select_weighted_round_robin(cluster_name, &candidates, fallback_used)
            }
            LoadBalancingAlgorithm::PowerOfTwoChoices => {
                self.metrics.power_of_two_selection_count.fetch_add(1, Ordering::SeqCst);
                self.select_power_of_two(&candidates, context.request_hash)
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
