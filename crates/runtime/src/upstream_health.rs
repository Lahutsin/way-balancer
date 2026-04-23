use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use crate::upstream_balancer::EndpointSelectionCandidate;
use crate::{EndpointRegistry, EndpointRegistryError};

const MAX_HEALTH_EVENTS: usize = 64;

/// Configurable thresholds for endpoint health transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHealthPolicy {
    /// Combined failure threshold that moves an endpoint into degraded state.
    pub degraded_failure_threshold: u32,
    /// Combined failure threshold that marks an endpoint unhealthy.
    pub unhealthy_failure_threshold: u32,
    /// Combined failure threshold that ejects an endpoint temporarily.
    pub ejection_failure_threshold: u32,
    /// Success threshold required for unhealthy or degraded endpoints to recover.
    pub recovery_success_threshold: u32,
    /// Duration for which an endpoint remains ejected.
    pub ejection_duration: Duration,
    /// Duration over which traffic is reintroduced after recovery or insertion.
    pub warmup_duration: Duration,
}

impl Default for EndpointHealthPolicy {
    fn default() -> Self {
        Self {
            degraded_failure_threshold: 1,
            unhealthy_failure_threshold: 2,
            ejection_failure_threshold: 3,
            recovery_success_threshold: 2,
            ejection_duration: Duration::from_secs(30),
            warmup_duration: Duration::from_secs(15),
        }
    }
}

/// Effective health status applied on top of the static endpoint model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointHealthStatus {
    /// Endpoint is fully available.
    Healthy,
    /// Endpoint remains available but is degraded and closer to exclusion.
    Degraded,
    /// Endpoint is unavailable until it recovers.
    Unhealthy,
    /// Endpoint is temporarily ejected due to repeated failures.
    Ejected,
    /// Endpoint is recovering and admitted with reduced effective weight.
    Warming,
}

impl EndpointHealthStatus {
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded | Self::Warming)
    }
}

/// Snapshot of the current health state for an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHealthSnapshot {
    /// Effective health status.
    pub status: EndpointHealthStatus,
    /// Number of consecutive active probe failures.
    pub active_failures: u32,
    /// Number of consecutive passive failures.
    pub passive_failures: u32,
    /// Number of consecutive recovery successes.
    pub recovery_successes: u32,
    /// Effective endpoint weight after warm-up is applied.
    pub effective_weight: u16,
    /// Remaining ejection duration if currently ejected.
    pub remaining_ejection: Option<Duration>,
    /// Remaining warm-up duration if currently warming.
    pub remaining_warmup: Option<Duration>,
}

/// Aggregate counters and gauges for upstream health management.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpstreamHealthMetrics {
    /// Count of active health-check successes.
    pub active_success_count: u64,
    /// Count of active health-check failures.
    pub active_failure_count: u64,
    /// Count of passive success hints.
    pub passive_success_count: u64,
    /// Count of passive failure hints.
    pub passive_failure_count: u64,
    /// Count of state transitions across all endpoints.
    pub state_change_count: u64,
    /// Count of ejection events.
    pub ejection_count: u64,
    /// Current number of degraded endpoints.
    pub degraded_endpoint_count: u64,
    /// Current number of unhealthy endpoints.
    pub unhealthy_endpoint_count: u64,
    /// Current number of ejected endpoints.
    pub ejected_endpoint_count: u64,
    /// Current number of warming endpoints.
    pub warming_endpoint_count: u64,
}

/// Errors returned by the upstream health registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamHealthError {
    /// Underlying registry operation failed.
    Registry(EndpointRegistryError),
    /// Registry topology and health records diverged unexpectedly.
    InconsistentState {
        cluster: lb_net_core::UpstreamClusterName,
        endpoint_id: lb_net_core::UpstreamEndpointId,
    },
    /// Health state was requested for an untracked endpoint.
    EndpointNotTracked {
        cluster: lb_net_core::UpstreamClusterName,
        endpoint_id: lb_net_core::UpstreamEndpointId,
    },
}

impl fmt::Display for UpstreamHealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => write!(formatter, "upstream health registry error: {error}"),
            Self::InconsistentState { cluster, endpoint_id } => write!(
                formatter,
                "endpoint {endpoint_id} in cluster {cluster} is missing health state"
            ),
            Self::EndpointNotTracked { cluster, endpoint_id } => {
                write!(formatter, "endpoint {endpoint_id} in cluster {cluster} is not tracked")
            }
        }
    }
}

impl std::error::Error for UpstreamHealthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            Self::InconsistentState { .. } => None,
            Self::EndpointNotTracked { .. } => None,
        }
    }
}

impl From<EndpointRegistryError> for UpstreamHealthError {
    fn from(value: EndpointRegistryError) -> Self {
        Self::Registry(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EndpointKey {
    cluster: lb_net_core::UpstreamClusterName,
    endpoint_id: lb_net_core::UpstreamEndpointId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointHealthRecord {
    status: EndpointHealthStatus,
    active_failures: u32,
    passive_failures: u32,
    recovery_successes: u32,
    effective_weight: u16,
    remaining_ejection: Duration,
    warmup_elapsed: Duration,
    nominal_weight: u16,
}

impl EndpointHealthRecord {
    fn new(endpoint: &lb_net_core::UpstreamEndpoint, policy: &EndpointHealthPolicy) -> Self {
        let nominal_weight = endpoint.metadata().weight;
        if endpoint.state().is_ready() && !policy.warmup_duration.is_zero() {
            Self {
                status: EndpointHealthStatus::Warming,
                active_failures: 0,
                passive_failures: 0,
                recovery_successes: 0,
                effective_weight: 1,
                remaining_ejection: Duration::ZERO,
                warmup_elapsed: Duration::ZERO,
                nominal_weight,
            }
        } else {
            Self {
                status: EndpointHealthStatus::Healthy,
                active_failures: 0,
                passive_failures: 0,
                recovery_successes: 0,
                effective_weight: nominal_weight,
                remaining_ejection: Duration::ZERO,
                warmup_elapsed: Duration::ZERO,
                nominal_weight,
            }
        }
    }

    fn snapshot(&self, policy: &EndpointHealthPolicy) -> EndpointHealthSnapshot {
        let remaining_ejection =
            (!self.remaining_ejection.is_zero()).then_some(self.remaining_ejection);
        let remaining_warmup = if matches!(self.status, EndpointHealthStatus::Warming) {
            policy.warmup_duration.checked_sub(self.warmup_elapsed).or(Some(Duration::ZERO))
        } else {
            None
        };

        EndpointHealthSnapshot {
            status: self.status,
            active_failures: self.active_failures,
            passive_failures: self.passive_failures,
            recovery_successes: self.recovery_successes,
            effective_weight: self.effective_weight,
            remaining_ejection,
            remaining_warmup,
        }
    }

    fn combined_failures(&self) -> u32 {
        self.active_failures.saturating_add(self.passive_failures)
    }
}

#[derive(Debug, Default)]
struct MetricsState {
    active_success_count: AtomicU64,
    active_failure_count: AtomicU64,
    passive_success_count: AtomicU64,
    passive_failure_count: AtomicU64,
    state_change_count: AtomicU64,
    ejection_count: AtomicU64,
}

impl MetricsState {
    fn snapshot(
        &self,
        records: &BTreeMap<EndpointKey, EndpointHealthRecord>,
    ) -> UpstreamHealthMetrics {
        let mut degraded_endpoint_count = 0_u64;
        let mut unhealthy_endpoint_count = 0_u64;
        let mut ejected_endpoint_count = 0_u64;
        let mut warming_endpoint_count = 0_u64;

        for record in records.values() {
            match record.status {
                EndpointHealthStatus::Healthy => {}
                EndpointHealthStatus::Degraded => degraded_endpoint_count += 1,
                EndpointHealthStatus::Unhealthy => unhealthy_endpoint_count += 1,
                EndpointHealthStatus::Ejected => ejected_endpoint_count += 1,
                EndpointHealthStatus::Warming => warming_endpoint_count += 1,
            }
        }

        UpstreamHealthMetrics {
            active_success_count: self.active_success_count.load(Ordering::SeqCst),
            active_failure_count: self.active_failure_count.load(Ordering::SeqCst),
            passive_success_count: self.passive_success_count.load(Ordering::SeqCst),
            passive_failure_count: self.passive_failure_count.load(Ordering::SeqCst),
            state_change_count: self.state_change_count.load(Ordering::SeqCst),
            ejection_count: self.ejection_count.load(Ordering::SeqCst),
            degraded_endpoint_count,
            unhealthy_endpoint_count,
            ejected_endpoint_count,
            warming_endpoint_count,
        }
    }
}

/// Endpoint registry with active/passive health semantics and warm-up support.
#[derive(Debug)]
pub struct UpstreamHealthRegistry {
    registry: EndpointRegistry,
    policy: EndpointHealthPolicy,
    topology: RwLock<()>,
    records: RwLock<BTreeMap<EndpointKey, EndpointHealthRecord>>,
    events: Mutex<VecDeque<lb_observability::UpstreamHealthEvent>>,
    metrics: MetricsState,
}

impl UpstreamHealthRegistry {
    /// Creates an empty health-aware upstream registry.
    #[must_use]
    pub fn new(policy: EndpointHealthPolicy) -> Self {
        Self {
            registry: EndpointRegistry::new(),
            policy,
            topology: RwLock::new(()),
            records: RwLock::new(BTreeMap::new()),
            events: Mutex::new(VecDeque::with_capacity(MAX_HEALTH_EVENTS)),
            metrics: MetricsState::default(),
        }
    }

    /// Inserts a cluster and initializes health tracking for its endpoints.
    pub fn insert_cluster(
        &self,
        cluster: lb_net_core::UpstreamCluster,
    ) -> Result<(), UpstreamHealthError> {
        let _topology = self.topology.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster_name = cluster.name().clone();
        let endpoints = cluster.endpoints().to_vec();
        self.registry.insert_cluster(cluster)?;
        let mut records = self.records.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        for endpoint in &endpoints {
            let key =
                EndpointKey { cluster: cluster_name.clone(), endpoint_id: endpoint.id().clone() };
            let record = EndpointHealthRecord::new(endpoint, &self.policy);
            if matches!(record.status, EndpointHealthStatus::Warming) {
                self.push_event(
                    lb_observability::UpstreamHealthEventKind::WarmupStarted,
                    &cluster_name,
                    endpoint.id(),
                    "endpoint admitted in warm-up mode",
                );
            }
            records.insert(key, record);
        }
        Ok(())
    }

    /// Removes a cluster and all associated health records.
    #[must_use]
    pub fn remove_cluster(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
    ) -> Option<lb_net_core::UpstreamCluster> {
        let _topology = self.topology.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = self.registry.remove_cluster(cluster_name);
        if removed.is_some() {
            let mut records = self.records.write().unwrap_or_else(|poisoned| poisoned.into_inner());
            records.retain(|key, _| &key.cluster != cluster_name);
        }
        removed
    }

    /// Inserts a new endpoint and initializes its health state.
    pub fn insert_endpoint(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint: lb_net_core::UpstreamEndpoint,
    ) -> Result<(), UpstreamHealthError> {
        let _topology = self.topology.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let endpoint_id = endpoint.id().clone();
        let record = EndpointHealthRecord::new(&endpoint, &self.policy);
        self.registry.insert_endpoint(cluster_name, endpoint)?;
        let mut records = self.records.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        records.insert(
            EndpointKey { cluster: cluster_name.clone(), endpoint_id: endpoint_id.clone() },
            record,
        );
        if self.policy.warmup_duration > Duration::ZERO {
            self.push_event(
                lb_observability::UpstreamHealthEventKind::WarmupStarted,
                cluster_name,
                &endpoint_id,
                "endpoint admitted in warm-up mode",
            );
        }
        Ok(())
    }

    /// Removes an endpoint and its health record.
    pub fn remove_endpoint(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<lb_net_core::UpstreamEndpoint, UpstreamHealthError> {
        let _topology = self.topology.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let endpoint = self.registry.remove_endpoint(cluster_name, endpoint_id)?;
        let mut records = self.records.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = records.remove(&EndpointKey {
            cluster: cluster_name.clone(),
            endpoint_id: endpoint_id.clone(),
        });
        Ok(endpoint)
    }

    /// Records an active health-check success.
    pub fn note_active_success(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        self.metrics.active_success_count.fetch_add(1, Ordering::SeqCst);
        self.apply_signal(cluster_name, endpoint_id, HealthSignal::ActiveSuccess)
    }

    /// Records an active health-check failure.
    pub fn note_active_failure(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        self.metrics.active_failure_count.fetch_add(1, Ordering::SeqCst);
        self.apply_signal(cluster_name, endpoint_id, HealthSignal::ActiveFailure)
    }

    /// Records a passive success hint.
    pub fn note_passive_success(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        self.metrics.passive_success_count.fetch_add(1, Ordering::SeqCst);
        self.apply_signal(cluster_name, endpoint_id, HealthSignal::PassiveSuccess)
    }

    /// Records a passive failure hint.
    pub fn note_passive_failure(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        self.metrics.passive_failure_count.fetch_add(1, Ordering::SeqCst);
        self.apply_signal(cluster_name, endpoint_id, HealthSignal::PassiveFailure)
    }

    /// Advances ejection and warm-up timers for all tracked endpoints.
    pub fn advance_time(&self, elapsed: Duration) {
        if elapsed.is_zero() {
            return;
        }

        let mut state_changes = 0_u64;
        let mut ejection_expirations = Vec::new();
        let mut warmup_completions = Vec::new();
        let mut records = self.records.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        for (key, record) in records.iter_mut() {
            if matches!(record.status, EndpointHealthStatus::Ejected) {
                if elapsed >= record.remaining_ejection {
                    record.remaining_ejection = Duration::ZERO;
                    let previous_status = record.status;
                    record.status = EndpointHealthStatus::Unhealthy;
                    state_changes += u64::from(previous_status != record.status);
                    ejection_expirations.push((key.cluster.clone(), key.endpoint_id.clone()));
                } else {
                    record.remaining_ejection -= elapsed;
                }
            }

            if matches!(record.status, EndpointHealthStatus::Warming) {
                record.warmup_elapsed = record.warmup_elapsed.saturating_add(elapsed);
                record.effective_weight = warmup_weight(
                    record.nominal_weight,
                    record.warmup_elapsed,
                    self.policy.warmup_duration,
                );
                if record.warmup_elapsed >= self.policy.warmup_duration {
                    record.status = EndpointHealthStatus::Healthy;
                    record.effective_weight = record.nominal_weight;
                    state_changes += 1;
                    warmup_completions.push((key.cluster.clone(), key.endpoint_id.clone()));
                }
            }
        }
        if state_changes != 0 {
            self.metrics.state_change_count.fetch_add(state_changes, Ordering::SeqCst);
        }
        drop(records);

        for (cluster, endpoint_id) in ejection_expirations {
            self.push_event(
                lb_observability::UpstreamHealthEventKind::RecoveryStarted,
                &cluster,
                &endpoint_id,
                "endpoint ejection expired and recovery checks may resume",
            );
        }
        for (cluster, endpoint_id) in warmup_completions {
            self.push_event(
                lb_observability::UpstreamHealthEventKind::WarmupCompleted,
                &cluster,
                &endpoint_id,
                "endpoint completed warm-up and is fully admitted",
            );
        }
    }

    /// Returns the effective cluster state after health filtering is applied.
    pub fn cluster_state(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
    ) -> Result<lb_net_core::UpstreamClusterState, UpstreamHealthError> {
        let _topology = self.topology.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster = self.registry.cluster(cluster_name).ok_or_else(|| {
            UpstreamHealthError::Registry(EndpointRegistryError::ClusterNotFound(
                cluster_name.clone(),
            ))
        })?;
        let total_endpoints = cluster.endpoints().len();
        if total_endpoints == 0 {
            return Ok(lb_net_core::UpstreamClusterState::Empty);
        }

        let records = self.records.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut ready_endpoints = 0_usize;
        for endpoint in cluster.endpoints() {
            let key =
                EndpointKey { cluster: cluster_name.clone(), endpoint_id: endpoint.id().clone() };
            let record = records.get(&key).ok_or_else(|| UpstreamHealthError::InconsistentState {
                cluster: cluster_name.clone(),
                endpoint_id: endpoint.id().clone(),
            })?;
            if endpoint.state().is_ready() && record.status.is_available() {
                ready_endpoints += 1;
            }
        }

        if ready_endpoints == 0 {
            Ok(lb_net_core::UpstreamClusterState::Unavailable { total_endpoints })
        } else {
            Ok(lb_net_core::UpstreamClusterState::Ready { total_endpoints, ready_endpoints })
        }
    }

    /// Returns the health snapshot for a tracked endpoint.
    pub fn endpoint_health(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        let _topology = self.topology.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster = self.registry.cluster(cluster_name).ok_or_else(|| {
            UpstreamHealthError::Registry(EndpointRegistryError::ClusterNotFound(
                cluster_name.clone(),
            ))
        })?;
        if cluster.endpoint(endpoint_id).is_none() {
            return Err(UpstreamHealthError::EndpointNotTracked {
                cluster: cluster_name.clone(),
                endpoint_id: endpoint_id.clone(),
            });
        }
        let records = self.records.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = records
            .get(&EndpointKey { cluster: cluster_name.clone(), endpoint_id: endpoint_id.clone() })
            .ok_or_else(|| UpstreamHealthError::InconsistentState {
                cluster: cluster_name.clone(),
                endpoint_id: endpoint_id.clone(),
            })?;
        Ok(record.snapshot(&self.policy))
    }

    /// Returns selection candidates after combining static readiness with dynamic health state.
    pub fn selection_candidates(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        include_unhealthy: bool,
    ) -> Result<Vec<EndpointSelectionCandidate>, UpstreamHealthError> {
        let _topology = self.topology.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster = self.registry.cluster(cluster_name).ok_or_else(|| {
            UpstreamHealthError::Registry(EndpointRegistryError::ClusterNotFound(
                cluster_name.clone(),
            ))
        })?;
        let records = self.records.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut candidates = Vec::new();

        for endpoint in cluster.endpoints() {
            if !endpoint.state().is_ready() {
                continue;
            }
            let key =
                EndpointKey { cluster: cluster_name.clone(), endpoint_id: endpoint.id().clone() };
            let record = records.get(&key).ok_or_else(|| UpstreamHealthError::InconsistentState {
                cluster: cluster_name.clone(),
                endpoint_id: endpoint.id().clone(),
            })?;
            let snapshot = record.snapshot(&self.policy);
            let allowed = snapshot.status.is_available()
                || (include_unhealthy
                    && matches!(snapshot.status, EndpointHealthStatus::Unhealthy));
            if !allowed {
                continue;
            }
            candidates.push(EndpointSelectionCandidate {
                cluster_name: cluster_name.clone(),
                endpoint_id: endpoint.id().clone(),
                address: endpoint.address(),
                metadata: endpoint.metadata().clone(),
                health: snapshot,
            });
        }

        candidates.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
        Ok(candidates)
    }

    /// Returns the current health metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> UpstreamHealthMetrics {
        let records = self.records.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.metrics.snapshot(&records)
    }

    /// Returns recent bounded health events.
    #[must_use]
    pub fn recent_events(&self) -> Vec<lb_observability::UpstreamHealthEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    fn apply_signal(
        &self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
        signal: HealthSignal,
    ) -> Result<EndpointHealthSnapshot, UpstreamHealthError> {
        let _topology = self.topology.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut records = self.records.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = EndpointKey { cluster: cluster_name.clone(), endpoint_id: endpoint_id.clone() };
        let record =
            records.get_mut(&key).ok_or_else(|| UpstreamHealthError::EndpointNotTracked {
                cluster: cluster_name.clone(),
                endpoint_id: endpoint_id.clone(),
            })?;

        let previous_status = record.status;
        match signal {
            HealthSignal::ActiveFailure => {
                record.active_failures = record.active_failures.saturating_add(1);
                record.recovery_successes = 0;
                transition_on_failures(record, &self.policy);
            }
            HealthSignal::PassiveFailure => {
                record.passive_failures = record.passive_failures.saturating_add(1);
                record.recovery_successes = 0;
                transition_on_failures(record, &self.policy);
            }
            HealthSignal::ActiveSuccess | HealthSignal::PassiveSuccess => {
                transition_on_success(record, &self.policy);
            }
        }

        let state_changed = previous_status != record.status;
        if state_changed {
            self.metrics.state_change_count.fetch_add(1, Ordering::SeqCst);
            if matches!(record.status, EndpointHealthStatus::Ejected) {
                self.metrics.ejection_count.fetch_add(1, Ordering::SeqCst);
            }
        }
        let snapshot = record.snapshot(&self.policy);
        drop(records);

        if state_changed {
            let (kind, detail) = event_for_transition(previous_status, snapshot.status);
            self.push_event(kind, cluster_name, endpoint_id, detail);
        }

        Ok(snapshot)
    }

    fn push_event(
        &self,
        kind: lb_observability::UpstreamHealthEventKind,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
        detail: impl Into<String>,
    ) {
        let mut events = self.events.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() == MAX_HEALTH_EVENTS {
            let _ = events.pop_front();
        }
        events.push_back(lb_observability::UpstreamHealthEvent {
            kind,
            cluster_name: cluster_name.to_string(),
            endpoint_id: endpoint_id.to_string(),
            detail: detail.into(),
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthSignal {
    ActiveSuccess,
    ActiveFailure,
    PassiveSuccess,
    PassiveFailure,
}

fn transition_on_failures(record: &mut EndpointHealthRecord, policy: &EndpointHealthPolicy) {
    if matches!(record.status, EndpointHealthStatus::Ejected) {
        return;
    }

    let combined_failures = record.combined_failures();
    if combined_failures >= policy.ejection_failure_threshold {
        record.status = EndpointHealthStatus::Ejected;
        record.remaining_ejection = policy.ejection_duration;
        record.effective_weight = 0;
        record.recovery_successes = 0;
        return;
    }

    if combined_failures >= policy.unhealthy_failure_threshold {
        record.status = EndpointHealthStatus::Unhealthy;
        record.effective_weight = 0;
        return;
    }

    if combined_failures >= policy.degraded_failure_threshold {
        record.status = EndpointHealthStatus::Degraded;
        record.effective_weight = record.nominal_weight;
    }
}

fn transition_on_success(record: &mut EndpointHealthRecord, policy: &EndpointHealthPolicy) {
    if matches!(record.status, EndpointHealthStatus::Ejected) {
        return;
    }

    if matches!(record.status, EndpointHealthStatus::Healthy | EndpointHealthStatus::Warming) {
        record.active_failures = 0;
        record.passive_failures = 0;
        record.recovery_successes = 0;
        return;
    }

    record.recovery_successes = record.recovery_successes.saturating_add(1);
    if record.recovery_successes < policy.recovery_success_threshold {
        return;
    }

    record.active_failures = 0;
    record.passive_failures = 0;
    record.recovery_successes = 0;
    if policy.warmup_duration.is_zero() {
        record.status = EndpointHealthStatus::Healthy;
        record.effective_weight = record.nominal_weight;
    } else {
        record.status = EndpointHealthStatus::Warming;
        record.warmup_elapsed = Duration::ZERO;
        record.effective_weight = 1;
    }
}

fn warmup_weight(nominal_weight: u16, warmup_elapsed: Duration, warmup_duration: Duration) -> u16 {
    if warmup_duration.is_zero() || warmup_elapsed >= warmup_duration {
        return nominal_weight;
    }

    let numerator = nominal_weight as u128 * warmup_elapsed.as_millis();
    let denominator = warmup_duration.as_millis().max(1);
    let progressive_weight = (numerator / denominator) as u16;
    progressive_weight.max(1).min(nominal_weight)
}

fn event_for_transition(
    previous: EndpointHealthStatus,
    current: EndpointHealthStatus,
) -> (lb_observability::UpstreamHealthEventKind, &'static str) {
    match (previous, current) {
        (_, EndpointHealthStatus::Degraded) => (
            lb_observability::UpstreamHealthEventKind::Degraded,
            "endpoint entered degraded health state",
        ),
        (_, EndpointHealthStatus::Unhealthy) => (
            lb_observability::UpstreamHealthEventKind::Unhealthy,
            "endpoint became unhealthy and is excluded from traffic",
        ),
        (_, EndpointHealthStatus::Ejected) => (
            lb_observability::UpstreamHealthEventKind::Ejected,
            "endpoint was ejected after repeated failures",
        ),
        (_, EndpointHealthStatus::Warming) => (
            lb_observability::UpstreamHealthEventKind::WarmupStarted,
            "endpoint re-entered warm-up after recovery",
        ),
        (_, EndpointHealthStatus::Healthy) => (
            lb_observability::UpstreamHealthEventKind::Recovered,
            "endpoint recovered and is fully healthy",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        EndpointHealthPolicy, EndpointKey, UpstreamHealthError, UpstreamHealthRegistry,
    };

    fn endpoint(
        id: &str,
        port: u16,
        weight: u16,
    ) -> Result<lb_net_core::UpstreamEndpoint, Box<dyn std::error::Error>> {
        Ok(lb_net_core::UpstreamEndpoint::new(
            lb_net_core::UpstreamEndpointId::new(id)?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            lb_net_core::EndpointState::Ready,
            lb_net_core::EndpointMetadata { zone: None, locality: None, weight },
        )?)
    }

    #[test]
    fn inconsistent_endpoint_records_are_reported_explicitly(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = UpstreamHealthRegistry::new(EndpointHealthPolicy::default());
        let cluster_name = lb_net_core::UpstreamClusterName::new("payments")?;
        let endpoint_id = lb_net_core::UpstreamEndpointId::new("a")?;
        registry.insert_cluster(lb_net_core::UpstreamCluster::new(
            cluster_name.clone(),
            vec![endpoint(endpoint_id.as_str(), 8080, 3)?],
        )?)?;

        let mut records = registry.records.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        records.remove(&EndpointKey {
            cluster: cluster_name.clone(),
            endpoint_id: endpoint_id.clone(),
        });
        drop(records);

        assert!(matches!(
            registry.endpoint_health(&cluster_name, &endpoint_id),
            Err(UpstreamHealthError::InconsistentState { cluster, endpoint_id: id })
                if cluster == cluster_name && id == endpoint_id
        ));
        assert!(matches!(
            registry.cluster_state(&cluster_name),
            Err(UpstreamHealthError::InconsistentState { cluster, endpoint_id: id })
                if cluster == cluster_name && id == endpoint_id
        ));
        assert!(matches!(
            registry.selection_candidates(&cluster_name, false),
            Err(UpstreamHealthError::InconsistentState { cluster, endpoint_id: id })
                if cluster == cluster_name && id == endpoint_id
        ));
        Ok(())
    }
}
