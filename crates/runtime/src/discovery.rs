use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::Duration;

use crate::{
    LifecycleStateMachine, RuntimeTelemetry, UpstreamHealthError, UpstreamHealthRegistry,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiscoveryProviderKind {
    DnsAaaa,
    DnsSrv,
    KubernetesEndpointSlice,
    ConsulLike,
}

impl DiscoveryProviderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DnsAaaa => "dns_aaaa",
            Self::DnsSrv => "dns_srv",
            Self::KubernetesEndpointSlice => "k8s_endpoint_slice",
            Self::ConsulLike => "consul_like",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiscoverySourceId {
    pub provider: DiscoveryProviderKind,
    pub source_name: String,
    pub cluster_name: lb_net_core::UpstreamClusterName,
}

impl DiscoverySourceId {
    pub fn new(
        provider: DiscoveryProviderKind,
        source_name: impl Into<String>,
        cluster_name: impl Into<String>,
    ) -> Result<Self, lb_net_core::UpstreamModelError> {
        Ok(Self {
            provider,
            source_name: source_name.into(),
            cluster_name: lb_net_core::UpstreamClusterName::new(cluster_name.into())?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryEndpoint {
    pub endpoint_id: lb_net_core::UpstreamEndpointId,
    pub address: SocketAddr,
    pub zone: Option<String>,
    pub locality: Option<String>,
    pub weight: u16,
}

impl DiscoveryEndpoint {
    pub fn new(
        endpoint_id: impl Into<String>,
        address: SocketAddr,
        zone: Option<String>,
        locality: Option<String>,
        weight: u16,
    ) -> Result<Self, lb_net_core::UpstreamModelError> {
        Ok(Self {
            endpoint_id: lb_net_core::UpstreamEndpointId::new(endpoint_id.into())?,
            address,
            zone,
            locality,
            weight,
        })
    }

    pub fn into_upstream_endpoint(
        &self,
        state: lb_net_core::EndpointState,
    ) -> Result<lb_net_core::UpstreamEndpoint, lb_net_core::UpstreamModelError> {
        lb_net_core::UpstreamEndpoint::new(
            self.endpoint_id.clone(),
            self.address,
            state,
            lb_net_core::EndpointMetadata {
                zone: self.zone.clone(),
                locality: self.locality.clone(),
                weight: self.weight,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverySnapshot {
    pub source: DiscoverySourceId,
    pub generation: u64,
    pub valid_for: Duration,
    pub endpoints: Vec<DiscoveryEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryRefreshHealth {
    Fresh,
    Stale,
    Backoff,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRefreshState {
    pub health: DiscoveryRefreshHealth,
    pub valid_for: Duration,
    pub next_refresh_in: Duration,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
}

impl DiscoveryRefreshState {
    #[must_use]
    pub fn fresh(valid_for: Duration) -> Self {
        Self {
            health: DiscoveryRefreshHealth::Fresh,
            valid_for,
            next_refresh_in: jittered_refresh_delay(valid_for, 0, 0x4D2),
            consecutive_failures: 0,
            last_error: None,
        }
    }

    #[must_use]
    pub fn on_failure(mut self, error: impl Into<String>) -> Self {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_error = Some(error.into());
        self.health = DiscoveryRefreshHealth::Backoff;
        self.next_refresh_in = failure_backoff_delay(self.consecutive_failures);
        self
    }

    #[must_use]
    pub fn on_expired(mut self) -> Self {
        self.health = DiscoveryRefreshHealth::Stale;
        self.next_refresh_in = Duration::from_secs(0);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiscoveryReconcileOutcome {
    pub inserted: usize,
    pub updated: usize,
    pub marked_draining: usize,
    pub removed_after_drain: usize,
    pub lifecycle_warming: usize,
    pub lifecycle_active: usize,
    pub lifecycle_draining: usize,
    pub lifecycle_drained: usize,
    pub lifecycle_removed: usize,
}

#[derive(Debug)]
pub enum DiscoveryReconcileError {
    HealthRegistry(UpstreamHealthError),
    InvalidEndpoint(lb_net_core::UpstreamModelError),
}

impl std::fmt::Display for DiscoveryReconcileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HealthRegistry(error) => write!(formatter, "discovery reconcile failed: {error}"),
            Self::InvalidEndpoint(error) => {
                write!(formatter, "discovery reconcile rejected endpoint: {error}")
            }
        }
    }
}

impl std::error::Error for DiscoveryReconcileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HealthRegistry(error) => Some(error),
            Self::InvalidEndpoint(error) => Some(error),
        }
    }
}

impl From<UpstreamHealthError> for DiscoveryReconcileError {
    fn from(value: UpstreamHealthError) -> Self {
        Self::HealthRegistry(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DrainingEndpointKey {
    cluster_name: lb_net_core::UpstreamClusterName,
    endpoint_id: lb_net_core::UpstreamEndpointId,
}

#[derive(Debug)]
pub struct DiscoveryMembershipReconciler {
    drain_grace: Duration,
    now: Duration,
    active_endpoints_by_source: BTreeMap<DiscoverySourceId, BTreeMap<lb_net_core::UpstreamEndpointId, DiscoveryEndpoint>>,
    draining_deadlines: BTreeMap<DrainingEndpointKey, Duration>,
    endpoint_lifecycle: BTreeMap<DrainingEndpointKey, LifecycleStateMachine>,
    telemetry_scope: Option<String>,
    telemetry: Option<std::sync::Arc<RuntimeTelemetry>>,
}

impl DiscoveryMembershipReconciler {
    #[must_use]
    pub fn new(drain_grace: Duration) -> Self {
        Self {
            drain_grace,
            now: Duration::ZERO,
            active_endpoints_by_source: BTreeMap::new(),
            draining_deadlines: BTreeMap::new(),
            endpoint_lifecycle: BTreeMap::new(),
            telemetry_scope: None,
            telemetry: None,
        }
    }

    #[must_use]
    pub fn with_telemetry(
        mut self,
        scope: impl Into<String>,
        telemetry: std::sync::Arc<RuntimeTelemetry>,
    ) -> Self {
        self.telemetry_scope = Some(scope.into());
        self.telemetry = Some(telemetry);
        self
    }

    pub fn reconcile_snapshot(
        &mut self,
        registry: &UpstreamHealthRegistry,
        snapshot: DiscoverySnapshot,
    ) -> Result<DiscoveryReconcileOutcome, DiscoveryReconcileError> {
        let mut outcome = DiscoveryReconcileOutcome::default();
        let source = snapshot.source.clone();
        let cluster_name = source.cluster_name.clone();
        let mut activated_endpoint_ids = Vec::new();
        let mut draining_endpoint_ids = Vec::new();
        let next_endpoints = snapshot
            .endpoints
            .iter()
            .cloned()
            .map(|endpoint| (endpoint.endpoint_id.clone(), endpoint))
            .collect::<BTreeMap<_, _>>();

        let applied_endpoint_count = {
            let previous = self.active_endpoints_by_source.entry(source.clone()).or_default();

            for (endpoint_id, endpoint) in &next_endpoints {
                match previous.get(endpoint_id) {
                    Some(current) if current == endpoint => {}
                    Some(_) => {
                        registry.remove_endpoint(&cluster_name, endpoint_id)?;
                        let refreshed = endpoint
                            .into_upstream_endpoint(lb_net_core::EndpointState::Ready)
                            .map_err(DiscoveryReconcileError::InvalidEndpoint)?;
                        registry.insert_endpoint(&cluster_name, refreshed)?;
                        self.draining_deadlines.remove(&DrainingEndpointKey {
                            cluster_name: cluster_name.clone(),
                            endpoint_id: endpoint_id.clone(),
                        });
                        activated_endpoint_ids.push(endpoint_id.clone());
                        outcome.updated += 1;
                    }
                    None => {
                        let inserted = endpoint
                            .into_upstream_endpoint(lb_net_core::EndpointState::Ready)
                            .map_err(DiscoveryReconcileError::InvalidEndpoint)?;
                        registry.insert_endpoint(&cluster_name, inserted)?;
                        self.draining_deadlines.remove(&DrainingEndpointKey {
                            cluster_name: cluster_name.clone(),
                            endpoint_id: endpoint_id.clone(),
                        });
                        activated_endpoint_ids.push(endpoint_id.clone());
                        outcome.inserted += 1;
                    }
                }
            }

            let next_ids = next_endpoints.keys().cloned().collect::<BTreeSet<_>>();
            let previous_ids = previous.keys().cloned().collect::<BTreeSet<_>>();
            for removed_id in previous_ids.difference(&next_ids) {
                registry.set_endpoint_state(&cluster_name, removed_id, lb_net_core::EndpointState::Draining)?;
                self.draining_deadlines.insert(
                    DrainingEndpointKey {
                        cluster_name: cluster_name.clone(),
                        endpoint_id: removed_id.clone(),
                    },
                    self.now.saturating_add(self.drain_grace),
                );
                draining_endpoint_ids.push(removed_id.clone());
                outcome.marked_draining += 1;
            }

            *previous = next_endpoints;
            previous.len()
        };
        for endpoint_id in &activated_endpoint_ids {
            self.record_endpoint_activated(&cluster_name, endpoint_id, &mut outcome);
        }
        for endpoint_id in &draining_endpoint_ids {
            self.record_endpoint_draining(&cluster_name, endpoint_id, &mut outcome);
        }
        self.emit_discovery_event(
            lb_observability::DecisionTraceKind::DiscoveryUpdate,
            "accepted",
            &source.cluster_name,
            &format!(
                "source {} applied generation {} with {} endpoints (inserted={}, updated={}, draining={})",
                source.source_name,
                snapshot.generation,
                applied_endpoint_count,
                outcome.inserted,
                outcome.updated,
                outcome.marked_draining
            ),
        );
        Ok(outcome)
    }

    pub fn advance_time(
        &mut self,
        registry: &UpstreamHealthRegistry,
        elapsed: Duration,
    ) -> Result<DiscoveryReconcileOutcome, DiscoveryReconcileError> {
        self.now = self.now.saturating_add(elapsed);
        let mut outcome = DiscoveryReconcileOutcome::default();
        let expired = self
            .draining_deadlines
            .iter()
            .filter(|(_, deadline)| **deadline <= self.now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();

        for key in expired {
            self.record_endpoint_drained(&key, &mut outcome);
            registry.remove_endpoint(&key.cluster_name, &key.endpoint_id)?;
            self.draining_deadlines.remove(&key);
            self.record_endpoint_removed(&key, &mut outcome);
            outcome.removed_after_drain += 1;
            self.emit_discovery_event(
                lb_observability::DecisionTraceKind::DiscoveryUpdate,
                "drained",
                &key.cluster_name,
                &format!("endpoint {} fully removed after drain window", key.endpoint_id),
            );
        }

        Ok(outcome)
    }

    fn emit_discovery_event(
        &self,
        kind: lb_observability::DecisionTraceKind,
        result: &str,
        cluster_name: &lb_net_core::UpstreamClusterName,
        detail: &str,
    ) {
        let (Some(scope), Some(telemetry)) = (&self.telemetry_scope, &self.telemetry) else {
            return;
        };
        let _ = telemetry.record_decision_trace(
            scope,
            kind,
            result,
            None,
            None,
            None,
            Some(cluster_name.as_str()),
            detail,
        );
    }

    fn endpoint_key(
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
    ) -> DrainingEndpointKey {
        DrainingEndpointKey {
            cluster_name: cluster_name.clone(),
            endpoint_id: endpoint_id.clone(),
        }
    }

    fn record_endpoint_activated(
        &mut self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
        outcome: &mut DiscoveryReconcileOutcome,
    ) {
        let key = Self::endpoint_key(cluster_name, endpoint_id);
        let machine = self
            .endpoint_lifecycle
            .entry(key)
            .or_insert_with(LifecycleStateMachine::new_warming);
        outcome.lifecycle_warming += 1;
        if machine.activate().is_err() {
            *machine = LifecycleStateMachine::new_active();
        }
        outcome.lifecycle_active += 1;
    }

    fn record_endpoint_draining(
        &mut self,
        cluster_name: &lb_net_core::UpstreamClusterName,
        endpoint_id: &lb_net_core::UpstreamEndpointId,
        outcome: &mut DiscoveryReconcileOutcome,
    ) {
        let key = Self::endpoint_key(cluster_name, endpoint_id);
        let machine = self
            .endpoint_lifecycle
            .entry(key)
            .or_insert_with(LifecycleStateMachine::new_active);
        if machine.start_draining().is_err() {
            machine.force_remove();
        }
        outcome.lifecycle_draining += 1;
    }

    fn record_endpoint_drained(
        &mut self,
        key: &DrainingEndpointKey,
        outcome: &mut DiscoveryReconcileOutcome,
    ) {
        let Some(machine) = self.endpoint_lifecycle.get_mut(key) else {
            return;
        };
        if machine.mark_drained().is_err() {
            machine.force_remove();
            return;
        }
        outcome.lifecycle_drained += 1;
    }

    fn record_endpoint_removed(
        &mut self,
        key: &DrainingEndpointKey,
        outcome: &mut DiscoveryReconcileOutcome,
    ) {
        let Some(mut machine) = self.endpoint_lifecycle.remove(key) else {
            return;
        };
        if machine.mark_removed().is_err() {
            machine.force_remove();
        }
        outcome.lifecycle_removed += 1;
    }
}

#[must_use]
pub fn jittered_refresh_delay(valid_for: Duration, attempt: u32, seed: u64) -> Duration {
    let base = if valid_for.is_zero() {
        Duration::from_secs(1)
    } else {
        valid_for
    };
    let jitter_window_ms = (base.as_millis() / 5).max(1) as u64;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    attempt.hash(&mut hasher);
    let jitter = hasher.finish() % jitter_window_ms;
    base.saturating_sub(Duration::from_millis(jitter))
}

#[must_use]
pub fn failure_backoff_delay(consecutive_failures: u32) -> Duration {
    let bounded = consecutive_failures.min(6);
    Duration::from_secs(1_u64 << bounded)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::{
        failure_backoff_delay, jittered_refresh_delay, DiscoveryEndpoint, DiscoveryMembershipReconciler,
        DiscoveryProviderKind, DiscoverySnapshot, DiscoverySourceId,
    };
    use crate::{EndpointHealthPolicy, UpstreamHealthRegistry};

    fn cluster_name() -> Result<lb_net_core::UpstreamClusterName, Box<dyn std::error::Error>> {
        Ok(lb_net_core::UpstreamClusterName::new("payments")?)
    }

    fn endpoint(id: &str, port: u16) -> Result<DiscoveryEndpoint, Box<dyn std::error::Error>> {
        Ok(DiscoveryEndpoint {
            endpoint_id: lb_net_core::UpstreamEndpointId::new(id.to_string())?,
            address: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            zone: None,
            locality: None,
            weight: 1,
        })
    }

    fn snapshot(
        generation: u64,
        endpoints: Vec<DiscoveryEndpoint>,
    ) -> Result<DiscoverySnapshot, Box<dyn std::error::Error>> {
        Ok(DiscoverySnapshot {
            source: DiscoverySourceId {
                provider: DiscoveryProviderKind::DnsAaaa,
                source_name: "payments.internal".to_string(),
                cluster_name: cluster_name()?,
            },
            generation,
            valid_for: Duration::from_secs(30),
            endpoints,
        })
    }

    fn registry() -> Result<UpstreamHealthRegistry, Box<dyn std::error::Error>> {
        let cluster = lb_net_core::UpstreamCluster::new(cluster_name()?, Vec::new())?;
        let registry = UpstreamHealthRegistry::new(EndpointHealthPolicy::default());
        registry.insert_cluster(cluster)?;
        Ok(registry)
    }

    #[test]
    fn reconciler_marks_removed_endpoints_draining_then_removes_after_grace(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = registry()?;
        let mut reconciler = DiscoveryMembershipReconciler::new(Duration::from_secs(5));

        let first = snapshot(1, vec![endpoint("payments-a", 8080)?, endpoint("payments-b", 8081)?])?;
        let applied = reconciler.reconcile_snapshot(&registry, first)?;
        assert_eq!(applied.inserted, 2);

        let second = snapshot(2, vec![endpoint("payments-a", 8080)?])?;
        let applied = reconciler.reconcile_snapshot(&registry, second)?;
        assert_eq!(applied.marked_draining, 1);

        let cluster_name = cluster_name()?;
        let draining_id = lb_net_core::UpstreamEndpointId::new("payments-b".to_string())?;
        let cluster = registry
            .selection_candidates(&cluster_name, true)?
            .into_iter()
            .map(|candidate| candidate.endpoint_id)
            .collect::<Vec<_>>();
        assert_eq!(cluster, vec![lb_net_core::UpstreamEndpointId::new("payments-a".to_string())?]);

        let before = reconciler.advance_time(&registry, Duration::from_secs(4))?;
        assert_eq!(before.removed_after_drain, 0);
        let after = reconciler.advance_time(&registry, Duration::from_secs(1))?;
        assert_eq!(after.removed_after_drain, 1);
        assert!(matches!(
            registry.endpoint_health(&cluster_name, &draining_id),
            Err(crate::UpstreamHealthError::EndpointNotTracked { .. })
                | Err(crate::UpstreamHealthError::Registry(crate::EndpointRegistryError::EndpointNotFound { .. }))
                | Err(crate::UpstreamHealthError::Registry(crate::EndpointRegistryError::ClusterNotFound(_)))
        ));
        Ok(())
    }

    #[test]
    fn refresh_delay_uses_ttl_jitter_and_failure_backoff() {
        let ttl = Duration::from_secs(30);
        let delayed = jittered_refresh_delay(ttl, 0, 123);
        assert!(delayed <= ttl);
        assert!(delayed >= Duration::from_secs(24));

        assert_eq!(failure_backoff_delay(0), Duration::from_secs(1));
        assert_eq!(failure_backoff_delay(1), Duration::from_secs(2));
        assert_eq!(failure_backoff_delay(6), Duration::from_secs(64));
        assert_eq!(failure_backoff_delay(12), Duration::from_secs(64));
    }
}
