use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    collect_wave_health_signals, evaluate_wave_gate, plan_staged_rollout, render_staged_status_surface,
    FleetAbortRollbackDecision, FleetAutoRollbackOutcome, FleetHealthGatePolicy, FleetNodeBackend,
    FleetRollbackPolicyConfig, FleetRolloutCoordinator, FleetRolloutError, FleetRolloutRequest, FleetRolloutResponse,
    FleetRolloutStrategy, FleetStagedRolloutPlan, FleetStagedRolloutRequest,
    FleetStagedStatusSurface, FleetWaveGateEvaluation, InvalidFleetStagedRolloutRequest,
    SnapshotControlService, SnapshotDiffPreview, SnapshotDiffPreviewError, SnapshotImpactSeverity,
    SnapshotLookupError,
};

const MAX_LISTENER_NAME_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerCanaryApplyRequest {
    pub listener_name: String,
    pub candidate_version: String,
    pub baseline_version: Option<String>,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
    pub node_ids: Vec<String>,
    pub canary_nodes: usize,
    pub canary_max_parallel: usize,
    pub fleet_max_parallel: usize,
    pub max_allowed_divergence_ms: u64,
    pub gate_policy: FleetHealthGatePolicy,
    pub allow_staged_apply: bool,
    pub rollback_policy: FleetRollbackPolicyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerCanaryApplyResponse {
    pub listener_name: String,
    pub candidate_version: String,
    pub snapshot_preview: SnapshotDiffPreview,
    pub staged_plan: FleetStagedRolloutPlan,
    pub rollout: FleetRolloutResponse,
    pub wave_gates: BTreeMap<String, FleetWaveGateEvaluation>,
    pub abort_decision: Option<FleetAbortRollbackDecision>,
    pub auto_rollback: Option<FleetAutoRollbackOutcome>,
    pub status: FleetStagedStatusSurface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListenerCanaryMetrics {
    pub apply_count: u64,
    pub blocked_apply_count: u64,
    pub auto_rollback_count: u64,
}

#[derive(Debug)]
pub enum ListenerCanaryError {
    EmptyListenerName,
    ListenerNameTooLong,
    EmptyCandidateVersion,
    InvalidCanaryNodes,
    InvalidCanaryMaxParallel,
    InvalidFleetMaxParallel,
    CandidateNotPublished(String),
    SnapshotLookup(SnapshotLookupError),
    DiffPreview(SnapshotDiffPreviewError),
    StagedApplyRequired { severity: SnapshotImpactSeverity },
    Plan(InvalidFleetStagedRolloutRequest),
    Fleet(FleetRolloutError),
    Internal(SystemTimeError),
}

impl std::fmt::Display for ListenerCanaryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyListenerName => write!(formatter, "listener_name must not be empty"),
            Self::ListenerNameTooLong => write!(formatter, "listener_name exceeds max length"),
            Self::EmptyCandidateVersion => write!(formatter, "candidate_version must not be empty"),
            Self::InvalidCanaryNodes => {
                write!(formatter, "canary_nodes must be in 1..=node_ids.len()")
            }
            Self::InvalidCanaryMaxParallel => write!(
                formatter,
                "canary_max_parallel must be in 1..=canary wave size"
            ),
            Self::InvalidFleetMaxParallel => {
                write!(formatter, "fleet_max_parallel must be in 1..=fleet wave size")
            }
            Self::CandidateNotPublished(version) => {
                write!(formatter, "candidate version '{version}' was not found")
            }
            Self::SnapshotLookup(error) => write!(formatter, "listener canary lookup failed: {error}"),
            Self::DiffPreview(error) => {
                write!(formatter, "listener canary preview failed: {error}")
            }
            Self::StagedApplyRequired { severity } => write!(
                formatter,
                "listener canary apply requires staged acknowledgment for {severity:?} impact"
            ),
            Self::Plan(error) => write!(formatter, "listener canary staged plan is invalid: {error}"),
            Self::Fleet(error) => write!(formatter, "listener canary fleet apply failed: {error}"),
            Self::Internal(error) => write!(formatter, "listener canary failed internally: {error}"),
        }
    }
}

impl std::error::Error for ListenerCanaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SnapshotLookup(error) => Some(error),
            Self::DiffPreview(error) => Some(error),
            Self::Plan(error) => Some(error),
            Self::Fleet(error) => Some(error),
            Self::Internal(error) => Some(error),
            Self::EmptyListenerName
            | Self::ListenerNameTooLong
            | Self::EmptyCandidateVersion
            | Self::InvalidCanaryNodes
            | Self::InvalidCanaryMaxParallel
            | Self::InvalidFleetMaxParallel
            | Self::CandidateNotPublished(_)
            | Self::StagedApplyRequired { .. } => None,
        }
    }
}

#[derive(Debug)]
pub struct SystemTimeError(std::time::SystemTimeError);

impl std::fmt::Display for SystemTimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "failed to read system time: {}", self.0)
    }
}

impl std::error::Error for SystemTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug, Default)]
pub struct ListenerCanaryCoordinator {
    metrics: ListenerCanaryMetrics,
}

impl ListenerCanaryCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply<B>(
        &mut self,
        control: &SnapshotControlService,
        fleet: &mut FleetRolloutCoordinator,
        backend: &mut B,
        request: ListenerCanaryApplyRequest,
    ) -> Result<ListenerCanaryApplyResponse, ListenerCanaryError>
    where
        B: FleetNodeBackend,
    {
        let listener_name = request.listener_name.trim();
        if listener_name.is_empty() {
            return Err(ListenerCanaryError::EmptyListenerName);
        }
        if listener_name.len() > MAX_LISTENER_NAME_LEN {
            return Err(ListenerCanaryError::ListenerNameTooLong);
        }

        let candidate_version = request.candidate_version.trim();
        if candidate_version.is_empty() {
            return Err(ListenerCanaryError::EmptyCandidateVersion);
        }
        if request.canary_nodes == 0 || request.canary_nodes > request.node_ids.len() {
            return Err(ListenerCanaryError::InvalidCanaryNodes);
        }

        let candidate = match control.get_version(candidate_version) {
            Ok(record) => record,
            Err(SnapshotLookupError::VersionNotFound(version)) => {
                return Err(ListenerCanaryError::CandidateNotPublished(version));
            }
            Err(error) => return Err(ListenerCanaryError::SnapshotLookup(error)),
        };

        let snapshot_preview = control
            .preview_diff(request.baseline_version.as_deref(), &candidate.snapshot)
            .map_err(ListenerCanaryError::DiffPreview)?;
        let needs_staged_ack = matches!(
            snapshot_preview.impact_analysis.severity,
            SnapshotImpactSeverity::Medium | SnapshotImpactSeverity::High
        );
        if needs_staged_ack && !request.allow_staged_apply {
            self.metrics.blocked_apply_count = self.metrics.blocked_apply_count.saturating_add(1);
            return Err(ListenerCanaryError::StagedApplyRequired {
                severity: snapshot_preview.impact_analysis.severity,
            });
        }

        let canary_nodes = request.node_ids[..request.canary_nodes].to_vec();
        let fleet_nodes = request.node_ids[request.canary_nodes..].to_vec();
        if request.canary_max_parallel == 0 || request.canary_max_parallel > canary_nodes.len() {
            return Err(ListenerCanaryError::InvalidCanaryMaxParallel);
        }
        if !fleet_nodes.is_empty()
            && (request.fleet_max_parallel == 0 || request.fleet_max_parallel > fleet_nodes.len())
        {
            return Err(ListenerCanaryError::InvalidFleetMaxParallel);
        }

        let mut waves = vec![crate::FleetRolloutWaveDefinition {
            wave_id: format!("{listener_name}-canary"),
            node_ids: canary_nodes,
            max_parallel: request.canary_max_parallel,
            gate_policy: request.gate_policy.clone(),
        }];
        if !fleet_nodes.is_empty() {
            waves.push(crate::FleetRolloutWaveDefinition {
                wave_id: format!("{listener_name}-fleet"),
                node_ids: fleet_nodes,
                max_parallel: request.fleet_max_parallel,
                gate_policy: request.gate_policy.clone(),
            });
        }

        let staged_plan = plan_staged_rollout(FleetStagedRolloutRequest {
            rollout: FleetRolloutRequest {
                version: candidate_version.to_string(),
                requested_by: request.requested_by.clone(),
                reason: request.reason.clone(),
                node_ids: request.node_ids.clone(),
                strategy: FleetRolloutStrategy::Canary {
                    canary_nodes: request.canary_nodes,
                },
                max_allowed_divergence_ms: request.max_allowed_divergence_ms,
            },
            waves,
        })
        .map_err(ListenerCanaryError::Plan)?;

        let occurred_at_unix_ms = current_unix_ms().map_err(ListenerCanaryError::Internal)?;
        let rollout = fleet
            .rollout_at(control, backend, staged_plan.rollout.clone(), occurred_at_unix_ms)
            .map_err(ListenerCanaryError::Fleet)?;

        let mut wave_gates = BTreeMap::new();
        for wave in &staged_plan.waves {
            let signals = collect_wave_health_signals(backend, wave);
            let evaluated_at = current_unix_ms().map_err(ListenerCanaryError::Internal)?;
            let gate = evaluate_wave_gate(wave, &signals, occurred_at_unix_ms, evaluated_at);
            wave_gates.insert(wave.wave_id.clone(), gate);
        }

        let abort_decision = staged_plan
            .waves
            .first()
            .and_then(|first| wave_gates.get(&first.wave_id))
            .map(|gate| {
                FleetRolloutCoordinator::decide_wave_abort_and_rollback(
                    gate,
                    request.rollback_policy,
                )
            });

        let auto_rollback = if let Some(decision) = &abort_decision {
            let outcome = fleet
                .execute_auto_rollback_if_needed(
                    control,
                    backend,
                    &request.node_ids,
                    decision,
                    request.requested_by.clone(),
                    request.reason.clone(),
                    request.max_allowed_divergence_ms,
                    occurred_at_unix_ms,
                )
                .map_err(ListenerCanaryError::Fleet)?;
            if outcome.attempted {
                self.metrics.auto_rollback_count = self.metrics.auto_rollback_count.saturating_add(1);
                Some(outcome)
            } else {
                None
            }
        } else {
            None
        };

        let status = render_staged_status_surface(
            &staged_plan,
            &rollout.convergence,
            &wave_gates,
            abort_decision.as_ref(),
            auto_rollback.as_ref(),
        );

        self.metrics.apply_count = self.metrics.apply_count.saturating_add(1);
        Ok(ListenerCanaryApplyResponse {
            listener_name: listener_name.to_string(),
            candidate_version: candidate_version.to_string(),
            snapshot_preview,
            staged_plan,
            rollout,
            wave_gates,
            abort_decision,
            auto_rollback,
            status,
        })
    }

    #[must_use]
    pub const fn metrics(&self) -> ListenerCanaryMetrics {
        self.metrics
    }
}

fn current_unix_ms() -> Result<u64, SystemTimeError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(SystemTimeError)?;
    let millis = duration.as_millis();
    Ok(u64::try_from(millis).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lb_config_model::WorkspaceConfig;
    use lb_test_support::{configure_test_trusted_signers, test_artifact_attestation};

    use super::{ListenerCanaryApplyRequest, ListenerCanaryCoordinator, ListenerCanaryError};

    #[derive(Debug, Clone)]
    struct MockNode {
        status: crate::FleetNodeRuntimeStatus,
    }

    #[derive(Debug, Default)]
    struct MockBackend {
        nodes: BTreeMap<String, MockNode>,
        digests: BTreeMap<String, String>,
    }

    impl MockBackend {
        fn with_node(mut self, node_id: &str, version: &str, digest: &str) -> Self {
            self.nodes.insert(
                node_id.to_string(),
                MockNode {
                    status: crate::FleetNodeRuntimeStatus {
                        node_id: node_id.to_string(),
                        desired_version: Some(version.to_string()),
                        desired_digest_sha256: Some(digest.to_string()),
                        active_version: Some(version.to_string()),
                        active_digest_sha256: Some(digest.to_string()),
                        last_known_good_version: Some(version.to_string()),
                        readiness: Some(String::from("ready")),
                        observed_at_unix_ms: 10,
                    },
                },
            );
            self
        }
    }

    impl crate::FleetNodeBackend for MockBackend {
        fn fetch_status(
            &self,
            node_id: &str,
        ) -> Result<crate::FleetNodeRuntimeStatus, crate::FleetNodeBackendError> {
            self.nodes
                .get(node_id)
                .map(|node| node.status.clone())
                .ok_or_else(|| crate::FleetNodeBackendError::Unreachable(String::from("missing node")))
        }

        fn fetch_health_signals(
            &self,
            node_id: &str,
            window_ms: u64,
        ) -> Result<Option<crate::FleetNodeHealthSignal>, crate::FleetNodeBackendError> {
            if self.nodes.contains_key(node_id) {
                Ok(Some(crate::FleetNodeHealthSignal {
                    node_id: node_id.to_string(),
                    window_ms,
                    observed_at_unix_ms: 10,
                    ready_percent: 99,
                    error_percent: 1,
                    request_count: 200,
                }))
            } else {
                Ok(None)
            }
        }

        fn rollout_node(
            &mut self,
            node_id: &str,
            request: crate::RolloutRequest,
            occurred_at_unix_ms: u64,
        ) -> Result<crate::RolloutResponse, crate::FleetNodeBackendError> {
            let node = self
                .nodes
                .get_mut(node_id)
                .ok_or_else(|| crate::FleetNodeBackendError::Unreachable(String::from("missing node")))?;
            let digest = self
                .digests
                .get(&request.version)
                .cloned()
                .ok_or_else(|| crate::FleetNodeBackendError::Rejected(String::from("unknown digest")))?;
            node.status.active_version = Some(request.version.clone());
            node.status.active_digest_sha256 = Some(digest.clone());
            node.status.desired_version = Some(request.version.clone());
            node.status.desired_digest_sha256 = Some(digest.clone());
            node.status.last_known_good_version = Some(request.version.clone());
            node.status.observed_at_unix_ms = occurred_at_unix_ms;
            Ok(crate::RolloutResponse {
                action: crate::RolloutActionKind::Rollout,
                result: crate::RolloutResultKind::Applied,
                active_version: request.version,
                active_digest_sha256: digest,
                last_known_good_version: node
                    .status
                    .last_known_good_version
                    .clone()
                    .unwrap_or_default(),
            })
        }

        fn rollback_node(
            &mut self,
            node_id: &str,
            request: crate::RollbackRequest,
            occurred_at_unix_ms: u64,
        ) -> Result<crate::RolloutResponse, crate::FleetNodeBackendError> {
            let target = request.target_version.unwrap_or_else(|| String::from("stable-v1"));
            let digest = self
                .digests
                .get(&target)
                .cloned()
                .ok_or_else(|| crate::FleetNodeBackendError::Rejected(String::from("unknown digest")))?;
            let node = self
                .nodes
                .get_mut(node_id)
                .ok_or_else(|| crate::FleetNodeBackendError::Unreachable(String::from("missing node")))?;
            node.status.active_version = Some(target.clone());
            node.status.active_digest_sha256 = Some(digest.clone());
            node.status.observed_at_unix_ms = occurred_at_unix_ms;
            Ok(crate::RolloutResponse {
                action: crate::RolloutActionKind::Rollback,
                result: crate::RolloutResultKind::Applied,
                active_version: target.clone(),
                active_digest_sha256: digest,
                last_known_good_version: target,
            })
        }
    }

    fn publish_snapshot(
        control: &mut crate::SnapshotControlService,
        version: &str,
        workspace_name: &str,
        published_at_unix_ms: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        config.name = workspace_name.to_string();
        configure_test_trusted_signers(&mut config)?;
        let snapshot = config.compile_snapshot()?;
        let digest = snapshot.metadata().digest_sha256().to_owned();
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let _ = control.publish_at(
            crate::SnapshotPublishRequest {
                version: version.to_string(),
                snapshot,
                artifact_attestation: Some(artifact_attestation),
                expected_digest_sha256: Some(digest.clone()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("seed")),
            },
            published_at_unix_ms,
        )?;
        Ok(digest)
    }

    fn weighted_route_snapshot(
        stable_weight: u16,
        canary_weight: u16,
    ) -> Result<lb_config_model::WorkspaceSnapshot, Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        config.listeners.push(lb_config_model::ListenerResourceConfig {
            protocol: lb_config_model::ListenerProtocolConfig::Http1,
            routes: vec![String::from("payments-api")],
            ..lb_config_model::ListenerResourceConfig::foundation(
                "public-http",
                lb_config_model::ListenerClassConfig::Public,
                8080,
            )
        });
        config.routes.push(lb_config_model::RouteConfig {
            name: String::from("payments-api"),
            match_rule: lb_config_model::RouteMatchConfig::PathPrefix {
                prefix: String::from("/api"),
                hostnames: vec![String::from("payments.localhost")],
                methods: Vec::new(),
                headers: Vec::new(),
                query_params: Vec::new(),
                content_types: Vec::new(),
                grpc_services: Vec::new(),
                grpc_methods: Vec::new(),
                source_cidrs: Vec::new(),
            },
            upstream_cluster: None,
            destinations: vec![
                lb_config_model::RouteDestinationConfig {
                    upstream_cluster: String::from("payments-stable"),
                    weight: stable_weight,
                    policies: lb_config_model::PolicyBindingConfig::default(),
                },
                lb_config_model::RouteDestinationConfig {
                    upstream_cluster: String::from("payments-canary"),
                    weight: canary_weight,
                    policies: lb_config_model::PolicyBindingConfig::default(),
                },
            ],
            policies: lb_config_model::PolicyBindingConfig::default(),
            upgrade: lb_config_model::UpgradePolicyConfig::default(),
        });
        config.upstream_clusters.push(lb_config_model::UpstreamClusterConfig {
            name: String::from("payments-stable"),
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            endpoints: vec![lb_config_model::UpstreamEndpointConfig::foundation(
                "payments-stable-a",
                "127.0.0.1:9000".parse()?,
            )],
            discovery: None,
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig::default(),
            policies: lb_config_model::PolicyBindingConfig::default(),
        });
        config.upstream_clusters.push(lb_config_model::UpstreamClusterConfig {
            name: String::from("payments-canary"),
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            endpoints: vec![lb_config_model::UpstreamEndpointConfig::foundation(
                "payments-canary-a",
                "127.0.0.1:9001".parse()?,
            )],
            discovery: None,
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig::default(),
            policies: lb_config_model::PolicyBindingConfig::default(),
        });
        configure_test_trusted_signers(&mut config)?;
        Ok(config.compile_snapshot()?)
    }

    fn publish_weighted_snapshot(
        control: &mut crate::SnapshotControlService,
        version: &str,
        stable_weight: u16,
        canary_weight: u16,
        published_at_unix_ms: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let snapshot = weighted_route_snapshot(stable_weight, canary_weight)?;
        let digest = snapshot.metadata().digest_sha256().to_owned();
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let _ = control.publish_at(
            crate::SnapshotPublishRequest {
                version: version.to_string(),
                snapshot,
                artifact_attestation: Some(artifact_attestation),
                expected_digest_sha256: Some(digest.clone()),
                published_by: Some(String::from("ops")),
                reason: Some(String::from("seed")),
            },
            published_at_unix_ms,
        )?;
        Ok(digest)
    }

    #[test]
    fn listener_canary_apply_returns_status_surface() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();

        let stable_digest = publish_snapshot(&mut control, "stable-v1", "stable", 1)?;
        let canary_digest = publish_snapshot(&mut control, "canary-v2", "canary", 2)?;

        let mut backend = MockBackend::default()
            .with_node("node-a", "stable-v1", &stable_digest)
            .with_node("node-b", "stable-v1", &stable_digest)
            .with_node("node-c", "stable-v1", &stable_digest);
        backend
            .digests
            .insert(String::from("stable-v1"), stable_digest.clone());
        backend
            .digests
            .insert(String::from("canary-v2"), canary_digest.clone());

        let mut fleet = crate::FleetRolloutCoordinator::new();
        let mut coordinator = ListenerCanaryCoordinator::new();
        let response = coordinator.apply(
            &control,
            &mut fleet,
            &mut backend,
            ListenerCanaryApplyRequest {
                listener_name: String::from("public-http"),
                candidate_version: String::from("canary-v2"),
                baseline_version: Some(String::from("stable-v1")),
                requested_by: Some(String::from("ops")),
                reason: Some(String::from("listener canary")),
                node_ids: vec![
                    String::from("node-a"),
                    String::from("node-b"),
                    String::from("node-c"),
                ],
                canary_nodes: 1,
                canary_max_parallel: 1,
                fleet_max_parallel: 2,
                max_allowed_divergence_ms: 30_000,
                gate_policy: crate::FleetHealthGatePolicy::default(),
                allow_staged_apply: true,
                rollback_policy: crate::FleetRollbackPolicyConfig::default(),
            },
        )?;

        assert_eq!(response.listener_name, "public-http");
        assert_eq!(response.rollout.desired_version, "canary-v2");
        assert_eq!(response.status.waves.len(), 2);
        Ok(())
    }

    #[test]
    fn listener_canary_requires_staged_ack_for_high_or_medium_impact(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        let stable_digest = publish_weighted_snapshot(&mut control, "stable-v1", 90, 10, 1)?;
        let changed_digest = publish_weighted_snapshot(&mut control, "canary-v2", 80, 20, 2)?;

        let mut backend = MockBackend::default();
        backend
            .digests
            .insert(String::from("canary-v2"), changed_digest);
        backend
            .digests
            .insert(String::from("stable-v1"), stable_digest.clone());
        backend = backend.with_node("node-a", "stable-v1", &stable_digest);

        let mut fleet = crate::FleetRolloutCoordinator::new();
        let mut coordinator = ListenerCanaryCoordinator::new();
        let error = coordinator
            .apply(
                &control,
                &mut fleet,
                &mut backend,
                ListenerCanaryApplyRequest {
                    listener_name: String::from("public-http"),
                    candidate_version: String::from("canary-v2"),
                    baseline_version: Some(String::from("stable-v1")),
                    requested_by: Some(String::from("ops")),
                    reason: Some(String::from("listener canary")),
                    node_ids: vec![String::from("node-a")],
                    canary_nodes: 1,
                    canary_max_parallel: 1,
                    fleet_max_parallel: 1,
                    max_allowed_divergence_ms: 30_000,
                    gate_policy: crate::FleetHealthGatePolicy::default(),
                    allow_staged_apply: false,
                    rollback_policy: crate::FleetRollbackPolicyConfig {
                        auto_rollback_mode: crate::FleetAutoRollbackMode::Disabled,
                    },
                },
            )
            .expect_err("staged ack should be required for changed snapshot");

        assert!(matches!(
            error,
            ListenerCanaryError::StagedApplyRequired { .. }
        ));
        Ok(())
    }
}
