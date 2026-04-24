use serde::{Deserialize, Serialize};

use crate::{
    RolloutCoordinator, RolloutError, RolloutRequest, RolloutResponse, SnapshotControlService,
    SnapshotDiffPreview, SnapshotDiffPreviewError, SnapshotImpactSeverity, SnapshotLookupError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionExecutionStrategy {
    Immediate,
    StagedCanary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionPreviewRequest {
    pub candidate_version: String,
    pub baseline_version: Option<String>,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionApplyRequest {
    pub candidate_version: String,
    pub baseline_version: Option<String>,
    pub requested_by: Option<String>,
    pub reason: Option<String>,
    pub allow_staged_apply: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromotionPreviewResponse {
    pub candidate_version: String,
    pub preview: SnapshotDiffPreview,
    pub recommended_strategy: PromotionExecutionStrategy,
    pub requires_staged_apply_ack: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionApplyResponse {
    pub preview: PromotionPreviewResponse,
    pub rollout: RolloutResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PromotionMetrics {
    pub preview_count: u64,
    pub apply_count: u64,
    pub blocked_staged_apply_count: u64,
}

#[derive(Debug)]
pub enum PromotionError {
    MissingCandidateVersion,
    CandidateNotPublished(String),
    SnapshotLookup(SnapshotLookupError),
    DiffPreview(SnapshotDiffPreviewError),
    StagedApplyRequired {
        severity: SnapshotImpactSeverity,
        strategy: PromotionExecutionStrategy,
    },
    Rollout(RolloutError),
}

impl std::fmt::Display for PromotionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCandidateVersion => {
                write!(formatter, "promotion candidate_version must not be empty")
            }
            Self::CandidateNotPublished(version) => {
                write!(formatter, "promotion candidate version '{version}' was not found")
            }
            Self::SnapshotLookup(error) => write!(formatter, "promotion lookup failed: {error}"),
            Self::DiffPreview(error) => write!(formatter, "promotion diff preview failed: {error}"),
            Self::StagedApplyRequired { severity, strategy } => write!(
                formatter,
                "promotion apply requires staged acknowledgment for {severity:?} impact ({strategy:?})"
            ),
            Self::Rollout(error) => write!(formatter, "promotion apply rollout failed: {error}"),
        }
    }
}

impl std::error::Error for PromotionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SnapshotLookup(error) => Some(error),
            Self::DiffPreview(error) => Some(error),
            Self::Rollout(error) => Some(error),
            Self::MissingCandidateVersion
            | Self::CandidateNotPublished(_)
            | Self::StagedApplyRequired { .. } => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct PromotionCoordinator {
    metrics: PromotionMetrics,
}

impl PromotionCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn preview(
        &mut self,
        control: &SnapshotControlService,
        request: PromotionPreviewRequest,
    ) -> Result<PromotionPreviewResponse, PromotionError> {
        let candidate_version = request.candidate_version.trim();
        if candidate_version.is_empty() {
            return Err(PromotionError::MissingCandidateVersion);
        }
        let candidate = match control.get_version(candidate_version) {
            Ok(record) => record,
            Err(SnapshotLookupError::VersionNotFound(version)) => {
                return Err(PromotionError::CandidateNotPublished(version));
            }
            Err(error) => return Err(PromotionError::SnapshotLookup(error)),
        };

        let preview = control
            .preview_diff(request.baseline_version.as_deref(), &candidate.snapshot)
            .map_err(PromotionError::DiffPreview)?;
        let recommended_strategy = match preview.impact_analysis.severity {
            SnapshotImpactSeverity::Low => PromotionExecutionStrategy::Immediate,
            SnapshotImpactSeverity::Medium | SnapshotImpactSeverity::High => {
                PromotionExecutionStrategy::StagedCanary
            }
        };

        self.metrics.preview_count = self.metrics.preview_count.saturating_add(1);
        Ok(PromotionPreviewResponse {
            candidate_version: candidate_version.to_string(),
            preview,
            recommended_strategy,
            requires_staged_apply_ack: !matches!(recommended_strategy, PromotionExecutionStrategy::Immediate),
        })
    }

    pub fn apply(
        &mut self,
        control: &SnapshotControlService,
        rollout: &mut RolloutCoordinator,
        dataplane: &mut lb_runtime::DataplaneSnapshotManager,
        request: PromotionApplyRequest,
    ) -> Result<PromotionApplyResponse, PromotionError> {
        let preview = self.preview(
            control,
            PromotionPreviewRequest {
                candidate_version: request.candidate_version.clone(),
                baseline_version: request.baseline_version.clone(),
                requested_by: request.requested_by.clone(),
                reason: request.reason.clone(),
            },
        )?;

        if preview.requires_staged_apply_ack && !request.allow_staged_apply {
            self.metrics.blocked_staged_apply_count =
                self.metrics.blocked_staged_apply_count.saturating_add(1);
            return Err(PromotionError::StagedApplyRequired {
                severity: preview.preview.impact_analysis.severity,
                strategy: preview.recommended_strategy,
            });
        }

        let rollout_response = rollout
            .rollout(
                control,
                dataplane,
                RolloutRequest {
                    version: request.candidate_version,
                    requested_by: request.requested_by,
                    reason: request.reason,
                },
            )
            .map_err(PromotionError::Rollout)?;

        self.metrics.apply_count = self.metrics.apply_count.saturating_add(1);
        Ok(PromotionApplyResponse {
            preview,
            rollout: rollout_response,
        })
    }

    #[must_use]
    pub const fn metrics(&self) -> PromotionMetrics {
        self.metrics
    }
}

#[cfg(test)]
mod tests {
    use lb_config_model::WorkspaceConfig;
    use lb_test_support::{configure_test_trusted_signers, test_artifact_attestation};

    use super::{
        PromotionApplyRequest, PromotionCoordinator, PromotionError, PromotionExecutionStrategy,
        PromotionPreviewRequest,
    };

    fn publish_snapshot(
        control: &mut crate::SnapshotControlService,
        version: &str,
        stable_weight: u16,
        canary_weight: u16,
        published_at_unix_ms: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = weighted_route_snapshot(stable_weight, canary_weight)?;
        let _ = control.publish_at(
            crate::SnapshotPublishRequest {
                version: version.to_string(),
                expected_digest_sha256: Some(snapshot.metadata().digest_sha256().to_owned()),
                artifact_attestation: Some(test_artifact_attestation(&snapshot)?),
                snapshot,
                published_by: Some(String::from("ops")),
                reason: Some(String::from("promotion test")),
            },
            published_at_unix_ms,
        )?;
        Ok(())
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

    #[test]
    fn preview_recommends_staged_canary_for_medium_impact(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-v1", 90, 10, 1)?;
        publish_snapshot(&mut control, "canary-v2", 80, 20, 2)?;
        let mut coordinator = PromotionCoordinator::new();

        let preview = coordinator.preview(
            &control,
            PromotionPreviewRequest {
                candidate_version: String::from("canary-v2"),
                baseline_version: Some(String::from("stable-v1")),
                requested_by: Some(String::from("ops")),
                reason: Some(String::from("preview")),
            },
        )?;

        assert_eq!(preview.recommended_strategy, PromotionExecutionStrategy::StagedCanary);
        assert!(preview.requires_staged_apply_ack);
        Ok(())
    }

    #[test]
    fn apply_blocks_medium_impact_without_ack() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-v1", 90, 10, 1)?;
        publish_snapshot(&mut control, "canary-v2", 80, 20, 2)?;
        let mut coordinator = PromotionCoordinator::new();
        let mut rollout = crate::RolloutCoordinator::new();
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();

        let error = coordinator
            .apply(
                &control,
                &mut rollout,
                &mut dataplane,
                PromotionApplyRequest {
                    candidate_version: String::from("canary-v2"),
                    baseline_version: Some(String::from("stable-v1")),
                    requested_by: Some(String::from("ops")),
                    reason: Some(String::from("apply")),
                    allow_staged_apply: false,
                },
            )
            .expect_err("apply should require staged acknowledgement");

        assert!(matches!(error, PromotionError::StagedApplyRequired { .. }));
        Ok(())
    }

    #[test]
    fn apply_succeeds_with_staged_ack() -> Result<(), Box<dyn std::error::Error>> {
        let mut control = crate::SnapshotControlService::new();
        publish_snapshot(&mut control, "stable-v1", 90, 10, 1)?;
        publish_snapshot(&mut control, "canary-v2", 80, 20, 2)?;
        let mut coordinator = PromotionCoordinator::new();
        let mut rollout = crate::RolloutCoordinator::new();
        let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();

        let response = coordinator.apply(
            &control,
            &mut rollout,
            &mut dataplane,
            PromotionApplyRequest {
                candidate_version: String::from("canary-v2"),
                baseline_version: Some(String::from("stable-v1")),
                requested_by: Some(String::from("ops")),
                reason: Some(String::from("apply")),
                allow_staged_apply: true,
            },
        )?;

        assert_eq!(response.rollout.active_version, "canary-v2");
        Ok(())
    }
}
