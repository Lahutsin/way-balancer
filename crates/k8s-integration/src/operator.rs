use lb_admin_api::{
    RolloutCoordinator, RolloutError, RolloutRequest, SnapshotControlService,
    SnapshotPublicationError, SnapshotPublishRequest,
};

use crate::{
    GatewayApiResourceSet, GatewayApiTranslator, GatewayTranslationOptions, TranslationReport,
};

const MAX_REQUEUE_DELAY_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileRequest {
    pub resources: GatewayApiResourceSet,
    pub observed_generation: u64,
    pub actor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionStatus {
    True,
    False,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusConditionType {
    Ready,
    Progressing,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCondition {
    pub condition_type: StatusConditionType,
    pub status: ConditionStatus,
    pub reason: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorState {
    Ready,
    Progressing,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequeueDecision {
    None,
    AfterMillis(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorStatus {
    pub state: OperatorState,
    pub observed_generation: u64,
    pub desired_version: Option<String>,
    pub active_version: Option<String>,
    pub last_known_good_version: Option<String>,
    pub conditions: Vec<StatusCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileResult {
    pub changed: bool,
    pub desired_digest_sha256: Option<String>,
    pub requeue: RequeueDecision,
    pub status: OperatorStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileTransitionEvent {
    pub previous_state: Option<OperatorState>,
    pub next_state: OperatorState,
    pub observed_generation: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReconcileMetrics {
    pub success_count: u64,
    pub failure_count: u64,
    pub requeue_count: u64,
    pub status_transition_count: u64,
    pub total_reconcile_duration_ms: u64,
}

#[derive(Debug)]
pub enum ReconcileError {
    Translation(TranslationReport),
    Snapshot(lb_config_model::SnapshotCompileError),
    Backend(ReconcileBackendError),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Translation(report) => write!(formatter, "translation failed: {report}"),
            Self::Snapshot(error) => write!(formatter, "snapshot compilation failed: {error}"),
            Self::Backend(error) => write!(formatter, "operator backend failed: {error}"),
        }
    }
}

impl std::error::Error for ReconcileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Translation(report) => Some(report),
            Self::Snapshot(error) => Some(error),
            Self::Backend(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub enum ReconcileBackendError {
    Publish(SnapshotPublicationError),
    Rollout(RolloutError),
}

impl std::fmt::Display for ReconcileBackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Publish(error) => write!(formatter, "publish failed: {error}"),
            Self::Rollout(error) => write!(formatter, "rollout failed: {error}"),
        }
    }
}

impl std::error::Error for ReconcileBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Publish(error) => Some(error),
            Self::Rollout(error) => Some(error),
        }
    }
}

pub trait ReconcileBackend {
    fn trusted_signers(&self) -> Vec<lb_config_model::TrustedArtifactSignerConfig>;

    fn publish_snapshot(
        &mut self,
        version: &str,
        snapshot: lb_config_model::WorkspaceSnapshot,
        actor: Option<String>,
        reason: Option<String>,
        occurred_at_unix_ms: u64,
    ) -> Result<(), ReconcileBackendError>;

    fn rollout_version(
        &mut self,
        version: &str,
        actor: Option<String>,
        reason: Option<String>,
        occurred_at_unix_ms: u64,
    ) -> Result<lb_admin_api::RolloutResponse, ReconcileBackendError>;

    fn active_version(&self) -> Option<&str>;
    fn active_digest_sha256(&self) -> Option<&str>;
    fn last_known_good_version(&self) -> Option<&str>;
}

pub struct InMemoryReconcileBackend {
    control: SnapshotControlService,
    rollout: RolloutCoordinator,
    dataplane: lb_runtime::DataplaneSnapshotManager,
    signer: lb_config_model::ArtifactSigner,
}

impl InMemoryReconcileBackend {
    #[must_use]
    pub fn new(signer: lb_config_model::ArtifactSigner) -> Self {
        Self {
            control: SnapshotControlService::new(),
            rollout: RolloutCoordinator::new(),
            dataplane: lb_runtime::DataplaneSnapshotManager::new(),
            signer,
        }
    }
}

impl ReconcileBackend for InMemoryReconcileBackend {
    fn trusted_signers(&self) -> Vec<lb_config_model::TrustedArtifactSignerConfig> {
        vec![self.signer.trusted_signer()]
    }

    fn publish_snapshot(
        &mut self,
        version: &str,
        snapshot: lb_config_model::WorkspaceSnapshot,
        actor: Option<String>,
        reason: Option<String>,
        occurred_at_unix_ms: u64,
    ) -> Result<(), ReconcileBackendError> {
        let artifact_attestation = self.signer.attest_snapshot(&snapshot);
        self.control
            .publish_at(
                SnapshotPublishRequest {
                    version: String::from(version),
                    expected_digest_sha256: Some(snapshot.metadata().digest_sha256().to_owned()),
                    snapshot,
                    artifact_attestation: Some(artifact_attestation),
                    published_by: actor,
                    reason,
                },
                occurred_at_unix_ms,
            )
            .map(|_| ())
            .map_err(ReconcileBackendError::Publish)
    }

    fn rollout_version(
        &mut self,
        version: &str,
        actor: Option<String>,
        reason: Option<String>,
        occurred_at_unix_ms: u64,
    ) -> Result<lb_admin_api::RolloutResponse, ReconcileBackendError> {
        self.rollout
            .rollout_at(
                &self.control,
                &mut self.dataplane,
                RolloutRequest { version: String::from(version), requested_by: actor, reason },
                occurred_at_unix_ms,
            )
            .map_err(ReconcileBackendError::Rollout)
    }

    fn active_version(&self) -> Option<&str> {
        self.dataplane.active_record().map(|record| record.version.as_str())
    }

    fn active_digest_sha256(&self) -> Option<&str> {
        self.dataplane.active_record().map(|record| record.digest_sha256.as_str())
    }

    fn last_known_good_version(&self) -> Option<&str> {
        self.dataplane.last_known_good_record().map(|record| record.version.as_str())
    }
}

#[derive(Debug)]
pub struct KubernetesOperatorReconciler<B> {
    translator: GatewayApiTranslator,
    backend: B,
    options: GatewayTranslationOptions,
    metrics: ReconcileMetrics,
    status: OperatorStatus,
    events: Vec<ReconcileTransitionEvent>,
    consecutive_backend_failures: u32,
}

impl<B> KubernetesOperatorReconciler<B>
where
    B: ReconcileBackend,
{
    #[must_use]
    pub fn new(backend: B, options: GatewayTranslationOptions) -> Self {
        Self {
            translator: GatewayApiTranslator::new(),
            backend,
            options,
            metrics: ReconcileMetrics::default(),
            status: OperatorStatus {
                state: OperatorState::Progressing,
                observed_generation: 0,
                desired_version: None,
                active_version: None,
                last_known_good_version: None,
                conditions: progressing_conditions(String::from("operator not reconciled yet")),
            },
            events: Vec::new(),
            consecutive_backend_failures: 0,
        }
    }

    pub fn reconcile_at(
        &mut self,
        request: ReconcileRequest,
        occurred_at_unix_ms: u64,
    ) -> Result<ReconcileResult, ReconcileError> {
        match self
            .translator
            .translate(&request.resources, self.options)
            .map_err(ReconcileError::Translation)
        {
            Ok(mut config) => {
                if matches!(
                    config.security.artifact_verification.mode,
                    lb_config_model::ArtifactVerificationMode::Enforced
                ) && config.security.artifact_verification.trusted_signers.is_empty()
                {
                    config.security.artifact_verification.trusted_signers =
                        self.backend.trusted_signers();
                }

                match config.compile_snapshot() {
                    Ok(snapshot) => {
                    let desired_digest_sha256 = snapshot.metadata().digest_sha256().to_owned();
                    let desired_version =
                        derive_desired_version(&config.name, &desired_digest_sha256);
                    if self.backend.active_digest_sha256() == Some(desired_digest_sha256.as_str())
                        && self.status.desired_version.as_deref() == Some(desired_version.as_str())
                    {
                        self.consecutive_backend_failures = 0;
                        self.metrics.success_count = self.metrics.success_count.saturating_add(1);
                        self.metrics.total_reconcile_duration_ms =
                            self.metrics.total_reconcile_duration_ms.saturating_add(0);
                        let status = self.set_status(
                            OperatorStatus {
                                state: OperatorState::Ready,
                                observed_generation: request.observed_generation,
                                desired_version: Some(desired_version.clone()),
                                active_version: self.backend.active_version().map(String::from),
                                last_known_good_version: self
                                    .backend
                                    .last_known_good_version()
                                    .map(String::from),
                                conditions: ready_conditions(String::from(
                                    "desired state already converged",
                                )),
                            },
                            request.observed_generation,
                            String::from("reconcile detected no desired-state change"),
                        );
                        return Ok(ReconcileResult {
                            changed: false,
                            desired_digest_sha256: Some(desired_digest_sha256),
                            requeue: RequeueDecision::None,
                            status,
                        });
                    }

                    if let Err(error) = self.backend.publish_snapshot(
                        &desired_version,
                        snapshot,
                        request.actor.clone(),
                        Some(String::from("operator reconcile publish")),
                        occurred_at_unix_ms,
                    ) {
                        return Err(self.handle_backend_error(
                            error,
                            request.observed_generation,
                            desired_version,
                            String::from("publish failed during reconcile"),
                        ));
                    }

                    if let Err(error) = self.backend.rollout_version(
                        &desired_version,
                        request.actor,
                        Some(String::from("operator reconcile rollout")),
                        occurred_at_unix_ms,
                    ) {
                        return Err(self.handle_backend_error(
                            error,
                            request.observed_generation,
                            desired_version,
                            String::from("rollout failed during reconcile"),
                        ));
                    }

                    self.consecutive_backend_failures = 0;
                    self.metrics.success_count = self.metrics.success_count.saturating_add(1);
                    let status = self.set_status(
                        OperatorStatus {
                            state: OperatorState::Ready,
                            observed_generation: request.observed_generation,
                            desired_version: Some(desired_version.clone()),
                            active_version: self.backend.active_version().map(String::from),
                            last_known_good_version: self
                                .backend
                                .last_known_good_version()
                                .map(String::from),
                            conditions: ready_conditions(String::from(
                                "desired state translated, published and rolled out",
                            )),
                        },
                        request.observed_generation,
                        String::from("reconcile converged desired state"),
                    );

                    Ok(ReconcileResult {
                        changed: true,
                        desired_digest_sha256: Some(desired_digest_sha256),
                        requeue: RequeueDecision::None,
                        status,
                    })
                    }
                    Err(error) => Err(self.handle_snapshot_error(error, request.observed_generation)),
                }
            }
            Err(error) => {
                self.metrics.failure_count = self.metrics.failure_count.saturating_add(1);
                let message = match &error {
                    ReconcileError::Translation(report) => report.to_string(),
                    _ => String::from("unexpected reconcile translation state"),
                };
                let status = self.set_status(
                    OperatorStatus {
                        state: OperatorState::Invalid,
                        observed_generation: request.observed_generation,
                        desired_version: None,
                        active_version: self.backend.active_version().map(String::from),
                        last_known_good_version: self
                            .backend
                            .last_known_good_version()
                            .map(String::from),
                        conditions: invalid_conditions(message),
                    },
                    request.observed_generation,
                    String::from("translation invalidated desired state"),
                );
                let _ = status;
                Err(error)
            }
        }
    }

    #[must_use]
    pub const fn metrics(&self) -> ReconcileMetrics {
        self.metrics
    }

    #[must_use]
    pub fn status(&self) -> &OperatorStatus {
        &self.status
    }

    #[must_use]
    pub fn events(&self) -> &[ReconcileTransitionEvent] {
        &self.events
    }

    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    #[must_use]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    fn handle_backend_error(
        &mut self,
        error: ReconcileBackendError,
        observed_generation: u64,
        desired_version: String,
        detail: String,
    ) -> ReconcileError {
        self.metrics.failure_count = self.metrics.failure_count.saturating_add(1);
        self.consecutive_backend_failures = self.consecutive_backend_failures.saturating_add(1);
        let shift = self.consecutive_backend_failures.min(5);
        let delay_ms = (1_u64 << shift).saturating_mul(1_000).min(MAX_REQUEUE_DELAY_MS);
        self.metrics.requeue_count = self.metrics.requeue_count.saturating_add(1);
        let _ = self.set_status(
            OperatorStatus {
                state: OperatorState::Progressing,
                observed_generation,
                desired_version: Some(desired_version),
                active_version: self.backend.active_version().map(String::from),
                last_known_good_version: self.backend.last_known_good_version().map(String::from),
                conditions: progressing_conditions(format!("{detail}; retry in {delay_ms}ms")),
            },
            observed_generation,
            format!("reconcile scheduled retry after backend error: {error}"),
        );
        ReconcileError::Backend(error)
    }

    fn handle_snapshot_error(
        &mut self,
        error: lb_config_model::SnapshotCompileError,
        observed_generation: u64,
    ) -> ReconcileError {
        self.metrics.failure_count = self.metrics.failure_count.saturating_add(1);
        let _ = self.set_status(
            OperatorStatus {
                state: OperatorState::Invalid,
                observed_generation,
                desired_version: None,
                active_version: self.backend.active_version().map(String::from),
                last_known_good_version: self.backend.last_known_good_version().map(String::from),
                conditions: invalid_conditions(error.to_string()),
            },
            observed_generation,
            String::from("snapshot compilation invalidated desired state"),
        );
        ReconcileError::Snapshot(error)
    }

    fn set_status(
        &mut self,
        next_status: OperatorStatus,
        observed_generation: u64,
        detail: String,
    ) -> OperatorStatus {
        let previous_state = Some(self.status.state);
        if previous_state != Some(next_status.state) {
            self.metrics.status_transition_count =
                self.metrics.status_transition_count.saturating_add(1);
            self.events.push(ReconcileTransitionEvent {
                previous_state,
                next_state: next_status.state,
                observed_generation,
                detail,
            });
        }
        self.status = next_status.clone();
        next_status
    }
}

fn derive_desired_version(workspace_name: &str, digest_sha256: &str) -> String {
    format!("k8s-{}-{}", workspace_name.replace(['_', '.'], "-"), &digest_sha256[..12])
}

fn ready_conditions(message: String) -> Vec<StatusCondition> {
    vec![
        StatusCondition {
            condition_type: StatusConditionType::Ready,
            status: ConditionStatus::True,
            reason: String::from("Converged"),
            message: message.clone(),
        },
        StatusCondition {
            condition_type: StatusConditionType::Progressing,
            status: ConditionStatus::False,
            reason: String::from("Converged"),
            message: message.clone(),
        },
        StatusCondition {
            condition_type: StatusConditionType::Invalid,
            status: ConditionStatus::False,
            reason: String::from("Converged"),
            message,
        },
    ]
}

fn progressing_conditions(message: String) -> Vec<StatusCondition> {
    vec![
        StatusCondition {
            condition_type: StatusConditionType::Ready,
            status: ConditionStatus::False,
            reason: String::from("Progressing"),
            message: message.clone(),
        },
        StatusCondition {
            condition_type: StatusConditionType::Progressing,
            status: ConditionStatus::True,
            reason: String::from("RetryScheduled"),
            message: message.clone(),
        },
        StatusCondition {
            condition_type: StatusConditionType::Invalid,
            status: ConditionStatus::False,
            reason: String::from("Progressing"),
            message,
        },
    ]
}

fn invalid_conditions(message: String) -> Vec<StatusCondition> {
    vec![
        StatusCondition {
            condition_type: StatusConditionType::Ready,
            status: ConditionStatus::False,
            reason: String::from("InvalidDesiredState"),
            message: message.clone(),
        },
        StatusCondition {
            condition_type: StatusConditionType::Progressing,
            status: ConditionStatus::False,
            reason: String::from("InvalidDesiredState"),
            message: message.clone(),
        },
        StatusCondition {
            condition_type: StatusConditionType::Invalid,
            status: ConditionStatus::True,
            reason: String::from("InvalidDesiredState"),
            message,
        },
    ]
}

#[cfg(test)]
mod tests {
    use lb_admin_api::RolloutError;
    use lb_test_support::test_artifact_signer;

    use super::{
        ConditionStatus, InMemoryReconcileBackend, KubernetesOperatorReconciler, OperatorState,
        ReconcileBackend, ReconcileBackendError, ReconcileError, ReconcileRequest, RequeueDecision,
    };
    use crate::{
        BackendReferenceResource, CoreApiVersion, GatewayApiResourceSet, GatewayApiVersion,
        GatewayClassResource, GatewayListenerProtocol, GatewayListenerResource,
        GatewayParentReference, GatewayResource, GatewayTranslationOptions, HttpRouteMatchResource,
        HttpRouteResource, HttpRouteRuleResource, ObjectMeta, ServiceEndpointResource,
        ServicePortResource, ServiceResource, SUPPORTED_GATEWAY_CONTROLLER_NAME,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[derive(Debug, Default)]
    struct FailingBackend {
        fail_rollout_once: bool,
        active_version: Option<String>,
        active_digest_sha256: Option<String>,
        last_known_good_version: Option<String>,
    }

    impl ReconcileBackend for FailingBackend {
        fn trusted_signers(&self) -> Vec<lb_config_model::TrustedArtifactSignerConfig> {
            vec![test_artifact_signer()
                .expect("test signer")
                .trusted_signer()]
        }

        fn publish_snapshot(
            &mut self,
            _version: &str,
            _snapshot: lb_config_model::WorkspaceSnapshot,
            _actor: Option<String>,
            _reason: Option<String>,
            _occurred_at_unix_ms: u64,
        ) -> Result<(), ReconcileBackendError> {
            Ok(())
        }

        fn rollout_version(
            &mut self,
            version: &str,
            _actor: Option<String>,
            _reason: Option<String>,
            _occurred_at_unix_ms: u64,
        ) -> Result<lb_admin_api::RolloutResponse, ReconcileBackendError> {
            if self.fail_rollout_once {
                self.fail_rollout_once = false;
                return Err(ReconcileBackendError::Rollout(RolloutError::UnknownPublishedVersion(
                    String::from(version),
                )));
            }
            self.active_version = Some(String::from(version));
            self.last_known_good_version = Some(String::from(version));
            self.active_digest_sha256 = Some(String::from("digest"));
            Ok(lb_admin_api::RolloutResponse {
                action: lb_admin_api::RolloutActionKind::Rollout,
                result: lb_admin_api::RolloutResultKind::Applied,
                active_version: String::from(version),
                active_digest_sha256: String::from("digest"),
                last_known_good_version: String::from(version),
            })
        }

        fn active_version(&self) -> Option<&str> {
            self.active_version.as_deref()
        }

        fn active_digest_sha256(&self) -> Option<&str> {
            self.active_digest_sha256.as_deref()
        }

        fn last_known_good_version(&self) -> Option<&str> {
            self.last_known_good_version.as_deref()
        }
    }

    fn sample_resources() -> GatewayApiResourceSet {
        GatewayApiResourceSet {
            gateway_classes: vec![GatewayClassResource {
                api_version: GatewayApiVersion::V1,
                metadata: ObjectMeta::new("cluster", "public-gateway"),
                controller_name: String::from(SUPPORTED_GATEWAY_CONTROLLER_NAME),
            }],
            gateways: vec![GatewayResource {
                api_version: GatewayApiVersion::V1,
                metadata: ObjectMeta::new("edge", "public"),
                gateway_class_name: String::from("public-gateway"),
                listeners: vec![GatewayListenerResource {
                    name: String::from("web"),
                    port: 8080,
                    protocol: GatewayListenerProtocol::Http,
                    hostname: None,
                }],
            }],
            http_routes: vec![HttpRouteResource {
                api_version: GatewayApiVersion::V1,
                metadata: ObjectMeta::new("edge", "payments"),
                hostnames: Vec::new(),
                parent_refs: vec![GatewayParentReference {
                    gateway_name: String::from("public"),
                    gateway_namespace: None,
                    section_name: Some(String::from("web")),
                }],
                rules: vec![HttpRouteRuleResource {
                    matches: vec![HttpRouteMatchResource {
                        path_prefix: String::from("/payments"),
                    }],
                    backend_refs: vec![BackendReferenceResource {
                        service_name: String::from("payments"),
                        port: 8080,
                    }],
                }],
            }],
            services: vec![ServiceResource {
                api_version: CoreApiVersion::V1,
                metadata: ObjectMeta::new("edge", "payments"),
                ports: vec![ServicePortResource { port: 8080, name: None }],
                endpoints: vec![ServiceEndpointResource {
                    id: String::from("payments-a"),
                    address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 8081),
                }],
            }],
        }
    }

    #[test]
    fn reconcile_converges_supported_resources_to_ready_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend = InMemoryReconcileBackend::new(test_artifact_signer()?);
        let mut reconciler =
            KubernetesOperatorReconciler::new(backend, GatewayTranslationOptions::default());

        let result = reconciler.reconcile_at(
            ReconcileRequest {
                resources: sample_resources(),
                observed_generation: 1,
                actor: Some(String::from("operator")),
            },
            100,
        )?;

        assert!(result.changed);
        assert_eq!(result.requeue, RequeueDecision::None);
        assert_eq!(result.status.state, OperatorState::Ready);
        assert!(result.status.active_version.is_some());
        assert_eq!(reconciler.metrics().success_count, 1);
        Ok(())
    }

    #[test]
    fn invalid_resources_set_invalid_status() {
        let backend = InMemoryReconcileBackend::new(test_artifact_signer().expect("test signer"));
        let mut reconciler =
            KubernetesOperatorReconciler::new(backend, GatewayTranslationOptions::default());
        let mut resources = sample_resources();
        resources.services.clear();

        let result = reconciler.reconcile_at(
            ReconcileRequest {
                resources,
                observed_generation: 2,
                actor: Some(String::from("operator")),
            },
            200,
        );

        assert!(matches!(result, Err(ReconcileError::Translation(_))));
        assert_eq!(reconciler.status().state, OperatorState::Invalid);
        assert!(reconciler
            .status()
            .conditions
            .iter()
            .any(|condition| condition.condition_type == super::StatusConditionType::Invalid
                && condition.status == ConditionStatus::True));
    }

    #[test]
    fn repeated_reconcile_of_same_state_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let backend = InMemoryReconcileBackend::new(test_artifact_signer()?);
        let mut reconciler =
            KubernetesOperatorReconciler::new(backend, GatewayTranslationOptions::default());

        let first = reconciler.reconcile_at(
            ReconcileRequest {
                resources: sample_resources(),
                observed_generation: 1,
                actor: Some(String::from("operator")),
            },
            100,
        )?;
        let second = reconciler.reconcile_at(
            ReconcileRequest {
                resources: sample_resources(),
                observed_generation: 2,
                actor: Some(String::from("operator")),
            },
            200,
        )?;

        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(second.status.state, OperatorState::Ready);
        Ok(())
    }

    #[test]
    fn backend_failures_trigger_bounded_requeue() {
        let backend = FailingBackend { fail_rollout_once: true, ..FailingBackend::default() };
        let mut reconciler =
            KubernetesOperatorReconciler::new(backend, GatewayTranslationOptions::default());

        let result = reconciler.reconcile_at(
            ReconcileRequest {
                resources: sample_resources(),
                observed_generation: 3,
                actor: Some(String::from("operator")),
            },
            300,
        );

        assert!(matches!(result, Err(ReconcileError::Backend(_))));
        assert_eq!(reconciler.status().state, OperatorState::Progressing);
        assert_eq!(reconciler.metrics().requeue_count, 1);
    }

    #[test]
    fn status_transitions_from_invalid_to_ready_after_fix() -> Result<(), Box<dyn std::error::Error>>
    {
        let backend = InMemoryReconcileBackend::new(test_artifact_signer()?);
        let mut reconciler =
            KubernetesOperatorReconciler::new(backend, GatewayTranslationOptions::default());

        let mut invalid = sample_resources();
        invalid.http_routes[0].parent_refs[0].section_name = None;
        let invalid_result = reconciler.reconcile_at(
            ReconcileRequest {
                resources: invalid,
                observed_generation: 1,
                actor: Some(String::from("operator")),
            },
            100,
        );
        assert!(invalid_result.is_err());

        let ready = reconciler.reconcile_at(
            ReconcileRequest {
                resources: sample_resources(),
                observed_generation: 2,
                actor: Some(String::from("operator")),
            },
            200,
        )?;

        assert_eq!(ready.status.state, OperatorState::Ready);
        assert!(reconciler.metrics().status_transition_count >= 1);
        assert!(!reconciler.events().is_empty());
        Ok(())
    }
}
