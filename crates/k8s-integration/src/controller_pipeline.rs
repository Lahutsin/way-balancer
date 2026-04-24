use std::collections::VecDeque;

use crate::{
    translate_gateway_api, EndpointSliceApplyError, EndpointSliceController, EndpointSliceResource,
    EndpointSliceStats, EndpointSliceUpdateOutcome, GatewayApiResourceSet,
    GatewayTranslationOptions, KubernetesOperatorReconciler, OperatorState, OperatorStatus,
    ReconcileBackend, ReconcileError, ReconcileRequest, ReconcileResult, ReconcileTransitionEvent,
    StatusCondition,
};

const MAX_RECENT_EVENTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedResourceKind {
    GatewayClass,
    Gateway,
    HttpRoute,
    Service,
    EndpointSlice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedResourceStatus {
    pub kind: ManagedResourceKind,
    pub namespace: String,
    pub name: String,
    pub state: OperatorState,
    pub conditions: Vec<StatusCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayControllerStatusReport {
    pub observed_generation: u64,
    pub operator_status: OperatorStatus,
    pub endpoint_slice_stats: EndpointSliceStats,
    pub managed_resources: Vec<ManagedResourceStatus>,
    pub recent_events: Vec<ReconcileTransitionEvent>,
    pub last_candidate_version: Option<String>,
    pub last_candidate_digest_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySnapshotCandidate {
    pub resources: GatewayApiResourceSet,
    pub config: lb_config_model::WorkspaceConfig,
    pub snapshot: lb_config_model::WorkspaceSnapshot,
    pub desired_version: String,
    pub desired_digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedGatewaySnapshot {
    pub desired_version: String,
    pub desired_digest_sha256: String,
}

#[derive(Debug)]
pub struct GatewayControllerPipeline<B> {
    resources: GatewayApiResourceSet,
    endpoint_slices: EndpointSliceController,
    reconciler: KubernetesOperatorReconciler<B>,
    options: GatewayTranslationOptions,
    observed_generation: u64,
    last_translation_report: Option<crate::TranslationReport>,
    recent_events: VecDeque<ReconcileTransitionEvent>,
    synced_reconciler_event_count: usize,
    last_candidate_version: Option<String>,
    last_candidate_digest_sha256: Option<String>,
}

impl<B> GatewayControllerPipeline<B>
where
    B: ReconcileBackend,
{
    #[must_use]
    pub fn new(backend: B, options: GatewayTranslationOptions) -> Self {
        Self {
            resources: GatewayApiResourceSet::default(),
            endpoint_slices: EndpointSliceController::new(),
            reconciler: KubernetesOperatorReconciler::new(backend, options),
            options,
            observed_generation: 0,
            last_translation_report: None,
            recent_events: VecDeque::new(),
            synced_reconciler_event_count: 0,
            last_candidate_version: None,
            last_candidate_digest_sha256: None,
        }
    }

    pub fn replace_resources(&mut self, resources: GatewayApiResourceSet) {
        self.resources = resources;
    }

    #[must_use]
    pub fn resources(&self) -> &GatewayApiResourceSet {
        &self.resources
    }

    pub fn upsert_endpoint_slice(
        &mut self,
        slice: EndpointSliceResource,
    ) -> Result<EndpointSliceUpdateOutcome, EndpointSliceApplyError> {
        self.endpoint_slices.upsert_slice(slice)
    }

    pub fn delete_endpoint_slice(&mut self, namespace: &str, slice_name: &str) -> bool {
        self.endpoint_slices.delete_slice(namespace, slice_name)
    }

    #[must_use]
    pub const fn endpoint_slice_stats(&self) -> EndpointSliceStats {
        self.endpoint_slices.stats()
    }

    pub fn build_candidate(&mut self) -> Result<GatewaySnapshotCandidate, ReconcileError> {
        let resources = self.materialize_resources();
        let candidate = build_snapshot_candidate(&resources, self.options)?;
        self.last_translation_report = None;
        self.last_candidate_version = Some(candidate.desired_version.clone());
        self.last_candidate_digest_sha256 = Some(candidate.desired_digest_sha256.clone());
        Ok(candidate)
    }

    pub fn publish_candidate_at(
        &mut self,
        actor: Option<String>,
        reason: Option<String>,
        occurred_at_unix_ms: u64,
    ) -> Result<PublishedGatewaySnapshot, ReconcileError> {
        let candidate = self.build_candidate()?;
        self.reconciler
            .backend_mut()
            .publish_snapshot(
                &candidate.desired_version,
                candidate.snapshot.clone(),
                actor,
                reason,
                occurred_at_unix_ms,
            )
            .map_err(ReconcileError::Backend)?;
        Ok(PublishedGatewaySnapshot {
            desired_version: candidate.desired_version,
            desired_digest_sha256: candidate.desired_digest_sha256,
        })
    }

    pub fn reconcile_at(
        &mut self,
        observed_generation: u64,
        actor: Option<String>,
        occurred_at_unix_ms: u64,
    ) -> Result<ReconcileResult, ReconcileError> {
        self.observed_generation = observed_generation;
        let resources = self.materialize_resources();
        if let Ok(candidate) = build_snapshot_candidate(&resources, self.options) {
            self.last_candidate_version = Some(candidate.desired_version);
            self.last_candidate_digest_sha256 = Some(candidate.desired_digest_sha256);
        }
        let result = self.reconciler.reconcile_at(
            ReconcileRequest { resources, observed_generation, actor },
            occurred_at_unix_ms,
        );
        self.sync_recent_events();
        match &result {
            Ok(reconcile) => {
                self.last_translation_report = None;
                if self.last_candidate_version.is_none() {
                    self.last_candidate_version = reconcile.status.desired_version.clone();
                }
            }
            Err(ReconcileError::Translation(report)) => {
                self.last_translation_report = Some(report.clone());
                self.last_candidate_version = None;
                self.last_candidate_digest_sha256 = None;
            }
            Err(ReconcileError::Snapshot(_)) => {
                self.last_translation_report = None;
                self.last_candidate_version = None;
                self.last_candidate_digest_sha256 = None;
            }
            Err(ReconcileError::Backend(_)) => {
                self.last_translation_report = None;
            }
        }
        result
    }

    #[must_use]
    pub fn status_report(&self) -> GatewayControllerStatusReport {
        let operator_status = self.reconciler.status().clone();
        GatewayControllerStatusReport {
            observed_generation: self.observed_generation.max(operator_status.observed_generation),
            endpoint_slice_stats: self.endpoint_slices.stats(),
            managed_resources: self.collect_managed_resource_statuses(&operator_status),
            recent_events: self.recent_events.iter().cloned().collect(),
            last_candidate_version: self.last_candidate_version.clone(),
            last_candidate_digest_sha256: self.last_candidate_digest_sha256.clone(),
            operator_status,
        }
    }

    #[must_use]
    pub fn reconciler(&self) -> &KubernetesOperatorReconciler<B> {
        &self.reconciler
    }

    #[must_use]
    pub fn reconciler_mut(&mut self) -> &mut KubernetesOperatorReconciler<B> {
        &mut self.reconciler
    }

    fn materialize_resources(&mut self) -> GatewayApiResourceSet {
        let resources = self.endpoint_slices.flush_into(&self.resources);
        self.resources = resources.clone();
        resources
    }

    fn sync_recent_events(&mut self) {
        for event in
            self.reconciler.events().iter().skip(self.synced_reconciler_event_count).cloned()
        {
            if self.recent_events.len() == MAX_RECENT_EVENTS {
                let _ = self.recent_events.pop_front();
            }
            self.recent_events.push_back(event);
            self.synced_reconciler_event_count =
                self.synced_reconciler_event_count.saturating_add(1);
        }
    }

    fn collect_managed_resource_statuses(
        &self,
        operator_status: &OperatorStatus,
    ) -> Vec<ManagedResourceStatus> {
        let mut statuses = Vec::new();
        statuses.extend(self.resources.gateway_classes.iter().map(|resource| {
            self.project_managed_resource_status(
                ManagedResourceKind::GatewayClass,
                &resource.metadata.namespace,
                &resource.metadata.name,
                operator_status,
            )
        }));
        statuses.extend(self.resources.gateways.iter().map(|resource| {
            self.project_managed_resource_status(
                ManagedResourceKind::Gateway,
                &resource.metadata.namespace,
                &resource.metadata.name,
                operator_status,
            )
        }));
        statuses.extend(self.resources.http_routes.iter().map(|resource| {
            self.project_managed_resource_status(
                ManagedResourceKind::HttpRoute,
                &resource.metadata.namespace,
                &resource.metadata.name,
                operator_status,
            )
        }));
        statuses.extend(self.resources.services.iter().map(|resource| {
            self.project_managed_resource_status(
                ManagedResourceKind::Service,
                &resource.metadata.namespace,
                &resource.metadata.name,
                operator_status,
            )
        }));
        statuses.extend(self.endpoint_slices.slice_refs().into_iter().map(|(namespace, name)| {
            self.project_managed_resource_status(
                ManagedResourceKind::EndpointSlice,
                &namespace,
                &name,
                operator_status,
            )
        }));
        statuses
    }

    fn project_managed_resource_status(
        &self,
        kind: ManagedResourceKind,
        namespace: &str,
        name: &str,
        operator_status: &OperatorStatus,
    ) -> ManagedResourceStatus {
        let conditions = self
            .matching_translation_conditions(kind, namespace, name)
            .unwrap_or_else(|| operator_status.conditions.clone());
        let state = if conditions.iter().any(|condition| {
            condition.condition_type == crate::StatusConditionType::Invalid
                && condition.status == crate::ConditionStatus::True
        }) {
            OperatorState::Invalid
        } else if conditions.iter().any(|condition| {
            condition.condition_type == crate::StatusConditionType::Progressing
                && condition.status == crate::ConditionStatus::True
        }) {
            OperatorState::Progressing
        } else {
            OperatorState::Ready
        };
        ManagedResourceStatus {
            kind,
            namespace: String::from(namespace),
            name: String::from(name),
            state,
            conditions,
        }
    }

    fn matching_translation_conditions(
        &self,
        kind: ManagedResourceKind,
        namespace: &str,
        name: &str,
    ) -> Option<Vec<StatusCondition>> {
        let report = self.last_translation_report.as_ref()?;
        let errors = report
            .errors
            .iter()
            .filter(|error| {
                translation_error_kind_matches(kind, error.resource_kind)
                    && error.resource_namespace == namespace
                    && error.resource_name == name
            })
            .collect::<Vec<_>>();
        if errors.is_empty() {
            return None;
        }
        let reason =
            if errors.iter().any(|error| error.category == crate::TranslationCategory::Unsupported)
            {
                "UnsupportedDesiredState"
            } else if errors
                .iter()
                .any(|error| error.category == crate::TranslationCategory::InvalidReference)
            {
                "InvalidReferences"
            } else {
                "InvalidDesiredState"
            };
        Some(vec![
            StatusCondition {
                condition_type: crate::StatusConditionType::Ready,
                status: crate::ConditionStatus::False,
                reason: String::from(reason),
                message: join_translation_error_messages(&errors),
            },
            StatusCondition {
                condition_type: crate::StatusConditionType::Progressing,
                status: crate::ConditionStatus::False,
                reason: String::from(reason),
                message: join_translation_error_messages(&errors),
            },
            StatusCondition {
                condition_type: crate::StatusConditionType::Invalid,
                status: crate::ConditionStatus::True,
                reason: String::from(reason),
                message: join_translation_error_messages(&errors),
            },
        ])
    }
}

fn translation_error_kind_matches(kind: ManagedResourceKind, resource_kind: &str) -> bool {
    matches!(
        (kind, resource_kind),
        (ManagedResourceKind::GatewayClass, "GatewayClass")
            | (ManagedResourceKind::Gateway, "Gateway")
            | (ManagedResourceKind::HttpRoute, "HTTPRoute")
            | (ManagedResourceKind::Service, "Service")
            | (ManagedResourceKind::EndpointSlice, "EndpointSlice")
    )
}

fn join_translation_error_messages(errors: &[&crate::TranslationError]) -> String {
    errors.iter().map(|error| error.detail.as_str()).collect::<Vec<_>>().join("; ")
}

fn build_snapshot_candidate(
    resources: &GatewayApiResourceSet,
    options: GatewayTranslationOptions,
) -> Result<GatewaySnapshotCandidate, ReconcileError> {
    let config = translate_gateway_api(resources, options).map_err(ReconcileError::Translation)?;
    let snapshot = config.compile_snapshot().map_err(ReconcileError::Snapshot)?;
    let desired_digest_sha256 = snapshot.metadata().digest_sha256().to_owned();
    let desired_version = derive_desired_version(&config.name, &desired_digest_sha256);
    Ok(GatewaySnapshotCandidate {
        resources: resources.clone(),
        config,
        snapshot,
        desired_version,
        desired_digest_sha256,
    })
}

fn derive_desired_version(workspace_name: &str, digest_sha256: &str) -> String {
    format!("k8s-{}-{}", workspace_name.replace(['_', '.'], "-"), &digest_sha256[..12])
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use lb_test_support::test_artifact_signer;

    use super::{GatewayControllerPipeline, ManagedResourceKind};
    use crate::OperatorState;
    use crate::{
        CoreApiVersion, DiscoveryApiVersion, EndpointAddressType, EndpointSliceConditions,
        EndpointSliceEndpoint, EndpointSliceResource, GatewayApiVersion, GatewayClassResource,
        GatewayListenerProtocol, GatewayListenerResource, GatewayParentReference, GatewayResource,
        GatewayTranslationOptions, HttpRouteMatchResource, HttpRouteResource,
        HttpRouteRuleResource, InMemoryReconcileBackend, ObjectMeta, ReconcileBackend,
        ReconcileBackendError, ReconcileError, ServiceEndpointResource, ServicePortResource,
        ServiceResource, StatusConditionType, SUPPORTED_GATEWAY_CONTROLLER_NAME,
    };

    #[derive(Debug, Default)]
    struct RecordingBackend {
        last_version: Option<String>,
        last_digest_sha256: Option<String>,
        fail_publish_once: bool,
        fail_rollout_once: bool,
        active_version: Option<String>,
        active_digest_sha256: Option<String>,
        last_known_good_version: Option<String>,
    }

    impl ReconcileBackend for RecordingBackend {
        fn trusted_signers(&self) -> Vec<lb_config_model::TrustedArtifactSignerConfig> {
            Vec::new()
        }

        fn publish_snapshot(
            &mut self,
            version: &str,
            snapshot: lb_config_model::WorkspaceSnapshot,
            _actor: Option<String>,
            _reason: Option<String>,
            _occurred_at_unix_ms: u64,
        ) -> Result<(), ReconcileBackendError> {
            if self.fail_publish_once {
                self.fail_publish_once = false;
                return Err(ReconcileBackendError::Publish(
                    lb_admin_api::SnapshotPublicationError::Conflict(
                        lb_admin_api::PublishConflict::VersionAlreadyExists {
                            version: String::from(version),
                            existing_digest_sha256: String::from("existing-digest"),
                        },
                    ),
                ));
            }
            self.last_version = Some(String::from(version));
            self.last_digest_sha256 = Some(snapshot.metadata().digest_sha256().to_owned());
            Ok(())
        }

        fn rollout_version(
            &mut self,
            _version: &str,
            _actor: Option<String>,
            _reason: Option<String>,
            _occurred_at_unix_ms: u64,
        ) -> Result<lb_admin_api::RolloutResponse, ReconcileBackendError> {
            if self.fail_rollout_once {
                self.fail_rollout_once = false;
                return Err(ReconcileBackendError::Rollout(
                    lb_admin_api::RolloutError::UnknownPublishedVersion(String::from("slice-2c")),
                ));
            }
            self.active_version = Some(String::from(_version));
            self.active_digest_sha256 = Some(String::from("digest"));
            self.last_known_good_version = Some(String::from(_version));
            Ok(lb_admin_api::RolloutResponse {
                action: lb_admin_api::RolloutActionKind::Rollout,
                result: lb_admin_api::RolloutResultKind::Applied,
                active_version: String::from(_version),
                active_digest_sha256: String::from("digest"),
                last_known_good_version: String::from(_version),
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

    fn sample_resources() -> crate::GatewayApiResourceSet {
        crate::GatewayApiResourceSet {
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
                    backend_refs: vec![crate::BackendReferenceResource {
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
                    id: String::from("bootstrap"),
                    address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
                }],
            }],
        }
    }

    fn endpoint_slice(generation: u64, endpoint_ids: &[&str]) -> EndpointSliceResource {
        EndpointSliceResource {
            api_version: DiscoveryApiVersion::V1,
            metadata: ObjectMeta::new("edge", "payments-slice"),
            service_name: String::from("payments"),
            generation,
            address_type: EndpointAddressType::Ipv4,
            ports: vec![8081],
            endpoints: endpoint_ids
                .iter()
                .enumerate()
                .map(|(index, id)| EndpointSliceEndpoint {
                    id: String::from(*id),
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10 + index as u8))],
                    conditions: EndpointSliceConditions::default(),
                })
                .collect(),
        }
    }

    #[test]
    fn build_candidate_translates_gateway_api_resources_into_supported_snapshot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend = InMemoryReconcileBackend::new(test_artifact_signer()?);
        let mut pipeline =
            GatewayControllerPipeline::new(backend, GatewayTranslationOptions::default());
        pipeline.replace_resources(sample_resources());

        let candidate = pipeline.build_candidate()?;

        assert_eq!(candidate.config.api_version, lb_config_model::ConfigApiVersion::V1Alpha1);
        assert_eq!(candidate.config.listeners.len(), 1);
        assert_eq!(candidate.config.upstream_clusters[0].endpoints.len(), 1);
        assert_eq!(candidate.snapshot.metadata().digest_sha256(), candidate.desired_digest_sha256);
        Ok(())
    }

    #[test]
    fn unsupported_listener_shapes_return_explicit_translation_error() {
        let backend = RecordingBackend::default();
        let mut pipeline =
            GatewayControllerPipeline::new(backend, GatewayTranslationOptions::default());
        let mut resources = sample_resources();
        resources.gateways[0].listeners[0].protocol = GatewayListenerProtocol::Https;
        pipeline.replace_resources(resources);

        let error = pipeline.build_candidate();

        assert!(matches!(
            error,
            Err(ReconcileError::Translation(ref report))
                if report.errors.iter().any(|error| {
                    error.code == crate::TranslationCode::UnsupportedListenerProtocol
                })
        ));
    }

    #[test]
    fn endpoint_slice_updates_adjust_compiled_upstreams_deterministically(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend = RecordingBackend::default();
        let mut pipeline =
            GatewayControllerPipeline::new(backend, GatewayTranslationOptions::default());
        pipeline.replace_resources(sample_resources());
        let _ = pipeline.upsert_endpoint_slice(endpoint_slice(1, &["payments-b", "payments-a"]))?;

        let candidate = pipeline.build_candidate()?;
        let endpoint_ids = candidate.config.upstream_clusters[0]
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(endpoint_ids, vec!["payments-a", "payments-b"]);

        let repeated = pipeline.build_candidate()?;
        assert_eq!(candidate.desired_digest_sha256, repeated.desired_digest_sha256);

        let _ = pipeline.upsert_endpoint_slice(endpoint_slice(2, &["payments-c", "payments-a"]))?;
        let updated = pipeline.build_candidate()?;
        let updated_ids = updated.config.upstream_clusters[0]
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(updated_ids, vec!["payments-a", "payments-c"]);
        assert_ne!(candidate.desired_digest_sha256, updated.desired_digest_sha256);
        Ok(())
    }

    #[test]
    fn publish_candidate_uses_backend_snapshot_publication_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend = RecordingBackend::default();
        let mut pipeline =
            GatewayControllerPipeline::new(backend, GatewayTranslationOptions::default());
        pipeline.replace_resources(sample_resources());

        let published = pipeline.publish_candidate_at(
            Some(String::from("operator")),
            Some(String::from("slice-2b publish")),
            1_700,
        )?;

        let backend = pipeline.reconciler().backend();
        assert_eq!(backend.last_version.as_deref(), Some(published.desired_version.as_str()));
        assert_eq!(
            backend.last_digest_sha256.as_deref(),
            Some(published.desired_digest_sha256.as_str())
        );
        Ok(())
    }

    #[test]
    fn status_report_marks_unsupported_shapes_explicitly() {
        let backend = RecordingBackend::default();
        let mut pipeline =
            GatewayControllerPipeline::new(backend, GatewayTranslationOptions::default());
        let mut resources = sample_resources();
        resources.gateways[0].listeners[0].protocol = GatewayListenerProtocol::Https;
        pipeline.replace_resources(resources);

        let result = pipeline.reconcile_at(4, Some(String::from("operator")), 400);

        assert!(matches!(result, Err(ReconcileError::Translation(_))));
        let report = pipeline.status_report();
        assert!(report.managed_resources.iter().any(|resource| {
            resource.kind == ManagedResourceKind::Gateway
                && resource.state == OperatorState::Invalid
                && resource.conditions.iter().any(|condition| {
                    condition.condition_type == StatusConditionType::Invalid
                        && condition.status == crate::ConditionStatus::True
                        && condition.reason == "UnsupportedDesiredState"
                })
        }));
    }

    #[test]
    fn failed_publish_does_not_advertise_stale_ready_condition(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend = RecordingBackend::default();
        let mut pipeline =
            GatewayControllerPipeline::new(backend, GatewayTranslationOptions::default());
        pipeline.replace_resources(sample_resources());
        let first = pipeline.reconcile_at(1, Some(String::from("operator")), 100)?;
        assert_eq!(first.status.state, OperatorState::Ready);

        let mut next_resources = sample_resources();
        next_resources.services[0].endpoints.push(ServiceEndpointResource {
            id: String::from("payments-b"),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)), 8081),
        });
        pipeline.replace_resources(next_resources);
        pipeline.reconciler_mut().backend_mut().fail_publish_once = true;

        let result = pipeline.reconcile_at(2, Some(String::from("operator")), 200);

        assert!(matches!(result, Err(ReconcileError::Backend(_))));
        let report = pipeline.status_report();
        assert_eq!(report.operator_status.state, OperatorState::Progressing);
        assert!(report.operator_status.last_known_good_version.is_some());
        assert!(report.operator_status.conditions.iter().any(|condition| {
            condition.condition_type == StatusConditionType::Ready
                && condition.status == crate::ConditionStatus::False
                && condition.reason == "PublishFailed"
        }));
        Ok(())
    }

    #[test]
    fn failed_rollout_keeps_last_known_good_and_exposes_bounded_events(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend = RecordingBackend::default();
        let mut pipeline =
            GatewayControllerPipeline::new(backend, GatewayTranslationOptions::default());
        pipeline.replace_resources(sample_resources());
        let first = pipeline.reconcile_at(1, Some(String::from("operator")), 100)?;
        assert_eq!(first.status.state, OperatorState::Ready);

        let mut next_resources = sample_resources();
        next_resources.http_routes[0].rules[0].matches[0].path_prefix =
            String::from("/payments/v2");
        pipeline.replace_resources(next_resources);
        pipeline.reconciler_mut().backend_mut().fail_rollout_once = true;

        let result = pipeline.reconcile_at(2, Some(String::from("operator")), 200);

        assert!(matches!(result, Err(ReconcileError::Backend(_))));
        let report = pipeline.status_report();
        assert_eq!(report.operator_status.state, OperatorState::Progressing);
        assert!(report.operator_status.last_known_good_version.is_some());
        assert!(report.operator_status.conditions.iter().any(|condition| {
            condition.condition_type == StatusConditionType::Progressing
                && condition.status == crate::ConditionStatus::True
                && condition.reason == "RolloutFailed"
        }));
        assert!(!report.recent_events.is_empty());
        assert!(report.recent_events.len() <= super::MAX_RECENT_EVENTS);
        Ok(())
    }
}
