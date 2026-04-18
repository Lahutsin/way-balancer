#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use lb_config_model::{ListenerClassConfig, ListenerProtocolConfig};
use lb_k8s_integration::{
    GatewayApiResourceSet, GatewayControllerPipeline, GatewayTranslationOptions, ReconcileError,
    ReconcileResult, SUPPORTED_GATEWAY_CONTROLLER_NAME,
};

type DynError = Box<dyn Error + Send + Sync>;

const DEFAULT_RECONCILE_DEBOUNCE_MS: u64 = 250;
const DEFAULT_MAX_REQUEUE_DELAY_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum WatchedResourceKind {
    GatewayClass,
    Gateway,
    HttpRoute,
    Service,
    EndpointSlice,
}

impl WatchedResourceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GatewayClass => "gatewayclasses.gateway.networking.k8s.io",
            Self::Gateway => "gateways.gateway.networking.k8s.io",
            Self::HttpRoute => "httproutes.gateway.networking.k8s.io",
            Self::Service => "services",
            Self::EndpointSlice => "endpointslices.discovery.k8s.io",
        }
    }
}

const WATCHED_RESOURCES: [WatchedResourceKind; 5] = [
    WatchedResourceKind::GatewayClass,
    WatchedResourceKind::Gateway,
    WatchedResourceKind::HttpRoute,
    WatchedResourceKind::Service,
    WatchedResourceKind::EndpointSlice,
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControllerConfig {
    controller_name: String,
    namespace_scope: Option<String>,
    bind_ip: IpAddr,
    listener_class: ListenerClassConfig,
    listener_protocol: ListenerProtocolConfig,
    reconcile_debounce: Duration,
    max_requeue_delay: Duration,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            controller_name: String::from(SUPPORTED_GATEWAY_CONTROLLER_NAME),
            namespace_scope: None,
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            listener_class: ListenerClassConfig::Public,
            listener_protocol: ListenerProtocolConfig::Http1,
            reconcile_debounce: Duration::from_millis(DEFAULT_RECONCILE_DEBOUNCE_MS),
            max_requeue_delay: Duration::from_millis(DEFAULT_MAX_REQUEUE_DELAY_MS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ControllerConfigError {
    BindIp(String),
    ListenerClass(String),
    ListenerProtocol(String),
    Duration(String),
}

impl fmt::Display for ControllerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindIp(value) => {
                write!(formatter, "invalid LB_K8S_CONTROLLER_BIND_IP {value}")
            }
            Self::ListenerClass(value) => {
                write!(formatter, "invalid LB_K8S_CONTROLLER_LISTENER_CLASS {value}")
            }
            Self::ListenerProtocol(value) => {
                write!(formatter, "invalid LB_K8S_CONTROLLER_LISTENER_PROTOCOL {value}")
            }
            Self::Duration(value) => {
                write!(formatter, "invalid controller duration value {value}")
            }
        }
    }
}

impl Error for ControllerConfigError {}

impl ControllerConfig {
    fn from_env() -> Result<Self, ControllerConfigError> {
        let env_map = env::vars().collect::<BTreeMap<_, _>>();
        Self::from_env_map(&env_map)
    }

    fn from_env_map(env_map: &BTreeMap<String, String>) -> Result<Self, ControllerConfigError> {
        let mut config = Self::default();

        if let Some(value) = env_map.get("LB_K8S_CONTROLLER_NAME") {
            if !value.trim().is_empty() {
                config.controller_name = value.clone();
            }
        }
        if let Some(value) = env_map.get("LB_K8S_CONTROLLER_NAMESPACE") {
            if !value.trim().is_empty() {
                config.namespace_scope = Some(value.clone());
            }
        }
        if let Some(value) = env_map.get("LB_K8S_CONTROLLER_BIND_IP") {
            config.bind_ip =
                value.parse().map_err(|_| ControllerConfigError::BindIp(value.clone()))?;
        }
        if let Some(value) = env_map.get("LB_K8S_CONTROLLER_LISTENER_CLASS") {
            config.listener_class = parse_listener_class(value)?;
        }
        if let Some(value) = env_map.get("LB_K8S_CONTROLLER_LISTENER_PROTOCOL") {
            config.listener_protocol = parse_listener_protocol(value)?;
        }
        if let Some(value) = env_map.get("LB_K8S_CONTROLLER_RECONCILE_DEBOUNCE_MS") {
            config.reconcile_debounce = Duration::from_millis(
                value.parse::<u64>().map_err(|_| ControllerConfigError::Duration(value.clone()))?,
            );
        }
        if let Some(value) = env_map.get("LB_K8S_CONTROLLER_MAX_REQUEUE_MS") {
            config.max_requeue_delay = Duration::from_millis(
                value.parse::<u64>().map_err(|_| ControllerConfigError::Duration(value.clone()))?,
            );
        }

        Ok(config)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    const fn translation_options(&self) -> GatewayTranslationOptions {
        GatewayTranslationOptions {
            bind_ip: self.bind_ip,
            listener_class: self.listener_class,
            listener_protocol: self.listener_protocol,
        }
    }
}

fn parse_listener_class(value: &str) -> Result<ListenerClassConfig, ControllerConfigError> {
    match value {
        "public" => Ok(ListenerClassConfig::Public),
        "admin" => Ok(ListenerClassConfig::Admin),
        _ => Err(ControllerConfigError::ListenerClass(String::from(value))),
    }
}

fn parse_listener_protocol(value: &str) -> Result<ListenerProtocolConfig, ControllerConfigError> {
    match value {
        "http1" => Ok(ListenerProtocolConfig::Http1),
        "http2" => Ok(ListenerProtocolConfig::Http2),
        "https" => Ok(ListenerProtocolConfig::Https),
        "tcp" => Ok(ListenerProtocolConfig::Tcp),
        _ => Err(ControllerConfigError::ListenerProtocol(String::from(value))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(not(test), allow(dead_code))]
struct ReconcileKey {
    namespace: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
struct QueuedReconcile {
    key: ReconcileKey,
    resources: GatewayApiResourceSet,
    observed_generation: u64,
    actor: Option<String>,
    not_before_unix_ms: u64,
}

#[derive(Debug, Default)]
#[cfg_attr(not(test), allow(dead_code))]
struct ReconcileQueue {
    entries: BTreeMap<ReconcileKey, QueuedReconcile>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ReconcileQueue {
    fn enqueue(&mut self, entry: QueuedReconcile) {
        match self.entries.get_mut(&entry.key) {
            Some(existing) => {
                if entry.observed_generation >= existing.observed_generation {
                    existing.resources = entry.resources;
                    existing.observed_generation = entry.observed_generation;
                    existing.actor = entry.actor;
                }
                existing.not_before_unix_ms =
                    existing.not_before_unix_ms.min(entry.not_before_unix_ms);
            }
            None => {
                self.entries.insert(entry.key.clone(), entry);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn schedule_requeue(
        &mut self,
        key: &ReconcileKey,
        resources: GatewayApiResourceSet,
        observed_generation: u64,
        actor: Option<String>,
        now_unix_ms: u64,
        requested_delay_ms: u64,
        max_requeue_delay_ms: u64,
    ) {
        let bounded_delay_ms = requested_delay_ms.min(max_requeue_delay_ms);
        self.enqueue(QueuedReconcile {
            key: key.clone(),
            resources,
            observed_generation,
            actor,
            not_before_unix_ms: now_unix_ms.saturating_add(bounded_delay_ms),
        });
    }

    fn pop_due(&mut self, now_unix_ms: u64) -> Vec<QueuedReconcile> {
        let due_keys = self
            .entries
            .iter()
            .filter(|(_key, value)| value.not_before_unix_ms <= now_unix_ms)
            .map(|(key, _value)| key.clone())
            .collect::<Vec<_>>();

        due_keys.into_iter().filter_map(|key| self.entries.remove(&key)).collect()
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
struct ControllerRuntime<B> {
    config: ControllerConfig,
    watched_resources: &'static [WatchedResourceKind],
    queue: ReconcileQueue,
    pipeline: GatewayControllerPipeline<B>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl<B> ControllerRuntime<B>
where
    B: lb_k8s_integration::ReconcileBackend,
{
    fn new(config: ControllerConfig, backend: B) -> Self {
        let pipeline = GatewayControllerPipeline::new(backend, config.translation_options());
        Self {
            config,
            watched_resources: &WATCHED_RESOURCES,
            queue: ReconcileQueue::default(),
            pipeline,
        }
    }

    fn watched_resources(&self) -> &'static [WatchedResourceKind] {
        self.watched_resources
    }

    fn submit_reconcile(
        &mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        resources: GatewayApiResourceSet,
        observed_generation: u64,
        actor: Option<String>,
        now_unix_ms: u64,
    ) {
        self.queue.enqueue(QueuedReconcile {
            key: ReconcileKey { namespace: namespace.into(), name: name.into() },
            resources,
            observed_generation,
            actor,
            not_before_unix_ms: now_unix_ms
                .saturating_add(self.config.reconcile_debounce.as_millis() as u64),
        });
    }

    fn drive_once(&mut self, now_unix_ms: u64) -> Vec<Result<ReconcileResult, ReconcileError>> {
        self.queue
            .pop_due(now_unix_ms)
            .into_iter()
            .map(|entry| {
                let key = entry.key.clone();
                let resources_for_requeue = entry.resources.clone();
                let actor_for_requeue = entry.actor.clone();
                let observed_generation = entry.observed_generation;
                self.pipeline.replace_resources(entry.resources);
                let result =
                    self.pipeline.reconcile_at(observed_generation, entry.actor, now_unix_ms);
                if let Err(ReconcileError::Backend(_)) = &result {
                    self.queue.schedule_requeue(
                        &key,
                        resources_for_requeue,
                        observed_generation,
                        actor_for_requeue,
                        now_unix_ms,
                        DEFAULT_MAX_REQUEUE_DELAY_MS,
                        self.config.max_requeue_delay.as_millis() as u64,
                    );
                }
                result
            })
            .collect()
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), DynError> {
    let config = ControllerConfig::from_env()?;

    eprintln!(
        "lb-k8s-controller starting with controller={} namespace_scope={} bind_ip={} watches={}",
        config.controller_name,
        config.namespace_scope.as_deref().unwrap_or("all"),
        config.bind_ip,
        WATCHED_RESOURCES.iter().map(|resource| resource.as_str()).collect::<Vec<_>>().join(", ")
    );

    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lb_config_model::{ArtifactSigner, ListenerProtocolConfig};

    use super::{
        ControllerConfig, ControllerRuntime, ReconcileQueue, WatchedResourceKind,
        DEFAULT_MAX_REQUEUE_DELAY_MS,
    };
    use lb_k8s_integration::{
        ConditionStatus, InMemoryReconcileBackend, OperatorState, ReconcileBackend,
        ReconcileBackendError, ReconcileError, RequeueDecision,
    };
    use lb_test_support::test_artifact_signer;

    fn sample_resources() -> lb_k8s_integration::GatewayApiResourceSet {
        use lb_k8s_integration::{
            BackendReferenceResource, CoreApiVersion, GatewayApiVersion, GatewayClassResource,
            GatewayListenerProtocol, GatewayListenerResource, GatewayParentReference,
            GatewayResource, HttpRouteMatchResource, HttpRouteResource, HttpRouteRuleResource,
            ObjectMeta, ServiceEndpointResource, ServicePortResource, ServiceResource,
            SUPPORTED_GATEWAY_CONTROLLER_NAME,
        };
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        lb_k8s_integration::GatewayApiResourceSet {
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

    #[derive(Debug, Default)]
    struct AlwaysFailBackend;

    impl ReconcileBackend for AlwaysFailBackend {
        fn trusted_signers(&self) -> Vec<lb_config_model::TrustedArtifactSignerConfig> {
            ArtifactSigner::from_signing_key_hex(
                "test-signer",
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .map(|signer| vec![signer.trusted_signer()])
            .unwrap_or_default()
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
            _version: &str,
            _actor: Option<String>,
            _reason: Option<String>,
            _occurred_at_unix_ms: u64,
        ) -> Result<lb_admin_api::RolloutResponse, ReconcileBackendError> {
            Err(ReconcileBackendError::Rollout(
                lb_admin_api::RolloutError::UnknownPublishedVersion(String::from("fail")),
            ))
        }

        fn active_version(&self) -> Option<&str> {
            None
        }

        fn active_digest_sha256(&self) -> Option<&str> {
            None
        }

        fn last_known_good_version(&self) -> Option<&str> {
            None
        }
    }

    #[test]
    fn controller_config_parses_env_overrides() -> Result<(), Box<dyn std::error::Error>> {
        let env_map = BTreeMap::from([
            (String::from("LB_K8S_CONTROLLER_NAME"), String::from("lb.example/controller")),
            (String::from("LB_K8S_CONTROLLER_NAMESPACE"), String::from("edge-system")),
            (String::from("LB_K8S_CONTROLLER_BIND_IP"), String::from("127.0.0.2")),
            (String::from("LB_K8S_CONTROLLER_LISTENER_CLASS"), String::from("public")),
            (String::from("LB_K8S_CONTROLLER_LISTENER_PROTOCOL"), String::from("http2")),
            (String::from("LB_K8S_CONTROLLER_RECONCILE_DEBOUNCE_MS"), String::from("500")),
            (String::from("LB_K8S_CONTROLLER_MAX_REQUEUE_MS"), String::from("15000")),
        ]);

        let config = ControllerConfig::from_env_map(&env_map)?;

        assert_eq!(config.controller_name, "lb.example/controller");
        assert_eq!(config.namespace_scope.as_deref(), Some("edge-system"));
        assert_eq!(config.bind_ip.to_string(), "127.0.0.2");
        assert_eq!(config.listener_protocol, ListenerProtocolConfig::Http2);
        assert_eq!(config.reconcile_debounce.as_millis(), 500);
        assert_eq!(config.max_requeue_delay.as_millis(), 15_000);
        Ok(())
    }

    #[test]
    fn controller_runtime_exposes_expected_watch_set() -> Result<(), Box<dyn std::error::Error>> {
        let backend = InMemoryReconcileBackend::new(test_artifact_signer()?);
        let runtime = ControllerRuntime::new(ControllerConfig::default(), backend);

        assert_eq!(
            runtime.watched_resources(),
            &[
                WatchedResourceKind::GatewayClass,
                WatchedResourceKind::Gateway,
                WatchedResourceKind::HttpRoute,
                WatchedResourceKind::Service,
                WatchedResourceKind::EndpointSlice,
            ]
        );
        Ok(())
    }

    #[test]
    fn reconcile_queue_coalesces_latest_generation() {
        let mut queue = ReconcileQueue::default();
        let resources = sample_resources();

        queue.enqueue(super::QueuedReconcile {
            key: super::ReconcileKey {
                namespace: String::from("edge"),
                name: String::from("public"),
            },
            resources: resources.clone(),
            observed_generation: 1,
            actor: Some(String::from("operator-a")),
            not_before_unix_ms: 100,
        });
        queue.enqueue(super::QueuedReconcile {
            key: super::ReconcileKey {
                namespace: String::from("edge"),
                name: String::from("public"),
            },
            resources,
            observed_generation: 3,
            actor: Some(String::from("operator-b")),
            not_before_unix_ms: 120,
        });

        let due = queue.pop_due(100);
        assert_eq!(queue.len(), 0);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].observed_generation, 3);
        assert_eq!(due[0].actor.as_deref(), Some("operator-b"));
        assert_eq!(due[0].not_before_unix_ms, 100);
    }

    #[test]
    fn controller_runtime_schedules_bounded_requeue_after_backend_failure() {
        let mut runtime = ControllerRuntime::new(ControllerConfig::default(), AlwaysFailBackend);
        runtime.submit_reconcile(
            "edge",
            "public",
            sample_resources(),
            7,
            Some(String::from("operator")),
            1_000,
        );

        let first = runtime.drive_once(1_250);
        assert_eq!(first.len(), 1);
        assert!(matches!(first[0], Err(ReconcileError::Backend(_))));
        assert_eq!(runtime.queue.len(), 1);

        let premature = runtime.drive_once(1_250 + DEFAULT_MAX_REQUEUE_DELAY_MS - 1);
        assert!(premature.is_empty());

        let due = runtime.drive_once(1_250 + DEFAULT_MAX_REQUEUE_DELAY_MS);
        assert_eq!(due.len(), 1);
        assert!(matches!(due[0], Err(ReconcileError::Backend(_))));
    }

    #[test]
    fn controller_runtime_reconciles_supported_snapshot_to_ready(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend = InMemoryReconcileBackend::new(test_artifact_signer()?);
        let mut runtime = ControllerRuntime::new(ControllerConfig::default(), backend);
        runtime.submit_reconcile(
            "edge",
            "public",
            sample_resources(),
            1,
            Some(String::from("operator")),
            100,
        );

        let result = runtime.drive_once(350);
        assert_eq!(result.len(), 1);
        let result = result.into_iter().next().ok_or("missing reconcile result")??;
        assert_eq!(result.requeue, RequeueDecision::None);
        assert_eq!(result.status.state, OperatorState::Ready);
        assert_eq!(result.status.conditions[0].status, ConditionStatus::True,);
        Ok(())
    }
}
