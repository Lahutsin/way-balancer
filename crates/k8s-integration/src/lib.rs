#![forbid(unsafe_code)]

mod endpoint_slices;
mod operator;

pub use endpoint_slices::{
    DiscoveryApiVersion, EndpointAddressType, EndpointSliceApplyError, EndpointSliceConditions,
    EndpointSliceController, EndpointSliceEndpoint, EndpointSliceResource, EndpointSliceStats,
    EndpointSliceUpdateOutcome,
};
pub use operator::{
    ConditionStatus, InMemoryReconcileBackend, KubernetesOperatorReconciler, OperatorState,
    OperatorStatus, ReconcileBackend, ReconcileBackendError, ReconcileError, ReconcileMetrics,
    ReconcileRequest, ReconcileResult, ReconcileTransitionEvent, RequeueDecision, StatusCondition,
    StatusConditionType,
};

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use lb_config_model::{
    ConfigApiVersion, ListenerClassConfig, ListenerProtocolConfig, ListenerResourceConfig,
    PolicyBindingConfig, RouteConfig, UpstreamClusterConfig, UpstreamEndpointConfig,
    UpstreamTrafficPolicyConfig, WorkspaceConfig,
};
use serde::{Deserialize, Serialize};

pub const CRATE_ID: &str = "lb-k8s-integration";
pub const SUPPORTED_GATEWAY_CONTROLLER_NAME: &str = "lb.way-balancer.dev/gateway-controller";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayApiVersion {
    V1,
    V1Beta1,
}

impl GatewayApiVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "gateway.networking.k8s.io/v1",
            Self::V1Beta1 => "gateway.networking.k8s.io/v1beta1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreApiVersion {
    V1,
}

impl CoreApiVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectMeta {
    pub namespace: String,
    pub name: String,
}

impl ObjectMeta {
    #[must_use]
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self { namespace: namespace.into(), name: name.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayClassResource {
    pub api_version: GatewayApiVersion,
    pub metadata: ObjectMeta,
    pub controller_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayResource {
    pub api_version: GatewayApiVersion,
    pub metadata: ObjectMeta,
    pub gateway_class_name: String,
    pub listeners: Vec<GatewayListenerResource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayListenerProtocol {
    Http,
    Https,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayListenerResource {
    pub name: String,
    pub port: u16,
    pub protocol: GatewayListenerProtocol,
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRouteResource {
    pub api_version: GatewayApiVersion,
    pub metadata: ObjectMeta,
    #[serde(default)]
    pub hostnames: Vec<String>,
    pub parent_refs: Vec<GatewayParentReference>,
    pub rules: Vec<HttpRouteRuleResource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayParentReference {
    pub gateway_name: String,
    #[serde(default)]
    pub gateway_namespace: Option<String>,
    #[serde(default)]
    pub section_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRouteRuleResource {
    pub matches: Vec<HttpRouteMatchResource>,
    pub backend_refs: Vec<BackendReferenceResource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRouteMatchResource {
    pub path_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendReferenceResource {
    pub service_name: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceResource {
    pub api_version: CoreApiVersion,
    pub metadata: ObjectMeta,
    pub ports: Vec<ServicePortResource>,
    pub endpoints: Vec<ServiceEndpointResource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePortResource {
    pub port: u16,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceEndpointResource {
    pub id: String,
    pub address: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayApiResourceSet {
    pub gateway_classes: Vec<GatewayClassResource>,
    pub gateways: Vec<GatewayResource>,
    pub http_routes: Vec<HttpRouteResource>,
    pub services: Vec<ServiceResource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayTranslationOptions {
    pub bind_ip: IpAddr,
    pub listener_class: ListenerClassConfig,
    pub listener_protocol: ListenerProtocolConfig,
}

impl Default for GatewayTranslationOptions {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            listener_class: ListenerClassConfig::Public,
            listener_protocol: ListenerProtocolConfig::Http1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationCategory {
    InvalidReference,
    Unsupported,
    InvalidShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationCode {
    MissingGatewayClass,
    UnsupportedGatewayController,
    UnsupportedListenerProtocol,
    UnsupportedHostname,
    MissingParentSectionName,
    MissingGatewayListener,
    CrossNamespaceReferenceUnsupported,
    MissingService,
    MissingServicePort,
    EmptyBackendRefs,
    MultipleBackendRefsUnsupported,
    EmptyRouteRules,
    EmptyRouteMatches,
    EmptyPathPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslationError {
    pub category: TranslationCategory,
    pub code: TranslationCode,
    pub resource_kind: &'static str,
    pub resource_namespace: String,
    pub resource_name: String,
    pub detail: String,
}

impl std::fmt::Display for TranslationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} {}/{}: {}",
            self.resource_kind, self.resource_namespace, self.resource_name, self.detail
        )
    }
}

impl std::error::Error for TranslationError {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TranslationReport {
    pub errors: Vec<TranslationError>,
}

impl TranslationReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    fn push(&mut self, error: TranslationError) {
        self.errors.push(error);
    }
}

impl std::fmt::Display for TranslationReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, error) in self.errors.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for TranslationReport {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GatewayTranslationStats {
    pub success_count: u64,
    pub failure_count: u64,
    pub invalid_reference_count: u64,
    pub unsupported_count: u64,
    pub invalid_shape_count: u64,
}

#[derive(Debug, Default)]
pub struct GatewayApiTranslator {
    stats: GatewayTranslationStats,
}

impl GatewayApiTranslator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn translate(
        &mut self,
        resources: &GatewayApiResourceSet,
        options: GatewayTranslationOptions,
    ) -> Result<WorkspaceConfig, TranslationReport> {
        match translate_gateway_api(resources, options) {
            Ok(config) => {
                self.stats.success_count = self.stats.success_count.saturating_add(1);
                Ok(config)
            }
            Err(report) => {
                self.stats.failure_count = self.stats.failure_count.saturating_add(1);
                for error in &report.errors {
                    match error.category {
                        TranslationCategory::InvalidReference => {
                            self.stats.invalid_reference_count =
                                self.stats.invalid_reference_count.saturating_add(1);
                        }
                        TranslationCategory::Unsupported => {
                            self.stats.unsupported_count =
                                self.stats.unsupported_count.saturating_add(1);
                        }
                        TranslationCategory::InvalidShape => {
                            self.stats.invalid_shape_count =
                                self.stats.invalid_shape_count.saturating_add(1);
                        }
                    }
                }
                Err(report)
            }
        }
    }

    #[must_use]
    pub const fn stats(&self) -> GatewayTranslationStats {
        self.stats
    }
}

pub fn translate_gateway_api(
    resources: &GatewayApiResourceSet,
    options: GatewayTranslationOptions,
) -> Result<WorkspaceConfig, TranslationReport> {
    let mut report = TranslationReport::default();

    let gateway_classes = resources
        .gateway_classes
        .iter()
        .map(|gateway_class| (gateway_class.metadata.name.clone(), gateway_class))
        .collect::<BTreeMap<_, _>>();
    let services = resources
        .services
        .iter()
        .map(|service| {
            (format!("{}/{}", service.metadata.namespace, service.metadata.name), service)
        })
        .collect::<BTreeMap<_, _>>();

    let mut listener_by_parent = BTreeMap::new();
    let mut listeners = Vec::new();

    for gateway in &resources.gateways {
        let Some(gateway_class) = gateway_classes.get(&gateway.gateway_class_name) else {
            report.push(translation_error(
                TranslationCategory::InvalidReference,
                TranslationCode::MissingGatewayClass,
                "Gateway",
                &gateway.metadata,
                format!("references missing GatewayClass '{}'", gateway.gateway_class_name),
            ));
            continue;
        };

        if gateway_class.controller_name != SUPPORTED_GATEWAY_CONTROLLER_NAME {
            report.push(translation_error(
                TranslationCategory::Unsupported,
                TranslationCode::UnsupportedGatewayController,
                "Gateway",
                &gateway.metadata,
                format!(
                    "GatewayClass '{}' uses unsupported controller '{}'",
                    gateway_class.metadata.name, gateway_class.controller_name
                ),
            ));
            continue;
        }

        for listener in &gateway.listeners {
            if listener.hostname.is_some() {
                report.push(translation_error(
                    TranslationCategory::Unsupported,
                    TranslationCode::UnsupportedHostname,
                    "Gateway",
                    &gateway.metadata,
                    format!("listener '{}' sets unsupported hostname filtering", listener.name),
                ));
                continue;
            }

            if listener.protocol != GatewayListenerProtocol::Http {
                report.push(translation_error(
                    TranslationCategory::Unsupported,
                    TranslationCode::UnsupportedListenerProtocol,
                    "Gateway",
                    &gateway.metadata,
                    format!(
                        "listener '{}' uses unsupported protocol {:?}",
                        listener.name, listener.protocol
                    ),
                ));
                continue;
            }

            let listener_name = format!(
                "{}.{}.{}",
                gateway.metadata.namespace, gateway.metadata.name, listener.name
            );
            listener_by_parent.insert(
                (
                    gateway.metadata.namespace.clone(),
                    gateway.metadata.name.clone(),
                    listener.name.clone(),
                ),
                listener_name.clone(),
            );
            listeners.push(ListenerResourceConfig {
                name: listener_name,
                class: options.listener_class,
                bind_address: SocketAddr::new(options.bind_ip, listener.port),
                protocol: options.listener_protocol,
                tls_termination: None,
                allow_unspecified_bind: false,
                max_connections: None,
                backlog: None,
                idle_timeout_ms: None,
                drain_timeout_ms: None,
                routes: Vec::new(),
                policies: PolicyBindingConfig::default(),
            });
        }
    }

    let mut route_bindings = BTreeMap::<String, Vec<String>>::new();
    let mut routes = Vec::new();
    let mut upstreams = BTreeMap::<String, UpstreamClusterConfig>::new();

    for http_route in &resources.http_routes {
        if !http_route.hostnames.is_empty() {
            report.push(translation_error(
                TranslationCategory::Unsupported,
                TranslationCode::UnsupportedHostname,
                "HTTPRoute",
                &http_route.metadata,
                String::from(
                    "HTTPRoute hostnames are not yet supported by the internal route model",
                ),
            ));
            continue;
        }

        if http_route.rules.is_empty() {
            report.push(translation_error(
                TranslationCategory::InvalidShape,
                TranslationCode::EmptyRouteRules,
                "HTTPRoute",
                &http_route.metadata,
                String::from("HTTPRoute must declare at least one rule"),
            ));
            continue;
        }

        let mut parent_listener_names = Vec::new();
        for parent_ref in &http_route.parent_refs {
            if parent_ref.gateway_namespace.as_deref().unwrap_or(&http_route.metadata.namespace)
                != http_route.metadata.namespace
            {
                report.push(translation_error(
                    TranslationCategory::Unsupported,
                    TranslationCode::CrossNamespaceReferenceUnsupported,
                    "HTTPRoute",
                    &http_route.metadata,
                    format!(
                        "cross-namespace parent reference to Gateway '{}' is not supported",
                        parent_ref.gateway_name
                    ),
                ));
                continue;
            }

            let Some(section_name) = &parent_ref.section_name else {
                report.push(translation_error(
                    TranslationCategory::InvalidReference,
                    TranslationCode::MissingParentSectionName,
                    "HTTPRoute",
                    &http_route.metadata,
                    format!(
                        "parent reference to Gateway '{}' must include section_name",
                        parent_ref.gateway_name
                    ),
                ));
                continue;
            };

            let key = (
                http_route.metadata.namespace.clone(),
                parent_ref.gateway_name.clone(),
                section_name.clone(),
            );
            let Some(listener_name) = listener_by_parent.get(&key) else {
                report.push(translation_error(
                    TranslationCategory::InvalidReference,
                    TranslationCode::MissingGatewayListener,
                    "HTTPRoute",
                    &http_route.metadata,
                    format!(
                        "references missing Gateway listener '{}.{}'",
                        parent_ref.gateway_name, section_name
                    ),
                ));
                continue;
            };
            parent_listener_names.push(listener_name.clone());
        }

        if parent_listener_names.is_empty() {
            continue;
        }

        for (rule_index, rule) in http_route.rules.iter().enumerate() {
            if rule.matches.is_empty() {
                report.push(translation_error(
                    TranslationCategory::InvalidShape,
                    TranslationCode::EmptyRouteMatches,
                    "HTTPRoute",
                    &http_route.metadata,
                    format!("rule {} must declare at least one path match", rule_index),
                ));
                continue;
            }

            if rule.backend_refs.is_empty() {
                report.push(translation_error(
                    TranslationCategory::InvalidShape,
                    TranslationCode::EmptyBackendRefs,
                    "HTTPRoute",
                    &http_route.metadata,
                    format!("rule {} must declare exactly one backend_ref", rule_index),
                ));
                continue;
            }

            if rule.backend_refs.len() != 1 {
                report.push(translation_error(
                    TranslationCategory::Unsupported,
                    TranslationCode::MultipleBackendRefsUnsupported,
                    "HTTPRoute",
                    &http_route.metadata,
                    format!(
                        "rule {} declares {} backend_refs; only one is supported",
                        rule_index,
                        rule.backend_refs.len()
                    ),
                ));
                continue;
            }

            let backend_ref = &rule.backend_refs[0];
            let service_key =
                format!("{}/{}", http_route.metadata.namespace, backend_ref.service_name);
            let Some(service) = services.get(&service_key) else {
                report.push(translation_error(
                    TranslationCategory::InvalidReference,
                    TranslationCode::MissingService,
                    "HTTPRoute",
                    &http_route.metadata,
                    format!(
                        "references missing Service '{}' on port {}",
                        backend_ref.service_name, backend_ref.port
                    ),
                ));
                continue;
            };

            if !service.ports.iter().any(|port| port.port == backend_ref.port) {
                report.push(translation_error(
                    TranslationCategory::InvalidReference,
                    TranslationCode::MissingServicePort,
                    "HTTPRoute",
                    &http_route.metadata,
                    format!(
                        "references Service '{}' port {} that is not declared",
                        backend_ref.service_name, backend_ref.port
                    ),
                ));
                continue;
            }

            let cluster_name = format!(
                "{}.{}.{}",
                http_route.metadata.namespace, backend_ref.service_name, backend_ref.port
            );
            upstreams.entry(cluster_name.clone()).or_insert_with(|| UpstreamClusterConfig {
                name: cluster_name.clone(),
                endpoints: service
                    .endpoints
                    .iter()
                    .map(|endpoint| {
                        UpstreamEndpointConfig::foundation(endpoint.id.clone(), endpoint.address)
                    })
                    .collect(),
                traffic_policy: UpstreamTrafficPolicyConfig::default(),
                policies: PolicyBindingConfig::default(),
            });

            for (match_index, route_match) in rule.matches.iter().enumerate() {
                if route_match.path_prefix.trim().is_empty() {
                    report.push(translation_error(
                        TranslationCategory::InvalidShape,
                        TranslationCode::EmptyPathPrefix,
                        "HTTPRoute",
                        &http_route.metadata,
                        format!(
                            "rule {} match {} must declare a non-empty path_prefix",
                            rule_index, match_index
                        ),
                    ));
                    continue;
                }

                let route_name = format!(
                    "{}.{}.r{}.m{}",
                    http_route.metadata.namespace,
                    http_route.metadata.name,
                    rule_index,
                    match_index
                );
                routes.push(RouteConfig::foundation_path_prefix(
                    route_name.clone(),
                    route_match.path_prefix.clone(),
                    cluster_name.clone(),
                ));
                for listener_name in &parent_listener_names {
                    route_bindings
                        .entry(listener_name.clone())
                        .or_default()
                        .push(route_name.clone());
                }
            }
        }
    }

    if !report.is_empty() {
        return Err(report);
    }

    listeners.sort_by(|left, right| left.name.cmp(&right.name));
    for listener in &mut listeners {
        if let Some(routes_for_listener) = route_bindings.get_mut(&listener.name) {
            routes_for_listener.sort();
            listener.routes = routes_for_listener.clone();
        }
    }
    routes.sort_by(|left, right| left.name.cmp(&right.name));
    let mut upstream_clusters = upstreams.into_values().collect::<Vec<_>>();
    upstream_clusters.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(WorkspaceConfig {
        api_version: ConfigApiVersion::V1Alpha1,
        name: derive_workspace_name(resources),
        defaults: lb_config_model::WorkspaceDefaultsConfig::default(),
        security: lb_config_model::WorkspaceSecurityConfig::default(),
        listeners,
        routes,
        upstream_clusters,
        policies: lb_config_model::PolicyResourcesConfig::default(),
    })
}

fn derive_workspace_name(resources: &GatewayApiResourceSet) -> String {
    let mut namespaces = resources
        .gateways
        .iter()
        .map(|gateway| gateway.metadata.namespace.clone())
        .collect::<Vec<_>>();
    namespaces.sort();
    namespaces.dedup();
    if namespaces.is_empty() {
        String::from("k8s-gateway-api")
    } else {
        format!("k8s-{}", namespaces.join("-"))
    }
}

fn translation_error(
    category: TranslationCategory,
    code: TranslationCode,
    resource_kind: &'static str,
    metadata: &ObjectMeta,
    detail: String,
) -> TranslationError {
    TranslationError {
        category,
        code,
        resource_kind,
        resource_namespace: metadata.namespace.clone(),
        resource_name: metadata.name.clone(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        translate_gateway_api, BackendReferenceResource, CoreApiVersion, GatewayApiResourceSet,
        GatewayApiTranslator, GatewayApiVersion, GatewayClassResource, GatewayListenerProtocol,
        GatewayListenerResource, GatewayParentReference, GatewayResource,
        GatewayTranslationOptions, HttpRouteMatchResource, HttpRouteResource,
        HttpRouteRuleResource, ObjectMeta, ServiceEndpointResource, ServicePortResource,
        ServiceResource, TranslationCode, TranslationReport, SUPPORTED_GATEWAY_CONTROLLER_NAME,
    };

    fn sample_resources(api_version: GatewayApiVersion) -> GatewayApiResourceSet {
        GatewayApiResourceSet {
            gateway_classes: vec![GatewayClassResource {
                api_version,
                metadata: ObjectMeta::new("cluster", "public-gateway"),
                controller_name: String::from(SUPPORTED_GATEWAY_CONTROLLER_NAME),
            }],
            gateways: vec![GatewayResource {
                api_version,
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
                api_version,
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
                ports: vec![ServicePortResource { port: 8080, name: Some(String::from("http")) }],
                endpoints: vec![
                    ServiceEndpointResource {
                        id: String::from("payments-a"),
                        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 8081),
                    },
                    ServiceEndpointResource {
                        id: String::from("payments-b"),
                        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)), 8081),
                    },
                ],
            }],
        }
    }

    fn report_contains_code(report: &TranslationReport, code: TranslationCode) -> bool {
        report.errors.iter().any(|error| error.code == code)
    }

    #[test]
    fn translates_gateway_api_resources_into_workspace_config(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resources = sample_resources(GatewayApiVersion::V1);

        let config = translate_gateway_api(&resources, GatewayTranslationOptions::default())?;

        assert_eq!(config.name, "k8s-edge");
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].name, "edge.public.web");
        assert_eq!(config.listeners[0].routes, vec![String::from("edge.payments.r0.m0")]);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].upstream_cluster, "edge.payments.8080");
        assert_eq!(config.upstream_clusters.len(), 1);
        assert_eq!(config.upstream_clusters[0].endpoints.len(), 2);
        config.validate()?;
        let _ = config.compile_snapshot()?;
        Ok(())
    }

    #[test]
    fn missing_service_reference_produces_actionable_error() {
        let mut resources = sample_resources(GatewayApiVersion::V1);
        resources.services.clear();
        let mut translator = GatewayApiTranslator::new();

        let result = translator.translate(&resources, GatewayTranslationOptions::default());

        assert!(result.is_err());
        let report = result.err().unwrap_or_default();
        assert!(report_contains_code(&report, TranslationCode::MissingService));
        assert_eq!(translator.stats().failure_count, 1);
        assert_eq!(translator.stats().invalid_reference_count, 1);
    }

    #[test]
    fn unsupported_security_sensitive_fields_fail_explicitly() {
        let mut resources = sample_resources(GatewayApiVersion::V1);
        resources.gateways[0].listeners[0].protocol = GatewayListenerProtocol::Https;
        resources.http_routes[0].hostnames.push(String::from("payments.example.com"));

        let result = translate_gateway_api(&resources, GatewayTranslationOptions::default());

        assert!(result.is_err());
        let report = result.err().unwrap_or_default();
        assert!(report_contains_code(&report, TranslationCode::UnsupportedListenerProtocol));
        assert!(report_contains_code(&report, TranslationCode::UnsupportedHostname));
    }

    #[test]
    fn translation_output_matches_expected_golden_json() -> Result<(), Box<dyn std::error::Error>> {
        let resources = sample_resources(GatewayApiVersion::V1);

        let config = translate_gateway_api(&resources, GatewayTranslationOptions::default())?;
        let rendered = serde_json::to_string_pretty(&config)?;

        let expected = concat!(
            "{\n",
            "  \"api_version\": \"v1_alpha1\",\n",
            "  \"name\": \"k8s-edge\",\n",
            "  \"defaults\": {\n",
            "    \"listener\": {\n",
            "      \"max_connections\": 128,\n",
            "      \"backlog\": 1024,\n",
            "      \"idle_timeout_ms\": 30000,\n",
            "      \"drain_timeout_ms\": 5000,\n",
            "      \"allow_unspecified_bind\": false\n",
            "    },\n",
            "    \"http\": {\n",
            "      \"http1\": {\n",
            "        \"max_head_bytes\": 16384,\n",
            "        \"max_header_count\": 64,\n",
            "        \"max_body_bytes\": 8388608\n",
            "      },\n",
            "      \"http2\": {\n",
            "        \"max_concurrent_streams\": 128,\n",
            "        \"max_body_bytes\": 8388608\n",
            "      }\n",
            "    }\n",
            "  },\n",
            "  \"security\": {\n",
            "    \"insecure_dev_mode\": {\n",
            "      \"enabled\": false,\n",
            "      \"acknowledgement\": null\n",
            "    },\n",
            "    \"artifact_verification\": {\n",
            "      \"mode\": \"enforced\",\n",
            "      \"trusted_signers\": []\n",
            "    }\n",
            "  },\n",
            "  \"listeners\": [\n",
            "    {\n",
            "      \"name\": \"edge.public.web\",\n",
            "      \"class\": \"public\",\n",
            "      \"bind_address\": \"127.0.0.1:8080\",\n",
            "      \"protocol\": \"http1\",\n",
            "      \"tls_termination\": null,\n",
            "      \"allow_unspecified_bind\": false,\n",
            "      \"max_connections\": null,\n",
            "      \"backlog\": null,\n",
            "      \"idle_timeout_ms\": null,\n",
            "      \"drain_timeout_ms\": null,\n",
            "      \"routes\": [\n",
            "        \"edge.payments.r0.m0\"\n",
            "      ],\n",
            "      \"policies\": {\n",
            "        \"local_rate_limits\": [],\n",
            "        \"local_concurrency_limits\": [],\n",
            "        \"retry_budget\": null,\n",
            "        \"timeout_hierarchy\": null,\n",
            "        \"circuit_breaker\": null,\n",
            "        \"overload_response\": null,\n",
            "        \"cache_policy\": null\n",
            "      }\n",
            "    }\n",
            "  ],\n",
            "  \"routes\": [\n",
            "    {\n",
            "      \"name\": \"edge.payments.r0.m0\",\n",
            "      \"match\": {\n",
            "        \"type\": \"path_prefix\",\n",
            "        \"prefix\": \"/payments\"\n",
            "      },\n",
            "      \"upstream_cluster\": \"edge.payments.8080\",\n",
            "      \"policies\": {\n",
            "        \"local_rate_limits\": [],\n",
            "        \"local_concurrency_limits\": [],\n",
            "        \"retry_budget\": null,\n",
            "        \"timeout_hierarchy\": null,\n",
            "        \"circuit_breaker\": null,\n",
            "        \"overload_response\": null,\n",
            "        \"cache_policy\": null\n",
            "      }\n",
            "    }\n",
            "  ],\n",
            "  \"upstream_clusters\": [\n",
            "    {\n",
            "      \"name\": \"edge.payments.8080\",\n",
            "      \"endpoints\": [\n",
            "        {\n",
            "          \"id\": \"payments-a\",\n",
            "          \"address\": \"10.0.0.10:8081\",\n",
            "          \"state\": \"ready\",\n",
            "          \"zone\": null,\n",
            "          \"locality\": null,\n",
            "          \"weight\": 1\n",
            "        },\n",
            "        {\n",
            "          \"id\": \"payments-b\",\n",
            "          \"address\": \"10.0.0.11:8081\",\n",
            "          \"state\": \"ready\",\n",
            "          \"zone\": null,\n",
            "          \"locality\": null,\n",
            "          \"weight\": 1\n",
            "        }\n",
            "      ],\n",
            "      \"traffic_policy\": {\n",
            "        \"algorithm\": \"round_robin\",\n",
            "        \"locality\": \"disabled\",\n",
            "        \"no_healthy_fallback\": \"fail\"\n",
            "      },\n",
            "      \"policies\": {\n",
            "        \"local_rate_limits\": [],\n",
            "        \"local_concurrency_limits\": [],\n",
            "        \"retry_budget\": null,\n",
            "        \"timeout_hierarchy\": null,\n",
            "        \"circuit_breaker\": null,\n",
            "        \"overload_response\": null,\n",
            "        \"cache_policy\": null\n",
            "      }\n",
            "    }\n",
            "  ],\n",
            "  \"policies\": {\n",
            "    \"local_rate_limits\": [],\n",
            "    \"local_concurrency_limits\": [],\n",
            "    \"retry_budgets\": [],\n",
            "    \"timeout_hierarchies\": [],\n",
            "    \"circuit_breakers\": [],\n",
            "    \"overload_responses\": [],\n",
            "    \"http_caches\": []\n",
            "  }\n",
            "}"
        );

        assert_eq!(rendered, expected);
        Ok(())
    }

    #[test]
    fn supported_gateway_api_versions_translate_compatibly(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let v1 = translate_gateway_api(
            &sample_resources(GatewayApiVersion::V1),
            GatewayTranslationOptions::default(),
        )?;
        let v1beta1 = translate_gateway_api(
            &sample_resources(GatewayApiVersion::V1Beta1),
            GatewayTranslationOptions::default(),
        )?;

        assert_eq!(v1, v1beta1);
        Ok(())
    }

    #[test]
    fn api_version_string_constants_are_stable() {
        assert_eq!(GatewayApiVersion::V1.as_str(), "gateway.networking.k8s.io/v1");
        assert_eq!(GatewayApiVersion::V1Beta1.as_str(), "gateway.networking.k8s.io/v1beta1");
        assert_eq!(CoreApiVersion::V1.as_str(), "v1");
    }

    #[test]
    fn translator_stats_track_success_and_multiple_failure_categories(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut translator = GatewayApiTranslator::new();
        let success = translator.translate(&sample_resources(GatewayApiVersion::V1), GatewayTranslationOptions::default());
        assert!(success.is_ok());

        let mut unsupported = sample_resources(GatewayApiVersion::V1);
        unsupported.gateways[0].listeners[0].protocol = GatewayListenerProtocol::Tcp;
        let unsupported_result = translator.translate(&unsupported, GatewayTranslationOptions::default());
        assert!(unsupported_result.is_err());

        let mut invalid_shape = sample_resources(GatewayApiVersion::V1);
        invalid_shape.http_routes[0].rules.clear();
        let invalid_shape_result = translator.translate(&invalid_shape, GatewayTranslationOptions::default());
        assert!(invalid_shape_result.is_err());

        let stats = translator.stats();
        assert_eq!(stats.success_count, 1);
        assert_eq!(stats.failure_count, 2);
        assert_eq!(stats.unsupported_count, 1);
        assert_eq!(stats.invalid_shape_count, 1);
        Ok(())
    }

    #[test]
    fn empty_resource_set_translates_to_empty_workspace_name() -> Result<(), Box<dyn std::error::Error>> {
        let config = translate_gateway_api(&GatewayApiResourceSet::default(), GatewayTranslationOptions::default())?;

        assert_eq!(config.name, "k8s-gateway-api");
        assert!(config.listeners.is_empty());
        assert!(config.routes.is_empty());
        assert!(config.upstream_clusters.is_empty());
        Ok(())
    }
}
