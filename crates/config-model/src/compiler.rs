use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    ConfigApiVersion, EndpointStateConfig, ListenerCertificateSourceConfig, ListenerClassConfig,
    ListenerProtocolConfig, PolicyBindingConfig, PolicyResourcesConfig, RouteMatchConfig,
    UpstreamTrafficPolicyConfig, ValidationReport, WorkspaceConfig, WorkspaceConfigError,
    WorkspaceSecurityConfig,
};

const SNAPSHOT_FORMAT_VERSION: &str = "v1";

/// Immutable snapshot compiler metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotMetadata {
    format_version: String,
    api_version: ConfigApiVersion,
    digest_sha256: String,
}

impl SnapshotMetadata {
    #[must_use]
    pub fn format_version(&self) -> &str {
        &self.format_version
    }

    #[must_use]
    pub const fn api_version(&self) -> ConfigApiVersion {
        self.api_version
    }

    #[must_use]
    pub fn digest_sha256(&self) -> &str {
        &self.digest_sha256
    }
}

/// Immutable normalized listener snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerSnapshot {
    name: String,
    class: ListenerClassConfig,
    protocol: ListenerProtocolConfig,
    admin: crate::AdminListenerPolicyConfig,
    tls_termination: Option<ListenerTlsTerminationSnapshot>,
    bind_address: SocketAddr,
    max_connections: usize,
    backlog: u32,
    idle_timeout_ms: u64,
    drain_timeout_ms: u64,
    allow_unspecified_bind: bool,
    routes: Vec<String>,
    policies: PolicyBindingConfig,
}

impl ListenerSnapshot {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerTlsTerminationSnapshot {
    certificate_source: ListenerCertificateSourceSnapshot,
    sni_certificates: Vec<ListenerTlsSniCertificateSnapshot>,
    session_resumption: crate::ListenerTlsSessionResumptionConfig,
    minimum_version: crate::ListenerTlsMinimumVersionConfig,
    alpn_protocols: Vec<crate::ListenerAlpnProtocolConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerTlsSniCertificateSnapshot {
    server_names: Vec<String>,
    certificate_source: ListenerCertificateSourceSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ListenerCertificateSourceSnapshot {
    Files { cert_path: String, key_path: String, ocsp_path: Option<String> },
}

fn snapshot_certificate_source(
    source: &ListenerCertificateSourceConfig,
) -> ListenerCertificateSourceSnapshot {
    match source {
        ListenerCertificateSourceConfig::Files { cert_path, key_path, ocsp_path } => {
            ListenerCertificateSourceSnapshot::Files {
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                ocsp_path: ocsp_path.clone(),
            }
        }
    }
}

/// Immutable normalized route snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteSnapshot {
    name: String,
    match_rule: RouteMatchConfig,
    upstream_cluster: String,
    policies: PolicyBindingConfig,
}

impl RouteSnapshot {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Immutable normalized upstream endpoint snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamEndpointSnapshot {
    id: String,
    address: SocketAddr,
    state: EndpointStateConfig,
    zone: Option<String>,
    locality: Option<String>,
    weight: u16,
}

/// Immutable normalized upstream cluster snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamClusterSnapshot {
    name: String,
    endpoints: Vec<UpstreamEndpointSnapshot>,
    traffic_policy: UpstreamTrafficPolicyConfig,
    policies: PolicyBindingConfig,
}

impl UpstreamClusterSnapshot {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Diff-friendly immutable view of the compiled snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceSnapshotView {
    metadata: SnapshotMetadata,
    workspace_name: String,
    security: WorkspaceSecurityConfig,
    policies: PolicyResourcesConfig,
    listeners: Vec<ListenerSnapshot>,
    routes: Vec<RouteSnapshot>,
    upstream_clusters: Vec<UpstreamClusterSnapshot>,
}

impl WorkspaceSnapshotView {
    #[must_use]
    pub fn metadata(&self) -> &SnapshotMetadata {
        &self.metadata
    }
}

/// Immutable compiled snapshot / IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSnapshot {
    metadata: SnapshotMetadata,
    workspace_name: String,
    security: WorkspaceSecurityConfig,
    policies: PolicyResourcesConfig,
    listeners: Vec<ListenerSnapshot>,
    routes: Vec<RouteSnapshot>,
    upstream_clusters: Vec<UpstreamClusterSnapshot>,
    compiled_listeners: Vec<lb_net_core::ListenerConfig>,
    compiled_route_rules: Vec<lb_proto_http::RoutePrefixRule>,
    compiled_upstream_clusters: Vec<lb_net_core::UpstreamCluster>,
}

impl WorkspaceSnapshot {
    #[must_use]
    pub fn metadata(&self) -> &SnapshotMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn workspace_name(&self) -> &str {
        &self.workspace_name
    }

    #[must_use]
    pub fn listeners(&self) -> &[ListenerSnapshot] {
        &self.listeners
    }

    #[must_use]
    pub fn security(&self) -> &WorkspaceSecurityConfig {
        &self.security
    }

    #[must_use]
    pub fn policies(&self) -> &PolicyResourcesConfig {
        &self.policies
    }

    #[must_use]
    pub fn routes(&self) -> &[RouteSnapshot] {
        &self.routes
    }

    #[must_use]
    pub fn upstream_clusters(&self) -> &[UpstreamClusterSnapshot] {
        &self.upstream_clusters
    }

    #[must_use]
    pub fn compiled_listeners(&self) -> &[lb_net_core::ListenerConfig] {
        &self.compiled_listeners
    }

    #[must_use]
    pub fn compiled_route_rules(&self) -> &[lb_proto_http::RoutePrefixRule] {
        &self.compiled_route_rules
    }

    #[must_use]
    pub fn compiled_upstream_clusters(&self) -> &[lb_net_core::UpstreamCluster] {
        &self.compiled_upstream_clusters
    }

    #[must_use]
    pub fn view(&self) -> WorkspaceSnapshotView {
        WorkspaceSnapshotView {
            metadata: self.metadata.clone(),
            workspace_name: self.workspace_name.clone(),
            security: self.security.clone(),
            policies: self.policies.clone(),
            listeners: self.listeners.clone(),
            routes: self.routes.clone(),
            upstream_clusters: self.upstream_clusters.clone(),
        }
    }

    pub fn render_json(&self) -> Result<String, SnapshotCompileError> {
        serde_json::to_string_pretty(&self.view()).map_err(SnapshotCompileError::Serialization)
    }

    #[must_use]
    pub fn diff(&self, next: &Self) -> WorkspaceSnapshotDiff {
        WorkspaceSnapshotDiff {
            previous_digest_sha256: self.metadata.digest_sha256.clone(),
            next_digest_sha256: next.metadata.digest_sha256.clone(),
            listener_changes: diff_named_resources(&self.listeners, &next.listeners),
            route_changes: diff_named_resources(&self.routes, &next.routes),
            upstream_cluster_changes: diff_named_resources(
                &self.upstream_clusters,
                &next.upstream_clusters,
            ),
        }
    }
}

/// Stable snapshot change kind for diff output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotChangeKind {
    Added,
    Removed,
    Updated,
}

/// Diff entry for a named snapshot resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotResourceChange {
    pub name: String,
    pub kind: SnapshotChangeKind,
}

/// Diff-friendly representation between two compiled snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceSnapshotDiff {
    pub previous_digest_sha256: String,
    pub next_digest_sha256: String,
    pub listener_changes: Vec<SnapshotResourceChange>,
    pub route_changes: Vec<SnapshotResourceChange>,
    pub upstream_cluster_changes: Vec<SnapshotResourceChange>,
}

/// Stable snapshot compilation failures.
#[derive(Debug)]
pub enum SnapshotCompileError {
    Validation(ValidationReport),
    Model(WorkspaceConfigError),
    Serialization(serde_json::Error),
}

impl std::fmt::Display for SnapshotCompileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(report) => write!(formatter, "snapshot validation failed: {report}"),
            Self::Model(error) => write!(formatter, "snapshot compilation failed: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "snapshot serialization failed: {error}")
            }
        }
    }
}

impl std::error::Error for SnapshotCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(report) => Some(report),
            Self::Model(error) => Some(error),
            Self::Serialization(error) => Some(error),
        }
    }
}

/// Minimal compiler counters for config snapshot generation observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SnapshotCompileStats {
    pub success_count: u64,
    pub validation_failure_count: u64,
    pub model_failure_count: u64,
}

/// Snapshot compiler wrapper with success/failure counters.
#[derive(Debug, Default)]
pub struct WorkspaceSnapshotCompiler {
    stats: SnapshotCompileStats,
}

impl WorkspaceSnapshotCompiler {
    pub fn compile(
        &mut self,
        config: &WorkspaceConfig,
    ) -> Result<WorkspaceSnapshot, SnapshotCompileError> {
        match compile_workspace_snapshot(config) {
            Ok(snapshot) => {
                self.stats.success_count = self.stats.success_count.saturating_add(1);
                Ok(snapshot)
            }
            Err(SnapshotCompileError::Validation(error)) => {
                self.stats.validation_failure_count =
                    self.stats.validation_failure_count.saturating_add(1);
                Err(SnapshotCompileError::Validation(error))
            }
            Err(SnapshotCompileError::Model(error)) => {
                self.stats.model_failure_count = self.stats.model_failure_count.saturating_add(1);
                Err(SnapshotCompileError::Model(error))
            }
            Err(SnapshotCompileError::Serialization(error)) => {
                self.stats.model_failure_count = self.stats.model_failure_count.saturating_add(1);
                Err(SnapshotCompileError::Serialization(error))
            }
        }
    }

    #[must_use]
    pub const fn stats(&self) -> SnapshotCompileStats {
        self.stats
    }
}

pub(crate) fn compile_workspace_snapshot(
    config: &WorkspaceConfig,
) -> Result<WorkspaceSnapshot, SnapshotCompileError> {
    config.validate().map_err(SnapshotCompileError::Validation)?;

    let compiled_listeners = config.compile_listeners().map_err(SnapshotCompileError::Model)?;
    let compiled_route_rules =
        config.compile_http_route_rules().map_err(SnapshotCompileError::Model)?;
    let compiled_upstream_clusters =
        config.compile_upstream_clusters().map_err(SnapshotCompileError::Model)?;

    let listeners = config
        .listeners
        .iter()
        .zip(&compiled_listeners)
        .map(|(listener, compiled)| ListenerSnapshot {
            name: listener.name.clone(),
            class: listener.class,
            protocol: listener.protocol,
            admin: listener.admin.clone(),
            tls_termination: listener.tls_termination.as_ref().map(|tls_termination| {
                ListenerTlsTerminationSnapshot {
                    certificate_source: snapshot_certificate_source(
                        &tls_termination.certificate_source,
                    ),
                    sni_certificates: tls_termination
                        .sni_certificates
                        .iter()
                        .map(|certificate| ListenerTlsSniCertificateSnapshot {
                            server_names: certificate.server_names.clone(),
                            certificate_source: snapshot_certificate_source(
                                &certificate.certificate_source,
                            ),
                        })
                        .collect(),
                    session_resumption: tls_termination.session_resumption.clone(),
                    minimum_version: tls_termination.minimum_version,
                    alpn_protocols: tls_termination.alpn_protocols.clone(),
                }
            }),
            bind_address: compiled.bind_address,
            max_connections: compiled.max_connections,
            backlog: compiled.backlog,
            idle_timeout_ms: duration_to_millis(compiled.idle_timeout),
            drain_timeout_ms: duration_to_millis(compiled.drain_timeout),
            allow_unspecified_bind: compiled.allow_unspecified_bind,
            routes: listener.routes.clone(),
            policies: listener.policies.clone(),
        })
        .collect::<Vec<_>>();
    let routes = config
        .routes
        .iter()
        .map(|route| RouteSnapshot {
            name: route.name.clone(),
            match_rule: route.match_rule.clone(),
            upstream_cluster: route.upstream_cluster.clone(),
            policies: route.policies.clone(),
        })
        .collect::<Vec<_>>();
    let upstream_clusters = config
        .upstream_clusters
        .iter()
        .map(|cluster| UpstreamClusterSnapshot {
            name: cluster.name.clone(),
            endpoints: cluster
                .endpoints
                .iter()
                .map(|endpoint| UpstreamEndpointSnapshot {
                    id: endpoint.id.clone(),
                    address: endpoint.address,
                    state: endpoint.state,
                    zone: endpoint.zone.clone(),
                    locality: endpoint.locality.clone(),
                    weight: endpoint.weight,
                })
                .collect(),
            traffic_policy: cluster.traffic_policy.clone(),
            policies: cluster.policies.clone(),
        })
        .collect::<Vec<_>>();

    let digest_source = WorkspaceSnapshotView {
        metadata: SnapshotMetadata {
            format_version: String::from(SNAPSHOT_FORMAT_VERSION),
            api_version: config.api_version,
            digest_sha256: String::new(),
        },
        workspace_name: config.name.clone(),
        security: config.security.clone(),
        policies: config.policies.clone(),
        listeners: listeners.clone(),
        routes: routes.clone(),
        upstream_clusters: upstream_clusters.clone(),
    };
    let digest_sha256 = compute_digest(&digest_source)?;

    Ok(WorkspaceSnapshot {
        metadata: SnapshotMetadata {
            format_version: String::from(SNAPSHOT_FORMAT_VERSION),
            api_version: config.api_version,
            digest_sha256,
        },
        workspace_name: config.name.clone(),
        security: config.security.clone(),
        policies: config.policies.clone(),
        listeners,
        routes,
        upstream_clusters,
        compiled_listeners,
        compiled_route_rules,
        compiled_upstream_clusters,
    })
}

fn duration_to_millis(value: Duration) -> u64 {
    let millis = value.as_millis();
    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

fn compute_digest(view: &WorkspaceSnapshotView) -> Result<String, SnapshotCompileError> {
    let payload = serde_json::to_vec(view).map_err(SnapshotCompileError::Serialization)?;
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    Ok(encode_hex(&digest))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

trait NamedSnapshotResource {
    fn resource_name(&self) -> &str;
}

impl NamedSnapshotResource for ListenerSnapshot {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

impl NamedSnapshotResource for RouteSnapshot {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

impl NamedSnapshotResource for UpstreamClusterSnapshot {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

fn diff_named_resources<T>(previous: &[T], next: &[T]) -> Vec<SnapshotResourceChange>
where
    T: NamedSnapshotResource + Serialize,
{
    let previous_by_name = previous
        .iter()
        .map(|resource| (resource.resource_name().to_string(), resource_fingerprint(resource)))
        .collect::<BTreeMap<_, _>>();
    let next_by_name = next
        .iter()
        .map(|resource| (resource.resource_name().to_string(), resource_fingerprint(resource)))
        .collect::<BTreeMap<_, _>>();

    let mut names = BTreeSet::new();
    names.extend(previous_by_name.keys().cloned());
    names.extend(next_by_name.keys().cloned());

    let mut changes = Vec::new();
    for name in names {
        match (previous_by_name.get(&name), next_by_name.get(&name)) {
            (None, Some(_)) => {
                changes.push(SnapshotResourceChange { name, kind: SnapshotChangeKind::Added })
            }
            (Some(_), None) => {
                changes.push(SnapshotResourceChange { name, kind: SnapshotChangeKind::Removed })
            }
            (Some(previous_fingerprint), Some(next_fingerprint))
                if previous_fingerprint != next_fingerprint =>
            {
                changes.push(SnapshotResourceChange { name, kind: SnapshotChangeKind::Updated });
            }
            _ => {}
        }
    }
    changes
}

fn resource_fingerprint<T>(resource: &T) -> String
where
    T: Serialize,
{
    match serde_json::to_vec(resource) {
        Ok(payload) => {
            let mut hasher = Sha256::new();
            hasher.update(payload);
            encode_hex(&hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        compile_workspace_snapshot, SnapshotChangeKind, SnapshotCompileError,
        WorkspaceSnapshotCompiler,
    };
    use crate::{
        AdminAuditConfig, AdminAuthPolicyConfig, AdminAuthorizationScopeConfig,
        AdminListenerPolicyConfig, AdminOperatorConfig, AdminRateLimitConfig, ListenerClassConfig,
        ListenerProtocolConfig, ListenerResourceConfig, PolicyBindingConfig, RouteConfig,
        UpstreamClusterConfig, UpstreamEndpointConfig, UpstreamTrafficPolicyConfig,
        WorkspaceConfig,
    };

    fn valid_workspace() -> WorkspaceConfig {
        WorkspaceConfig {
            name: String::from("edge"),
            listeners: vec![ListenerResourceConfig {
                name: String::from("public"),
                class: ListenerClassConfig::Public,
                bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                protocol: ListenerProtocolConfig::Http1,
                tls_termination: None,
                allow_unspecified_bind: false,
                max_connections: None,
                backlog: None,
                idle_timeout_ms: None,
                drain_timeout_ms: None,
                routes: vec![String::from("api")],
                policies: PolicyBindingConfig::default(),
                admin: AdminListenerPolicyConfig::default(),
            }],
            routes: vec![RouteConfig::foundation_path_prefix("api", "/api", "payments")],
            upstream_clusters: vec![UpstreamClusterConfig {
                name: String::from("payments"),
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "payments-a",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000),
                )],
                traffic_policy: UpstreamTrafficPolicyConfig::default(),
                policies: PolicyBindingConfig::default(),
            }],
            ..WorkspaceConfig::foundation()
        }
    }

    #[test]
    fn snapshot_compilation_is_deterministic_and_idempotent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = valid_workspace();

        let first = compile_workspace_snapshot(&config)?;
        let second = compile_workspace_snapshot(&config)?;

        assert_eq!(first.metadata(), second.metadata());
        assert_eq!(first.view(), second.view());
        Ok(())
    }

    #[test]
    fn snapshot_view_matches_expected_golden_json() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = compile_workspace_snapshot(&valid_workspace())?;

        let rendered = snapshot.render_json()?;

        assert_eq!(
            rendered,
            concat!(
                "{\n",
                "  \"metadata\": {\n",
                "    \"format_version\": \"v1\",\n",
                "    \"api_version\": \"v1_alpha1\",\n",
                "    \"digest_sha256\": \"b88f3c2e0cef791c8a20c365f396c73cd3834fa07ebe7ed60c7306d1b4933fb7\"\n",
                "  },\n",
                "  \"workspace_name\": \"edge\",\n",
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
                "  \"policies\": {\n",
                "    \"local_rate_limits\": [],\n",
                "    \"local_concurrency_limits\": [],\n",
                "    \"retry_budgets\": [],\n",
                "    \"timeout_hierarchies\": [],\n",
                "    \"circuit_breakers\": [],\n",
                "    \"overload_responses\": [],\n",
                "    \"http_caches\": []\n",
                "  },\n",
                "  \"listeners\": [\n",
                "    {\n",
                "      \"name\": \"public\",\n",
                "      \"class\": \"public\",\n",
                "      \"protocol\": \"http1\",\n",
                "      \"admin\": {\n",
                "        \"auth\": {\n",
                "          \"mode\": \"bearer\",\n",
                "          \"secret_env\": \"LB_CTL_ADMIN_SECRET\",\n",
                "          \"permissions\": [\n",
                "            \"read\",\n",
                "            \"audit\",\n",
                "            \"write\"\n",
                "          ]\n",
                "        },\n",
                "        \"allowed_source_cidrs\": [],\n",
                "        \"rate_limit\": {\n",
                "          \"requests_per_minute\": 120,\n",
                "          \"burst\": 10\n",
                "        },\n",
                "        \"audit\": {\n",
                "          \"max_retained_events\": 64\n",
                "        }\n",
                "      },\n",
                "      \"tls_termination\": null,\n",
                "      \"bind_address\": \"127.0.0.1:8080\",\n",
                "      \"max_connections\": 128,\n",
                "      \"backlog\": 1024,\n",
                "      \"idle_timeout_ms\": 30000,\n",
                "      \"drain_timeout_ms\": 5000,\n",
                "      \"allow_unspecified_bind\": false,\n",
                "      \"routes\": [\n",
                "        \"api\"\n",
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
                "      \"name\": \"api\",\n",
                "      \"match_rule\": {\n",
                "        \"type\": \"path_prefix\",\n",
                "        \"prefix\": \"/api\"\n",
                "      },\n",
                "      \"upstream_cluster\": \"payments\",\n",
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
                "      \"name\": \"payments\",\n",
                "      \"endpoints\": [\n",
                "        {\n",
                "          \"id\": \"payments-a\",\n",
                "          \"address\": \"127.0.0.1:9000\",\n",
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
                "  ]\n",
                "}"
            )
        );
        Ok(())
    }

    #[test]
    fn snapshot_accessors_expose_compiled_resources_and_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = compile_workspace_snapshot(&valid_workspace())?;

        assert_eq!(snapshot.workspace_name(), "edge");
        assert_eq!(snapshot.listeners().len(), 1);
        assert_eq!(snapshot.listeners()[0].name(), "public");
        assert_eq!(snapshot.routes().len(), 1);
        assert_eq!(snapshot.upstream_clusters().len(), 1);
        assert_eq!(snapshot.compiled_listeners().len(), 1);
        assert_eq!(snapshot.compiled_route_rules().len(), 1);
        assert_eq!(snapshot.compiled_upstream_clusters().len(), 1);
        assert_eq!(snapshot.view().metadata().digest_sha256(), snapshot.metadata().digest_sha256());
        assert_eq!(snapshot.security(), &valid_workspace().security);
        assert_eq!(snapshot.policies(), &valid_workspace().policies);
        Ok(())
    }

    #[test]
    fn snapshot_diff_is_empty_for_identical_snapshots() -> Result<(), Box<dyn std::error::Error>> {
        let left = compile_workspace_snapshot(&valid_workspace())?;
        let right = compile_workspace_snapshot(&valid_workspace())?;

        let diff = left.diff(&right);
        assert!(diff.listener_changes.is_empty());
        assert!(diff.route_changes.is_empty());
        assert!(diff.upstream_cluster_changes.is_empty());
        assert_eq!(diff.previous_digest_sha256, diff.next_digest_sha256);
        Ok(())
    }

    #[test]
    fn snapshot_preserves_custom_signed_admin_policy() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace();
        config.listeners[0].class = ListenerClassConfig::Admin;
        config.listeners[0].routes.clear();
        config.listeners[0].admin = AdminListenerPolicyConfig {
            auth: AdminAuthPolicyConfig::SignedHeaders {
                operators: vec![
                    AdminOperatorConfig {
                        id: String::from("auditor"),
                        secret_env: String::from("LB_CTL_OPERATOR_AUDIT_SECRET"),
                        permissions: vec![AdminAuthorizationScopeConfig::Audit],
                    },
                    AdminOperatorConfig {
                        id: String::from("writer"),
                        secret_env: String::from("LB_CTL_OPERATOR_WRITE_SECRET"),
                        permissions: vec![
                            AdminAuthorizationScopeConfig::Read,
                            AdminAuthorizationScopeConfig::Audit,
                            AdminAuthorizationScopeConfig::Write,
                        ],
                    },
                ],
                max_clock_skew_secs: 45,
                nonce_ttl_secs: 180,
            },
            allowed_source_cidrs: vec![String::from("127.0.0.1/32")],
            rate_limit: AdminRateLimitConfig { requests_per_minute: 30, burst: 5 },
            audit: AdminAuditConfig { max_retained_events: 8 },
        };

        let snapshot = compile_workspace_snapshot(&config)?;

        assert_eq!(snapshot.listeners[0].class, ListenerClassConfig::Admin);
        assert_eq!(snapshot.listeners[0].admin, config.listeners[0].admin);
        assert!(matches!(
            snapshot.listeners[0].admin.auth,
            AdminAuthPolicyConfig::SignedHeaders { .. }
        ));
        assert_eq!(
            snapshot.listeners[0].admin.allowed_source_cidrs,
            vec![String::from("127.0.0.1/32")]
        );
        assert_eq!(snapshot.listeners[0].admin.rate_limit.requests_per_minute, 30);
        assert_eq!(snapshot.listeners[0].admin.rate_limit.burst, 5);
        assert_eq!(snapshot.listeners[0].admin.audit.max_retained_events, 8);
        Ok(())
    }

    #[test]
    fn snapshot_diff_reports_added_removed_and_updated_resources(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = compile_workspace_snapshot(&valid_workspace())?;
        let mut next_config = valid_workspace();
        next_config.listeners[0].backlog = Some(2048);
        next_config.routes[0].upstream_cluster = String::from("payments-v2");
        next_config.routes.push(RouteConfig::foundation_path_prefix(
            "grpc",
            "/grpc",
            "payments-v2",
        ));
        next_config.upstream_clusters[0].name = String::from("payments-v2");

        let next = compile_workspace_snapshot(&next_config)?;
        let diff = previous.diff(&next);

        assert_eq!(diff.listener_changes.len(), 1);
        assert_eq!(diff.listener_changes[0].name, "public");
        assert_eq!(diff.listener_changes[0].kind, SnapshotChangeKind::Updated);
        assert_eq!(diff.route_changes.len(), 2);
        assert_eq!(diff.route_changes[0].name, "api");
        assert_eq!(diff.route_changes[0].kind, SnapshotChangeKind::Updated);
        assert_eq!(diff.route_changes[1].name, "grpc");
        assert_eq!(diff.route_changes[1].kind, SnapshotChangeKind::Added);
        assert_eq!(diff.upstream_cluster_changes.len(), 2);
        assert_eq!(diff.upstream_cluster_changes[0].name, "payments");
        assert_eq!(diff.upstream_cluster_changes[0].kind, SnapshotChangeKind::Removed);
        assert_eq!(diff.upstream_cluster_changes[1].name, "payments-v2");
        assert_eq!(diff.upstream_cluster_changes[1].kind, SnapshotChangeKind::Added);
        Ok(())
    }

    #[test]
    fn compiler_tracks_success_and_failures() {
        let mut compiler = WorkspaceSnapshotCompiler::default();
        let success = compiler.compile(&valid_workspace());

        let mut invalid = valid_workspace();
        invalid.name = String::from(" ");
        let validation_failure = compiler.compile(&invalid);

        let mut model_invalid = valid_workspace();
        model_invalid.upstream_clusters[0].endpoints[0].address =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
        let model_failure = compiler.compile(&model_invalid);

        assert!(success.is_ok());
        assert!(matches!(validation_failure, Err(SnapshotCompileError::Validation(_))));
        assert!(matches!(model_failure, Err(SnapshotCompileError::Model(_))));
        assert_eq!(compiler.stats().success_count, 1);
        assert_eq!(compiler.stats().validation_failure_count, 1);
        assert_eq!(compiler.stats().model_failure_count, 1);
    }

    #[test]
    fn compile_rejects_invalid_prevalidated_model_input() {
        let mut config = valid_workspace();
        config.upstream_clusters[0].endpoints[0].address =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);

        let result = compile_workspace_snapshot(&config);

        assert!(matches!(result, Err(SnapshotCompileError::Model(_))));
    }
}
