#![forbid(unsafe_code)]

mod compiler;
mod defaults;
mod failure_policy;
mod limits;
mod listener;
mod overload_policy;
mod policy;
mod route;
mod security;
mod upstream;
mod validator;

pub use compiler::{
    ListenerSnapshot, RouteSnapshot, SnapshotChangeKind, SnapshotCompileError,
    SnapshotCompileStats, SnapshotMetadata, SnapshotResourceChange, UpstreamClusterSnapshot,
    UpstreamEndpointSnapshot, WorkspaceSnapshot, WorkspaceSnapshotCompiler, WorkspaceSnapshotDiff,
    WorkspaceSnapshotView,
};
pub use defaults::{
    Http1DefaultsConfig, Http2DefaultsConfig, HttpDefaultsConfig, ListenerDefaultsConfig,
    WorkspaceDefaultsConfig,
};
pub use failure_policy::{
    CircuitBreakerPolicyConfig, RetryBudgetPolicyConfig, TimeoutHierarchyConfig,
};
pub use limits::{
    LocalConcurrencyLimitPolicyConfig, LocalLimitKeyKindConfig, LocalLimitScopeConfig,
    LocalRateLimitPolicyConfig,
};
pub use listener::{
    AdminAuditConfig, AdminAuthPolicyConfig, AdminAuthorizationScopeConfig,
    AdminListenerPolicyConfig, AdminOperatorConfig, AdminRateLimitConfig,
    ListenerAlpnProtocolConfig, ListenerCertificateSourceConfig, ListenerClassConfig,
    ListenerProtocolConfig, ListenerResourceConfig, ListenerTlsMinimumVersionConfig,
    ListenerTlsSessionResumptionConfig, ListenerTlsSessionResumptionModeConfig,
    ListenerTlsSniCertificateConfig, ListenerTlsTerminationConfig,
};
pub use overload_policy::{
    BrownoutFeatureConfig, OverloadResponsePolicyConfig, TrafficClassConfig,
};
pub use policy::{
    AuthorizationCacheBehaviorConfig, CacheKeyPolicyConfig, CacheQueryKeyBehaviorConfig,
    HttpCacheMethodConfig, HttpCachePolicyConfig, HttpCacheStorageConfig,
    NamedBrownoutFeatureConfig, NamedCircuitBreakerPolicyConfig,
    NamedHttpCachePolicyConfig,
    NamedLocalConcurrencyLimitPolicyConfig, NamedLocalRateLimitPolicyConfig,
    NamedOverloadResponsePolicyConfig, NamedRetryBudgetPolicyConfig,
    NamedTimeoutHierarchyPolicyConfig, PolicyBindingConfig, PolicyResourcesConfig,
};
pub use route::{RouteConfig, RouteMatchConfig};
pub use security::{
    verify_snapshot_artifact_integrity, AnonymousSourceFilterConfig, ArtifactAttestation,
    ArtifactIntegrityError, ArtifactSigner, ArtifactSigningError,
    ArtifactVerificationConfig, ArtifactVerificationMode, InsecureDevModeConfig,
    TrustedArtifactSignerConfig, TrustedClientIpConfig, WorkspaceSecurityConfig,
};
pub use upstream::{
    EndpointStateConfig, LoadBalancingAlgorithmConfig, LocalityRoutingConfig,
    NoHealthyFallbackConfig, UpstreamClusterConfig, UpstreamEndpointConfig,
    UpstreamTrafficPolicyConfig, WorkspaceConfigError,
};
pub use validator::{
    ConfigValidationStats, ValidationCategory, ValidationCode, ValidationError, ValidationReport,
    WorkspaceConfigValidator,
};

use serde::{Deserialize, Serialize};

/// Returns the crate identifier for configuration modeling.
pub const CRATE_ID: &str = "lb-config-model";

/// Version marker for the typed config schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConfigApiVersion {
    /// Initial typed schema foundation.
    #[default]
    V1Alpha1,
}

/// Foundation config object used until feature-specific schemas land.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspaceConfig {
    /// Declared schema version.
    pub api_version: ConfigApiVersion,
    /// Human-readable workspace name.
    pub name: String,
    /// Shared declarative defaults.
    pub defaults: WorkspaceDefaultsConfig,
    /// Shared security and integrity posture.
    pub security: WorkspaceSecurityConfig,
    /// Declarative listener definitions.
    pub listeners: Vec<ListenerResourceConfig>,
    /// Declarative route definitions.
    pub routes: Vec<RouteConfig>,
    /// Declarative upstream cluster definitions.
    pub upstream_clusters: Vec<UpstreamClusterConfig>,
    /// Declarative reusable policy resources.
    pub policies: PolicyResourcesConfig,
}

impl WorkspaceConfig {
    /// Creates the default workspace configuration placeholder.
    #[must_use]
    pub fn foundation() -> Self {
        Self {
            api_version: ConfigApiVersion::V1Alpha1,
            name: String::from("way-balancer"),
            defaults: WorkspaceDefaultsConfig::default(),
            security: WorkspaceSecurityConfig::default(),
            listeners: Vec::new(),
            routes: Vec::new(),
            upstream_clusters: Vec::new(),
            policies: PolicyResourcesConfig::default(),
        }
    }

    /// Parses a workspace config from JSON text.
    pub fn parse_json_str(input: &str) -> Result<Self, ConfigParseError> {
        serde_json::from_str(input).map_err(ConfigParseError)
    }

    /// Validates typed config resources before compilation.
    pub fn validate(&self) -> Result<(), ValidationReport> {
        let report = validator::validate_workspace_config(self);
        if report.is_empty() {
            Ok(())
        } else {
            Err(report)
        }
    }

    /// Deterministically compiles validated config into an immutable snapshot/IR.
    pub fn compile_snapshot(&self) -> Result<WorkspaceSnapshot, SnapshotCompileError> {
        compiler::compile_workspace_snapshot(self)
    }

    /// Compiles declarative listener definitions into strong internal models.
    pub fn compile_listeners(
        &self,
    ) -> Result<Vec<lb_net_core::ListenerConfig>, WorkspaceConfigError> {
        listener::compile_listeners(&self.listeners, &self.defaults)
    }

    /// Compiles declarative route definitions into shared prefix rules.
    pub fn compile_http_route_rules(
        &self,
    ) -> Result<Vec<lb_proto_http::RoutePrefixRule>, WorkspaceConfigError> {
        route::compile_route_rules(&self.routes)
    }

    /// Compiles declarative cluster definitions into strong internal models.
    pub fn compile_upstream_clusters(
        &self,
    ) -> Result<Vec<lb_net_core::UpstreamCluster>, WorkspaceConfigError> {
        upstream::compile_clusters(&self.upstream_clusters)
    }
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self::foundation()
    }
}

/// Stable parse failure wrapper for typed config ingestion.
#[derive(Debug)]
pub struct ConfigParseError(serde_json::Error);

impl std::fmt::Display for ConfigParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid workspace config JSON: {}", self.0)
    }
}

impl std::error::Error for ConfigParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Minimal parse counters for config ingestion observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConfigParseStats {
    /// Count of successful parse attempts.
    pub success_count: u64,
    /// Count of failed parse attempts.
    pub failure_count: u64,
}

/// Parser wrapper that exposes minimal success/failure hooks.
#[derive(Debug, Default)]
pub struct WorkspaceConfigParser {
    stats: ConfigParseStats,
}

impl WorkspaceConfigParser {
    /// Parses a workspace config and records success/failure counters.
    pub fn parse_json_str(&mut self, input: &str) -> Result<WorkspaceConfig, ConfigParseError> {
        match WorkspaceConfig::parse_json_str(input) {
            Ok(config) => {
                self.stats.success_count = self.stats.success_count.saturating_add(1);
                Ok(config)
            }
            Err(error) => {
                self.stats.failure_count = self.stats.failure_count.saturating_add(1);
                Err(error)
            }
        }
    }

    /// Returns the current parse counters.
    #[must_use]
    pub const fn stats(&self) -> ConfigParseStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        AuthorizationCacheBehaviorConfig, CacheQueryKeyBehaviorConfig, HttpCacheStorageConfig,
        ConfigApiVersion, EndpointStateConfig, ListenerAlpnProtocolConfig,
        ListenerCertificateSourceConfig, ListenerClassConfig, ListenerProtocolConfig,
        ListenerResourceConfig, ListenerTlsMinimumVersionConfig,
        ListenerTlsSessionResumptionConfig, ListenerTlsSessionResumptionModeConfig,
        ListenerTlsSniCertificateConfig, ListenerTlsTerminationConfig, PolicyBindingConfig, RouteConfig,
        UpstreamClusterConfig, UpstreamEndpointConfig, UpstreamTrafficPolicyConfig,
        WorkspaceConfig, WorkspaceConfigParser,
    };

    #[test]
    fn foundation_workspace_compiles_empty_upstream_set() -> Result<(), Box<dyn std::error::Error>>
    {
        let config = WorkspaceConfig::foundation();

        let listeners = config.compile_listeners()?;
        let routes = config.compile_http_route_rules()?;
        let compiled = config.compile_upstream_clusters()?;

        assert!(listeners.is_empty());
        assert!(routes.is_empty());
        assert!(compiled.is_empty());
        Ok(())
    }

    #[test]
    fn workspace_compiles_static_cluster_model() -> Result<(), Box<dyn std::error::Error>> {
        let config = WorkspaceConfig {
            api_version: ConfigApiVersion::V1Alpha1,
            name: String::from("way-balancer"),
            defaults: crate::WorkspaceDefaultsConfig::default(),
            security: crate::WorkspaceSecurityConfig::default(),
            listeners: vec![ListenerResourceConfig::foundation(
                "public",
                ListenerClassConfig::Public,
                8080,
            )],
            routes: vec![RouteConfig::foundation_path_prefix("api", "/api", "payments")],
            upstream_clusters: vec![UpstreamClusterConfig {
                name: String::from("payments"),
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "a",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                )],
                traffic_policy: UpstreamTrafficPolicyConfig::default(),
                policies: PolicyBindingConfig::default(),
            }],
            policies: crate::PolicyResourcesConfig::default(),
        };

        let listeners = config.compile_listeners()?;
        let routes = config.compile_http_route_rules()?;
        let compiled = config.compile_upstream_clusters()?;

        assert_eq!(listeners.len(), 1);
        assert_eq!(routes.len(), 1);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].name().as_str(), "payments");
        Ok(())
    }

    #[test]
    fn foundation_workspace_uses_secure_defaults() {
        let config = WorkspaceConfig::foundation();

        assert_eq!(
            config.security.artifact_verification.mode,
            crate::ArtifactVerificationMode::Enforced
        );
        assert!(config.security.artifact_verification.trusted_signers.is_empty());
        assert!(!config.security.insecure_dev_mode.enabled);
    }

    #[test]
    fn workspace_json_parses_into_typed_resources() -> Result<(), Box<dyn std::error::Error>> {
        let config = WorkspaceConfig::parse_json_str(
            r#"{
                "api_version": "v1_alpha1",
                "name": "edge",
                "listeners": [
                    {
                        "name": "public",
                        "class": "public",
                        "bind_address": "127.0.0.1:8443",
                        "protocol": "http2",
                        "routes": ["grpc"]
                    }
                ],
                "routes": [
                    {
                        "name": "grpc",
                        "match": { "type": "path_prefix", "prefix": "/grpc" },
                        "upstream_cluster": "payments",
                        "policies": {
                            "retry_budget": "standard",
                            "cache_policy": "public-cache"
                        }
                    }
                ],
                "upstream_clusters": [
                    {
                        "name": "payments",
                        "endpoints": [
                            {
                                "id": "payments-a",
                                "address": "127.0.0.1:9000",
                                "state": "ready",
                                "weight": 5
                            }
                        ]
                    }
                ],
                "policies": {
                    "retry_budgets": [
                        {
                            "name": "standard",
                            "spec": {
                                "min_retry_tokens": 3,
                                "retry_percent": 20,
                                "window_ms": 10000
                            }
                        }
                    ],
                    "http_caches": [
                        {
                            "name": "public-cache",
                            "spec": {
                                "methods": ["get", "head"],
                                "default_ttl_secs": 30,
                                "max_ttl_secs": 120,
                                "stale_while_revalidate_secs": 15,
                                "stale_if_error_secs": 60,
                                "cacheable_status_codes": [200, 304, 404],
                                "vary_headers": ["accept-encoding"],
                                "max_object_bytes": 65536,
                                "honor_cache_control": true,
                                "allow_set_cookie_storage": false,
                                "authorization": "bypass",
                                "revalidation_enabled": true,
                                "purge_enabled": true,
                                "cache_key": {
                                    "include_host": true,
                                    "include_method": false,
                                    "query": "include_all",
                                    "headers": ["accept-language"]
                                },
                                "storage": {
                                    "type": "memory",
                                    "max_entries": 1024,
                                    "max_bytes": 1048576
                                }
                            }
                        }
                    ]
                }
            }"#,
        )?;

        assert_eq!(config.api_version, ConfigApiVersion::V1Alpha1);
        assert_eq!(config.listeners[0].protocol, ListenerProtocolConfig::Http2);
        assert_eq!(config.routes[0].policies.retry_budget.as_deref(), Some("standard"));
        assert_eq!(config.routes[0].policies.cache_policy.as_deref(), Some("public-cache"));
        assert_eq!(config.upstream_clusters[0].endpoints[0].state, EndpointStateConfig::Ready);
        assert_eq!(config.policies.http_caches.len(), 1);
        assert_eq!(config.policies.http_caches[0].spec.authorization, AuthorizationCacheBehaviorConfig::Bypass);
        assert_eq!(config.policies.http_caches[0].spec.cache_key.query, CacheQueryKeyBehaviorConfig::IncludeAll);
        assert_eq!(config.policies.http_caches[0].spec.storage, HttpCacheStorageConfig::Memory { max_entries: 1024, max_bytes: 1_048_576 });
        Ok(())
    }

    #[test]
    fn omitted_defaults_are_applied_during_parsing() -> Result<(), Box<dyn std::error::Error>> {
        let config = WorkspaceConfig::parse_json_str(
            r#"{
                "name": "edge",
                "listeners": [
                    {
                        "name": "public",
                        "bind_address": "127.0.0.1:8080"
                    }
                ],
                "upstream_clusters": []
            }"#,
        )?;

        assert_eq!(config.api_version, ConfigApiVersion::V1Alpha1);
        assert_eq!(config.defaults.listener.backlog, 1024);
        assert_eq!(config.listeners[0].class, ListenerClassConfig::Public);
        Ok(())
    }

    #[test]
    fn https_listener_json_parses_tls_termination() -> Result<(), Box<dyn std::error::Error>> {
        let config = WorkspaceConfig::parse_json_str(
            r#"{
                "name": "edge",
                "listeners": [
                    {
                        "name": "public-https",
                        "bind_address": "127.0.0.1:8443",
                        "protocol": "https",
                        "tls_termination": {
                            "sni_certificates": [
                                {
                                    "server_names": ["tenant.example"],
                                    "certificate_source": {
                                        "type": "files",
                                        "cert_path": "certs/tenant.pem",
                                        "key_path": "certs/tenant.key",
                                        "ocsp_path": null
                                    }
                                }
                            ],
                            "session_resumption": {
                                "mode": "tickets",
                                "session_cache_size": 128,
                                "tls13_ticket_count": 4
                            },
                            "minimum_version": "tls13",
                            "alpn_protocols": ["http2"],
                            "certificate_source": {
                                "type": "files",
                                "cert_path": "certs/server.pem",
                                "key_path": "certs/server.key",
                                "ocsp_path": "certs/server.ocsp"
                            }
                        },
                        "routes": ["web"]
                    }
                ],
                "routes": [
                    {
                        "name": "web",
                        "match": { "type": "path_prefix", "prefix": "/" },
                        "upstream_cluster": "frontend"
                    }
                ],
                "upstream_clusters": [
                    {
                        "name": "frontend",
                        "endpoints": [
                            {
                                "id": "frontend-a",
                                "address": "127.0.0.1:9000",
                                "state": "ready",
                                "weight": 1
                            }
                        ]
                    }
                ]
            }"#,
        )?;

        assert_eq!(config.listeners[0].protocol, ListenerProtocolConfig::Https);
        assert_eq!(
            config.listeners[0].tls_termination,
            Some(ListenerTlsTerminationConfig {
                certificate_source: ListenerCertificateSourceConfig::Files {
                    cert_path: String::from("certs/server.pem"),
                    key_path: String::from("certs/server.key"),
                    ocsp_path: Some(String::from("certs/server.ocsp")),
                },
                sni_certificates: vec![ListenerTlsSniCertificateConfig {
                    server_names: vec![String::from("tenant.example")],
                    certificate_source: ListenerCertificateSourceConfig::Files {
                        cert_path: String::from("certs/tenant.pem"),
                        key_path: String::from("certs/tenant.key"),
                        ocsp_path: None,
                    },
                }],
                session_resumption: ListenerTlsSessionResumptionConfig {
                    mode: ListenerTlsSessionResumptionModeConfig::Tickets,
                    session_cache_size: 128,
                    tls13_ticket_count: 4,
                },
                minimum_version: ListenerTlsMinimumVersionConfig::Tls13,
                alpn_protocols: vec![ListenerAlpnProtocolConfig::Http2],
            })
        );
        Ok(())
    }

    #[test]
    fn parser_tracks_parse_failures_for_invalid_type_shapes() {
        let mut parser = WorkspaceConfigParser::default();

        let success = parser.parse_json_str(
            r#"{
                "name": "edge",
                "listeners": [
                    {
                        "name": "public",
                        "bind_address": "127.0.0.1:8080"
                    }
                ],
                "upstream_clusters": []
            }"#,
        );
        let failure = parser.parse_json_str(
            r#"{
                "name": "edge",
                "listeners": [
                    {
                        "name": "public",
                        "bind_address": true
                    }
                ],
                "upstream_clusters": []
            }"#,
        );

        assert!(success.is_ok());
        assert!(failure.is_err());
        assert_eq!(parser.stats().success_count, 1);
        assert_eq!(parser.stats().failure_count, 1);
    }
}
