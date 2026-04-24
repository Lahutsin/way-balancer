use serde::{Deserialize, Serialize};

use crate::{
    BrownoutFeatureConfig, CircuitBreakerPolicyConfig, LocalConcurrencyLimitPolicyConfig,
    LocalRateLimitPolicyConfig, OverloadResponsePolicyConfig, RetryBudgetPolicyConfig,
    TimeoutHierarchyConfig, AuthorizationPolicyConfig, ExternalAuthPolicyConfig,
    JwtAuthPolicyConfig, RequestClassificationPolicyConfig, UpstreamIdentityPolicyConfig,
};

/// Named policy resources referenced by listeners, routes, and upstreams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyResourcesConfig {
    /// Reusable local rate-limit policies.
    pub local_rate_limits: Vec<NamedLocalRateLimitPolicyConfig>,
    /// Reusable local concurrency-limit policies.
    pub local_concurrency_limits: Vec<NamedLocalConcurrencyLimitPolicyConfig>,
    /// Reusable hostile-edge protection policies.
    pub hostile_edge_protections: Vec<NamedHostileEdgeProtectionPolicyConfig>,
    /// Reusable retry-budget policies.
    pub retry_budgets: Vec<NamedRetryBudgetPolicyConfig>,
    /// Reusable timeout hierarchy policies.
    pub timeout_hierarchies: Vec<NamedTimeoutHierarchyPolicyConfig>,
    /// Reusable circuit-breaker policies.
    pub circuit_breakers: Vec<NamedCircuitBreakerPolicyConfig>,
    /// Reusable overload response policies.
    pub overload_responses: Vec<NamedOverloadResponsePolicyConfig>,
    /// Reusable HTTP cache policies.
    pub http_caches: Vec<NamedHttpCachePolicyConfig>,
    /// Reusable request and response transform policies.
    pub transforms: Vec<NamedTransformPolicyConfig>,
    /// Reusable traffic mirroring policies.
    pub traffic_mirrors: Vec<NamedTrafficMirrorPolicyConfig>,
    /// Reusable fault injection policies.
    pub fault_injections: Vec<NamedFaultInjectionPolicyConfig>,
    /// Reusable JWT auth policies.
    pub jwt_auth_policies: Vec<NamedJwtAuthPolicyConfig>,
    /// Reusable external auth policies.
    pub external_auth_policies: Vec<NamedExternalAuthPolicyConfig>,
    /// Reusable authorization policies.
    pub authorization_policies: Vec<NamedAuthorizationPolicyConfig>,
    /// Reusable upstream identity policies.
    pub upstream_identity_policies: Vec<NamedUpstreamIdentityPolicyConfig>,
    /// Reusable request classification policies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_classification_policies: Vec<NamedRequestClassificationPolicyConfig>,
}

/// Reference set that attaches named policy resources to another resource.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyBindingConfig {
    /// Referenced local rate-limit policy names.
    pub local_rate_limits: Vec<String>,
    /// Referenced local concurrency-limit policy names.
    pub local_concurrency_limits: Vec<String>,
    /// Referenced hostile-edge protection policy name.
    pub hostile_edge_protection: Option<String>,
    /// Referenced retry-budget policy name.
    pub retry_budget: Option<String>,
    /// Referenced timeout hierarchy policy name.
    pub timeout_hierarchy: Option<String>,
    /// Referenced circuit-breaker policy name.
    pub circuit_breaker: Option<String>,
    /// Referenced overload response policy name.
    pub overload_response: Option<String>,
    /// Referenced HTTP cache policy name.
    pub cache_policy: Option<String>,
    /// Referenced request and response transform policy name.
    pub transform_policy: Option<String>,
    /// Referenced traffic mirroring policy name.
    pub traffic_mirror: Option<String>,
    /// Referenced fault injection policy name.
    pub fault_injection: Option<String>,
    /// Referenced JWT auth policy name.
    pub jwt_auth_policy: Option<String>,
    /// Referenced external auth policy name.
    pub external_auth_policy: Option<String>,
    /// Referenced request authorization policy name.
    pub authorization_policy: Option<String>,
    /// Referenced upstream identity policy name.
    pub upstream_identity_policy: Option<String>,
    /// Referenced request classification policy name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_classification_policy: Option<String>,
}

impl PolicyBindingConfig {
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

/// Declarative request and response transform policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TransformPolicyConfig {
    /// Request-side transforms applied before upstream dispatch.
    pub request: RequestTransformConfig,
    /// Response-side header mutations applied after upstream normalization.
    pub response: ResponseTransformConfig,
}

/// Declarative traffic mirroring policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficMirrorPolicyConfig {
    /// Percent of eligible requests to mirror.
    pub percentage: u8,
    /// Target upstream cluster that receives mirrored traffic.
    pub target_upstream_cluster: String,
    /// Optional HTTP method allow-list for mirroring.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
}

impl Default for TrafficMirrorPolicyConfig {
    fn default() -> Self {
        Self {
            percentage: 100,
            target_upstream_cluster: String::new(),
            methods: Vec::new(),
        }
    }
}

/// Declarative destination-local fault injection policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct FaultInjectionPolicyConfig {
    /// Optional fixed delay injection.
    pub delay: Option<FaultInjectionDelayConfig>,
    /// Optional local abort injection.
    pub abort: Option<FaultInjectionAbortConfig>,
}

/// Fixed delay fault injection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct FaultInjectionDelayConfig {
    /// Percent of requests that should incur the delay.
    pub percentage: u8,
    /// Fixed delay to inject before upstream dispatch.
    pub fixed_delay_ms: u64,
}

/// Local abort fault injection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct FaultInjectionAbortConfig {
    /// Percent of requests that should abort locally.
    pub percentage: u8,
    /// Local HTTP status to return when the abort triggers.
    pub http_status: u16,
}

/// Declarative request transform policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RequestTransformConfig {
    /// Optional path rewrite rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_rewrite: Option<PathRewriteTransformConfig>,
    /// Optional authority or host rewrite.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_rewrite: Option<String>,
    /// Request header mutations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_mutations: Vec<HeaderMutationConfig>,
}

/// Declarative response transform policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseTransformConfig {
    /// Response header mutations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_mutations: Vec<HeaderMutationConfig>,
}

/// Declarative path rewrite rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathRewriteTransformConfig {
    /// Replace a matched leading prefix with a new prefix.
    ReplacePrefix { match_prefix: String, replacement: String },
}

/// Declarative request or response header mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HeaderMutationConfig {
    /// Set or replace a header value.
    Set { name: String, value: String },
    /// Remove a header.
    Remove { name: String },
}

/// Declarative HTTP cache policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpCachePolicyConfig {
    /// Allowed cacheable methods.
    pub methods: Vec<HttpCacheMethodConfig>,
    /// Default TTL applied when origin metadata is absent.
    pub default_ttl_secs: u64,
    /// Upper bound for effective freshness.
    pub max_ttl_secs: u64,
    /// Additional window for serving stale while async revalidation occurs.
    pub stale_while_revalidate_secs: u64,
    /// Additional window for serving stale on upstream errors.
    pub stale_if_error_secs: u64,
    /// Response status codes eligible for storage.
    pub cacheable_status_codes: Vec<u16>,
    /// Response headers that participate in vary key material.
    pub vary_headers: Vec<String>,
    /// Maximum cacheable object size.
    pub max_object_bytes: u64,
    /// Whether to honor origin cache-control directives.
    pub honor_cache_control: bool,
    /// Whether set-cookie responses may be stored.
    pub allow_set_cookie_storage: bool,
    /// How authorization-bearing traffic is handled.
    pub authorization: AuthorizationCacheBehaviorConfig,
    /// Whether conditional revalidation is enabled.
    pub revalidation_enabled: bool,
    /// Whether purge APIs are enabled.
    pub purge_enabled: bool,
    /// Cache key construction policy.
    pub cache_key: CacheKeyPolicyConfig,
    /// Storage backend configuration.
    pub storage: HttpCacheStorageConfig,
}

impl Default for HttpCachePolicyConfig {
    fn default() -> Self {
        Self {
            methods: vec![HttpCacheMethodConfig::Get, HttpCacheMethodConfig::Head],
            default_ttl_secs: 60,
            max_ttl_secs: 300,
            stale_while_revalidate_secs: 30,
            stale_if_error_secs: 60,
            cacheable_status_codes: vec![200, 203, 204, 300, 301, 404, 410],
            vary_headers: Vec::new(),
            max_object_bytes: 1024 * 1024,
            honor_cache_control: true,
            allow_set_cookie_storage: false,
            authorization: AuthorizationCacheBehaviorConfig::Bypass,
            revalidation_enabled: true,
            purge_enabled: false,
            cache_key: CacheKeyPolicyConfig::default(),
            storage: HttpCacheStorageConfig::default(),
        }
    }
}

/// Cacheable HTTP methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpCacheMethodConfig {
    Get,
    Head,
}

/// Authorization behavior for shared cache lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationCacheBehaviorConfig {
    #[default]
    Bypass,
    Partition,
}

/// Query-string participation in cache key construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CacheQueryKeyBehaviorConfig {
    #[default]
    IncludeAll,
    IgnoreAll,
}

/// Declarative cache key construction controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheKeyPolicyConfig {
    /// Whether host participates in the cache key.
    pub include_host: bool,
    /// Whether method participates in the cache key.
    pub include_method: bool,
    /// How query parameters participate in the cache key.
    pub query: CacheQueryKeyBehaviorConfig,
    /// Request headers included in the cache key.
    pub headers: Vec<String>,
}

impl Default for CacheKeyPolicyConfig {
    fn default() -> Self {
        Self {
            include_host: true,
            include_method: false,
            query: CacheQueryKeyBehaviorConfig::IncludeAll,
            headers: Vec::new(),
        }
    }
}

/// Declarative cache storage backing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HttpCacheStorageConfig {
    /// In-memory bounded cache store.
    Memory { max_entries: usize, max_bytes: u64 },
}

impl Default for HttpCacheStorageConfig {
    fn default() -> Self {
        Self::Memory { max_entries: 10_000, max_bytes: 64 * 1024 * 1024 }
    }
}

/// Named HTTP cache resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedHttpCachePolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: HttpCachePolicyConfig,
}

/// Named local rate-limit resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedLocalRateLimitPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: LocalRateLimitPolicyConfig,
}

/// Named local concurrency-limit resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedLocalConcurrencyLimitPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: LocalConcurrencyLimitPolicyConfig,
}

/// Source aggregation strategy for hostile-edge fairness controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostileEdgeSourceAggregationConfig {
    #[default]
    ExactIp,
    Ipv4Subnet24,
    Ipv6Subnet64,
}

/// Declarative source quota guard for hostile-edge admission fairness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostileEdgeSourceQuotaConfig {
    /// Source key aggregation strategy.
    pub aggregation: HostileEdgeSourceAggregationConfig,
    /// Maximum active connections admitted for a single source bucket.
    pub max_active_per_source: usize,
    /// Maximum number of concurrently tracked source buckets.
    pub max_tracked_sources: usize,
}

impl Default for HostileEdgeSourceQuotaConfig {
    fn default() -> Self {
        Self {
            aggregation: HostileEdgeSourceAggregationConfig::ExactIp,
            max_active_per_source: 32,
            max_tracked_sources: 4096,
        }
    }
}

/// Declarative handshake concurrency guard for hostile-edge traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostileEdgeHandshakeGuardConfig {
    /// Maximum concurrent handshakes allowed for the listener.
    pub max_inflight: usize,
    /// Timeout applied to the protected handshake window in milliseconds.
    pub timeout_ms: u64,
}

impl Default for HostileEdgeHandshakeGuardConfig {
    fn default() -> Self {
        Self { max_inflight: 256, timeout_ms: 5_000 }
    }
}

/// Declarative hostile-edge listener protections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct HostileEdgeProtectionPolicyConfig {
    /// Optional per-source active connection quota.
    pub source_quota: Option<HostileEdgeSourceQuotaConfig>,
    /// Optional concurrent handshake guard.
    pub handshake_guard: Option<HostileEdgeHandshakeGuardConfig>,
}

/// Named hostile-edge protection resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedHostileEdgeProtectionPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: HostileEdgeProtectionPolicyConfig,
}

/// Named retry-budget resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedRetryBudgetPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: RetryBudgetPolicyConfig,
}

/// Named timeout hierarchy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedTimeoutHierarchyPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: TimeoutHierarchyConfig,
}

/// Named circuit-breaker resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedCircuitBreakerPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: CircuitBreakerPolicyConfig,
}

/// Named overload response resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedOverloadResponsePolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: OverloadResponsePolicyConfig,
}

/// Named transform policy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedTransformPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: TransformPolicyConfig,
}

/// Named traffic mirroring policy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedTrafficMirrorPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: TrafficMirrorPolicyConfig,
}

/// Named fault injection policy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedFaultInjectionPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: FaultInjectionPolicyConfig,
}

/// Named JWT auth policy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedJwtAuthPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: JwtAuthPolicyConfig,
}

/// Named external auth policy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedExternalAuthPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: ExternalAuthPolicyConfig,
}

/// Named request authorization policy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedAuthorizationPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: AuthorizationPolicyConfig,
}

/// Named upstream identity policy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedUpstreamIdentityPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: UpstreamIdentityPolicyConfig,
}

/// Named request classification policy resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedRequestClassificationPolicyConfig {
    /// Stable policy name.
    pub name: String,
    /// Policy specification.
    pub spec: RequestClassificationPolicyConfig,
}

/// Named brownout feature placeholder for future standalone resource extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedBrownoutFeatureConfig {
    /// Stable feature name.
    pub name: String,
    /// Feature specification.
    pub spec: BrownoutFeatureConfig,
}

#[cfg(test)]
mod tests {
    use super::{
        HeaderMutationConfig, HostileEdgeHandshakeGuardConfig, HostileEdgeProtectionPolicyConfig,
        HostileEdgeSourceQuotaConfig, HttpCachePolicyConfig, NamedHostileEdgeProtectionPolicyConfig,
        NamedHttpCachePolicyConfig, NamedRetryBudgetPolicyConfig, NamedTrafficMirrorPolicyConfig,
        NamedTransformPolicyConfig, NamedAuthorizationPolicyConfig,
        NamedExternalAuthPolicyConfig, NamedJwtAuthPolicyConfig,
        NamedRequestClassificationPolicyConfig, NamedUpstreamIdentityPolicyConfig,
        PathRewriteTransformConfig, PolicyBindingConfig,
        PolicyResourcesConfig, RequestTransformConfig, ResponseTransformConfig,
        TrafficMirrorPolicyConfig, TransformPolicyConfig, FaultInjectionPolicyConfig,
        FaultInjectionDelayConfig, FaultInjectionAbortConfig, NamedFaultInjectionPolicyConfig,
    };
    use crate::{
        AuthorizationPolicyConfig, ExternalAuthPolicyConfig, JwtAuthPolicyConfig,
        RequestClassificationContextConfig, RequestClassificationPolicyConfig,
        RequestClassificationSignalWeightsConfig, RequestClassifierSensitivityConfig,
        RetryBudgetPolicyConfig,
        UpstreamIdentityPolicyConfig,
    };

    #[test]
    fn policy_resources_and_bindings_are_constructible() {
        let resources = PolicyResourcesConfig {
            retry_budgets: vec![NamedRetryBudgetPolicyConfig {
                name: String::from("standard"),
                spec: RetryBudgetPolicyConfig {
                    min_retry_tokens: 3,
                    retry_percent: 20,
                    window_ms: 10_000,
                },
            }],
            http_caches: vec![NamedHttpCachePolicyConfig {
                name: String::from("public-cache"),
                spec: HttpCachePolicyConfig::default(),
            }],
            hostile_edge_protections: vec![NamedHostileEdgeProtectionPolicyConfig {
                name: String::from("edge-default"),
                spec: HostileEdgeProtectionPolicyConfig {
                    source_quota: Some(HostileEdgeSourceQuotaConfig::default()),
                    handshake_guard: Some(HostileEdgeHandshakeGuardConfig::default()),
                },
            }],
            transforms: vec![NamedTransformPolicyConfig {
                name: String::from("api-transform"),
                spec: TransformPolicyConfig {
                    request: RequestTransformConfig {
                        path_rewrite: Some(PathRewriteTransformConfig::ReplacePrefix {
                            match_prefix: String::from("/api"),
                            replacement: String::from("/v1/api"),
                        }),
                        host_rewrite: Some(String::from("backend.internal")),
                        header_mutations: vec![HeaderMutationConfig::Set {
                            name: String::from("x-route"),
                            value: String::from("api"),
                        }],
                    },
                    response: ResponseTransformConfig {
                        header_mutations: vec![HeaderMutationConfig::Remove {
                            name: String::from("server"),
                        }],
                    },
                },
            }],
            traffic_mirrors: vec![NamedTrafficMirrorPolicyConfig {
                name: String::from("shadow-payments"),
                spec: TrafficMirrorPolicyConfig {
                    percentage: 20,
                    target_upstream_cluster: String::from("payments-shadow"),
                    methods: Vec::new(),
                },
            }],
            fault_injections: vec![NamedFaultInjectionPolicyConfig {
                name: String::from("canary-chaos"),
                spec: FaultInjectionPolicyConfig {
                    delay: Some(FaultInjectionDelayConfig {
                        percentage: 10,
                        fixed_delay_ms: 250,
                    }),
                    abort: Some(FaultInjectionAbortConfig {
                        percentage: 5,
                        http_status: 503,
                    }),
                },
            }],
            jwt_auth_policies: vec![NamedJwtAuthPolicyConfig {
                name: String::from("issuer-default"),
                spec: JwtAuthPolicyConfig::default(),
            }],
            external_auth_policies: vec![NamedExternalAuthPolicyConfig {
                name: String::from("authz-service"),
                spec: ExternalAuthPolicyConfig::default(),
            }],
            authorization_policies: vec![NamedAuthorizationPolicyConfig {
                name: String::from("rbac-default"),
                spec: AuthorizationPolicyConfig::default(),
            }],
            upstream_identity_policies: vec![NamedUpstreamIdentityPolicyConfig {
                name: String::from("spiffe-default"),
                spec: UpstreamIdentityPolicyConfig::default(),
            }],
            request_classification_policies: vec![NamedRequestClassificationPolicyConfig {
                name: String::from("waf-baseline"),
                spec: RequestClassificationPolicyConfig {
                    sensitivity: RequestClassifierSensitivityConfig::Medium,
                    challenge_threshold: 55,
                    block_threshold: 80,
                    signal_weights: RequestClassificationSignalWeightsConfig::default(),
                    context: RequestClassificationContextConfig::default(),
                    header_scoring: crate::HeaderAnomalyScoringConfig::default(),
                    body_scoring: crate::BodyInspectionScoringConfig::default(),
                },
            }],
            ..PolicyResourcesConfig::default()
        };
        let binding = PolicyBindingConfig {
            hostile_edge_protection: Some(String::from("edge-default")),
            retry_budget: Some(String::from("standard")),
            cache_policy: Some(String::from("public-cache")),
            transform_policy: Some(String::from("api-transform")),
            traffic_mirror: Some(String::from("shadow-payments")),
            fault_injection: Some(String::from("canary-chaos")),
            jwt_auth_policy: Some(String::from("issuer-default")),
            external_auth_policy: Some(String::from("authz-service")),
            authorization_policy: Some(String::from("rbac-default")),
            upstream_identity_policy: Some(String::from("spiffe-default")),
            request_classification_policy: Some(String::from("waf-baseline")),
            ..PolicyBindingConfig::default()
        };

        assert_eq!(resources.retry_budgets.len(), 1);
        assert_eq!(resources.http_caches.len(), 1);
        assert_eq!(resources.hostile_edge_protections.len(), 1);
        assert_eq!(resources.transforms.len(), 1);
        assert_eq!(resources.traffic_mirrors.len(), 1);
        assert_eq!(resources.fault_injections.len(), 1);
        assert_eq!(resources.jwt_auth_policies.len(), 1);
        assert_eq!(resources.external_auth_policies.len(), 1);
        assert_eq!(resources.authorization_policies.len(), 1);
        assert_eq!(resources.upstream_identity_policies.len(), 1);
        assert_eq!(resources.request_classification_policies.len(), 1);
        assert_eq!(binding.hostile_edge_protection.as_deref(), Some("edge-default"));
        assert_eq!(binding.retry_budget.as_deref(), Some("standard"));
        assert_eq!(binding.cache_policy.as_deref(), Some("public-cache"));
        assert_eq!(binding.transform_policy.as_deref(), Some("api-transform"));
        assert_eq!(binding.traffic_mirror.as_deref(), Some("shadow-payments"));
        assert_eq!(binding.fault_injection.as_deref(), Some("canary-chaos"));
        assert_eq!(binding.jwt_auth_policy.as_deref(), Some("issuer-default"));
        assert_eq!(binding.external_auth_policy.as_deref(), Some("authz-service"));
        assert_eq!(binding.authorization_policy.as_deref(), Some("rbac-default"));
        assert_eq!(binding.upstream_identity_policy.as_deref(), Some("spiffe-default"));
        assert_eq!(binding.request_classification_policy.as_deref(), Some("waf-baseline"));
    }
}
