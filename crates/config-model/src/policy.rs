use serde::{Deserialize, Serialize};

use crate::{
    BrownoutFeatureConfig, CircuitBreakerPolicyConfig, LocalConcurrencyLimitPolicyConfig,
    LocalRateLimitPolicyConfig, OverloadResponsePolicyConfig, RetryBudgetPolicyConfig,
    TimeoutHierarchyConfig,
};

/// Named policy resources referenced by listeners, routes, and upstreams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyResourcesConfig {
    /// Reusable local rate-limit policies.
    pub local_rate_limits: Vec<NamedLocalRateLimitPolicyConfig>,
    /// Reusable local concurrency-limit policies.
    pub local_concurrency_limits: Vec<NamedLocalConcurrencyLimitPolicyConfig>,
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
}

/// Reference set that attaches named policy resources to another resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyBindingConfig {
    /// Referenced local rate-limit policy names.
    pub local_rate_limits: Vec<String>,
    /// Referenced local concurrency-limit policy names.
    pub local_concurrency_limits: Vec<String>,
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
        HttpCachePolicyConfig, NamedHttpCachePolicyConfig, NamedRetryBudgetPolicyConfig,
        PolicyBindingConfig, PolicyResourcesConfig,
    };
    use crate::RetryBudgetPolicyConfig;

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
            ..PolicyResourcesConfig::default()
        };
        let binding = PolicyBindingConfig {
            retry_budget: Some(String::from("standard")),
            cache_policy: Some(String::from("public-cache")),
            ..PolicyBindingConfig::default()
        };

        assert_eq!(resources.retry_budgets.len(), 1);
        assert_eq!(resources.http_caches.len(), 1);
        assert_eq!(binding.retry_budget.as_deref(), Some("standard"));
        assert_eq!(binding.cache_policy.as_deref(), Some("public-cache"));
    }
}
