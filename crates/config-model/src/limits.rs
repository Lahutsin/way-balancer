use serde::{Deserialize, Serialize};

/// Declarative scope for local limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalLimitScopeConfig {
    /// Listener-level limit.
    Listener { name: String },
    /// Route-level limit.
    Route { name: String },
    /// Upstream-level limit.
    UpstreamCluster { name: String },
}

/// Declarative sharding key for local limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalLimitKeyKindConfig {
    /// Single shared bucket for the scope.
    #[default]
    Global,
    /// Per-source-ip keying.
    SourceIp,
    /// Per-route-name keying.
    RouteName,
    /// Per-upstream-cluster keying.
    UpstreamCluster,
}

/// Declarative local rate-limit config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRateLimitPolicyConfig {
    /// Limit scope.
    pub scope: LocalLimitScopeConfig,
    /// Keying model.
    pub key_kind: LocalLimitKeyKindConfig,
    /// Maximum requests per fixed window.
    pub requests_per_window: u64,
    /// Window duration in milliseconds.
    pub window_ms: u64,
    /// Maximum tracked normalized keys.
    pub max_tracked_keys: usize,
}

/// Declarative local concurrency-limit config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConcurrencyLimitPolicyConfig {
    /// Limit scope.
    pub scope: LocalLimitScopeConfig,
    /// Keying model.
    pub key_kind: LocalLimitKeyKindConfig,
    /// Maximum concurrent in-flight operations.
    pub max_concurrent: usize,
    /// Maximum tracked normalized keys.
    pub max_tracked_keys: usize,
}

#[cfg(test)]
mod tests {
    use super::{
        LocalConcurrencyLimitPolicyConfig, LocalLimitKeyKindConfig, LocalLimitScopeConfig,
        LocalRateLimitPolicyConfig,
    };

    #[test]
    fn declarative_limit_types_are_constructible() {
        let rate = LocalRateLimitPolicyConfig {
            scope: LocalLimitScopeConfig::Listener { name: String::from("public") },
            key_kind: LocalLimitKeyKindConfig::SourceIp,
            requests_per_window: 100,
            window_ms: 1_000,
            max_tracked_keys: 1024,
        };
        let concurrency = LocalConcurrencyLimitPolicyConfig {
            scope: LocalLimitScopeConfig::UpstreamCluster { name: String::from("payments") },
            key_kind: LocalLimitKeyKindConfig::Global,
            max_concurrent: 64,
            max_tracked_keys: 8,
        };

        assert_eq!(rate.requests_per_window, 100);
        assert_eq!(concurrency.max_concurrent, 64);
    }
}
