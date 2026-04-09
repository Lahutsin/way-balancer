use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryBudgetPolicyConfig {
    pub min_retry_tokens: u32,
    pub retry_percent: u8,
    pub window_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutHierarchyConfig {
    pub request_timeout_ms: u64,
    pub attempt_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub idle_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerPolicyConfig {
    pub open_failure_threshold: u32,
    pub open_duration_ms: u64,
    pub half_open_success_threshold: u32,
}

#[cfg(test)]
mod tests {
    use super::{CircuitBreakerPolicyConfig, RetryBudgetPolicyConfig, TimeoutHierarchyConfig};

    #[test]
    fn failure_policy_types_are_constructible() {
        let retry =
            RetryBudgetPolicyConfig { min_retry_tokens: 3, retry_percent: 20, window_ms: 10_000 };
        let timeout = TimeoutHierarchyConfig {
            request_timeout_ms: 30_000,
            attempt_timeout_ms: 10_000,
            connect_timeout_ms: 1_000,
            idle_timeout_ms: 5_000,
        };
        let breaker = CircuitBreakerPolicyConfig {
            open_failure_threshold: 5,
            open_duration_ms: 30_000,
            half_open_success_threshold: 2,
        };

        assert_eq!(retry.retry_percent, 20);
        assert_eq!(timeout.connect_timeout_ms, 1_000);
        assert_eq!(breaker.open_failure_threshold, 5);
    }
}
