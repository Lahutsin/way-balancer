use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficClassConfig {
    Critical,
    Default,
    BestEffort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrownoutFeatureConfig {
    pub name: String,
    pub priority: TrafficClassConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverloadResponsePolicyConfig {
    pub signal_window_ms: u64,
    pub constrained_signal_threshold: u64,
    pub shedding_signal_threshold: u64,
    pub brownout_signal_threshold: u64,
    pub brownout_features: Vec<BrownoutFeatureConfig>,
}

#[cfg(test)]
mod tests {
    use super::{BrownoutFeatureConfig, OverloadResponsePolicyConfig, TrafficClassConfig};

    #[test]
    fn overload_response_policy_is_constructible() {
        let policy = OverloadResponsePolicyConfig {
            signal_window_ms: 10_000,
            constrained_signal_threshold: 3,
            shedding_signal_threshold: 6,
            brownout_signal_threshold: 9,
            brownout_features: vec![BrownoutFeatureConfig {
                name: String::from("expensive_search"),
                priority: TrafficClassConfig::BestEffort,
            }],
        };

        assert_eq!(policy.brownout_features.len(), 1);
        assert_eq!(policy.shedding_signal_threshold, 6);
    }
}
