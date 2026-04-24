use serde::{Deserialize, Serialize};

/// Sensitivity profile used by request anomaly classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RequestClassifierSensitivityConfig {
    Low,
    #[default]
    Medium,
    High,
}

/// Signal-weight controls for request anomaly scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestClassificationSignalWeightsConfig {
    /// Header anomaly signal weight.
    pub header_anomaly: u8,
    /// Body anomaly signal weight.
    pub body_anomaly: u8,
    /// Query anomaly signal weight.
    pub query_anomaly: u8,
    /// User-agent anomaly signal weight.
    pub user_agent_anomaly: u8,
    /// Reputation signal weight.
    pub reputation: u8,
    /// Bot signal weight.
    pub bot_signal: u8,
}

impl Default for RequestClassificationSignalWeightsConfig {
    fn default() -> Self {
        Self {
            header_anomaly: 25,
            body_anomaly: 20,
            query_anomaly: 20,
            user_agent_anomaly: 15,
            reputation: 20,
            bot_signal: 20,
        }
    }
}

/// Context features forwarded to classifier adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestClassificationContextConfig {
    /// Include normalized request method in classifier context.
    pub include_method: bool,
    /// Include normalized request path in classifier context.
    pub include_path: bool,
    /// Include source IP in classifier context.
    pub include_source_ip: bool,
    /// Include user-agent in classifier context.
    pub include_user_agent: bool,
    /// Explicit header names included in classifier context.
    pub include_headers: Vec<String>,
    /// Explicit query parameter names included in classifier context.
    pub include_query_params: Vec<String>,
}

impl Default for RequestClassificationContextConfig {
    fn default() -> Self {
        Self {
            include_method: true,
            include_path: true,
            include_source_ip: true,
            include_user_agent: true,
            include_headers: vec![String::from("user-agent"), String::from("x-forwarded-for")],
            include_query_params: Vec::new(),
        }
    }
}

/// Header anomaly scoring controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeaderAnomalyScoringConfig {
    /// Maximum allowed request header count before anomaly signal.
    pub max_header_count: u16,
    /// Maximum allowed header value length before anomaly signal.
    pub max_header_value_length: u16,
    /// Maximum duplicate occurrences per normalized header name.
    pub max_duplicate_headers_per_name: u8,
    /// Header names treated as suspicious when present.
    pub suspicious_headers: Vec<String>,
    /// Case-insensitive user-agent patterns treated as suspicious.
    pub suspicious_user_agent_patterns: Vec<String>,
}

impl Default for HeaderAnomalyScoringConfig {
    fn default() -> Self {
        Self {
            max_header_count: 64,
            max_header_value_length: 2048,
            max_duplicate_headers_per_name: 4,
            suspicious_headers: vec![String::from("x-original-url"), String::from("x-rewrite-url")],
            suspicious_user_agent_patterns: vec![
                String::from("sqlmap"),
                String::from("nikto"),
                String::from("nmap"),
            ],
        }
    }
}

/// Bounded body inspection controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BodyInspectionScoringConfig {
    /// Maximum number of bytes considered by the scorer.
    pub max_inspect_bytes: u32,
    /// Absolute body-size limit before anomaly signal.
    pub max_body_bytes: u32,
    /// Minimum suspicious token length.
    pub min_suspicious_token_length: u8,
    /// Case-insensitive patterns treated as suspicious.
    pub suspicious_patterns: Vec<String>,
    /// Content-type prefixes that skip pattern inspection.
    pub allowlisted_content_types: Vec<String>,
}

impl Default for BodyInspectionScoringConfig {
    fn default() -> Self {
        Self {
            max_inspect_bytes: 8 * 1024,
            max_body_bytes: 128 * 1024,
            min_suspicious_token_length: 6,
            suspicious_patterns: vec![
                String::from("union select"),
                String::from("<script"),
                String::from("../"),
            ],
            allowlisted_content_types: vec![
                String::from("application/grpc"),
                String::from("application/octet-stream"),
            ],
        }
    }
}

/// Declarative request classification policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestClassificationPolicyConfig {
    /// Sensitivity profile used by default scorers.
    pub sensitivity: RequestClassifierSensitivityConfig,
    /// Threshold (0-100) for challenge-oriented action suggestions.
    pub challenge_threshold: u8,
    /// Threshold (0-100) for block-oriented action suggestions.
    pub block_threshold: u8,
    /// Weighted scoring surface for normalized anomaly signals.
    pub signal_weights: RequestClassificationSignalWeightsConfig,
    /// Context projection settings for classifier inputs.
    pub context: RequestClassificationContextConfig,
    /// Header anomaly scoring controls.
    pub header_scoring: HeaderAnomalyScoringConfig,
    /// Bounded request-body inspection controls.
    pub body_scoring: BodyInspectionScoringConfig,
}

impl Default for RequestClassificationPolicyConfig {
    fn default() -> Self {
        Self {
            sensitivity: RequestClassifierSensitivityConfig::Medium,
            challenge_threshold: 55,
            block_threshold: 80,
            signal_weights: RequestClassificationSignalWeightsConfig::default(),
            context: RequestClassificationContextConfig::default(),
            header_scoring: HeaderAnomalyScoringConfig::default(),
            body_scoring: BodyInspectionScoringConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BodyInspectionScoringConfig, HeaderAnomalyScoringConfig,
        RequestClassificationContextConfig,
        RequestClassificationPolicyConfig,
        RequestClassificationSignalWeightsConfig, RequestClassifierSensitivityConfig,
    };

    #[test]
    fn request_classification_policy_defaults_are_constructible() {
        let policy = RequestClassificationPolicyConfig::default();
        assert_eq!(policy.sensitivity, RequestClassifierSensitivityConfig::Medium);
        assert_eq!(policy.challenge_threshold, 55);
        assert_eq!(policy.block_threshold, 80);
        assert!(policy.context.include_method);
        assert!(policy.context.include_path);
        assert!(policy.context.include_source_ip);
        assert!(policy.header_scoring.max_header_count > 0);
        assert!(policy.body_scoring.max_body_bytes > 0);
    }

    #[test]
    fn request_classification_models_are_constructible() {
        let policy = RequestClassificationPolicyConfig {
            sensitivity: RequestClassifierSensitivityConfig::High,
            challenge_threshold: 40,
            block_threshold: 70,
            signal_weights: RequestClassificationSignalWeightsConfig {
                header_anomaly: 30,
                body_anomaly: 15,
                query_anomaly: 20,
                user_agent_anomaly: 10,
                reputation: 20,
                bot_signal: 20,
            },
            context: RequestClassificationContextConfig {
                include_method: true,
                include_path: true,
                include_source_ip: false,
                include_user_agent: true,
                include_headers: vec![String::from("user-agent"), String::from("x-request-id")],
                include_query_params: vec![String::from("debug")],
            },
            header_scoring: HeaderAnomalyScoringConfig {
                max_header_count: 40,
                max_header_value_length: 512,
                max_duplicate_headers_per_name: 2,
                suspicious_headers: vec![String::from("x-forwarded-host")],
                suspicious_user_agent_patterns: vec![String::from("scanner")],
            },
            body_scoring: BodyInspectionScoringConfig {
                max_inspect_bytes: 4096,
                max_body_bytes: 65536,
                min_suspicious_token_length: 8,
                suspicious_patterns: vec![String::from("drop table")],
                allowlisted_content_types: vec![String::from("application/octet-stream")],
            },
        };

        assert_eq!(policy.block_threshold, 70);
        assert_eq!(policy.signal_weights.header_anomaly, 30);
        assert_eq!(policy.context.include_query_params.len(), 1);
    }
}
