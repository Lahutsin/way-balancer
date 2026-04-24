use std::collections::BTreeMap;

use crate::{
    BotSignalAdapterChain, BotSignalInput, HeaderAnomalyScorer, ReputationAdapterChain,
    ReputationSignalInput, RequestBodyInspector, RequestClassificationAdaptiveMitigationDecision,
    RequestClassificationAdaptiveMitigator, RequestClassificationAdaptiveMitigationPolicy,
    RequestClassificationAuthContext,
    RequestClassificationEnforcementDecision, RequestClassificationEnforcementPolicy,
    RequestClassificationEnforcer, SheddingDecision,
};

/// Request context forwarded to pluggable classifier adapters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestClassificationAdapterContext {
    pub source_ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Classifier signal categories contributing to request anomaly score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestClassifierSignalKind {
    HeaderAnomaly,
    BodyAnomaly,
    QueryAnomaly,
    UserAgentAnomaly,
    Reputation,
    BotSignal,
}

/// One normalized classifier signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestClassifierSignal {
    pub kind: RequestClassifierSignalKind,
    /// Signal strength in range 0..=100.
    pub strength: u8,
    pub detail: String,
}

/// Candidate action suggested by aggregated anomaly score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClassificationAction {
    Allow,
    Challenge,
    Block,
}

/// Deterministic request-classification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestClassificationResult {
    pub anomaly_score: u8,
    pub action: RequestClassificationAction,
    pub signal_scores: BTreeMap<RequestClassifierSignalKind, u8>,
}

/// Runtime request classification evaluator.
#[derive(Debug, Clone)]
pub struct RequestClassificationPolicyRuntime {
    challenge_threshold: u8,
    block_threshold: u8,
    weights: lb_config_model::RequestClassificationSignalWeightsConfig,
    header_anomaly_scorer: HeaderAnomalyScorer,
    body_inspector: RequestBodyInspector,
    reputation_adapter: ReputationAdapterChain,
    bot_signal_adapter: BotSignalAdapterChain,
}

impl RequestClassificationPolicyRuntime {
    #[must_use]
    pub fn from_config(config: &lb_config_model::RequestClassificationPolicyConfig) -> Self {
        Self {
            challenge_threshold: config.challenge_threshold,
            block_threshold: config.block_threshold,
            weights: config.signal_weights.clone(),
            header_anomaly_scorer: HeaderAnomalyScorer::from_config(&config.header_scoring),
            body_inspector: RequestBodyInspector::from_config(&config.body_scoring),
            reputation_adapter: ReputationAdapterChain::new(),
            bot_signal_adapter: BotSignalAdapterChain::new(),
        }
    }

    #[must_use]
    pub fn with_reputation_adapter(mut self, adapter: ReputationAdapterChain) -> Self {
        self.reputation_adapter = adapter;
        self
    }

    #[must_use]
    pub fn with_bot_signal_adapter(mut self, adapter: BotSignalAdapterChain) -> Self {
        self.bot_signal_adapter = adapter;
        self
    }

    #[must_use]
    pub fn classify_headers<I, N, V>(&self, headers: I) -> RequestClassificationResult
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let signals = self.header_anomaly_scorer.score_headers(headers);
        self.classify(&signals)
    }

    #[must_use]
    pub fn classify_with_adapters(
        &self,
        context: &RequestClassificationAdapterContext,
    ) -> RequestClassificationResult {
        self.classify_with_adapters_and_body(context, &[])
    }

    #[must_use]
    pub fn classify_with_adapters_and_body(
        &self,
        context: &RequestClassificationAdapterContext,
        body: &[u8],
    ) -> RequestClassificationResult {
        let mut signals = self.header_anomaly_scorer.score_headers(
            context
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );

        signals.extend(
            self.body_inspector
                .score_body(body, context.content_type.as_deref()),
        );

        signals.extend(self.reputation_adapter.score(&ReputationSignalInput {
            source_ip: context.source_ip.clone(),
            method: context.method.clone(),
            path: context.path.clone(),
            user_agent: context.user_agent.clone(),
        }));

        signals.extend(self.bot_signal_adapter.score(&BotSignalInput {
            source_ip: context.source_ip.clone(),
            method: context.method.clone(),
            path: context.path.clone(),
            user_agent: context.user_agent.clone(),
            header_count: context.headers.len() as u16,
        }));

        self.classify(&signals)
    }

    #[must_use]
    pub fn classify_and_enforce_with_adapters(
        &self,
        context: &RequestClassificationAdapterContext,
        auth_context: &RequestClassificationAuthContext,
        enforcement_policy: &RequestClassificationEnforcementPolicy,
    ) -> RequestClassificationEnforcementDecision {
        let classification = self.classify_with_adapters_and_body(context, &[]);
        RequestClassificationEnforcer::from_policy(enforcement_policy.clone())
            .evaluate(&classification, auth_context)
    }

    #[must_use]
    pub fn classify_enforce_and_adapt_with_overload(
        &self,
        context: &RequestClassificationAdapterContext,
        body: &[u8],
        auth_context: &RequestClassificationAuthContext,
        enforcement_policy: &RequestClassificationEnforcementPolicy,
        adaptive_policy: &RequestClassificationAdaptiveMitigationPolicy,
        shedding_decision: &SheddingDecision,
    ) -> RequestClassificationAdaptiveMitigationDecision {
        let classification = self.classify_with_adapters_and_body(context, body);
        let enforcement = RequestClassificationEnforcer::from_policy(enforcement_policy.clone())
            .evaluate(&classification, auth_context);
        RequestClassificationAdaptiveMitigator::from_policy(adaptive_policy.clone())
            .adapt(&enforcement, shedding_decision)
    }

    #[must_use]
    pub fn classify(&self, signals: &[RequestClassifierSignal]) -> RequestClassificationResult {
        let mut weighted: BTreeMap<RequestClassifierSignalKind, u8> = BTreeMap::new();
        for signal in signals {
            let weight = self.weight_for(signal.kind);
            let score = ((weight as u16) * (signal.strength as u16) / 100) as u8;
            let current = weighted.entry(signal.kind).or_insert(0u8);
            *current = (*current).saturating_add(score);
        }

        let anomaly_score = weighted
            .values()
            .fold(0u16, |acc, score| acc.saturating_add(*score as u16))
            .min(100) as u8;
        let action = if anomaly_score >= self.block_threshold {
            RequestClassificationAction::Block
        } else if anomaly_score >= self.challenge_threshold {
            RequestClassificationAction::Challenge
        } else {
            RequestClassificationAction::Allow
        };

        RequestClassificationResult {
            anomaly_score,
            action,
            signal_scores: weighted,
        }
    }

    fn weight_for(&self, kind: RequestClassifierSignalKind) -> u8 {
        match kind {
            RequestClassifierSignalKind::HeaderAnomaly => self.weights.header_anomaly,
            RequestClassifierSignalKind::BodyAnomaly => self.weights.body_anomaly,
            RequestClassifierSignalKind::QueryAnomaly => self.weights.query_anomaly,
            RequestClassifierSignalKind::UserAgentAnomaly => self.weights.user_agent_anomaly,
            RequestClassifierSignalKind::Reputation => self.weights.reputation,
            RequestClassifierSignalKind::BotSignal => self.weights.bot_signal,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        RequestClassificationAction, RequestClassificationAdapterContext,
        RequestClassificationPolicyRuntime,
        RequestClassifierSignal, RequestClassifierSignalKind,
    };
    use crate::{
        BotSignalAdapterChain, BotSignalInput, BotSignalProvider, BotSignalVerdict,
        OverloadState, RequestClassificationAdaptiveMitigationPolicy,
        RequestClassificationAuthContext,
        RequestClassificationEnforcementAction, RequestClassificationEnforcementPolicy,
        ReputationAdapterChain, ReputationSignalInput, ReputationSignalProvider, ReputationVerdict,
        SheddingAction, SheddingDecision,
    };

    struct StaticReputationProvider {
        verdict: ReputationVerdict,
    }

    impl ReputationSignalProvider for StaticReputationProvider {
        fn provider_name(&self) -> &str {
            "reputation-test"
        }

        fn evaluate(&self, _input: &ReputationSignalInput) -> Result<ReputationVerdict, String> {
            Ok(self.verdict)
        }
    }

    struct StaticBotProvider {
        verdict: BotSignalVerdict,
    }

    impl BotSignalProvider for StaticBotProvider {
        fn provider_name(&self) -> &str {
            "bot-test"
        }

        fn evaluate(&self, _input: &BotSignalInput) -> Result<BotSignalVerdict, String> {
            Ok(self.verdict)
        }
    }

    struct FailingReputationProvider;

    impl ReputationSignalProvider for FailingReputationProvider {
        fn provider_name(&self) -> &str {
            "reputation-failing"
        }

        fn evaluate(&self, _input: &ReputationSignalInput) -> Result<ReputationVerdict, String> {
            Err(String::from("provider error"))
        }
    }

    struct FailingBotProvider;

    impl BotSignalProvider for FailingBotProvider {
        fn provider_name(&self) -> &str {
            "bot-failing"
        }

        fn evaluate(&self, _input: &BotSignalInput) -> Result<BotSignalVerdict, String> {
            Err(String::from("provider timeout"))
        }
    }

    fn baseline_policy() -> lb_config_model::RequestClassificationPolicyConfig {
        lb_config_model::RequestClassificationPolicyConfig {
            challenge_threshold: 50,
            block_threshold: 75,
            signal_weights: lb_config_model::RequestClassificationSignalWeightsConfig {
                header_anomaly: 40,
                body_anomaly: 10,
                query_anomaly: 20,
                user_agent_anomaly: 10,
                reputation: 20,
                bot_signal: 10,
            },
            ..lb_config_model::RequestClassificationPolicyConfig::default()
        }
    }

    #[test]
    fn request_classification_normalizes_signal_scores() {
        let runtime = RequestClassificationPolicyRuntime::from_config(&baseline_policy());
        let result = runtime.classify(&[
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::HeaderAnomaly,
                strength: 80,
                detail: String::from("suspicious header pattern"),
            },
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::QueryAnomaly,
                strength: 25,
                detail: String::from("high-entropy query token"),
            },
        ]);

        assert_eq!(result.signal_scores.get(&RequestClassifierSignalKind::HeaderAnomaly), Some(&32));
        assert_eq!(result.signal_scores.get(&RequestClassifierSignalKind::QueryAnomaly), Some(&5));
        assert_eq!(result.anomaly_score, 37);
        assert_eq!(result.action, RequestClassificationAction::Allow);
    }

    #[test]
    fn request_classification_default_policy_thresholds_suggest_actions() {
        let runtime = RequestClassificationPolicyRuntime::from_config(
            &lb_config_model::RequestClassificationPolicyConfig::default(),
        );

        let allow = runtime.classify(&[RequestClassifierSignal {
            kind: RequestClassifierSignalKind::UserAgentAnomaly,
            strength: 10,
            detail: String::from("minor user-agent deviation"),
        }]);
        assert_eq!(allow.action, RequestClassificationAction::Allow);

        let challenge = runtime.classify(&[
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::HeaderAnomaly,
                strength: 100,
                detail: String::from("header spoofing pattern"),
            },
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::QueryAnomaly,
                strength: 100,
                detail: String::from("query token spray"),
            },
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::BotSignal,
                strength: 100,
                detail: String::from("bot score high"),
            },
        ]);
        assert_eq!(challenge.action, RequestClassificationAction::Challenge);

        let block = runtime.classify(&[
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::HeaderAnomaly,
                strength: 100,
                detail: String::from("header spoofing pattern"),
            },
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::QueryAnomaly,
                strength: 100,
                detail: String::from("query token spray"),
            },
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::Reputation,
                strength: 100,
                detail: String::from("malicious reputation feed"),
            },
            RequestClassifierSignal {
                kind: RequestClassifierSignalKind::BotSignal,
                strength: 100,
                detail: String::from("bot score critical"),
            },
        ]);
        assert_eq!(block.action, RequestClassificationAction::Block);
    }

    #[test]
    fn request_classification_scores_headers_through_header_anomaly_scorer() {
        let runtime = RequestClassificationPolicyRuntime::from_config(&baseline_policy());
        let result = runtime.classify_headers([
            ("user-agent", "sqlmap"),
            ("x-original-url", "/admin"),
            ("x-extra", "abcd"),
            ("x-extra", "efgh"),
            ("x-extra", "ijkl"),
        ]);

        assert!(result.anomaly_score > 0);
        assert_ne!(result.action, RequestClassificationAction::Allow);
    }

    #[test]
    fn request_classification_ingests_reputation_and_bot_adapter_signals() {
        let mut policy = baseline_policy();
        policy.signal_weights.reputation = 60;
        policy.signal_weights.bot_signal = 40;
        policy.signal_weights.header_anomaly = 0;
        policy.signal_weights.query_anomaly = 0;
        policy.signal_weights.user_agent_anomaly = 0;

        let runtime = RequestClassificationPolicyRuntime::from_config(&policy)
            .with_reputation_adapter(
                ReputationAdapterChain::new().with_provider(Arc::new(StaticReputationProvider {
                    verdict: ReputationVerdict::Malicious,
                })),
            )
            .with_bot_signal_adapter(
                BotSignalAdapterChain::new().with_provider(Arc::new(StaticBotProvider {
                    verdict: BotSignalVerdict::AutomationConfirmed,
                })),
            );

        let result = runtime.classify_with_adapters(&RequestClassificationAdapterContext {
            source_ip: Some(String::from("198.51.100.12")),
            method: Some(String::from("GET")),
            path: Some(String::from("/login")),
            user_agent: Some(String::from("Mozilla/5.0")),
            content_type: None,
            headers: vec![(String::from("accept"), String::from("application/json"))],
        });

        assert_eq!(result.action, RequestClassificationAction::Block);
        assert!(result
            .signal_scores
            .contains_key(&RequestClassifierSignalKind::Reputation));
        assert!(result
            .signal_scores
            .contains_key(&RequestClassifierSignalKind::BotSignal));
    }

    #[test]
    fn request_classification_adapter_fallbacks_are_applied() {
        let runtime = RequestClassificationPolicyRuntime::from_config(&baseline_policy())
            .with_reputation_adapter(
                ReputationAdapterChain::new()
                    .with_provider(Arc::new(FailingReputationProvider))
                    .with_fallback_strength(80),
            )
            .with_bot_signal_adapter(
                BotSignalAdapterChain::new()
                    .with_provider(Arc::new(FailingBotProvider))
                    .with_fallback_strength(60),
            );

        let result = runtime.classify_with_adapters(&RequestClassificationAdapterContext {
            source_ip: Some(String::from("198.51.100.12")),
            method: Some(String::from("POST")),
            path: Some(String::from("/checkout")),
            user_agent: Some(String::from("Mozilla/5.0")),
            content_type: None,
            headers: vec![(String::from("accept"), String::from("application/json"))],
        });

        assert!(result.anomaly_score > 0);
        assert!(result
            .signal_scores
            .contains_key(&RequestClassifierSignalKind::Reputation));
        assert!(result
            .signal_scores
            .contains_key(&RequestClassifierSignalKind::BotSignal));
    }

    #[test]
    fn request_classification_can_map_adapter_output_to_enforcement_decision() {
        let mut policy = baseline_policy();
        policy.signal_weights.reputation = 80;
        policy.signal_weights.bot_signal = 20;
        policy.signal_weights.header_anomaly = 0;
        policy.signal_weights.query_anomaly = 0;
        policy.signal_weights.user_agent_anomaly = 0;

        let runtime = RequestClassificationPolicyRuntime::from_config(&policy)
            .with_reputation_adapter(
                ReputationAdapterChain::new().with_provider(Arc::new(StaticReputationProvider {
                    verdict: ReputationVerdict::Malicious,
                })),
            );

        let context = RequestClassificationAdapterContext {
            source_ip: Some(String::from("198.51.100.10")),
            method: Some(String::from("POST")),
            path: Some(String::from("/transfer")),
            user_agent: Some(String::from("Mozilla/5.0")),
            content_type: None,
            headers: vec![(String::from("accept"), String::from("application/json"))],
        };
        let auth = RequestClassificationAuthContext {
            context_headers: std::collections::BTreeMap::from([(
                String::from("x-way-balancer-abuse-disposition"),
                String::from("block"),
            )]),
            ..RequestClassificationAuthContext::default()
        };
        let decision = runtime.classify_and_enforce_with_adapters(
            &context,
            &auth,
            &RequestClassificationEnforcementPolicy::default(),
        );

        assert_eq!(decision.action, RequestClassificationEnforcementAction::Block);
    }

    #[test]
    fn request_classification_can_score_body_signals() {
        let mut policy = baseline_policy();
        policy.signal_weights.header_anomaly = 0;
        policy.signal_weights.body_anomaly = 100;
        policy.signal_weights.query_anomaly = 0;
        policy.signal_weights.user_agent_anomaly = 0;
        policy.signal_weights.reputation = 0;
        policy.signal_weights.bot_signal = 0;
        policy.challenge_threshold = 20;

        let runtime = RequestClassificationPolicyRuntime::from_config(&policy);
        let context = RequestClassificationAdapterContext {
            source_ip: None,
            method: Some(String::from("POST")),
            path: Some(String::from("/upload")),
            user_agent: None,
            content_type: Some(String::from("application/json")),
            headers: Vec::new(),
        };

        let result = runtime.classify_with_adapters_and_body(&context, b"{\"q\":\"union select 1\"}");
        assert_eq!(result.action, RequestClassificationAction::Challenge);
        assert!(result
            .signal_scores
            .contains_key(&RequestClassifierSignalKind::BodyAnomaly));
    }

    #[test]
    fn request_classification_adaptive_mitigation_escalates_under_overload() {
        let mut policy = baseline_policy();
        policy.signal_weights.header_anomaly = 0;
        policy.signal_weights.body_anomaly = 100;
        policy.signal_weights.query_anomaly = 0;
        policy.signal_weights.user_agent_anomaly = 0;
        policy.signal_weights.reputation = 0;
        policy.signal_weights.bot_signal = 0;
        policy.challenge_threshold = 20;
        policy.block_threshold = 95;

        let runtime = RequestClassificationPolicyRuntime::from_config(&policy);
        let context = RequestClassificationAdapterContext {
            source_ip: Some(String::from("198.51.100.24")),
            method: Some(String::from("POST")),
            path: Some(String::from("/auth")),
            user_agent: Some(String::from("Mozilla/5.0")),
            content_type: Some(String::from("application/json")),
            headers: vec![(String::from("x-request-id"), String::from("abc-1"))],
        };

        let adapted = runtime.classify_enforce_and_adapt_with_overload(
            &context,
            b"{\"payload\":\"union select 1\"}",
            &RequestClassificationAuthContext::default(),
            &RequestClassificationEnforcementPolicy::default(),
            &RequestClassificationAdaptiveMitigationPolicy::default(),
            &SheddingDecision {
                action: SheddingAction::Shed,
                state: OverloadState::Brownout,
                reason: None,
            },
        );

        assert_eq!(adapted.action, RequestClassificationEnforcementAction::Throttle);
    }
}
