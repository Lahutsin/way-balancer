use crate::{
    OverloadState, RequestClassificationEnforcementAction, RequestClassificationEnforcementDecision,
    SheddingAction, SheddingDecision,
};

/// Policy controls for adapting abuse mitigation during overload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestClassificationAdaptiveMitigationPolicy {
    pub escalate_tag_to_challenge_when_shedding: bool,
    pub escalate_challenge_to_throttle_when_brownout: bool,
}

impl Default for RequestClassificationAdaptiveMitigationPolicy {
    fn default() -> Self {
        Self {
            escalate_tag_to_challenge_when_shedding: true,
            escalate_challenge_to_throttle_when_brownout: true,
        }
    }
}

/// Final adaptive mitigation decision coordinated with overload state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestClassificationAdaptiveMitigationDecision {
    pub action: RequestClassificationEnforcementAction,
    pub overload_state: OverloadState,
    pub shedding_action: SheddingAction,
    pub reasons: Vec<String>,
}

/// Coordinator for abuse mitigation and overload-aware adaptation.
#[derive(Debug, Clone)]
pub struct RequestClassificationAdaptiveMitigator {
    policy: RequestClassificationAdaptiveMitigationPolicy,
}

impl RequestClassificationAdaptiveMitigator {
    #[must_use]
    pub fn from_policy(policy: RequestClassificationAdaptiveMitigationPolicy) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn adapt(
        &self,
        enforcement: &RequestClassificationEnforcementDecision,
        shedding: &SheddingDecision,
    ) -> RequestClassificationAdaptiveMitigationDecision {
        let mut reasons = Vec::new();
        let mut action = enforcement.action;

        // Preserve trusted-principal exception paths to avoid overload-driven false positives.
        if enforcement
            .audit
            .reasons
            .iter()
            .any(|reason| reason.contains("trusted principal exception"))
        {
            reasons.push(String::from(
                "adaptive mitigation skipped because trusted principal exception is active",
            ));
            return RequestClassificationAdaptiveMitigationDecision {
                action,
                overload_state: shedding.state,
                shedding_action: shedding.action,
                reasons,
            };
        }

        if matches!(shedding.action, SheddingAction::Shed)
            && self.policy.escalate_tag_to_challenge_when_shedding
            && matches!(action, RequestClassificationEnforcementAction::Tag)
        {
            action = RequestClassificationEnforcementAction::Challenge;
            reasons.push(String::from(
                "overload shedding escalated tag action to challenge",
            ));
        }

        if matches!(shedding.state, OverloadState::Brownout)
            && matches!(shedding.action, SheddingAction::Shed)
            && self.policy.escalate_challenge_to_throttle_when_brownout
            && matches!(action, RequestClassificationEnforcementAction::Challenge)
        {
            action = RequestClassificationEnforcementAction::Throttle;
            reasons.push(String::from(
                "brownout shedding escalated challenge action to throttle",
            ));
        }

        if reasons.is_empty() {
            reasons.push(String::from("adaptive mitigation kept enforcement action unchanged"));
        }

        RequestClassificationAdaptiveMitigationDecision {
            action,
            overload_state: shedding.state,
            shedding_action: shedding.action,
            reasons,
        }
    }
}

impl Default for RequestClassificationAdaptiveMitigator {
    fn default() -> Self {
        Self::from_policy(RequestClassificationAdaptiveMitigationPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::RequestClassificationAdaptiveMitigator;
    use crate::{
        RequestClassificationAction, RequestClassificationAuditRecord,
        RequestClassificationAuthContext, RequestClassificationEnforcer,
        RequestClassificationEnforcementAction, RequestClassificationEnforcementPolicy,
        RequestClassificationResult, RequestClassifierSignalKind, SheddingAction,
        SheddingDecision, OverloadState,
    };

    fn enforcement_decision(action: RequestClassificationAction) -> crate::RequestClassificationEnforcementDecision {
        RequestClassificationEnforcer::default().evaluate(
            &RequestClassificationResult {
                anomaly_score: 60,
                action,
                signal_scores: BTreeMap::from([(RequestClassifierSignalKind::HeaderAnomaly, 60)]),
            },
            &RequestClassificationAuthContext::default(),
        )
    }

    #[test]
    fn adaptive_mitigation_escalates_tag_to_challenge_under_shedding() {
        let mitigator = RequestClassificationAdaptiveMitigator::default();
        let tag_enforcement = crate::RequestClassificationEnforcementDecision {
            action: RequestClassificationEnforcementAction::Tag,
            audit: RequestClassificationAuditRecord {
                anomaly_score: 45,
                classifier_action: RequestClassificationAction::Allow,
                enforcement_action: RequestClassificationEnforcementAction::Tag,
                signal_scores: BTreeMap::new(),
                principal: None,
                external_auth_fail_open_applied: false,
                reasons: vec![String::from("allow-path request tagged for abuse monitoring")],
            },
        };

        let adapted = mitigator.adapt(
            &tag_enforcement,
            &SheddingDecision {
                action: SheddingAction::Shed,
                state: OverloadState::Shedding,
                reason: None,
            },
        );

        assert_eq!(adapted.action, RequestClassificationEnforcementAction::Challenge);
    }

    #[test]
    fn adaptive_mitigation_escalates_challenge_to_throttle_in_brownout() {
        let mitigator = RequestClassificationAdaptiveMitigator::default();
        let enforcement = enforcement_decision(RequestClassificationAction::Challenge);

        let adapted = mitigator.adapt(
            &enforcement,
            &SheddingDecision {
                action: SheddingAction::Shed,
                state: OverloadState::Brownout,
                reason: None,
            },
        );

        assert_eq!(adapted.action, RequestClassificationEnforcementAction::Throttle);
    }

    #[test]
    fn adaptive_mitigation_preserves_trusted_principal_exception() {
        let policy = RequestClassificationEnforcementPolicy {
            trusted_principals: BTreeSet::from([String::from("svc-ops")]),
            ..RequestClassificationEnforcementPolicy::default()
        };
        let enforcement = RequestClassificationEnforcer::from_policy(policy).evaluate(
            &RequestClassificationResult {
                anomaly_score: 80,
                action: RequestClassificationAction::Challenge,
                signal_scores: BTreeMap::new(),
            },
            &RequestClassificationAuthContext {
                principal: Some(String::from("svc-ops")),
                ..RequestClassificationAuthContext::default()
            },
        );

        let adapted = RequestClassificationAdaptiveMitigator::default().adapt(
            &enforcement,
            &SheddingDecision {
                action: SheddingAction::Shed,
                state: OverloadState::Brownout,
                reason: None,
            },
        );

        assert_eq!(adapted.action, RequestClassificationEnforcementAction::Allow);
        assert!(adapted
            .reasons
            .iter()
            .any(|reason| reason.contains("trusted principal exception")));
    }
}
