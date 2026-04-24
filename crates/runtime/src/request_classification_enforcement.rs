use std::collections::{BTreeMap, BTreeSet};

use crate::{RequestClassificationAction, RequestClassificationResult, RequestClassifierSignalKind};

/// Auth-context snapshot used for abuse enforcement mapping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestClassificationAuthContext {
    pub principal: Option<String>,
    pub context_headers: BTreeMap<String, String>,
    pub external_auth_fail_open_applied: bool,
}

/// Enforced action derived from classifier output and auth context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClassificationEnforcementAction {
    Allow,
    Tag,
    Challenge,
    Throttle,
    Block,
}

/// One explainable enforcement audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestClassificationAuditRecord {
    pub anomaly_score: u8,
    pub classifier_action: RequestClassificationAction,
    pub enforcement_action: RequestClassificationEnforcementAction,
    pub signal_scores: BTreeMap<RequestClassifierSignalKind, u8>,
    pub principal: Option<String>,
    pub external_auth_fail_open_applied: bool,
    pub reasons: Vec<String>,
}

/// Final enforcement decision with audit output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestClassificationEnforcementDecision {
    pub action: RequestClassificationEnforcementAction,
    pub audit: RequestClassificationAuditRecord,
}

/// Policy controls for classifier-to-enforcement mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestClassificationEnforcementPolicy {
    pub tag_min_anomaly_score: u8,
    pub trusted_principals: BTreeSet<String>,
}

impl Default for RequestClassificationEnforcementPolicy {
    fn default() -> Self {
        Self {
            tag_min_anomaly_score: 35,
            trusted_principals: BTreeSet::new(),
        }
    }
}

/// Runtime mapper from classifier result to concrete abuse enforcement action.
#[derive(Debug, Clone)]
pub struct RequestClassificationEnforcer {
    policy: RequestClassificationEnforcementPolicy,
}

impl RequestClassificationEnforcer {
    #[must_use]
    pub fn from_policy(policy: RequestClassificationEnforcementPolicy) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn evaluate(
        &self,
        classification: &RequestClassificationResult,
        auth_context: &RequestClassificationAuthContext,
    ) -> RequestClassificationEnforcementDecision {
        let mut reasons = Vec::new();

        if matches!(classification.action, RequestClassificationAction::Block)
            || matches!(
                auth_context
                    .context_headers
                    .get("x-way-balancer-abuse-disposition")
                    .map(String::as_str),
                Some("block")
            )
        {
            if matches!(classification.action, RequestClassificationAction::Block) {
                reasons.push(String::from("classifier suggested block"));
            }
            if matches!(
                auth_context
                    .context_headers
                    .get("x-way-balancer-abuse-disposition")
                    .map(String::as_str),
                Some("block")
            ) {
                reasons.push(String::from("auth context requested block disposition"));
            }
            return self.decision(
                RequestClassificationEnforcementAction::Block,
                classification,
                auth_context,
                reasons,
            );
        }

        if auth_context.principal.as_ref().is_some_and(|principal| {
            self.policy.trusted_principals.contains(principal)
        }) {
            reasons.push(String::from("trusted principal exception applied"));
            return self.decision(
                RequestClassificationEnforcementAction::Allow,
                classification,
                auth_context,
                reasons,
            );
        }

        if matches!(classification.action, RequestClassificationAction::Challenge)
            && auth_context.external_auth_fail_open_applied
        {
            reasons.push(String::from(
                "classifier suggested challenge with external auth fail-open; enforcing throttle",
            ));
            return self.decision(
                RequestClassificationEnforcementAction::Throttle,
                classification,
                auth_context,
                reasons,
            );
        }

        if matches!(classification.action, RequestClassificationAction::Challenge) {
            reasons.push(String::from("classifier suggested challenge"));
            return self.decision(
                RequestClassificationEnforcementAction::Challenge,
                classification,
                auth_context,
                reasons,
            );
        }

        if classification.anomaly_score >= self.policy.tag_min_anomaly_score
            || matches!(
                auth_context
                    .context_headers
                    .get("x-way-balancer-risk-tier")
                    .map(String::as_str),
                Some("elevated") | Some("high")
            )
        {
            reasons.push(String::from("allow-path request tagged for abuse monitoring"));
            return self.decision(
                RequestClassificationEnforcementAction::Tag,
                classification,
                auth_context,
                reasons,
            );
        }

        reasons.push(String::from("classifier suggested allow"));
        self.decision(
            RequestClassificationEnforcementAction::Allow,
            classification,
            auth_context,
            reasons,
        )
    }

    fn decision(
        &self,
        action: RequestClassificationEnforcementAction,
        classification: &RequestClassificationResult,
        auth_context: &RequestClassificationAuthContext,
        reasons: Vec<String>,
    ) -> RequestClassificationEnforcementDecision {
        RequestClassificationEnforcementDecision {
            action,
            audit: RequestClassificationAuditRecord {
                anomaly_score: classification.anomaly_score,
                classifier_action: classification.action,
                enforcement_action: action,
                signal_scores: classification.signal_scores.clone(),
                principal: auth_context.principal.clone(),
                external_auth_fail_open_applied: auth_context.external_auth_fail_open_applied,
                reasons,
            },
        }
    }
}

impl Default for RequestClassificationEnforcer {
    fn default() -> Self {
        Self::from_policy(RequestClassificationEnforcementPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        RequestClassificationAuthContext, RequestClassificationEnforcer,
        RequestClassificationEnforcementAction, RequestClassificationEnforcementPolicy,
    };
    use crate::{RequestClassificationAction, RequestClassificationResult, RequestClassifierSignalKind};

    fn classification_result(
        anomaly_score: u8,
        action: RequestClassificationAction,
    ) -> RequestClassificationResult {
        RequestClassificationResult {
            anomaly_score,
            action,
            signal_scores: BTreeMap::from([(RequestClassifierSignalKind::HeaderAnomaly, anomaly_score)]),
        }
    }

    #[test]
    fn enforcement_maps_classifier_actions_to_expected_outcomes() {
        let enforcer = RequestClassificationEnforcer::default();
        let auth = RequestClassificationAuthContext::default();

        let block = enforcer.evaluate(
            &classification_result(90, RequestClassificationAction::Block),
            &auth,
        );
        assert_eq!(block.action, RequestClassificationEnforcementAction::Block);

        let challenge = enforcer.evaluate(
            &classification_result(60, RequestClassificationAction::Challenge),
            &auth,
        );
        assert_eq!(challenge.action, RequestClassificationEnforcementAction::Challenge);

        let allow = enforcer.evaluate(
            &classification_result(5, RequestClassificationAction::Allow),
            &auth,
        );
        assert_eq!(allow.action, RequestClassificationEnforcementAction::Allow);
    }

    #[test]
    fn enforcement_uses_throttle_when_fail_open_intersects_challenge() {
        let enforcer = RequestClassificationEnforcer::default();
        let auth = RequestClassificationAuthContext {
            external_auth_fail_open_applied: true,
            ..RequestClassificationAuthContext::default()
        };

        let decision = enforcer.evaluate(
            &classification_result(65, RequestClassificationAction::Challenge),
            &auth,
        );
        assert_eq!(decision.action, RequestClassificationEnforcementAction::Throttle);
        assert!(decision
            .audit
            .reasons
            .iter()
            .any(|reason| reason.contains("fail-open")));
    }

    #[test]
    fn enforcement_applies_trusted_principal_exception_for_false_positives() {
        let policy = RequestClassificationEnforcementPolicy {
            trusted_principals: BTreeSet::from([String::from("svc-monitor")]),
            ..RequestClassificationEnforcementPolicy::default()
        };
        let enforcer = RequestClassificationEnforcer::from_policy(policy);
        let auth = RequestClassificationAuthContext {
            principal: Some(String::from("svc-monitor")),
            ..RequestClassificationAuthContext::default()
        };

        let decision = enforcer.evaluate(
            &classification_result(60, RequestClassificationAction::Challenge),
            &auth,
        );
        assert_eq!(decision.action, RequestClassificationEnforcementAction::Allow);
        assert!(decision
            .audit
            .reasons
            .iter()
            .any(|reason| reason.contains("trusted principal exception")));
    }

    #[test]
    fn enforcement_audit_contains_classifier_and_auth_context() {
        let enforcer = RequestClassificationEnforcer::default();
        let auth = RequestClassificationAuthContext {
            principal: Some(String::from("user-123")),
            external_auth_fail_open_applied: true,
            context_headers: BTreeMap::from([(String::from("x-way-balancer-risk-tier"), String::from("high"))]),
        };

        let decision = enforcer.evaluate(
            &classification_result(30, RequestClassificationAction::Allow),
            &auth,
        );

        assert_eq!(decision.action, RequestClassificationEnforcementAction::Tag);
        assert_eq!(decision.audit.principal.as_deref(), Some("user-123"));
        assert!(decision.audit.external_auth_fail_open_applied);
        assert_eq!(decision.audit.classifier_action, RequestClassificationAction::Allow);
        assert_eq!(decision.audit.enforcement_action, RequestClassificationEnforcementAction::Tag);
        assert!(decision
            .audit
            .signal_scores
            .contains_key(&RequestClassifierSignalKind::HeaderAnomaly));
    }
}
