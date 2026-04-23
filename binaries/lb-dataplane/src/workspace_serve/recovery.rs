#[derive(Debug, Clone)]
struct ControlPlaneRecoveryInfo {
    state: String,
    detail: String,
    last_persisted_at_unix_ms: Option<u64>,
    restored_reload_health: Option<String>,
    restored_last_reload_outcome_code: Option<String>,
    in_flight_operation: Option<JournalInFlightOperation>,
    reconciled_listeners: Vec<RecoveredListenerStatus>,
}

#[derive(Debug, Clone)]
struct RecoveryOperatorGuidance {
    recommended_action: String,
    urgency: String,
    operation_age_ms: Option<u64>,
    expected_completion_within_ms: Option<u64>,
    exceeded_expected_completion: bool,
}

impl RecoveryOperatorGuidance {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"recommended_action\":\"{}\",",
                "\"urgency\":\"{}\",",
                "\"operation_age_ms\":{},",
                "\"expected_completion_within_ms\":{},",
                "\"exceeded_expected_completion\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.recommended_action),
            crate::escape_json_string(&self.urgency),
            optional_u64_json(self.operation_age_ms),
            optional_u64_json(self.expected_completion_within_ms),
            self.exceeded_expected_completion,
        )
    }
}

#[derive(Debug, Clone)]
struct RecoveryReconciliationSummary {
    overall_verdict: String,
    recommended_action: String,
    settled_count: usize,
    draining_count: usize,
    failed_preserved_count: usize,
    drain_timeout_count: usize,
    missing_count: usize,
    needs_review_count: usize,
}

impl RecoveryReconciliationSummary {
    fn from_reconciled_listeners(listeners: &[RecoveredListenerStatus]) -> Self {
        let mut summary = Self {
            overall_verdict: String::from("none"),
            recommended_action: String::from("none"),
            settled_count: 0,
            draining_count: 0,
            failed_preserved_count: 0,
            drain_timeout_count: 0,
            missing_count: 0,
            needs_review_count: 0,
        };
        for listener in listeners {
            match listener.reconciliation_verdict.as_str() {
                "settled" => summary.settled_count += 1,
                "replacement_still_draining" => summary.draining_count += 1,
                "replacement_failed_preserved" => summary.failed_preserved_count += 1,
                "replacement_drain_timeout" => summary.drain_timeout_count += 1,
                "missing" => summary.missing_count += 1,
                _ => summary.needs_review_count += 1,
            }
        }
        summary.overall_verdict = if listeners.is_empty() {
            String::from("none")
        } else if summary.missing_count > 0 || summary.needs_review_count > 0 {
            String::from("needs_review")
        } else if summary.failed_preserved_count > 0 {
            String::from("replacement_failed_preserved")
        } else if summary.drain_timeout_count > 0 {
            String::from("replacement_drain_timeout")
        } else if summary.draining_count > 0 {
            String::from("replacement_still_draining")
        } else {
            String::from("settled")
        };
        summary.recommended_action = match summary.overall_verdict.as_str() {
            "none" => String::from("none"),
            "settled" => String::from("observe_only"),
            "replacement_still_draining" => String::from("wait_for_drain_completion"),
            "replacement_failed_preserved" => String::from("validate_and_retry_reload"),
            "replacement_drain_timeout" => String::from("investigate_drain_timeout"),
            _ => String::from("investigate_and_validate_reload"),
        };
        summary
    }

    fn urgency(&self) -> &'static str {
        match self.overall_verdict.as_str() {
            "none" | "settled" => "none",
            "replacement_still_draining" => "watch",
            "replacement_failed_preserved" => "action_required",
            "replacement_drain_timeout" | "needs_review" => "urgent",
            _ => "urgent",
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"overall_verdict\":\"{}\",",
                "\"recommended_action\":\"{}\",",
                "\"settled_count\":{},",
                "\"draining_count\":{},",
                "\"failed_preserved_count\":{},",
                "\"drain_timeout_count\":{},",
                "\"missing_count\":{},",
                "\"needs_review_count\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.overall_verdict),
            crate::escape_json_string(&self.recommended_action),
            self.settled_count,
            self.draining_count,
            self.failed_preserved_count,
            self.drain_timeout_count,
            self.missing_count,
            self.needs_review_count,
        )
    }
}

#[derive(Debug, Clone)]
struct RecoveredListenerStatus {
    name: String,
    listener_state: String,
    replacement_state: String,
    reconciliation_verdict: String,
}

impl RecoveredListenerStatus {
    fn new(name: String, listener_state: String, replacement_state: String) -> Self {
        let reconciliation_verdict = match (listener_state.as_str(), replacement_state.as_str()) {
            ("running", "stable") => String::from("settled"),
            ("running", "replacement_draining") => String::from("replacement_still_draining"),
            ("missing", "missing") => String::from("missing"),
            (_, "failed_start_preserved") => String::from("replacement_failed_preserved"),
            (_, "drain_timeout_expired") => String::from("replacement_drain_timeout"),
            _ => String::from("needs_review"),
        };
        Self { name, listener_state, replacement_state, reconciliation_verdict }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"name\":\"{}\",",
                "\"listener_state\":\"{}\",",
                "\"replacement_state\":\"{}\",",
                "\"reconciliation_verdict\":\"{}\"",
                "}}"
            ),
            crate::escape_json_string(&self.name),
            crate::escape_json_string(&self.listener_state),
            crate::escape_json_string(&self.replacement_state),
            crate::escape_json_string(&self.reconciliation_verdict),
        )
    }
}

impl Default for ControlPlaneRecoveryInfo {
    fn default() -> Self {
        Self {
            state: String::from("none"),
            detail: String::from("no durable control-plane state recovered"),
            last_persisted_at_unix_ms: None,
            restored_reload_health: None,
            restored_last_reload_outcome_code: None,
            in_flight_operation: None,
            reconciled_listeners: Vec::new(),
        }
    }
}

impl ControlPlaneRecoveryInfo {
    fn restored(payload: &ControlPlaneJournalPayload) -> Self {
        let (state, detail) = match &payload.in_flight_operation {
            Some(operation) => (
                String::from("needs_operator_action"),
                format!(
                    "recovered unfinished {} for desired snapshot {}",
                    operation.kind, operation.desired_snapshot.digest_sha256
                ),
            ),
            None => (
                String::from("restored"),
                String::from("restored durable control-plane state from local journal"),
            ),
        };
        Self {
            state,
            detail,
            last_persisted_at_unix_ms: Some(payload.persisted_at_unix_ms),
            restored_reload_health: Some(payload.reload_health.clone()),
            restored_last_reload_outcome_code: Some(payload.last_reload_outcome_code.clone()),
            in_flight_operation: payload.in_flight_operation.clone(),
            reconciled_listeners: Vec::new(),
        }
    }

    fn reconcile_with_listener_statuses(&mut self, listener_statuses: &[ListenerStatus]) {
        let Some(operation) = self.in_flight_operation.as_ref() else {
            self.reconciled_listeners.clear();
            return;
        };
        self.reconciled_listeners = operation
            .affected_listeners
            .iter()
            .map(|listener_name| {
                listener_statuses
                    .iter()
                    .find(|status| &status.name == listener_name)
                    .map(|status| {
                        RecoveredListenerStatus::new(
                            listener_name.clone(),
                            status.state.clone(),
                            status.replacement.state.clone(),
                        )
                    })
                    .unwrap_or_else(|| {
                        RecoveredListenerStatus::new(
                            listener_name.clone(),
                            String::from("missing"),
                            String::from("missing"),
                        )
                    })
            })
            .collect();
    }

    fn operator_guidance_at(&self, now_ms: u64) -> RecoveryOperatorGuidance {
        let reconciliation_summary =
            RecoveryReconciliationSummary::from_reconciled_listeners(&self.reconciled_listeners);
        let operation_age_ms = self
            .in_flight_operation
            .as_ref()
            .map(|operation| now_ms.saturating_sub(operation.started_at_unix_ms));
        let expected_completion_within_ms = self
            .in_flight_operation
            .as_ref()
            .and_then(|operation| operation.expected_completion_within_ms);
        let exceeded_expected_completion = match (operation_age_ms, expected_completion_within_ms) {
            (Some(age_ms), Some(expected_ms)) => age_ms > expected_ms,
            _ => false,
        };
        if self.state == "needs_operator_action" {
            let (recommended_action, urgency) = match reconciliation_summary
                .overall_verdict
                .as_str()
            {
                "replacement_still_draining" if exceeded_expected_completion => {
                    ("investigate_stalled_drain", "action_required")
                }
                "replacement_still_draining" => ("wait_for_drain_completion", "watch"),
                "replacement_failed_preserved" => ("validate_and_retry_reload", "action_required"),
                "replacement_drain_timeout" => ("investigate_drain_timeout", "urgent"),
                "needs_review" => ("investigate_and_validate_reload", "urgent"),
                _ => ("validate_and_retry_reload", "action_required"),
            };
            return RecoveryOperatorGuidance {
                recommended_action: String::from(recommended_action),
                urgency: String::from(urgency),
                operation_age_ms,
                expected_completion_within_ms,
                exceeded_expected_completion,
            };
        }

        let urgency = reconciliation_summary.urgency();
        RecoveryOperatorGuidance {
            recommended_action: reconciliation_summary.recommended_action,
            urgency: String::from(urgency),
            operation_age_ms,
            expected_completion_within_ms,
            exceeded_expected_completion,
        }
    }

    fn operator_guidance(&self) -> RecoveryOperatorGuidance {
        self.operator_guidance_at(unix_time_ms())
    }

    fn to_json(&self) -> String {
        let reconciliation_summary =
            RecoveryReconciliationSummary::from_reconciled_listeners(&self.reconciled_listeners);
        let operator_guidance = self.operator_guidance();
        format!(
            concat!(
                "{{",
                "\"state\":\"{}\",",
                "\"detail\":\"{}\",",
                "\"last_persisted_at_unix_ms\":{},",
                "\"restored_reload_health\":{},",
                "\"restored_last_reload_outcome_code\":{},",
                "\"in_flight_operation\":{},",
                "\"operator_guidance\":{},",
                "\"reconciled_listeners\":[{}],",
                "\"reconciliation_summary\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.state),
            crate::escape_json_string(&self.detail),
            optional_u64_json(self.last_persisted_at_unix_ms),
            optional_string_json(self.restored_reload_health.as_deref()),
            optional_string_json(self.restored_last_reload_outcome_code.as_deref()),
            self.in_flight_operation
                .as_ref()
                .map_or_else(|| String::from("null"), JournalInFlightOperation::to_json),
            operator_guidance.to_json(),
            self.reconciled_listeners
                .iter()
                .map(RecoveredListenerStatus::to_json)
                .collect::<Vec<_>>()
                .join(","),
            reconciliation_summary.to_json(),
        )
    }
}
