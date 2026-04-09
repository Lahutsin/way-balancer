use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{ProtocolAnomalyCategory, SlowClientStage};

const MAX_STORED_EVENTS: usize = 64;
const MAX_SWITCH_HISTORY: usize = 32;
const MAX_LABELS_PER_EVENT: usize = 8;
const MAX_DETAIL_LEN: usize = 256;
const MAX_LABEL_KEY_LEN: usize = 32;
const MAX_LABEL_VALUE_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EmergencyProtectionMode {
    Baseline,
    Elevated,
    Lockdown,
}

impl fmt::Display for EmergencyProtectionMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseline => formatter.write_str("baseline"),
            Self::Elevated => formatter.write_str("elevated"),
            Self::Lockdown => formatter.write_str("lockdown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowClientMitigationLevel {
    Standard,
    Tight,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyProtectionProfile {
    pub mode: EmergencyProtectionMode,
    pub source_quota_required: bool,
    pub protocol_anomaly_enforcement_required: bool,
    pub forensic_capture_enabled: bool,
    pub slow_client_mitigation: SlowClientMitigationLevel,
}

impl EmergencyProtectionProfile {
    #[must_use]
    pub const fn for_mode(mode: EmergencyProtectionMode) -> Self {
        match mode {
            EmergencyProtectionMode::Baseline => Self {
                mode,
                source_quota_required: true,
                protocol_anomaly_enforcement_required: true,
                forensic_capture_enabled: true,
                slow_client_mitigation: SlowClientMitigationLevel::Standard,
            },
            EmergencyProtectionMode::Elevated => Self {
                mode,
                source_quota_required: true,
                protocol_anomaly_enforcement_required: true,
                forensic_capture_enabled: true,
                slow_client_mitigation: SlowClientMitigationLevel::Tight,
            },
            EmergencyProtectionMode::Lockdown => Self {
                mode,
                source_quota_required: true,
                protocol_anomaly_enforcement_required: true,
                forensic_capture_enabled: true,
                slow_client_mitigation: SlowClientMitigationLevel::Aggressive,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AbuseEventCategory {
    SourceQuota,
    HandshakeGuard,
    ProtocolAnomaly(ProtocolAnomalyCategory),
    SlowClient(SlowClientStage),
}

impl fmt::Display for AbuseEventCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceQuota => formatter.write_str("source-quota"),
            Self::HandshakeGuard => formatter.write_str("handshake-guard"),
            Self::ProtocolAnomaly(category) => write!(formatter, "protocol-anomaly:{category}"),
            Self::SlowClient(stage) => write!(formatter, "slow-client:{stage}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseEventLabel {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseEventRecord {
    pub category: AbuseEventCategory,
    pub detail: String,
    pub labels: Vec<AbuseEventLabel>,
    pub observed_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseEventInput {
    pub category: AbuseEventCategory,
    pub detail: String,
    pub labels: Vec<AbuseEventLabel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyModeSwitchRequest {
    pub target_mode: EmergencyProtectionMode,
    pub allow_relaxation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyModeSwitchResult {
    Applied,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyModeSwitchRecord {
    pub previous_mode: EmergencyProtectionMode,
    pub active_mode: EmergencyProtectionMode,
    pub result: EmergencyModeSwitchResult,
    pub allow_relaxation: bool,
    pub occurred_at_unix_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyModeSwitchResponse {
    pub previous_mode: EmergencyProtectionMode,
    pub active_mode: EmergencyProtectionMode,
    pub result: EmergencyModeSwitchResult,
    pub active_profile: EmergencyProtectionProfile,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AbuseForensicsMetrics {
    pub successful_mode_switch_count: u64,
    pub rejected_mode_switch_count: u64,
    pub forensic_export_success_count: u64,
    pub forensic_export_failure_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyProtectionSnapshot {
    pub active_mode: EmergencyProtectionMode,
    pub active_profile: EmergencyProtectionProfile,
    pub abuse_event_counts: BTreeMap<AbuseEventCategory, u64>,
    pub recent_event_count: usize,
    pub switch_history_size: usize,
    pub metrics: AbuseForensicsMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseForensicsExport {
    pub active_mode: EmergencyProtectionMode,
    pub content: String,
    pub redaction_hit_count: u64,
    pub truncated: bool,
    pub included_event_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseForensicsError {
    InvalidArtifactLimit,
    TimeUnavailable,
}

impl fmt::Display for AbuseForensicsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifactLimit => {
                formatter.write_str("forensic artifact byte limit must be greater than zero")
            }
            Self::TimeUnavailable => formatter.write_str("failed to read system time"),
        }
    }
}

impl std::error::Error for AbuseForensicsError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyModeSwitchError {
    RelaxationRequiresExplicitOverride {
        current_mode: EmergencyProtectionMode,
        target_mode: EmergencyProtectionMode,
    },
    TimeUnavailable,
}

impl fmt::Display for EmergencyModeSwitchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelaxationRequiresExplicitOverride { current_mode, target_mode } => write!(
                formatter,
                "switching from {current_mode} to {target_mode} requires explicit relaxation approval"
            ),
            Self::TimeUnavailable => formatter.write_str("failed to read system time"),
        }
    }
}

impl std::error::Error for EmergencyModeSwitchError {}

#[derive(Debug)]
pub struct EmergencyProtectionController {
    active_mode: EmergencyProtectionMode,
    abuse_event_counts: BTreeMap<AbuseEventCategory, u64>,
    recent_events: VecDeque<AbuseEventRecord>,
    switch_history: VecDeque<EmergencyModeSwitchRecord>,
    metrics: AbuseForensicsMetrics,
}

impl Default for EmergencyProtectionController {
    fn default() -> Self {
        Self::new()
    }
}

impl EmergencyProtectionController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_mode: EmergencyProtectionMode::Baseline,
            abuse_event_counts: BTreeMap::new(),
            recent_events: VecDeque::with_capacity(MAX_STORED_EVENTS),
            switch_history: VecDeque::with_capacity(MAX_SWITCH_HISTORY),
            metrics: AbuseForensicsMetrics::default(),
        }
    }

    #[must_use]
    pub fn active_mode(&self) -> EmergencyProtectionMode {
        self.active_mode
    }

    #[must_use]
    pub fn active_profile(&self) -> EmergencyProtectionProfile {
        EmergencyProtectionProfile::for_mode(self.active_mode)
    }

    #[must_use]
    pub fn metrics(&self) -> AbuseForensicsMetrics {
        self.metrics
    }

    #[must_use]
    pub fn recent_switches(&self) -> Vec<EmergencyModeSwitchRecord> {
        self.switch_history.iter().cloned().collect()
    }

    pub fn switch_mode(
        &mut self,
        request: EmergencyModeSwitchRequest,
    ) -> Result<EmergencyModeSwitchResponse, EmergencyModeSwitchError> {
        let occurred_at_unix_ms =
            current_unix_ms().map_err(|_| EmergencyModeSwitchError::TimeUnavailable)?;
        self.switch_mode_at(request, occurred_at_unix_ms)
    }

    pub fn switch_mode_at(
        &mut self,
        request: EmergencyModeSwitchRequest,
        occurred_at_unix_ms: u64,
    ) -> Result<EmergencyModeSwitchResponse, EmergencyModeSwitchError> {
        let previous_mode = self.active_mode;
        if request.target_mode < self.active_mode && !request.allow_relaxation {
            self.metrics.rejected_mode_switch_count =
                self.metrics.rejected_mode_switch_count.saturating_add(1);
            return Err(EmergencyModeSwitchError::RelaxationRequiresExplicitOverride {
                current_mode: self.active_mode,
                target_mode: request.target_mode,
            });
        }

        let result = if request.target_mode == self.active_mode {
            EmergencyModeSwitchResult::Unchanged
        } else {
            self.active_mode = request.target_mode;
            self.metrics.successful_mode_switch_count =
                self.metrics.successful_mode_switch_count.saturating_add(1);
            EmergencyModeSwitchResult::Applied
        };

        self.push_switch_history(EmergencyModeSwitchRecord {
            previous_mode,
            active_mode: self.active_mode,
            result,
            allow_relaxation: request.allow_relaxation,
            occurred_at_unix_ms,
            detail: switch_detail(previous_mode, self.active_mode, result),
        });

        Ok(EmergencyModeSwitchResponse {
            previous_mode,
            active_mode: self.active_mode,
            result,
            active_profile: self.active_profile(),
            occurred_at_unix_ms,
        })
    }

    pub fn record_abuse_event(
        &mut self,
        input: AbuseEventInput,
    ) -> Result<(), AbuseForensicsError> {
        let observed_at_unix_ms =
            current_unix_ms().map_err(|_| AbuseForensicsError::TimeUnavailable)?;
        self.record_abuse_event_at(input, observed_at_unix_ms);
        Ok(())
    }

    pub fn record_abuse_event_at(&mut self, input: AbuseEventInput, observed_at_unix_ms: u64) {
        *self.abuse_event_counts.entry(input.category).or_insert(0) += 1;
        let record = AbuseEventRecord {
            category: input.category,
            detail: truncate_chars(&input.detail, MAX_DETAIL_LEN),
            labels: input
                .labels
                .into_iter()
                .take(MAX_LABELS_PER_EVENT)
                .map(|label| AbuseEventLabel {
                    key: truncate_chars(&label.key, MAX_LABEL_KEY_LEN),
                    value: truncate_chars(&label.value, MAX_LABEL_VALUE_LEN),
                })
                .collect(),
            observed_at_unix_ms,
        };
        self.push_event(record);
    }

    #[must_use]
    pub fn snapshot(&self) -> EmergencyProtectionSnapshot {
        EmergencyProtectionSnapshot {
            active_mode: self.active_mode,
            active_profile: self.active_profile(),
            abuse_event_counts: self.abuse_event_counts.clone(),
            recent_event_count: self.recent_events.len(),
            switch_history_size: self.switch_history.len(),
            metrics: self.metrics,
        }
    }

    pub fn export_forensics(
        &mut self,
        limits: lb_observability::DiagnosticsLimits,
        redactor: &lb_observability::RedactionEngine,
    ) -> Result<AbuseForensicsExport, AbuseForensicsError> {
        if limits.max_artifact_bytes == 0 {
            self.metrics.forensic_export_failure_count =
                self.metrics.forensic_export_failure_count.saturating_add(1);
            return Err(AbuseForensicsError::InvalidArtifactLimit);
        }

        let mut redaction_hit_count = 0_u64;
        let mut truncated = self.recent_events.len() > limits.max_event_records;
        let mut content = String::new();
        content.push_str(&format!("active_mode={}\n", self.active_mode));
        content.push_str(&format!("recent_events={}\n", self.recent_events.len()));
        content.push_str("abuse_event_counts:\n");
        for (category, count) in &self.abuse_event_counts {
            content.push_str(&format!("- {category}: {count}\n"));
        }
        content.push_str("recent_switches:\n");
        for switch in &self.switch_history {
            content.push_str(&format!(
                "- {} -> {} result={} at={}\n",
                switch.previous_mode,
                switch.active_mode,
                match switch.result {
                    EmergencyModeSwitchResult::Applied => "applied",
                    EmergencyModeSwitchResult::Unchanged => "unchanged",
                },
                switch.occurred_at_unix_ms,
            ));
        }
        content.push_str("recent_abuse_events:\n");
        for event in self.recent_events.iter().rev().take(limits.max_event_records) {
            let (detail, detail_redacted) = redactor.redact_text(&event.detail);
            redaction_hit_count += u64::from(detail_redacted);
            let mut rendered_labels = Vec::new();
            for label in &event.labels {
                let (value, redacted) = redactor.redact_text(&label.value);
                redaction_hit_count += u64::from(redacted);
                rendered_labels.push(format!("{}={}", label.key, value));
            }
            content.push_str(&format!(
                "- at={} category={} detail={} labels=[{}]\n",
                event.observed_at_unix_ms,
                event.category,
                detail,
                rendered_labels.join(", "),
            ));
        }

        let (content, artifact_truncated) = truncate_text_bytes(content, limits.max_artifact_bytes);
        if artifact_truncated {
            truncated = true;
        }
        self.metrics.forensic_export_success_count =
            self.metrics.forensic_export_success_count.saturating_add(1);

        Ok(AbuseForensicsExport {
            active_mode: self.active_mode,
            content,
            redaction_hit_count,
            truncated,
            included_event_count: self.recent_events.len().min(limits.max_event_records),
        })
    }

    fn push_event(&mut self, event: AbuseEventRecord) {
        if self.recent_events.len() == MAX_STORED_EVENTS {
            let _ = self.recent_events.pop_front();
        }
        self.recent_events.push_back(event);
    }

    fn push_switch_history(&mut self, entry: EmergencyModeSwitchRecord) {
        if self.switch_history.len() == MAX_SWITCH_HISTORY {
            let _ = self.switch_history.pop_front();
        }
        self.switch_history.push_back(entry);
    }
}

fn current_unix_ms() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

fn switch_detail(
    previous_mode: EmergencyProtectionMode,
    active_mode: EmergencyProtectionMode,
    result: EmergencyModeSwitchResult,
) -> String {
    match result {
        EmergencyModeSwitchResult::Applied => {
            format!("emergency protection mode changed from {previous_mode} to {active_mode}")
        }
        EmergencyModeSwitchResult::Unchanged => {
            format!("emergency protection mode remained at {active_mode}")
        }
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

fn truncate_text_bytes(mut input: String, max_bytes: usize) -> (String, bool) {
    if input.len() <= max_bytes {
        return (input, false);
    }

    const SUFFIX: &str = "\n[TRUNCATED]";
    if max_bytes <= SUFFIX.len() {
        return (SUFFIX[..max_bytes].to_string(), true);
    }
    let target_len = max_bytes - SUFFIX.len();
    while input.len() > target_len {
        let _ = input.pop();
    }
    input.push_str(SUFFIX);
    (input, true)
}

#[cfg(test)]
mod tests {
    use super::{
        AbuseEventCategory, AbuseEventInput, AbuseEventLabel, AbuseForensicsError,
        EmergencyModeSwitchError, EmergencyModeSwitchRequest, EmergencyModeSwitchResult,
        EmergencyProtectionController, EmergencyProtectionMode,
    };
    use crate::{ProtocolAnomalyCategory, SlowClientStage};

    #[test]
    fn emergency_mode_relaxation_requires_explicit_override() {
        let mut controller = EmergencyProtectionController::new();

        let raised = controller.switch_mode_at(
            EmergencyModeSwitchRequest {
                target_mode: EmergencyProtectionMode::Lockdown,
                allow_relaxation: false,
            },
            10,
        );
        let lowered = controller.switch_mode_at(
            EmergencyModeSwitchRequest {
                target_mode: EmergencyProtectionMode::Baseline,
                allow_relaxation: false,
            },
            20,
        );

        assert!(
            matches!(raised, Ok(response) if response.result == EmergencyModeSwitchResult::Applied)
        );
        assert!(matches!(
            lowered,
            Err(EmergencyModeSwitchError::RelaxationRequiresExplicitOverride { .. })
        ));
        assert_eq!(controller.active_mode(), EmergencyProtectionMode::Lockdown);
        assert_eq!(controller.metrics().rejected_mode_switch_count, 1);
    }

    #[test]
    fn abuse_event_categories_are_counted_explicitly() {
        let mut controller = EmergencyProtectionController::new();
        controller.record_abuse_event_at(
            AbuseEventInput {
                category: AbuseEventCategory::ProtocolAnomaly(
                    ProtocolAnomalyCategory::HeaderCountLimitExceeded,
                ),
                detail: String::from("header bombing detected"),
                labels: Vec::new(),
            },
            42,
        );
        controller.record_abuse_event_at(
            AbuseEventInput {
                category: AbuseEventCategory::SlowClient(SlowClientStage::RequestBody),
                detail: String::from("request body stalled"),
                labels: Vec::new(),
            },
            43,
        );

        let snapshot = controller.snapshot();
        assert_eq!(
            snapshot.abuse_event_counts.get(&AbuseEventCategory::ProtocolAnomaly(
                ProtocolAnomalyCategory::HeaderCountLimitExceeded,
            )),
            Some(&1)
        );
        assert_eq!(
            snapshot
                .abuse_event_counts
                .get(&AbuseEventCategory::SlowClient(SlowClientStage::RequestBody)),
            Some(&1)
        );
    }

    #[test]
    fn forensic_export_redacts_and_bounds_output() -> Result<(), Box<dyn std::error::Error>> {
        let mut controller = EmergencyProtectionController::new();
        controller.record_abuse_event_at(
            AbuseEventInput {
                category: AbuseEventCategory::SourceQuota,
                detail: String::from("authorization: bearer top-secret"),
                labels: vec![AbuseEventLabel {
                    key: String::from("token"),
                    value: String::from("api_key=super-secret"),
                }],
            },
            100,
        );

        let export = controller.export_forensics(
            lb_observability::DiagnosticsLimits {
                max_metrics_bytes: 128,
                max_log_records: 8,
                max_event_records: 1,
                max_artifact_bytes: 512,
            },
            &lb_observability::RedactionEngine,
        )?;

        assert!(export.content.contains("[REDACTED]"));
        assert!(!export.content.contains("top-secret"));
        assert!(export.redaction_hit_count >= 2);
        Ok(())
    }

    #[test]
    fn forensic_export_rejects_zero_artifact_limit() {
        let mut controller = EmergencyProtectionController::new();

        let result = controller.export_forensics(
            lb_observability::DiagnosticsLimits {
                max_metrics_bytes: 0,
                max_log_records: 0,
                max_event_records: 0,
                max_artifact_bytes: 0,
            },
            &lb_observability::RedactionEngine,
        );

        assert_eq!(result, Err(AbuseForensicsError::InvalidArtifactLimit));
        assert_eq!(controller.metrics().forensic_export_failure_count, 1);
    }
}
