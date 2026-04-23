#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalInFlightOperation {
    kind: String,
    started_at_unix_ms: u64,
    desired_snapshot: DurableSnapshotIdentity,
    lifecycle_code: String,
    detail: String,
    expected_completion_within_ms: Option<u64>,
    affected_listeners: Vec<String>,
}

impl JournalInFlightOperation {
    fn from_reload_plan(desired_snapshot: DurableSnapshotIdentity, plan: &ReloadAuditPlan) -> Self {
        let affected_listeners = if !plan.supported_replacements.is_empty() {
            plan.supported_replacements.clone()
        } else {
            plan.blocked_replacements.clone()
        };
        Self {
            kind: String::from(if !plan.supported_replacements.is_empty() {
                "reload_overlap_drain"
            } else {
                "reload"
            }),
            started_at_unix_ms: unix_time_ms(),
            desired_snapshot,
            lifecycle_code: String::from(plan.start_code()),
            detail: plan.start_detail(),
            expected_completion_within_ms: plan.expected_completion_within_ms,
            affected_listeners,
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"kind\":\"{}\",",
                "\"started_at_unix_ms\":{},",
                "\"desired_snapshot\":{},",
                "\"lifecycle_code\":\"{}\",",
                "\"detail\":\"{}\",",
                "\"expected_completion_within_ms\":{},",
                "\"affected_listeners\":[{}]",
                "}}"
            ),
            crate::escape_json_string(&self.kind),
            self.started_at_unix_ms,
            self.desired_snapshot.to_json(),
            crate::escape_json_string(&self.lifecycle_code),
            crate::escape_json_string(&self.detail),
            optional_u64_json(self.expected_completion_within_ms),
            self.affected_listeners
                .iter()
                .map(|listener| format!("\"{}\"", crate::escape_json_string(listener)))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlPlaneJournalPayload {
    persisted_at_unix_ms: u64,
    desired_snapshot: Option<DurableSnapshotIdentity>,
    applied_snapshot: Option<DurableSnapshotIdentity>,
    reload_health: String,
    last_reload_outcome_code: String,
    last_reload_result: String,
    recent_admin_audit: Vec<AdminAuditEvent>,
    in_flight_operation: Option<JournalInFlightOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlPlaneJournalEnvelope {
    version: u32,
    payload_json: String,
    payload_sha256: String,
}

#[derive(Debug, Clone)]

struct ControlPlaneJournalRuntime {
    journal_path: String,
    desired_snapshot: Option<DurableSnapshotIdentity>,
    applied_snapshot: Option<DurableSnapshotIdentity>,
    in_flight_operation: Option<JournalInFlightOperation>,
    recovery: ControlPlaneRecoveryInfo,
}

impl ControlPlaneJournalRuntime {
    fn new(config_path: &str) -> Self {
        Self {
            journal_path: control_plane_journal_path(config_path),
            desired_snapshot: None,
            applied_snapshot: None,
            in_flight_operation: None,
            recovery: ControlPlaneRecoveryInfo::default(),
        }
    }

    fn to_status_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"path\":\"{}\",",
                "\"desired_snapshot\":{},",
                "\"applied_snapshot\":{},",
                "\"recovery\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.journal_path),
            self.desired_snapshot
                .as_ref()
                .map_or_else(|| String::from("null"), DurableSnapshotIdentity::to_json),
            self.applied_snapshot
                .as_ref()
                .map_or_else(|| String::from("null"), DurableSnapshotIdentity::to_json),
            self.recovery.to_json(),
        )
    }
}

fn control_plane_journal_path(config_path: &str) -> String {
    format!("{config_path}.control-plane.json")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_control_plane_journal_atomic(
    journal_path: &str,
    payload: &ControlPlaneJournalPayload,
) -> Result<(), DynError> {
    let payload_json = serde_json::to_string_pretty(payload).map_err(to_dyn_error)?;
    let envelope = ControlPlaneJournalEnvelope {
        version: CONTROL_PLANE_JOURNAL_VERSION,
        payload_sha256: sha256_hex(payload_json.as_bytes()),
        payload_json,
    };
    let serialized = serde_json::to_vec_pretty(&envelope).map_err(to_dyn_error)?;
    let write_sequence = NEXT_CONTROL_PLANE_JOURNAL_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_path =
        format!("{journal_path}.tmp-{}-{}-{write_sequence}", std::process::id(), unix_time_ms());
    fs::write(&temporary_path, serialized).map_err(to_dyn_error)?;
    fs::rename(&temporary_path, journal_path).map_err(to_dyn_error)?;
    Ok(())
}
