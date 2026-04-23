#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminAuditEvent {
    observed_at_unix_ms: u64,
    request_id: String,
    listener: String,
    actor: String,
    auth_mode: String,
    action: String,
    code: String,
    source: String,
    outcome: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DurableSnapshotIdentity {
    source_label: String,
    digest_sha256: String,
    api_version: String,
    snapshot_format_version: String,
}

impl DurableSnapshotIdentity {
    fn from_snapshot(source_label: &str, snapshot: &lb_config_model::WorkspaceSnapshot) -> Self {
        Self {
            source_label: source_label.to_string(),
            digest_sha256: snapshot.metadata().digest_sha256().to_owned(),
            api_version: serde_json::to_value(snapshot.metadata().api_version())
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| String::from("unknown")),
            snapshot_format_version: snapshot.metadata().format_version().to_string(),
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"source_label\":\"{}\",",
                "\"digest_sha256\":\"{}\",",
                "\"api_version\":\"{}\",",
                "\"snapshot_format_version\":\"{}\"",
                "}}"
            ),
            crate::escape_json_string(&self.source_label),
            crate::escape_json_string(&self.digest_sha256),
            crate::escape_json_string(&self.api_version),
            crate::escape_json_string(&self.snapshot_format_version),
        )
    }
}

async fn record_admin_audit(
    state: &WorkspaceServeState,
    event: AdminAuditEvent,
) -> Result<(), DynError> {
    state.record_admin_audit(event).await;
    Ok(())
}

fn optional_string_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", crate::escape_json_string(value)))
        .unwrap_or_else(|| String::from("null"))
}

fn optional_u64_json(value: Option<u64>) -> String {
    value.map_or_else(|| String::from("null"), |value| value.to_string())
}

