fn reduce_listener_readiness(listener: &ListenerStatus) -> ListenerReadinessStatus {
    let mut reason_codes = Vec::new();

    match listener.state.as_str() {
        "running" => {}
        "draining" => push_unique_reason(&mut reason_codes, "listener_draining"),
        _ => push_unique_reason(&mut reason_codes, "listener_not_running"),
    }

    match listener.overload_state.as_str() {
        "shedding" => push_unique_reason(&mut reason_codes, "listener_overload_shedding"),
        "brownout" => push_unique_reason(&mut reason_codes, "listener_overload_brownout"),
        _ => {}
    }

    if listener.replacement.failed_start.is_some()
        || listener.replacement.state == "failed_start_preserved"
    {
        push_unique_reason(&mut reason_codes, "listener_replacement_failed");
    }

    for reason in &listener.abuse_protection.reason_codes {
        match reason.as_str() {
            "tracked_source_capacity_saturated" => {
                push_unique_reason(&mut reason_codes, "listener_abuse_source_tracking_saturated");
            }
            "handshake_guard_saturated" => {
                push_unique_reason(&mut reason_codes, "listener_abuse_handshake_saturated");
            }
            _ => {}
        }
    }

    ListenerReadinessStatus {
        name: listener.name.clone(),
        class: listener.class,
        protocol: listener.protocol,
        configured_bind: listener.configured_bind,
        ready: reason_codes.is_empty(),
        status: String::from(if reason_codes.is_empty() { "ready" } else { "not_ready" }),
        reason_codes,
    }
}

fn push_unique_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(String::from(reason));
    }
}

impl ConfigValidationPreview {
    fn render_json(&self) -> Result<String, DynError> {
        serde_json::to_string_pretty(self).map_err(to_dyn_error)
    }
}

