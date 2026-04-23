#[derive(Debug, Clone)]
struct ListenerStatus {
    name: String,
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    configured_bind: SocketAddr,
    local_addr: SocketAddr,
    state: String,
    overload_state: String,
    accepted_connections: u64,
    active_connections: usize,
    completed_connections: u64,
    shed_connections: u64,
    abuse_protection: ListenerAbuseProtectionStatus,
    brownout_features: Vec<String>,
    recent_overload_events: Vec<OverloadEventStatus>,
    replacement: ListenerReplacementStatus,
    tls: Option<ListenerTlsStatus>,
}

#[derive(Debug, Clone)]
struct ListenerAbuseProtectionStatus {
    state: String,
    source_quota: Option<SourceQuotaStatus>,
    handshake_guard: Option<HandshakeGuardStatus>,
    source_quota_rejections: u64,
    tracked_source_limit_rejections: u64,
    handshake_guard_rejections: u64,
    tracked_sources: usize,
    active_handshakes: usize,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone)]
struct SourceQuotaStatus {
    aggregation: String,
    max_active_per_source: usize,
    max_tracked_sources: usize,
}

#[derive(Debug, Clone)]
struct HandshakeGuardStatus {
    max_inflight: usize,
    timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadHealthState {
    NotRequested,
    Healthy,
    Failed,
}

#[derive(Debug, Clone)]
struct ListenerReadinessStatus {
    name: String,
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    configured_bind: SocketAddr,
    ready: bool,
    status: String,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone)]
struct WorkspaceReadinessStatus {
    ready: bool,
    status: String,
    evaluated_listener_scope: String,
    reload_status: String,
    reason_codes: Vec<String>,
    listeners: Vec<ListenerReadinessStatus>,
}

#[derive(Debug, Clone)]
struct ListenerIdentityStatus {
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    configured_bind: SocketAddr,
    bind_mode: lb_net_core::ListenerBindMode,
}

impl From<ListenerIdentity> for ListenerIdentityStatus {
    fn from(identity: ListenerIdentity) -> Self {
        Self {
            class: identity.class,
            protocol: identity.protocol,
            configured_bind: identity.configured_bind,
            bind_mode: identity.bind_mode,
        }
    }
}

impl ListenerIdentityStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"class\":\"{}\",",
                "\"protocol\":\"{}\",",
                "\"configured_bind\":\"{}\",",
                "\"bind_mode\":\"{}\"",
                "}}"
            ),
            listener_class_name(self.class),
            listener_protocol_name(self.protocol),
            self.configured_bind,
            listener_bind_mode_name(self.bind_mode),
        )
    }
}

impl ListenerReadinessStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"name\":\"{}\",",
                "\"class\":\"{}\",",
                "\"protocol\":\"{}\",",
                "\"configured_bind\":\"{}\",",
                "\"ready\":{},",
                "\"status\":\"{}\",",
                "\"reason_codes\":[{}]",
                "}}"
            ),
            crate::escape_json_string(&self.name),
            listener_class_name(self.class),
            listener_protocol_name(self.protocol),
            self.configured_bind,
            self.ready,
            crate::escape_json_string(&self.status),
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", crate::escape_json_string(code)))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

impl WorkspaceReadinessStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"ready\":{},",
                "\"status\":\"{}\",",
                "\"evaluated_listener_scope\":\"{}\",",
                "\"reload_status\":\"{}\",",
                "\"reason_codes\":[{}],",
                "\"listeners\":[{}]",
                "}}"
            ),
            self.ready,
            crate::escape_json_string(&self.status),
            crate::escape_json_string(&self.evaluated_listener_scope),
            crate::escape_json_string(&self.reload_status),
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", crate::escape_json_string(code)))
                .collect::<Vec<_>>()
                .join(","),
            self.listeners
                .iter()
                .map(ListenerReadinessStatus::to_json)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

#[derive(Debug, Clone)]
struct FailedListenerStartStatus {
    identity: ListenerIdentityStatus,
    detail: String,
}

impl FailedListenerStartStatus {
    fn to_json(&self) -> String {
        format!(
            "{{\"identity\":{},\"detail\":\"{}\"}}",
            self.identity.to_json(),
            crate::escape_json_string(&self.detail),
        )
    }
}

#[derive(Debug, Clone)]
struct ListenerReplacementStatus {
    state: String,
    desired: ListenerIdentityStatus,
    draining: Vec<ListenerIdentityStatus>,
    retired_recent: Vec<ListenerIdentityStatus>,
    drain_timeout_recent: Vec<ListenerIdentityStatus>,
    failed_start: Option<FailedListenerStartStatus>,
}

impl ListenerReplacementStatus {
    fn from_lifecycle(lifecycle: &ListenerLifecycleModel) -> Self {
        let state = if !lifecycle.draining_identities.is_empty() {
            "replacement_draining"
        } else if lifecycle.failed_start.is_some() {
            "failed_start_preserved"
        } else if !lifecycle.drain_timed_out_identities.is_empty() {
            "drain_timeout_expired"
        } else {
            "stable"
        };

        Self {
            state: String::from(state),
            desired: lifecycle.desired_identity.into(),
            draining: lifecycle
                .draining_identities
                .iter()
                .copied()
                .map(ListenerIdentityStatus::from)
                .collect(),
            retired_recent: lifecycle
                .retired_identities
                .iter()
                .copied()
                .map(ListenerIdentityStatus::from)
                .collect(),
            drain_timeout_recent: lifecycle
                .drain_timed_out_identities
                .iter()
                .copied()
                .map(ListenerIdentityStatus::from)
                .collect(),
            failed_start: lifecycle.failed_start.as_ref().map(|failed_start| {
                FailedListenerStartStatus {
                    identity: failed_start.identity.into(),
                    detail: failed_start.detail.clone(),
                }
            }),
        }
    }

    fn to_json(&self) -> String {
        let draining =
            self.draining.iter().map(ListenerIdentityStatus::to_json).collect::<Vec<_>>().join(",");
        let retired_recent = self
            .retired_recent
            .iter()
            .map(ListenerIdentityStatus::to_json)
            .collect::<Vec<_>>()
            .join(",");
        let drain_timeout_recent = self
            .drain_timeout_recent
            .iter()
            .map(ListenerIdentityStatus::to_json)
            .collect::<Vec<_>>()
            .join(",");
        let failed_start = self
            .failed_start
            .as_ref()
            .map_or_else(|| String::from("null"), FailedListenerStartStatus::to_json);

        format!(
            concat!(
                "{{",
                "\"state\":\"{}\",",
                "\"desired\":{},",
                "\"draining\":[{}],",
                "\"retired_recent\":[{}],",
                "\"drain_timeout_recent\":[{}],",
                "\"failed_start\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.state),
            self.desired.to_json(),
            draining,
            retired_recent,
            drain_timeout_recent,
            failed_start,
        )
    }
}

impl ListenerStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"name\":\"{}\",",
                "\"class\":\"{}\",",
                "\"protocol\":\"{}\",",
                "\"configured_bind\":\"{}\",",
                "\"local_addr\":\"{}\",",
                "\"state\":\"{}\",",
                "\"overload_state\":\"{}\",",
                "\"accepted_connections\":{},",
                "\"active_connections\":{},",
                "\"shed_connections\":{},",
                "\"completed_connections\":{},",
                "\"abuse_protection\":{},",
                "\"brownout_features\":[{}],",
                "\"recent_overload_events\":[{}],",
                "\"replacement\":{},",
                "\"tls\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.name),
            listener_class_name(self.class),
            listener_protocol_name(self.protocol),
            self.configured_bind,
            self.local_addr,
            crate::escape_json_string(&self.state),
            crate::escape_json_string(&self.overload_state),
            self.accepted_connections,
            self.active_connections,
            self.shed_connections,
            self.completed_connections,
            self.abuse_protection.to_json(),
            self.brownout_features
                .iter()
                .map(|feature| format!("\"{}\"", crate::escape_json_string(feature)))
                .collect::<Vec<_>>()
                .join(","),
            self.recent_overload_events
                .iter()
                .map(OverloadEventStatus::to_json)
                .collect::<Vec<_>>()
                .join(","),
            self.replacement.to_json(),
            self.tls.as_ref().map_or_else(|| String::from("null"), ListenerTlsStatus::to_json),
        )
    }
}

impl ListenerAbuseProtectionStatus {
    fn from_runtime(
        policy: Option<&CompiledListenerAbuseProtectionPolicy>,
        snapshot: lb_runtime::ListenerAbuseProtectionSnapshot,
    ) -> Self {
        let mut reason_codes = Vec::new();
        if snapshot.source_quota_rejections > 0 {
            push_unique_reason(
                &mut reason_codes,
                lb_runtime::AbuseRejectionReason::SourceQuotaExceeded.code(),
            );
        }
        if snapshot.tracked_source_limit_rejections > 0 {
            push_unique_reason(
                &mut reason_codes,
                lb_runtime::AbuseRejectionReason::TrackedSourceLimitReached.code(),
            );
        }
        if snapshot.handshake_guard_rejections > 0 {
            push_unique_reason(
                &mut reason_codes,
                lb_runtime::AbuseRejectionReason::HandshakeLimitReached.code(),
            );
        }

        let source_quota = policy.and_then(|policy| {
            policy.source_quota.map(|source_quota| SourceQuotaStatus {
                aggregation: String::from(source_aggregation_name(source_quota.aggregation)),
                max_active_per_source: source_quota.max_active_per_source,
                max_tracked_sources: source_quota.max_tracked_sources,
            })
        });
        if source_quota.as_ref().is_some_and(|source_quota| {
            snapshot.tracked_sources >= source_quota.max_tracked_sources
        }) {
            push_unique_reason(&mut reason_codes, "tracked_source_capacity_saturated");
        }

        let handshake_guard = policy.and_then(|policy| {
            policy.handshake_guard.map(|handshake_guard| HandshakeGuardStatus {
                max_inflight: handshake_guard.max_inflight,
                timeout_ms: handshake_guard.timeout.as_millis() as u64,
            })
        });
        if handshake_guard.as_ref().is_some_and(|handshake_guard| {
            snapshot.active_handshakes >= handshake_guard.max_inflight
        }) {
            push_unique_reason(&mut reason_codes, "handshake_guard_saturated");
        }

        let state = if policy.is_none() {
            "disabled"
        } else if reason_codes.iter().any(|reason| {
            reason == "tracked_source_capacity_saturated" || reason == "handshake_guard_saturated"
        }) {
            "constrained"
        } else {
            "enforcing"
        };

        Self {
            state: String::from(state),
            source_quota,
            handshake_guard,
            source_quota_rejections: snapshot.source_quota_rejections,
            tracked_source_limit_rejections: snapshot.tracked_source_limit_rejections,
            handshake_guard_rejections: snapshot.handshake_guard_rejections,
            tracked_sources: snapshot.tracked_sources,
            active_handshakes: snapshot.active_handshakes,
            reason_codes,
        }
    }

    fn to_json(&self) -> String {
        let source_quota = self.source_quota.as_ref().map_or_else(
            || String::from("null"),
            |source_quota| {
                format!(
                    concat!(
                        "{{",
                        "\"aggregation\":\"{}\",",
                        "\"max_active_per_source\":{},",
                        "\"max_tracked_sources\":{}",
                        "}}"
                    ),
                    crate::escape_json_string(&source_quota.aggregation),
                    source_quota.max_active_per_source,
                    source_quota.max_tracked_sources,
                )
            },
        );
        let handshake_guard = self.handshake_guard.as_ref().map_or_else(
            || String::from("null"),
            |handshake_guard| {
                format!(
                    concat!("{{", "\"max_inflight\":{},", "\"timeout_ms\":{}", "}}"),
                    handshake_guard.max_inflight, handshake_guard.timeout_ms,
                )
            },
        );

        format!(
            concat!(
                "{{",
                "\"state\":\"{}\",",
                "\"source_quota\":{},",
                "\"handshake_guard\":{},",
                "\"source_quota_rejections\":{},",
                "\"tracked_source_limit_rejections\":{},",
                "\"handshake_guard_rejections\":{},",
                "\"tracked_sources\":{},",
                "\"active_handshakes\":{},",
                "\"reason_codes\":[{}]",
                "}}"
            ),
            crate::escape_json_string(&self.state),
            source_quota,
            handshake_guard,
            self.source_quota_rejections,
            self.tracked_source_limit_rejections,
            self.handshake_guard_rejections,
            self.tracked_sources,
            self.active_handshakes,
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", crate::escape_json_string(code)))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

fn evaluate_workspace_readiness(
    listener_statuses: &[ListenerStatus],
    reload_health: ReloadHealthState,
) -> WorkspaceReadinessStatus {
    let evaluate_public_only = listener_statuses
        .iter()
        .any(|listener| listener.class == lb_config_model::ListenerClassConfig::Public);
    let evaluated_listener_scope = if evaluate_public_only { "public" } else { "all" };
    let listeners = listener_statuses
        .iter()
        .filter(|listener| {
            !evaluate_public_only || listener.class == lb_config_model::ListenerClassConfig::Public
        })
        .map(reduce_listener_readiness)
        .collect::<Vec<_>>();
    let mut reason_codes = Vec::new();

    if matches!(reload_health, ReloadHealthState::Failed) {
        push_unique_reason(&mut reason_codes, "reload_failed");
    }
    if listeners.is_empty() {
        push_unique_reason(&mut reason_codes, "no_serving_listeners");
    }
    for listener in &listeners {
        for reason in &listener.reason_codes {
            push_unique_reason(&mut reason_codes, reason);
        }
    }

    WorkspaceReadinessStatus {
        ready: reason_codes.is_empty(),
        status: String::from(if reason_codes.is_empty() { "ready" } else { "not_ready" }),
        evaluated_listener_scope: String::from(evaluated_listener_scope),
        reload_status: String::from(reload_health_name(reload_health)),
        reason_codes,
        listeners,
    }
}

