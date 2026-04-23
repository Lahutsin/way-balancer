fn reload_health_from_name(name: &str) -> ReloadHealthState {
    match name {
        "healthy" => ReloadHealthState::Healthy,
        "failed" => ReloadHealthState::Failed,
        _ => ReloadHealthState::NotRequested,
    }
}

fn next_admin_sequence_from_events(events: &[AdminAuditEvent]) -> u64 {
    events
        .iter()
        .filter_map(|event| {
            event
                .request_id
                .strip_prefix("admin-")
                .and_then(|suffix| u64::from_str_radix(suffix, 16).ok())
        })
        .max()
        .map_or(1, |sequence| sequence.saturating_add(1))
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn reload_health_name(state: ReloadHealthState) -> &'static str {
    match state {
        ReloadHealthState::NotRequested => "not_requested",
        ReloadHealthState::Healthy => "healthy",
        ReloadHealthState::Failed => "failed",
    }
}

fn elapsed_millis_at_least_one(duration: Duration) -> u64 {
    let millis = match u64::try_from(duration.as_millis()) {
        Ok(millis) => millis,
        Err(_) => u64::MAX,
    };
    millis.max(1)
}

const fn reload_health_index(state: ReloadHealthState) -> usize {
    match state {
        ReloadHealthState::NotRequested => 0,
        ReloadHealthState::Healthy => 1,
        ReloadHealthState::Failed => 2,
    }
}

fn build_config_validation_preview(
    config_path: &str,
    active_snapshot: Option<&lb_config_model::WorkspaceSnapshot>,
    current_identities: &BTreeMap<String, CurrentListenerIdentity>,
    candidate: &CompiledWorkspaceRuntime,
) -> ConfigValidationPreview {
    let diff_preview = active_snapshot.map(|active| active.diff(&candidate.snapshot));
    let warnings = build_config_safety_warnings(active_snapshot, current_identities, candidate);
    let blocked_replacements =
        collect_blocked_listener_replacements(current_identities, &candidate.listeners);
    let supported_replacements =
        collect_supported_listener_replacements(current_identities, &candidate.listeners);
    let apply_preview = if !blocked_replacements.is_empty() {
        ConfigApplyPreview {
            strategy: String::from("blocked_requires_rebind"),
            rollback_safe: true,
            summary: format!(
                "reload would still be blocked because these listeners cannot be overlap-replaced on their current live socket: {}",
                blocked_replacements.join(", ")
            ),
        }
    } else if !supported_replacements.is_empty() {
        ConfigApplyPreview {
            strategy: String::from("overlap_and_drain_replacement"),
            rollback_safe: true,
            summary: format!(
                "replacement listeners can be started before retirement for: {}; failed replacement startup leaves the active runtime unchanged",
                supported_replacements.join(", ")
            ),
        }
    } else {
        ConfigApplyPreview {
            strategy: String::from("in_place_or_additive_swap"),
            rollback_safe: true,
            summary: String::from(
                "candidate config compiles before apply; new listeners are started before old listeners retire, and failed reloads leave the active runtime unchanged",
            ),
        }
    };

    ConfigValidationPreview {
        config_path: config_path.to_string(),
        active_snapshot: active_snapshot.map(lb_config_model::WorkspaceSnapshot::view),
        candidate_snapshot: candidate.snapshot.view(),
        diff_preview,
        warnings,
        apply_preview,
        compatibility: ConfigCompatibilityPreview {
            active_api_version: active_snapshot.map(|snapshot| snapshot.metadata().api_version()),
            candidate_api_version: candidate.snapshot.metadata().api_version(),
            snapshot_format_version: candidate
                .snapshot
                .metadata()
                .format_version()
                .to_string(),
            migration_strategy: String::from(
                "candidate configs must compile to the current snapshot format and supported api_version before apply; unsupported version jumps fail during validation and the active snapshot remains available for rollback",
            ),
        },
    }
}

fn build_config_safety_warnings(
    active_snapshot: Option<&lb_config_model::WorkspaceSnapshot>,
    current_identities: &BTreeMap<String, CurrentListenerIdentity>,
    candidate: &CompiledWorkspaceRuntime,
) -> Vec<ConfigSafetyWarning> {
    let mut warnings = Vec::new();

    if let Some(active_snapshot) = active_snapshot {
        let diff = active_snapshot.diff(&candidate.snapshot);
        if !diff.listener_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("listener_topology_changed"),
                message: format!(
                    "listener changes detected: {}",
                    summarize_snapshot_changes(&diff.listener_changes)
                ),
            });
        }
        if !diff.route_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("route_table_changed"),
                message: format!(
                    "route matching changes detected: {}",
                    summarize_snapshot_changes(&diff.route_changes)
                ),
            });
        }
        if !diff.upstream_cluster_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("upstream_clusters_changed"),
                message: format!(
                    "upstream topology changes detected: {}",
                    summarize_snapshot_changes(&diff.upstream_cluster_changes)
                ),
            });
        }
        if active_snapshot.security() != candidate.snapshot.security() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("security_posture_changed"),
                message: String::from(
                    "workspace security settings changed; review trusted proxy, anonymous-source, and artifact verification posture before apply",
                ),
            });
        }
    } else {
        warnings.push(ConfigSafetyWarning {
            code: String::from("bootstrap_apply"),
            message: String::from(
                "no active snapshot is loaded yet; this validation is for the first apply and has no prior diff baseline",
            ),
        });
    }

    for listener_name in
        collect_supported_listener_replacements(current_identities, &candidate.listeners)
    {
        warnings.push(ConfigSafetyWarning {
            code: String::from("listener_replacement_planned"),
            message: format!(
                "listener {listener_name} changes bind or protocol semantics and will be staged through replacement plus drain instead of an in-place swap"
            ),
        });
    }

    for listener_name in
        collect_blocked_listener_replacements(current_identities, &candidate.listeners)
    {
        warnings.push(ConfigSafetyWarning {
            code: String::from("listener_rebind_required"),
            message: format!(
                "listener {listener_name} cannot be staged safely on a new socket before retiring the current live listener, so reload will still be rejected"
            ),
        });
    }

    warnings
}

fn collect_supported_listener_replacements(
    current_identities: &BTreeMap<String, CurrentListenerIdentity>,
    candidate_listeners: &BTreeMap<String, CompiledServeListener>,
) -> Vec<String> {
    let mut supported = Vec::new();
    for (name, spec) in candidate_listeners {
        if let Some(current) = current_identities.get(name) {
            if current.needs_replacement(spec) && current.can_stage_replacement(spec) {
                supported.push(name.clone());
            }
        }
    }
    supported
}

fn collect_blocked_listener_replacements(
    current_identities: &BTreeMap<String, CurrentListenerIdentity>,
    candidate_listeners: &BTreeMap<String, CompiledServeListener>,
) -> Vec<String> {
    let mut blocked = Vec::new();
    for (name, spec) in candidate_listeners {
        if let Some(current) = current_identities.get(name) {
            if current.needs_replacement(spec) && !current.can_stage_replacement(spec) {
                blocked.push(name.clone());
            }
        }
    }
    blocked
}

fn summarize_snapshot_changes(changes: &[lb_config_model::SnapshotResourceChange]) -> String {
    changes
        .iter()
        .map(|change| format!("{}:{:?}", change.name, change.kind))
        .collect::<Vec<_>>()
        .join(", ")
}

fn listener_class_name(class: lb_config_model::ListenerClassConfig) -> &'static str {
    match class {
        lb_config_model::ListenerClassConfig::Public => "public",
        lb_config_model::ListenerClassConfig::Admin => "admin",
    }
}

fn listener_protocol_name(protocol: lb_config_model::ListenerProtocolConfig) -> &'static str {
    match protocol {
        lb_config_model::ListenerProtocolConfig::Tcp => "tcp",
        lb_config_model::ListenerProtocolConfig::Http1 => "http1",
        lb_config_model::ListenerProtocolConfig::Https => "https",
        lb_config_model::ListenerProtocolConfig::Http2 => "http2",
        lb_config_model::ListenerProtocolConfig::Http3 => "http3",
        lb_config_model::ListenerProtocolConfig::Auto => "auto",
    }
}

fn listener_bind_mode_name(bind_mode: lb_net_core::ListenerBindMode) -> &'static str {
    match bind_mode {
        lb_net_core::ListenerBindMode::SingleStack => "single_stack",
        lb_net_core::ListenerBindMode::DualStack => "dual_stack",
        lb_net_core::ListenerBindMode::Ipv6Only => "ipv6_only",
    }
}

fn source_aggregation_name(aggregation: lb_runtime::SourceAggregation) -> &'static str {
    match aggregation {
        lb_runtime::SourceAggregation::ExactIp => "exact_ip",
        lb_runtime::SourceAggregation::Ipv4Subnet24 => "ipv4_subnet_24",
        lb_runtime::SourceAggregation::Ipv6Subnet64 => "ipv6_subnet_64",
    }
}

