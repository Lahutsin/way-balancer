fn validate_named_hostile_edge_protections(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.hostile_edge_protections.iter().enumerate() {
        let base_path = format!("policies.hostile_edge_protections[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "hostile-edge protection policy",
            &mut registry.hostile_edge_protections,
            report,
        );
        validate_hostile_edge_policy(&policy.spec, &base_path, report);
    }
}


fn validate_named_overload_responses(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.overload_responses.iter().enumerate() {
        let base_path = format!("policies.overload_responses[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "overload response policy",
            &mut registry.overload_responses,
            report,
        );
        validate_overload_policy(&policy.spec, policy, &base_path, report);
    }
}

fn validate_overload_policy(
    policy: &OverloadResponsePolicyConfig,
    named: &NamedOverloadResponsePolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    let has_zero = policy.signal_window_ms == 0
        || policy.constrained_signal_threshold == 0
        || policy.shedding_signal_threshold == 0
        || policy.brownout_signal_threshold == 0;
    let invalid_order = policy.constrained_signal_threshold > policy.shedding_signal_threshold
        || policy.shedding_signal_threshold > policy.brownout_signal_threshold;
    if has_zero || invalid_order {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            format!(
                "overload response policy {} must use non-zero thresholds with constrained <= shedding <= brownout",
                named.name
            ),
        ));
    }

    let mut seen_features = BTreeSet::new();
    for (feature_index, feature) in policy.brownout_features.iter().enumerate() {
        let feature_path = format!("{base_path}.spec.brownout_features[{feature_index}]");
        let name = feature.name.trim();
        if name.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{feature_path}.name"),
                format!(
                    "overload response policy {} contains an empty brownout feature name",
                    named.name
                ),
            ));
            continue;
        }
        let normalized = normalize_component(name);
        if !seen_features.insert(normalized) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                format!("{feature_path}.name"),
                format!(
                    "overload response policy {} contains duplicate brownout feature {name}",
                    named.name
                ),
            ));
        }
    }
}

fn validate_hostile_edge_policy(
    policy: &HostileEdgeProtectionPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    if policy.source_quota.is_none() && policy.handshake_guard.is_none() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "hostile-edge protection policy must enable at least one guard",
        ));
    }

    if let Some(source_quota) = &policy.source_quota {
        if source_quota.max_active_per_source == 0 || source_quota.max_tracked_sources == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.source_quota"),
                "hostile-edge source quota must use non-zero max_active_per_source and max_tracked_sources",
            ));
        }
    }

    if let Some(handshake_guard) = &policy.handshake_guard {
        if handshake_guard.max_inflight == 0 || handshake_guard.timeout_ms == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.handshake_guard"),
                "hostile-edge handshake guard must use non-zero max_inflight and timeout_ms",
            ));
        }
    }
}

