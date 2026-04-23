fn validate_named_local_rate_limits(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.local_rate_limits.iter().enumerate() {
        let base_path = format!("policies.local_rate_limits[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "local rate-limit policy",
            &mut registry.local_rate_limits,
            report,
        );
        validate_rate_limit_policy(&policy.spec, &base_path, report);
        registry.rate_limit_scopes.insert(policy.name.clone(), policy.spec.scope.clone());
    }
}

fn validate_named_local_concurrency_limits(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.local_concurrency_limits.iter().enumerate() {
        let base_path = format!("policies.local_concurrency_limits[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "local concurrency-limit policy",
            &mut registry.local_concurrency_limits,
            report,
        );
        validate_concurrency_limit_policy(&policy.spec, &base_path, report);
        registry.concurrency_limit_scopes.insert(policy.name.clone(), policy.spec.scope.clone());
    }
}


fn validate_rate_limit_policy(
    policy: &LocalRateLimitPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    validate_local_limit_scope(&policy.scope, &format!("{base_path}.spec.scope"), report);
    if policy.requests_per_window == 0 || policy.window_ms == 0 || policy.max_tracked_keys == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "local rate-limit policy must use non-zero requests_per_window, window_ms, and max_tracked_keys",
        ));
    }
}

fn validate_concurrency_limit_policy(
    policy: &LocalConcurrencyLimitPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    validate_local_limit_scope(&policy.scope, &format!("{base_path}.spec.scope"), report);
    if policy.max_concurrent == 0 || policy.max_tracked_keys == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "local concurrency-limit policy must use non-zero max_concurrent and max_tracked_keys",
        ));
    }
}

fn validate_local_limit_scope(
    scope: &LocalLimitScopeConfig,
    path: &str,
    report: &mut ValidationReport,
) {
    match scope {
        LocalLimitScopeConfig::Listener { name }
        | LocalLimitScopeConfig::Route { name }
        | LocalLimitScopeConfig::UpstreamCluster { name } => {
            if name.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    path,
                    "local limit scope name must not be empty",
                ));
            }
        }
        LocalLimitScopeConfig::RouteDestination {
            route,
            upstream_cluster,
        } => {
            if route.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{path}.route"),
                    "local limit route-destination scope route must not be empty",
                ));
            }
            if upstream_cluster.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{path}.upstream_cluster"),
                    "local limit route-destination scope upstream_cluster must not be empty",
                ));
            }
        }
    }
}

