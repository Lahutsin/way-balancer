fn validate_named_retry_budgets(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.retry_budgets.iter().enumerate() {
        let base_path = format!("policies.retry_budgets[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "retry budget policy",
            &mut registry.retry_budgets,
            report,
        );
        if policy.spec.window_ms == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.window_ms"),
                format!("retry budget policy {} must use a window greater than zero", policy.name),
            ));
        }
    }
}

fn validate_named_timeout_hierarchies(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.timeout_hierarchies.iter().enumerate() {
        let base_path = format!("policies.timeout_hierarchies[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "timeout hierarchy policy",
            &mut registry.timeout_hierarchies,
            report,
        );
        let spec = &policy.spec;
        let per_try_timeout_ms = spec.per_try_timeout_ms.unwrap_or(spec.attempt_timeout_ms);
        let has_zero = spec.request_timeout_ms == 0
            || spec.attempt_timeout_ms == 0
            || per_try_timeout_ms == 0
            || spec.connect_timeout_ms == 0
            || spec.idle_timeout_ms == 0;
        let invalid_order = per_try_timeout_ms > spec.request_timeout_ms
            || spec.connect_timeout_ms > per_try_timeout_ms
            || spec.idle_timeout_ms > per_try_timeout_ms;
        if has_zero || invalid_order {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec"),
                format!(
                    "timeout hierarchy policy {} must use non-zero values with connect/idle <= per_try <= request",
                    policy.name
                ),
            ));
        }
    }
}

fn validate_named_circuit_breakers(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.circuit_breakers.iter().enumerate() {
        let base_path = format!("policies.circuit_breakers[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "circuit breaker policy",
            &mut registry.circuit_breakers,
            report,
        );
        if policy.spec.open_failure_threshold == 0
            || policy.spec.open_duration_ms == 0
            || policy.spec.half_open_success_threshold == 0
        {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec"),
                format!(
                    "circuit breaker policy {} must use non-zero thresholds and duration",
                    policy.name
                ),
            ));
        }
    }
}

