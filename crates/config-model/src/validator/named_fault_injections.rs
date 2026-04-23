fn validate_named_fault_injections(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.fault_injections.iter().enumerate() {
        let base_path = format!("policies.fault_injections[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "fault injection policy",
            &mut registry.fault_injections,
            report,
        );
        if policy.spec.delay.is_none() && policy.spec.abort.is_none() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec"),
                "fault injection policy must declare at least one of delay or abort",
            ));
        }
        if let Some(delay) = &policy.spec.delay {
            if delay.percentage == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.delay.percentage"),
                    "fault injection delay percentage must be between 1 and 100",
                ));
            }
            if delay.fixed_delay_ms == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.delay.fixed_delay_ms"),
                    "fault injection fixed_delay_ms must be greater than zero",
                ));
            }
        }
        if let Some(abort) = &policy.spec.abort {
            if abort.percentage == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.abort.percentage"),
                    "fault injection abort percentage must be between 1 and 100",
                ));
            }
            if !(400..=599).contains(&abort.http_status) {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.abort.http_status"),
                    "fault injection abort http_status must be between 400 and 599",
                ));
            }
        }
    }
}

