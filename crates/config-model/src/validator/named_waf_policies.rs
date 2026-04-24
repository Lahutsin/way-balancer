fn validate_named_request_classification_policies(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.request_classification_policies.iter().enumerate() {
        let base_path = format!("policies.request_classification_policies[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "request classification policy",
            &mut registry.request_classification_policies,
            report,
        );

        if policy.spec.challenge_threshold >= policy.spec.block_threshold {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec"),
                format!(
                    "request classification policy {} must use challenge_threshold < block_threshold",
                    policy.name
                ),
            ));
        }

        let weights = &policy.spec.signal_weights;
        if weights.header_anomaly == 0
            && weights.body_anomaly == 0
            && weights.query_anomaly == 0
            && weights.user_agent_anomaly == 0
            && weights.reputation == 0
            && weights.bot_signal == 0
        {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.signal_weights"),
                format!(
                    "request classification policy {} must enable at least one non-zero signal weight",
                    policy.name
                ),
            ));
        }

        for (header_index, header_name) in policy.spec.context.include_headers.iter().enumerate() {
            if lb_proto_http::normalize_http_header_name(header_name).is_none() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.context.include_headers[{header_index}]"),
                    format!(
                        "request classification policy {} declares invalid header {}",
                        policy.name, header_name
                    ),
                ));
            }
        }

        for (query_index, query_name) in policy.spec.context.include_query_params.iter().enumerate() {
            if query_name.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.context.include_query_params[{query_index}]"),
                    format!(
                        "request classification policy {} must use non-empty query param names",
                        policy.name
                    ),
                ));
            }
        }

        if policy.spec.header_scoring.max_header_count == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.header_scoring.max_header_count"),
                format!(
                    "request classification policy {} must use non-zero max_header_count",
                    policy.name
                ),
            ));
        }
        if policy.spec.header_scoring.max_header_value_length == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.header_scoring.max_header_value_length"),
                format!(
                    "request classification policy {} must use non-zero max_header_value_length",
                    policy.name
                ),
            ));
        }
        if policy.spec.header_scoring.max_duplicate_headers_per_name == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!(
                    "{base_path}.spec.header_scoring.max_duplicate_headers_per_name"
                ),
                format!(
                    "request classification policy {} must use non-zero max_duplicate_headers_per_name",
                    policy.name
                ),
            ));
        }

        for (header_index, header_name) in policy.spec.header_scoring.suspicious_headers.iter().enumerate() {
            if lb_proto_http::normalize_http_header_name(header_name).is_none() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.header_scoring.suspicious_headers[{header_index}]"),
                    format!(
                        "request classification policy {} declares invalid suspicious header {}",
                        policy.name, header_name
                    ),
                ));
            }
        }

        for (pattern_index, pattern) in policy
            .spec
            .header_scoring
            .suspicious_user_agent_patterns
            .iter()
            .enumerate()
        {
            if pattern.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!(
                        "{base_path}.spec.header_scoring.suspicious_user_agent_patterns[{pattern_index}]"
                    ),
                    format!(
                        "request classification policy {} must use non-empty suspicious user-agent patterns",
                        policy.name
                    ),
                ));
            }
        }

        if policy.spec.body_scoring.max_inspect_bytes == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.body_scoring.max_inspect_bytes"),
                format!(
                    "request classification policy {} must use non-zero max_inspect_bytes",
                    policy.name
                ),
            ));
        }
        if policy.spec.body_scoring.max_body_bytes == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.body_scoring.max_body_bytes"),
                format!(
                    "request classification policy {} must use non-zero max_body_bytes",
                    policy.name
                ),
            ));
        }
        if policy.spec.body_scoring.min_suspicious_token_length == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.body_scoring.min_suspicious_token_length"),
                format!(
                    "request classification policy {} must use non-zero min_suspicious_token_length",
                    policy.name
                ),
            ));
        }

        for (pattern_index, pattern) in policy.spec.body_scoring.suspicious_patterns.iter().enumerate() {
            if pattern.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.body_scoring.suspicious_patterns[{pattern_index}]"),
                    format!(
                        "request classification policy {} must use non-empty suspicious body patterns",
                        policy.name
                    ),
                ));
            }
        }

        for (content_type_index, content_type) in policy
            .spec
            .body_scoring
            .allowlisted_content_types
            .iter()
            .enumerate()
        {
            if content_type.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!(
                        "{base_path}.spec.body_scoring.allowlisted_content_types[{content_type_index}]"
                    ),
                    format!(
                        "request classification policy {} must use non-empty allowlisted content types",
                        policy.name
                    ),
                ));
            }
        }
    }
}
