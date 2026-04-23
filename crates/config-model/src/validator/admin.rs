fn validate_admin_listener_policy(
    listener: &crate::ListenerResourceConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    if listener.class != ListenerClassConfig::Admin && !listener.admin.is_default() {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.admin"),
            "admin policy is supported only on admin listeners",
        ));
        return;
    }

    if listener.class != ListenerClassConfig::Admin {
        return;
    }

    if listener.protocol == ListenerProtocolConfig::Http1
        && !listener.bind_address.ip().is_loopback()
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.protocol"),
            "admin listeners exposed beyond loopback must use https",
        ));
    }

    for (index, cidr) in listener.admin.allowed_source_cidrs.iter().enumerate() {
        if cidr.parse::<ipnet::IpNet>().is_err() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidListenerField,
                format!("{base_path}.admin.allowed_source_cidrs[{index}]"),
                format!("admin allowed source CIDR must be a valid IPv4 or IPv6 CIDR: {cidr}"),
            ));
        }
    }

    if listener.admin.rate_limit.requests_per_minute == 0 || listener.admin.rate_limit.burst == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.admin.rate_limit"),
            "admin rate limits must use non-zero requests_per_minute and burst values",
        ));
    }

    if listener.admin.audit.max_retained_events == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.admin.audit.max_retained_events"),
            "admin audit retention must keep at least one event",
        ));
    }

    match &listener.admin.auth {
        AdminAuthPolicyConfig::Bearer { secret_env, permissions } => {
            if secret_env.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.admin.auth.secret_env"),
                    "admin bearer auth must declare a non-empty secret_env",
                ));
            }
            validate_admin_permissions(
                permissions,
                &format!("{base_path}.admin.auth.permissions"),
                report,
            );
        }
        AdminAuthPolicyConfig::SignedHeaders { operators, max_clock_skew_secs, nonce_ttl_secs } => {
            if operators.is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.admin.auth.operators"),
                    "signed admin auth must declare at least one operator",
                ));
            }
            if *max_clock_skew_secs == 0 || *nonce_ttl_secs == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.admin.auth"),
                    "signed admin auth must use non-zero max_clock_skew_secs and nonce_ttl_secs",
                ));
            }

            let mut seen_operator_ids = BTreeSet::new();
            for (index, operator) in operators.iter().enumerate() {
                let operator_path = format!("{base_path}.admin.auth.operators[{index}]");
                if operator.id.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{operator_path}.id"),
                        "admin operator id must not be empty",
                    ));
                } else if !seen_operator_ids.insert(operator.id.trim().to_string()) {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::DuplicateResourceName,
                        format!("{operator_path}.id"),
                        format!("admin operator {} is declared more than once", operator.id),
                    ));
                }
                if operator.secret_env.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{operator_path}.secret_env"),
                        "admin operator secret_env must not be empty",
                    ));
                }
                validate_admin_permissions(
                    &operator.permissions,
                    &format!("{operator_path}.permissions"),
                    report,
                );
            }
        }
    }
}

fn listener_protocol_name(protocol: ListenerProtocolConfig) -> &'static str {
    match protocol {
        ListenerProtocolConfig::Tcp => "tcp",
        ListenerProtocolConfig::Http1 => "http1",
        ListenerProtocolConfig::Https => "https",
        ListenerProtocolConfig::Http2 => "http2",
        ListenerProtocolConfig::Http3 => "http3",
        ListenerProtocolConfig::Auto => "auto",
    }
}

fn validate_admin_permissions(
    permissions: &[AdminAuthorizationScopeConfig],
    path: &str,
    report: &mut ValidationReport,
) {
    if permissions.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerField,
            path.to_string(),
            "admin permissions must declare at least one scope",
        ));
        return;
    }

    let mut seen = BTreeSet::new();
    for permission in permissions {
        if !seen.insert(*permission) {
            let scope = match permission {
                AdminAuthorizationScopeConfig::Read => "read",
                AdminAuthorizationScopeConfig::Audit => "audit",
                AdminAuthorizationScopeConfig::Write => "write",
            };
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidListenerField,
                path.to_string(),
                format!("admin permissions must not repeat scope {scope}"),
            ));
        }
    }
}

