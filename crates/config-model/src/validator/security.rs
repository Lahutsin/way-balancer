fn validate_security(config: &WorkspaceConfig, report: &mut ValidationReport) {
    let security = &config.security;
    if security.insecure_dev_mode.enabled {
        let acknowledgement = security
            .insecure_dev_mode
            .acknowledgement
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if acknowledgement.is_none() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                "security.insecure_dev_mode.acknowledgement",
                "insecure_dev_mode requires a non-empty acknowledgement",
            ));
        }
    }

    if matches!(security.artifact_verification.mode, ArtifactVerificationMode::Disabled)
        && !security.insecure_dev_mode.enabled
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InsecureModeGated,
            "security.artifact_verification.mode",
            "artifact verification may only be disabled when insecure_dev_mode.enabled=true",
        ));
    }

    if matches!(security.artifact_verification.mode, ArtifactVerificationMode::Enforced)
        && security.artifact_verification.trusted_signers.iter().any(|trusted_signer| {
            trusted_signer.identity.trim().is_empty()
                || trusted_signer.public_key_ed25519.trim().is_empty()
        })
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidSecurityDefaults,
            "security.artifact_verification.trusted_signers",
            "artifact verification trusted_signers must not contain empty identities or public keys",
        ));
    }

    let mut trusted_signer_ids = BTreeSet::new();
    for (index, trusted_signer) in security.artifact_verification.trusted_signers.iter().enumerate()
    {
        let normalized_identity = trusted_signer.identity.trim();
        if normalized_identity.len() > 128 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                format!("security.artifact_verification.trusted_signers[{index}].identity"),
                "artifact verification signer identity exceeds max length",
            ));
        }
        if !crate::security::is_lower_hex_ed25519_public_key(&trusted_signer.public_key_ed25519) {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                format!(
                    "security.artifact_verification.trusted_signers[{index}].public_key_ed25519"
                ),
                "artifact verification signer public key must be a lowercase ed25519 hex string",
            ));
        }
        if !trusted_signer_ids.insert(normalized_identity) {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                "security.artifact_verification.trusted_signers",
                "artifact verification trusted_signers must not repeat identities",
            ));
        }
    }

    validate_anonymous_source_filter(&security.anonymous_source_filter, report);
    validate_trusted_client_ip(&security.trusted_client_ip, report);
}

fn validate_trusted_client_ip(config: &TrustedClientIpConfig, report: &mut ValidationReport) {
    for (index, cidr) in config.trusted_proxy_cidrs.iter().enumerate() {
        if cidr.parse::<ipnet::IpNet>().is_err() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                format!("security.trusted_client_ip.trusted_proxy_cidrs[{index}]"),
                format!("trusted proxy CIDR must be a valid IPv4 or IPv6 CIDR: {cidr}"),
            ));
        }
    }
}

fn validate_anonymous_source_filter(
    filter: &AnonymousSourceFilterConfig,
    report: &mut ValidationReport,
) {
    for (path, cidrs) in [
        ("security.anonymous_source_filter.deny_cidrs", &filter.deny_cidrs),
        ("security.anonymous_source_filter.vpn_cidrs", &filter.vpn_cidrs),
        ("security.anonymous_source_filter.proxy_cidrs", &filter.proxy_cidrs),
        ("security.anonymous_source_filter.socks_cidrs", &filter.socks_cidrs),
        ("security.anonymous_source_filter.tor_exit_cidrs", &filter.tor_exit_cidrs),
    ] {
        for (index, cidr) in cidrs.iter().enumerate() {
            if cidr.parse::<ipnet::IpNet>().is_err() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidSecurityDefaults,
                    format!("{path}[{index}]"),
                    format!("anonymous source CIDR must be a valid IPv4 or IPv6 CIDR: {cidr}"),
                ));
            }
        }
    }
}

