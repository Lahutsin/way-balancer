fn validate_named_l7_auth_policies(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    validate_named_jwt_auth_policies(resources, registry, report);
    validate_named_external_auth_policies(resources, registry, report);
    validate_named_authorization_policies(resources, registry, report);
    validate_named_upstream_identity_policies(resources, registry, report);
}

fn validate_named_jwt_auth_policies(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.jwt_auth_policies.iter().enumerate() {
        let base_path = format!("policies.jwt_auth_policies[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "jwt auth policy",
            &mut registry.jwt_auth_policies,
            report,
        );

        if policy.spec.issuers.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.issuers"),
                format!("jwt auth policy {} must declare at least one issuer", policy.name),
            ));
        }
        if policy.spec.audiences.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.audiences"),
                format!("jwt auth policy {} must declare at least one audience", policy.name),
            ));
        }

        match policy.spec.jwks.as_ref() {
            Some(crate::JwtJwksSourceConfig::File { path, refresh_secs }) => {
                if path.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.jwks.path"),
                        format!(
                            "jwt auth policy {} must use a non-empty JWKS file path",
                            policy.name
                        ),
                    ));
                }
                if *refresh_secs == 0 {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.jwks.refresh_secs"),
                        format!(
                            "jwt auth policy {} must use a non-zero JWKS refresh interval",
                            policy.name
                        ),
                    ));
                }
            }
            Some(crate::JwtJwksSourceConfig::Remote { url, refresh_secs }) => {
                if url.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.jwks.url"),
                        format!("jwt auth policy {} must use a non-empty JWKS URL", policy.name),
                    ));
                }
                if *refresh_secs == 0 {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.jwks.refresh_secs"),
                        format!(
                            "jwt auth policy {} must use a non-zero JWKS refresh interval",
                            policy.name
                        ),
                    ));
                }
            }
            Some(crate::JwtJwksSourceConfig::Inline { jwks_json }) => {
                if jwks_json.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.jwks.jwks_json"),
                        format!(
                            "jwt auth policy {} must use non-empty inline JWKS JSON",
                            policy.name
                        ),
                    ));
                }
            }
            None => {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.jwks"),
                    format!("jwt auth policy {} must declare a JWKS source", policy.name),
                ));
            }
        }
    }
}

fn validate_named_external_auth_policies(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.external_auth_policies.iter().enumerate() {
        let base_path = format!("policies.external_auth_policies[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "external auth policy",
            &mut registry.external_auth_policies,
            report,
        );

        if policy.spec.endpoint.trim().is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.endpoint"),
                format!("external auth policy {} must use a non-empty endpoint", policy.name),
            ));
        }
        if policy.spec.timeout_ms == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.timeout_ms"),
                format!("external auth policy {} must use a non-zero timeout_ms", policy.name),
            ));
        }

        for (header_index, header_name) in policy.spec.include_headers.iter().enumerate() {
            if lb_proto_http::normalize_http_header_name(header_name).is_none() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.include_headers[{header_index}]"),
                    format!(
                        "external auth policy {} declares invalid header {}",
                        policy.name, header_name
                    ),
                ));
            }
        }

        for (mapping_index, mapping) in policy.spec.context_mappings.iter().enumerate() {
            if mapping.source.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.context_mappings[{mapping_index}].source"),
                    format!(
                        "external auth policy {} must use non-empty context mapping source",
                        policy.name
                    ),
                ));
            }
            if lb_proto_http::normalize_http_header_name(&mapping.target_header).is_none() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.context_mappings[{mapping_index}].target_header"),
                    format!(
                        "external auth policy {} declares invalid target_header {}",
                        policy.name, mapping.target_header
                    ),
                ));
            }
        }
    }
}

fn validate_named_authorization_policies(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.authorization_policies.iter().enumerate() {
        let base_path = format!("policies.authorization_policies[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "authorization policy",
            &mut registry.authorization_policies,
            report,
        );

        for (rule_index, rule) in policy.spec.rules.iter().enumerate() {
            if rule.name.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.rules[{rule_index}].name"),
                    format!("authorization policy {} must use non-empty rule names", policy.name),
                ));
            }
            if rule.any_claims.is_empty()
                && rule.required_scopes.is_empty()
                && rule.required_roles.is_empty()
            {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.rules[{rule_index}]"),
                    format!(
                        "authorization policy {} rule {} must declare at least one matcher",
                        policy.name, rule.name
                    ),
                ));
            }
        }
    }
}

fn validate_named_upstream_identity_policies(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.upstream_identity_policies.iter().enumerate() {
        let base_path = format!("policies.upstream_identity_policies[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "upstream identity policy",
            &mut registry.upstream_identity_policies,
            report,
        );

        match &policy.spec.mode {
            crate::UpstreamIdentityModeConfig::Spiffe => {}
            crate::UpstreamIdentityModeConfig::SpireWorkloadApi { socket_path, trust_domain } => {
                if socket_path.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.mode.socket_path"),
                        format!(
                            "upstream identity policy {} must use a non-empty SPIRE socket_path",
                            policy.name
                        ),
                    ));
                }
                if trust_domain.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.mode.trust_domain"),
                        format!(
                            "upstream identity policy {} must use a non-empty SPIRE trust_domain",
                            policy.name
                        ),
                    ));
                }
            }
        }

        match &policy.spec.trust_bundle {
            crate::IdentityTrustBundleSourceConfig::File { path, refresh_secs } => {
                if path.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.trust_bundle.path"),
                        format!(
                            "upstream identity policy {} must use a non-empty trust bundle path",
                            policy.name
                        ),
                    ));
                }
                if *refresh_secs == 0 {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.trust_bundle.refresh_secs"),
                        format!(
                            "upstream identity policy {} must use non-zero trust bundle refresh_secs",
                            policy.name
                        ),
                    ));
                }
            }
            crate::IdentityTrustBundleSourceConfig::InlinePem { pem } => {
                if pem.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.trust_bundle.pem"),
                        format!(
                            "upstream identity policy {} must use non-empty inline trust bundle PEM",
                            policy.name
                        ),
                    ));
                }
            }
        }

        if policy.spec.allowed_spiffe_ids.is_empty() && policy.spec.allowed_trust_domains.is_empty()
        {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec"),
                format!(
                    "upstream identity policy {} must declare allowed_spiffe_ids or allowed_trust_domains",
                    policy.name
                ),
            ));
        }

        for (spiffe_index, spiffe_id) in policy.spec.allowed_spiffe_ids.iter().enumerate() {
            if !spiffe_id.starts_with("spiffe://") {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.allowed_spiffe_ids[{spiffe_index}]"),
                    format!(
                        "upstream identity policy {} declares invalid SPIFFE ID {}",
                        policy.name, spiffe_id
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod l7_auth_coverage_regressions {
    use super::{PolicyRegistry, ValidationCode, ValidationReport};
    use crate::{
        AuthContextMappingConfig, AuthorizationDecisionConfig, AuthorizationPolicyConfig,
        AuthorizationRuleConfig, ExternalAuthPolicyConfig, IdentityTrustBundleSourceConfig,
        JwtAuthPolicyConfig, JwtJwksSourceConfig, NamedAuthorizationPolicyConfig,
        NamedExternalAuthPolicyConfig, NamedJwtAuthPolicyConfig, NamedUpstreamIdentityPolicyConfig,
        PolicyResourcesConfig, UpstreamIdentityModeConfig, UpstreamIdentityPolicyConfig,
    };
    use std::collections::BTreeSet;

    #[test]
    fn validates_jwt_external_authorization_and_upstream_identity_edges() {
        let resources = PolicyResourcesConfig {
            jwt_auth_policies: vec![
                NamedJwtAuthPolicyConfig {
                    name: String::new(),
                    spec: JwtAuthPolicyConfig::default(),
                },
                NamedJwtAuthPolicyConfig {
                    name: String::from("file"),
                    spec: JwtAuthPolicyConfig {
                        jwks: Some(JwtJwksSourceConfig::File {
                            path: String::from(" "),
                            refresh_secs: 0,
                        }),
                        ..JwtAuthPolicyConfig::default()
                    },
                },
                NamedJwtAuthPolicyConfig {
                    name: String::from("remote"),
                    spec: JwtAuthPolicyConfig {
                        jwks: Some(JwtJwksSourceConfig::Remote {
                            url: String::new(),
                            refresh_secs: 0,
                        }),
                        ..JwtAuthPolicyConfig::default()
                    },
                },
                NamedJwtAuthPolicyConfig {
                    name: String::from("inline"),
                    spec: JwtAuthPolicyConfig {
                        jwks: Some(JwtJwksSourceConfig::Inline { jwks_json: String::from(" ") }),
                        ..JwtAuthPolicyConfig::default()
                    },
                },
            ],
            external_auth_policies: vec![NamedExternalAuthPolicyConfig {
                name: String::from("external"),
                spec: ExternalAuthPolicyConfig {
                    endpoint: String::from(" "),
                    timeout_ms: 0,
                    include_headers: vec![String::from("not a header")],
                    context_mappings: vec![AuthContextMappingConfig {
                        source: String::from(" "),
                        target_header: String::from("invalid header"),
                        required: true,
                    }],
                    ..ExternalAuthPolicyConfig::default()
                },
            }],
            authorization_policies: vec![NamedAuthorizationPolicyConfig {
                name: String::from("authorization"),
                spec: AuthorizationPolicyConfig {
                    rules: vec![
                        AuthorizationRuleConfig::default(),
                        AuthorizationRuleConfig {
                            name: String::from("allow-claim"),
                            action: AuthorizationDecisionConfig::Allow,
                            any_claims: vec![String::from("sub")],
                            required_scopes: Vec::new(),
                            required_roles: Vec::new(),
                        },
                    ],
                    default_decision: AuthorizationDecisionConfig::Deny,
                },
            }],
            upstream_identity_policies: vec![
                NamedUpstreamIdentityPolicyConfig {
                    name: String::from("spiffe"),
                    spec: UpstreamIdentityPolicyConfig {
                        allowed_spiffe_ids: vec![
                            String::from("not-spiffe"),
                            String::from("spiffe://example.org/service"),
                        ],
                        allowed_trust_domains: vec![String::from("example.org")],
                        ..UpstreamIdentityPolicyConfig::default()
                    },
                },
                NamedUpstreamIdentityPolicyConfig {
                    name: String::from("spire"),
                    spec: UpstreamIdentityPolicyConfig {
                        mode: UpstreamIdentityModeConfig::SpireWorkloadApi {
                            socket_path: String::from(" "),
                            trust_domain: String::new(),
                        },
                        trust_bundle: IdentityTrustBundleSourceConfig::InlinePem {
                            pem: String::from(" "),
                        },
                        allowed_spiffe_ids: Vec::new(),
                        allowed_trust_domains: Vec::new(),
                    },
                },
                NamedUpstreamIdentityPolicyConfig {
                    name: String::from("file-bundle"),
                    spec: UpstreamIdentityPolicyConfig {
                        trust_bundle: IdentityTrustBundleSourceConfig::File {
                            path: String::new(),
                            refresh_secs: 0,
                        },
                        allowed_trust_domains: vec![String::from("example.org")],
                        ..UpstreamIdentityPolicyConfig::default()
                    },
                },
            ],
            ..PolicyResourcesConfig::default()
        };
        let mut report = ValidationReport::default();
        let _registry = PolicyRegistry::new(&resources, &BTreeSet::new(), &mut report);
        for (code, path) in [
            (ValidationCode::EmptyResourceName, "policies.jwt_auth_policies[0].name"),
            (ValidationCode::InvalidPolicyField, "policies.jwt_auth_policies[0].spec.issuers"),
            (ValidationCode::InvalidPolicyField, "policies.jwt_auth_policies[0].spec.audiences"),
            (ValidationCode::InvalidPolicyField, "policies.jwt_auth_policies[0].spec.jwks"),
            (ValidationCode::InvalidPolicyField, "policies.jwt_auth_policies[1].spec.jwks.path"),
            (
                ValidationCode::InvalidPolicyField,
                "policies.jwt_auth_policies[1].spec.jwks.refresh_secs",
            ),
            (ValidationCode::InvalidPolicyField, "policies.jwt_auth_policies[2].spec.jwks.url"),
            (
                ValidationCode::InvalidPolicyField,
                "policies.jwt_auth_policies[2].spec.jwks.refresh_secs",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.jwt_auth_policies[3].spec.jwks.jwks_json",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.external_auth_policies[0].spec.endpoint",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.external_auth_policies[0].spec.timeout_ms",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.external_auth_policies[0].spec.include_headers[0]",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.external_auth_policies[0].spec.context_mappings[0].source",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.external_auth_policies[0].spec.context_mappings[0].target_header",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.authorization_policies[0].spec.rules[0].name",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.authorization_policies[0].spec.rules[0]",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.upstream_identity_policies[0].spec.allowed_spiffe_ids[0]",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.upstream_identity_policies[1].spec.mode.socket_path",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.upstream_identity_policies[1].spec.mode.trust_domain",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.upstream_identity_policies[1].spec.trust_bundle.pem",
            ),
            (ValidationCode::InvalidPolicyField, "policies.upstream_identity_policies[1].spec"),
            (
                ValidationCode::InvalidPolicyField,
                "policies.upstream_identity_policies[2].spec.trust_bundle.path",
            ),
            (
                ValidationCode::InvalidPolicyField,
                "policies.upstream_identity_policies[2].spec.trust_bundle.refresh_secs",
            ),
        ] {
            assert!(
                report.errors.iter().any(|error| error.code == code && error.path == path),
                "missing {path}"
            );
        }
    }
}
