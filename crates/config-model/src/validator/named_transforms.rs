fn validate_named_transforms(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.transforms.iter().enumerate() {
        let base_path = format!("policies.transforms[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "transform policy",
            &mut registry.transforms,
            report,
        );
        validate_transform_policy(&policy.spec, &base_path, report);
    }
}

fn validate_transform_policy(
    policy: &TransformPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    let has_any_transform = policy.request.path_rewrite.is_some()
        || policy.request.host_rewrite.is_some()
        || !policy.request.header_mutations.is_empty()
        || !policy.response.header_mutations.is_empty();
    if !has_any_transform {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "transform policy must declare at least one request or response transform",
        ));
    }

    if let Some(path_rewrite) = &policy.request.path_rewrite {
        match path_rewrite {
            PathRewriteTransformConfig::ReplacePrefix { match_prefix, replacement } => {
                if match_prefix.trim().is_empty()
                    || !match_prefix.starts_with('/')
                    || replacement.trim().is_empty()
                    || !replacement.starts_with('/')
                {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.request.path_rewrite"),
                        "path rewrite replace_prefix must use non-empty match_prefix and replacement values that start with '/'",
                    ));
                }
            }
        }
    }

    if let Some(host_rewrite) = &policy.request.host_rewrite {
        if lb_proto_http::canonicalize_host(host_rewrite).is_err() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.request.host_rewrite"),
                "host rewrite must use a valid canonical host or authority value",
            ));
        }
    }

    validate_header_mutations(
        &policy.request.header_mutations,
        &format!("{base_path}.spec.request.header_mutations"),
        HeaderMutationTarget::Request,
        report,
    );
    validate_header_mutations(
        &policy.response.header_mutations,
        &format!("{base_path}.spec.response.header_mutations"),
        HeaderMutationTarget::Response,
        report,
    );
}

