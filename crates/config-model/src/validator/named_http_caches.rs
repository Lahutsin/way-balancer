fn validate_named_http_caches(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.http_caches.iter().enumerate() {
        let base_path = format!("policies.http_caches[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "http cache policy",
            &mut registry.http_caches,
            report,
        );
        validate_http_cache_policy(&policy.spec, &base_path, report);
    }
}

fn validate_http_cache_policy(
    policy: &HttpCachePolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    if policy.methods.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec.methods"),
            "http cache policy must declare at least one cacheable method",
        ));
    }

    let mut seen_methods = BTreeSet::new();
    for (index, method) in policy.methods.iter().enumerate() {
        let method_key = format!("{method:?}");
        if !seen_methods.insert(method_key) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                format!("{base_path}.spec.methods[{index}]"),
                "http cache policy methods must not repeat entries",
            ));
        }
    }

    if policy.default_ttl_secs == 0
        || policy.max_ttl_secs == 0
        || policy.max_object_bytes == 0
        || policy.default_ttl_secs > policy.max_ttl_secs
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "http cache policy must use non-zero TTLs and max_object_bytes with default_ttl_secs <= max_ttl_secs",
        ));
    }

    if policy.cacheable_status_codes.is_empty()
        || policy.cacheable_status_codes.iter().any(|status| !(100..=599).contains(status))
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec.cacheable_status_codes"),
            "http cache policy must use non-empty cacheable_status_codes within the HTTP status code range",
        ));
    }

    validate_named_header_list(
        &policy.vary_headers,
        &format!("{base_path}.spec.vary_headers"),
        report,
    );
    validate_cache_key_policy(&policy.cache_key, &format!("{base_path}.spec.cache_key"), report);

    match policy.storage {
        HttpCacheStorageConfig::Memory { max_entries, max_bytes } => {
            if max_entries == 0 || max_bytes == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.storage"),
                    "memory cache storage must use non-zero max_entries and max_bytes",
                ));
            }
        }
    }
}

fn validate_cache_key_policy(
    policy: &CacheKeyPolicyConfig,
    path: &str,
    report: &mut ValidationReport,
) {
    validate_named_header_list(&policy.headers, &format!("{path}.headers"), report);
    if !policy.include_host && !policy.include_method && policy.headers.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            path,
            "cache key policy must include at least one differentiating component",
        ));
    }
}

