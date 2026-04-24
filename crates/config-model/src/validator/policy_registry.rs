struct PolicyRegistry {
    local_rate_limits: BTreeSet<String>,
    local_concurrency_limits: BTreeSet<String>,
    hostile_edge_protections: BTreeSet<String>,
    retry_budgets: BTreeSet<String>,
    timeout_hierarchies: BTreeSet<String>,
    circuit_breakers: BTreeSet<String>,
    overload_responses: BTreeSet<String>,
    http_caches: BTreeSet<String>,
    transforms: BTreeSet<String>,
    traffic_mirrors: BTreeSet<String>,
    fault_injections: BTreeSet<String>,
    jwt_auth_policies: BTreeSet<String>,
    external_auth_policies: BTreeSet<String>,
    authorization_policies: BTreeSet<String>,
    upstream_identity_policies: BTreeSet<String>,
    request_classification_policies: BTreeSet<String>,
    traffic_mirror_specs: BTreeMap<String, crate::TrafficMirrorPolicyConfig>,
    rate_limit_scopes: BTreeMap<String, LocalLimitScopeConfig>,
    concurrency_limit_scopes: BTreeMap<String, LocalLimitScopeConfig>,
}

impl PolicyRegistry {
    fn new(
        resources: &PolicyResourcesConfig,
        upstream_names: &BTreeSet<String>,
        report: &mut ValidationReport,
    ) -> Self {
        let mut registry = Self {
            local_rate_limits: BTreeSet::new(),
            local_concurrency_limits: BTreeSet::new(),
            hostile_edge_protections: BTreeSet::new(),
            retry_budgets: BTreeSet::new(),
            timeout_hierarchies: BTreeSet::new(),
            circuit_breakers: BTreeSet::new(),
            overload_responses: BTreeSet::new(),
            http_caches: BTreeSet::new(),
            transforms: BTreeSet::new(),
            traffic_mirrors: BTreeSet::new(),
            fault_injections: BTreeSet::new(),
            jwt_auth_policies: BTreeSet::new(),
            external_auth_policies: BTreeSet::new(),
            authorization_policies: BTreeSet::new(),
            upstream_identity_policies: BTreeSet::new(),
            request_classification_policies: BTreeSet::new(),
            traffic_mirror_specs: BTreeMap::new(),
            rate_limit_scopes: BTreeMap::new(),
            concurrency_limit_scopes: BTreeMap::new(),
        };

        validate_named_local_rate_limits(resources, &mut registry, report);
        validate_named_local_concurrency_limits(resources, &mut registry, report);
        validate_named_hostile_edge_protections(resources, &mut registry, report);
        validate_named_retry_budgets(resources, &mut registry, report);
        validate_named_timeout_hierarchies(resources, &mut registry, report);
        validate_named_circuit_breakers(resources, &mut registry, report);
        validate_named_overload_responses(resources, &mut registry, report);
        validate_named_http_caches(resources, &mut registry, report);
        validate_named_transforms(resources, &mut registry, report);
        validate_named_traffic_mirrors(resources, upstream_names, &mut registry, report);
        validate_named_fault_injections(resources, &mut registry, report);
        validate_named_l7_auth_policies(resources, &mut registry, report);
        validate_named_request_classification_policies(resources, &mut registry, report);

        registry
    }
}

fn validate_named_traffic_mirrors(
    resources: &PolicyResourcesConfig,
    upstream_names: &BTreeSet<String>,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.traffic_mirrors.iter().enumerate() {
        let base_path = format!("policies.traffic_mirrors[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "traffic mirroring policy",
            &mut registry.traffic_mirrors,
            report,
        );
        if policy.spec.percentage == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.percentage"),
                "traffic mirroring percentage must be between 1 and 100",
            ));
        }
        if policy.spec.target_upstream_cluster.trim().is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.target_upstream_cluster"),
                "traffic mirroring target_upstream_cluster must not be empty",
            ));
        } else if !upstream_names.contains(policy.spec.target_upstream_cluster.trim()) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidUpstreamReference,
                format!("{base_path}.spec.target_upstream_cluster"),
                format!(
                    "traffic mirroring policy {} references unknown upstream cluster {}",
                    policy.name, policy.spec.target_upstream_cluster
                ),
            ));
        }
        for (method_index, method) in policy.spec.methods.iter().enumerate() {
            if lb_proto_http::normalize_http_method(method).is_none() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.methods[{method_index}]"),
                    format!(
                        "traffic mirroring policy {} declares invalid method {}",
                        policy.name, method
                    ),
                ));
            }
        }
        registry.traffic_mirror_specs.insert(policy.name.clone(), policy.spec.clone());
    }
}

