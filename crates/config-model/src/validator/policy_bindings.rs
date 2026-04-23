fn validate_policy_binding(
    binding: &PolicyBindingConfig,
    base_path: &str,
    target: PolicyBindingTarget<'_>,
    registry: &PolicyRegistry,
    report: &mut ValidationReport,
) {
    let rate_limit_refs = validate_multi_policy_refs(
        &binding.local_rate_limits,
        &format!("{base_path}.local_rate_limits"),
        "local rate-limit policy",
        &registry.local_rate_limits,
        report,
    );
    for policy_name in rate_limit_refs {
        validate_rate_limit_scope(&policy_name, registry, target, report);
    }

    let concurrency_limit_refs = validate_multi_policy_refs(
        &binding.local_concurrency_limits,
        &format!("{base_path}.local_concurrency_limits"),
        "local concurrency-limit policy",
        &registry.local_concurrency_limits,
        report,
    );
    for policy_name in concurrency_limit_refs {
        validate_concurrency_scope(&policy_name, registry, target, report);
    }

    validate_single_policy_ref(
        binding.retry_budget.as_deref(),
        &format!("{base_path}.retry_budget"),
        "retry budget policy",
        &registry.retry_budgets,
        report,
    );
    validate_single_policy_ref(
        binding.timeout_hierarchy.as_deref(),
        &format!("{base_path}.timeout_hierarchy"),
        "timeout hierarchy policy",
        &registry.timeout_hierarchies,
        report,
    );
    validate_single_policy_ref(
        binding.circuit_breaker.as_deref(),
        &format!("{base_path}.circuit_breaker"),
        "circuit breaker policy",
        &registry.circuit_breakers,
        report,
    );
    validate_single_policy_ref(
        binding.overload_response.as_deref(),
        &format!("{base_path}.overload_response"),
        "overload response policy",
        &registry.overload_responses,
        report,
    );
    validate_single_policy_ref(
        binding.hostile_edge_protection.as_deref(),
        &format!("{base_path}.hostile_edge_protection"),
        "hostile-edge protection policy",
        &registry.hostile_edge_protections,
        report,
    );
    if binding.hostile_edge_protection.is_some()
        && !matches!(target, PolicyBindingTarget::Listener(_))
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.hostile_edge_protection"),
            "hostile-edge protection policies may only be bound to listeners",
        ));
    }
    validate_single_policy_ref(
        binding.cache_policy.as_deref(),
        &format!("{base_path}.cache_policy"),
        "http cache policy",
        &registry.http_caches,
        report,
    );
    validate_single_policy_ref(
        binding.transform_policy.as_deref(),
        &format!("{base_path}.transform_policy"),
        "transform policy",
        &registry.transforms,
        report,
    );
    validate_single_policy_ref(
        binding.traffic_mirror.as_deref(),
        &format!("{base_path}.traffic_mirror"),
        "traffic mirroring policy",
        &registry.traffic_mirrors,
        report,
    );
    validate_single_policy_ref(
        binding.fault_injection.as_deref(),
        &format!("{base_path}.fault_injection"),
        "fault injection policy",
        &registry.fault_injections,
        report,
    );
    if binding.transform_policy.is_some()
        && matches!(target, PolicyBindingTarget::UpstreamCluster(_))
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.transform_policy"),
            "transform policies may only be bound to listeners or routes",
        ));
    }
    if binding.traffic_mirror.is_some()
        && !matches!(target, PolicyBindingTarget::RouteDestination { .. })
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.traffic_mirror"),
            "traffic mirroring policies may only be bound to route destinations",
        ));
    }
    if let (
        Some(policy_name),
        PolicyBindingTarget::RouteDestination { upstream_cluster, .. },
    ) = (binding.traffic_mirror.as_deref(), target)
    {
        if let Some(spec) = registry.traffic_mirror_specs.get(policy_name) {
            if spec.target_upstream_cluster == upstream_cluster {
                report.errors.push(ValidationError::semantic(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.traffic_mirror"),
                    "traffic mirroring target_upstream_cluster must differ from the primary route destination upstream cluster",
                ));
            }
        }
    }
    if binding.fault_injection.is_some()
        && !matches!(target, PolicyBindingTarget::RouteDestination { .. })
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.fault_injection"),
            "fault injection policies may only be bound to route destinations",
        ));
    }
    if binding.overload_response.is_some()
        && matches!(target, PolicyBindingTarget::RouteDestination { .. })
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.overload_response"),
            "overload response policies may not be bound to route destinations",
        ));
    }
    if binding.cache_policy.is_some()
        && matches!(target, PolicyBindingTarget::RouteDestination { .. })
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.cache_policy"),
            "http cache policies may not be bound to route destinations",
        ));
    }
}

fn validate_multi_policy_refs(
    references: &[String],
    base_path: &str,
    resource_kind: &str,
    known: &BTreeSet<String>,
    report: &mut ValidationReport,
) -> Vec<String> {
    let mut resolved = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, reference) in references.iter().enumerate() {
        let path = format!("{base_path}[{index}]");
        let name = reference.trim();
        if name.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyReference,
                path,
                format!("{resource_kind} reference must not be empty"),
            ));
            continue;
        }
        if !seen.insert(name.to_string()) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::DuplicatePolicyReference,
                path.clone(),
                format!("{resource_kind} {name} is referenced more than once"),
            ));
        }
        if !known.contains(name) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidPolicyReference,
                path,
                format!("unknown {resource_kind} {name}"),
            ));
            continue;
        }
        resolved.push(name.to_string());
    }
    resolved
}

fn validate_single_policy_ref(
    reference: Option<&str>,
    path: &str,
    resource_kind: &str,
    known: &BTreeSet<String>,
    report: &mut ValidationReport,
) {
    if let Some(reference) = reference {
        let name = reference.trim();
        if name.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyReference,
                path,
                format!("{resource_kind} reference must not be empty"),
            ));
        } else if !known.contains(name) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidPolicyReference,
                path,
                format!("unknown {resource_kind} {name}"),
            ));
        }
    }
}

    #[derive(Clone, Copy)]


enum PolicyBindingTarget<'a> {
    Listener(&'a str),
    Route(&'a str),
    RouteDestination {
        route_name: &'a str,
        upstream_cluster: &'a str,
    },
    UpstreamCluster(&'a str),
}

impl PolicyBindingTarget<'_> {
    fn kind_name(self) -> &'static str {
        match self {
            Self::Listener(_) => "listener",
            Self::Route(_) => "route",
            Self::RouteDestination { .. } => "route destination",
            Self::UpstreamCluster(_) => "upstream cluster",
        }
    }

    fn resource_name(&self) -> String {
        match self {
            Self::Listener(name) | Self::Route(name) | Self::UpstreamCluster(name) => {
                (*name).to_string()
            }
            Self::RouteDestination {
                route_name,
                upstream_cluster,
            } => format!("{route_name}->{upstream_cluster}"),
        }
    }

    fn path_for_policy(self, policy_name: &str) -> String {
        format!("{} {} policy binding {}", self.kind_name(), self.resource_name(), policy_name)
    }
}

