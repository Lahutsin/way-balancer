fn validate_rate_limit_scope(
    policy_name: &str,
    registry: &PolicyRegistry,
    target: PolicyBindingTarget<'_>,
    report: &mut ValidationReport,
) {
    if let Some(scope) = registry.rate_limit_scopes.get(policy_name) {
        validate_scope_match(scope, target, policy_name, "local rate-limit policy", report);
    }
}

fn validate_concurrency_scope(
    policy_name: &str,
    registry: &PolicyRegistry,
    target: PolicyBindingTarget<'_>,
    report: &mut ValidationReport,
) {
    if let Some(scope) = registry.concurrency_limit_scopes.get(policy_name) {
        validate_scope_match(scope, target, policy_name, "local concurrency-limit policy", report);
    }
}

fn validate_scope_match(
    scope: &LocalLimitScopeConfig,
    target: PolicyBindingTarget<'_>,
    policy_name: &str,
    resource_kind: &str,
    report: &mut ValidationReport,
) {
    let matches = match (scope, target) {
        (LocalLimitScopeConfig::Listener { name }, PolicyBindingTarget::Listener(target_name)) => {
            normalize_component(name) == normalize_component(target_name)
        }
        (LocalLimitScopeConfig::Route { name }, PolicyBindingTarget::Route(target_name)) => {
            normalize_component(name) == normalize_component(target_name)
        }
        (
            LocalLimitScopeConfig::RouteDestination {
                route,
                upstream_cluster,
            },
            PolicyBindingTarget::RouteDestination {
                route_name,
                upstream_cluster: target_upstream_cluster,
            },
        ) => {
            normalize_component(route) == normalize_component(route_name)
                && normalize_component(upstream_cluster)
                    == normalize_component(target_upstream_cluster)
        }
        (
            LocalLimitScopeConfig::UpstreamCluster { name },
            PolicyBindingTarget::UpstreamCluster(target_name),
        ) => normalize_component(name) == normalize_component(target_name),
        _ => false,
    };

    if !matches {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            target.path_for_policy(policy_name),
            format!(
                "{resource_kind} {policy_name} scope {} does not match {} {}",
                describe_scope(scope),
                target.kind_name(),
                target.resource_name(),
            ),
        ));
    }
}

fn describe_scope(scope: &LocalLimitScopeConfig) -> String {
    match scope {
        LocalLimitScopeConfig::Listener { name } => format!("listener {name}"),
        LocalLimitScopeConfig::Route { name } => format!("route {name}"),
        LocalLimitScopeConfig::RouteDestination {
            route,
            upstream_cluster,
        } => format!("route destination {route}->{upstream_cluster}"),
        LocalLimitScopeConfig::UpstreamCluster { name } => format!("upstream cluster {name}"),
    }
}
