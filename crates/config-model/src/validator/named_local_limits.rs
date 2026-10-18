fn validate_named_local_rate_limits(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.local_rate_limits.iter().enumerate() {
        let base_path = format!("policies.local_rate_limits[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "local rate-limit policy",
            &mut registry.local_rate_limits,
            report,
        );
        validate_rate_limit_policy(&policy.spec, &base_path, report);
        registry.rate_limit_scopes.insert(policy.name.clone(), policy.spec.scope.clone());
    }
}

fn validate_named_local_concurrency_limits(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.local_concurrency_limits.iter().enumerate() {
        let base_path = format!("policies.local_concurrency_limits[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "local concurrency-limit policy",
            &mut registry.local_concurrency_limits,
            report,
        );
        validate_concurrency_limit_policy(&policy.spec, &base_path, report);
        registry.concurrency_limit_scopes.insert(policy.name.clone(), policy.spec.scope.clone());
    }
}

fn validate_rate_limit_policy(
    policy: &LocalRateLimitPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    validate_local_limit_scope(&policy.scope, &format!("{base_path}.spec.scope"), report);
    if policy.requests_per_window == 0 || policy.window_ms == 0 || policy.max_tracked_keys == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "local rate-limit policy must use non-zero requests_per_window, window_ms, and max_tracked_keys",
        ));
    }
}

fn validate_concurrency_limit_policy(
    policy: &LocalConcurrencyLimitPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    validate_local_limit_scope(&policy.scope, &format!("{base_path}.spec.scope"), report);
    if policy.max_concurrent == 0 || policy.max_tracked_keys == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "local concurrency-limit policy must use non-zero max_concurrent and max_tracked_keys",
        ));
    }
}

fn validate_local_limit_scope(
    scope: &LocalLimitScopeConfig,
    path: &str,
    report: &mut ValidationReport,
) {
    match scope {
        LocalLimitScopeConfig::Listener { name }
        | LocalLimitScopeConfig::Route { name }
        | LocalLimitScopeConfig::UpstreamCluster { name } => {
            if name.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    path,
                    "local limit scope name must not be empty",
                ));
            }
        }
        LocalLimitScopeConfig::RouteDestination { route, upstream_cluster } => {
            if route.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{path}.route"),
                    "local limit route-destination scope route must not be empty",
                ));
            }
            if upstream_cluster.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{path}.upstream_cluster"),
                    "local limit route-destination scope upstream_cluster must not be empty",
                ));
            }
        }
    }
}

#[cfg(test)]
mod local_limits_coverage_regressions {
    use super::{PolicyRegistry, ValidationCode, ValidationReport, validate_local_limit_scope};
    use crate::{
        LocalConcurrencyLimitPolicyConfig, LocalLimitKeyKindConfig, LocalLimitScopeConfig,
        LocalRateLimitPolicyConfig, NamedLocalConcurrencyLimitPolicyConfig,
        NamedLocalRateLimitPolicyConfig, PolicyResourcesConfig,
    };
    use std::collections::BTreeSet;

    #[test]
    fn validates_limit_names_scopes_and_nonzero_policy_values() {
        let resources = PolicyResourcesConfig {
            local_rate_limits: vec![
                NamedLocalRateLimitPolicyConfig {
                    name: String::from(" rate "),
                    spec: LocalRateLimitPolicyConfig {
                        scope: LocalLimitScopeConfig::Route { name: String::from(" ") },
                        key_kind: LocalLimitKeyKindConfig::SourceIp,
                        requests_per_window: 0,
                        window_ms: 0,
                        max_tracked_keys: 0,
                    },
                },
                NamedLocalRateLimitPolicyConfig {
                    name: String::from("rate"),
                    spec: LocalRateLimitPolicyConfig {
                        scope: LocalLimitScopeConfig::Listener { name: String::from("edge") },
                        key_kind: LocalLimitKeyKindConfig::SourceIp,
                        requests_per_window: 5,
                        window_ms: 1000,
                        max_tracked_keys: 10,
                    },
                },
                NamedLocalRateLimitPolicyConfig {
                    name: String::new(),
                    spec: LocalRateLimitPolicyConfig {
                        scope: LocalLimitScopeConfig::RouteDestination {
                            route: String::from(" "),
                            upstream_cluster: String::new(),
                        },
                        key_kind: LocalLimitKeyKindConfig::SourceIp,
                        requests_per_window: 1,
                        window_ms: 1,
                        max_tracked_keys: 1,
                    },
                },
            ],
            local_concurrency_limits: vec![
                NamedLocalConcurrencyLimitPolicyConfig {
                    name: String::from("concurrency"),
                    spec: LocalConcurrencyLimitPolicyConfig {
                        scope: LocalLimitScopeConfig::UpstreamCluster { name: String::from(" ") },
                        key_kind: LocalLimitKeyKindConfig::RouteName,
                        max_concurrent: 0,
                        max_tracked_keys: 0,
                    },
                },
                NamedLocalConcurrencyLimitPolicyConfig {
                    name: String::new(),
                    spec: LocalConcurrencyLimitPolicyConfig {
                        scope: LocalLimitScopeConfig::RouteDestination {
                            route: String::from("api"),
                            upstream_cluster: String::from("payments"),
                        },
                        key_kind: LocalLimitKeyKindConfig::RouteName,
                        max_concurrent: 2,
                        max_tracked_keys: 10,
                    },
                },
            ],
            ..PolicyResourcesConfig::default()
        };
        let mut report = ValidationReport::default();
        let _registry = PolicyRegistry::new(&resources, &BTreeSet::new(), &mut report);
        for (code, path) in [
            (ValidationCode::DuplicateResourceName, "policies.local_rate_limits[1].name"),
            (ValidationCode::EmptyResourceName, "policies.local_rate_limits[2].name"),
            (ValidationCode::InvalidPolicyField, "policies.local_rate_limits[0].spec"),
            (ValidationCode::InvalidPolicyField, "policies.local_rate_limits[2].spec.scope.route"),
            (
                ValidationCode::InvalidPolicyField,
                "policies.local_rate_limits[2].spec.scope.upstream_cluster",
            ),
            (ValidationCode::InvalidPolicyField, "policies.local_concurrency_limits[0].spec"),
            (ValidationCode::InvalidPolicyField, "policies.local_concurrency_limits[0].spec.scope"),
            (ValidationCode::EmptyResourceName, "policies.local_concurrency_limits[1].name"),
        ] {
            assert!(
                report.errors.iter().any(|error| error.code == code && error.path == path),
                "missing {path}"
            );
        }
        let mut valid_scopes = ValidationReport::default();
        for scope in [
            LocalLimitScopeConfig::Listener { name: String::from("edge") },
            LocalLimitScopeConfig::Route { name: String::from("api") },
            LocalLimitScopeConfig::UpstreamCluster { name: String::from("payments") },
            LocalLimitScopeConfig::RouteDestination {
                route: String::from("api"),
                upstream_cluster: String::from("payments"),
            },
        ] {
            validate_local_limit_scope(&scope, "scope", &mut valid_scopes);
        }
        assert!(valid_scopes.is_empty());
    }
}
