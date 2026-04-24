fn compile_admin_policy(
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<CompiledAdminPolicy, DynError> {
    let auth = match &listener.admin.auth {
        lb_config_model::AdminAuthPolicyConfig::Bearer { secret_env, permissions } => {
            CompiledAdminAuthPolicy::Bearer {
                secret_env: secret_env.clone(),
                permissions: compile_admin_permissions(permissions),
            }
        }
        lb_config_model::AdminAuthPolicyConfig::SignedHeaders {
            operators,
            max_clock_skew_secs,
            nonce_ttl_secs,
        } => CompiledAdminAuthPolicy::SignedHeaders {
            operators: operators
                .iter()
                .map(|operator| {
                    (
                        operator.id.clone(),
                        CompiledAdminOperator {
                            secret_env: operator.secret_env.clone(),
                            permissions: compile_admin_permissions(&operator.permissions),
                        },
                    )
                })
                .collect(),
            max_clock_skew: Duration::from_secs(*max_clock_skew_secs),
            nonce_ttl: Duration::from_secs(*nonce_ttl_secs),
        },
    };

    Ok(CompiledAdminPolicy {
        auth,
        allowed_source_cidrs: listener
            .admin
            .allowed_source_cidrs
            .iter()
            .map(|cidr| cidr.parse::<IpNet>().map_err(to_dyn_error))
            .collect::<Result<Vec<_>, _>>()?,
        rate_limit: CompiledAdminRateLimit {
            requests_per_minute: listener.admin.rate_limit.requests_per_minute,
            burst: listener.admin.rate_limit.burst,
        },
        audit_capacity: listener.admin.audit.max_retained_events,
    })
}

fn compile_admin_permissions(
    permissions: &[lb_config_model::AdminAuthorizationScopeConfig],
) -> BTreeSet<AdminPermission> {
    permissions
        .iter()
        .map(|permission| match permission {
            lb_config_model::AdminAuthorizationScopeConfig::Read => AdminPermission::Read,
            lb_config_model::AdminAuthorizationScopeConfig::Audit => AdminPermission::Audit,
            lb_config_model::AdminAuthorizationScopeConfig::Write => AdminPermission::Write,
        })
        .collect()
}

fn resolve_listener_request_transforms(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<
    (
        Option<lb_config_model::RequestTransformConfig>,
        Vec<(String, lb_config_model::RequestTransformConfig)>,
    ),
    DynError,
> {
    let listener_request_transform = listener
        .policies
        .transform_policy
        .as_deref()
        .map(|policy_name| resolve_named_request_transform(config, policy_name, &listener.name))
        .transpose()?;

    let route_request_transforms = listener
        .routes
        .iter()
        .filter_map(|route_name| {
            config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .and_then(|route| {
                    route.policies.transform_policy.as_deref().map(|policy_name| {
                        (route.name.clone(), policy_name.to_string())
                    })
                })
        })
        .map(|(route_name, policy_name)| {
            resolve_named_request_transform(config, &policy_name, &route_name)
                .map(|transform| (route_name, transform))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((listener_request_transform, route_request_transforms))
}

fn resolve_named_request_transform(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
    referrer_name: &str,
) -> Result<lb_config_model::RequestTransformConfig, DynError> {
    config
        .policies
        .transforms
        .iter()
        .find(|policy| policy.name == policy_name)
        .map(|policy| policy.spec.request.clone())
        .ok_or_else(|| {
            to_dyn_error(format!(
                "resource {} references unknown transform policy {}",
                referrer_name, policy_name
            ))
        })
}

fn resolve_listener_response_transforms(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<
    (
        Option<lb_config_model::ResponseTransformConfig>,
        Vec<(String, lb_config_model::ResponseTransformConfig)>,
    ),
    DynError,
> {
    let listener_response_transform = listener
        .policies
        .transform_policy
        .as_deref()
        .map(|policy_name| resolve_named_response_transform(config, policy_name, &listener.name))
        .transpose()?;

    let route_response_transforms = listener
        .routes
        .iter()
        .filter_map(|route_name| {
            config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .and_then(|route| {
                    route.policies.transform_policy.as_deref().map(|policy_name| {
                        (route.name.clone(), policy_name.to_string())
                    })
                })
        })
        .map(|(route_name, policy_name)| {
            resolve_named_response_transform(config, &policy_name, &route_name)
                .map(|transform| (route_name, transform))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((listener_response_transform, route_response_transforms))
}

fn resolve_named_response_transform(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
    referrer_name: &str,
) -> Result<lb_config_model::ResponseTransformConfig, DynError> {
    config
        .policies
        .transforms
        .iter()
        .find(|policy| policy.name == policy_name)
        .map(|policy| policy.spec.response.clone())
        .ok_or_else(|| {
            to_dyn_error(format!(
                "resource {} references unknown transform policy {}",
                referrer_name, policy_name
            ))
        })
}

fn compile_route_destination_policy_runtime(
    config: &lb_config_model::WorkspaceConfig,
    route_backend_policy_diagnostics: &BTreeMap<String, Vec<lb_runtime::EffectiveRouteDestinationPolicy>>,
) -> Result<BTreeMap<String, BTreeMap<String, lb_runtime::RouteDestinationPolicyRuntime>>, DynError>
{
    let mut shared_rate_limiters = BTreeMap::<String, Arc<lb_runtime::LocalRateLimiter>>::new();
    let mut shared_concurrency_limiters =
        BTreeMap::<String, Arc<lb_runtime::LocalConcurrencyLimiter>>::new();
    let mut shared_failure_managers = BTreeMap::<String, Arc<lb_runtime::FailureManager>>::new();

    route_backend_policy_diagnostics
        .iter()
        .map(|(route_name, diagnostics)| {
            let destination_runtime = diagnostics
                .iter()
                .map(|diagnostic| {
                    let rate_limiters = diagnostic
                        .local_rate_limits
                        .iter()
                        .map(|policy_name| {
                            resolve_named_local_rate_limiter(
                                config,
                                &mut shared_rate_limiters,
                                policy_name,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let concurrency_limiters = diagnostic
                        .local_concurrency_limits
                        .iter()
                        .map(|policy_name| {
                            resolve_named_local_concurrency_limiter(
                                config,
                                &mut shared_concurrency_limiters,
                                policy_name,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let failure_manager = resolve_destination_failure_manager(
                        config,
                        &mut shared_failure_managers,
                        diagnostic,
                    )?;

                    Ok((
                        diagnostic.upstream_cluster.clone(),
                        lb_runtime::RouteDestinationPolicyRuntime {
                            request_transform: diagnostic.effective_request_transform.clone(),
                            response_transform: diagnostic.effective_response_transform.clone(),
                            traffic_mirror: diagnostic.traffic_mirror.as_ref().map(|policy_name| {
                                config
                                    .policies
                                    .traffic_mirrors
                                    .iter()
                                    .find(|policy| policy.name == *policy_name)
                                    .expect("validated traffic mirroring policy reference")
                                    .spec
                                    .clone()
                            }),
                                    fault_injection: diagnostic.fault_injection.as_ref().map(|policy_name| {
                                    config
                                        .policies
                                        .fault_injections
                                        .iter()
                                        .find(|policy| policy.name == *policy_name)
                                        .expect("validated fault injection policy reference")
                                        .spec
                                        .clone()
                                    }),
                            rate_limiters,
                            concurrency_limiters,
                            failure_manager,
                            enforce_retry_budget: diagnostic.retry_budget.is_some(),
                            enforce_timeout_hierarchy: diagnostic.timeout_hierarchy.is_some(),
                            enforce_circuit_breaker: diagnostic.circuit_breaker.is_some(),
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, DynError>>()?;
            Ok((route_name.clone(), destination_runtime))
        })
        .collect()
}

fn compile_route_destination_jwt_auth_runtime(
    config: &lb_config_model::WorkspaceConfig,
    route_backend_policy_diagnostics: &BTreeMap<String, Vec<lb_runtime::EffectiveRouteDestinationPolicy>>,
) -> Result<BTreeMap<String, BTreeMap<String, lb_runtime::JwtAuthPolicyRuntime>>, DynError> {
    route_backend_policy_diagnostics
        .iter()
        .map(|(route_name, diagnostics)| {
            let destination_runtime = diagnostics
                .iter()
                .filter_map(|diagnostic| {
                    diagnostic
                        .jwt_auth_policy
                        .as_deref()
                        .map(|policy_name| (diagnostic.upstream_cluster.clone(), policy_name.to_string()))
                })
                .map(|(upstream_cluster, policy_name)| {
                    let policy = config
                        .policies
                        .jwt_auth_policies
                        .iter()
                        .find(|policy| policy.name == policy_name)
                        .ok_or_else(|| {
                            to_dyn_error(format!("unknown jwt auth policy {policy_name}"))
                        })?;
                    let runtime = lb_runtime::JwtAuthPolicyRuntime::from_config(&policy.spec)
                        .map_err(to_dyn_error)?;
                    Ok((upstream_cluster, runtime))
                })
                .collect::<Result<BTreeMap<_, _>, DynError>>()?;
            Ok((route_name.clone(), destination_runtime))
        })
        .collect()
}

fn compile_route_destination_external_auth_runtime(
    config: &lb_config_model::WorkspaceConfig,
    route_backend_policy_diagnostics: &BTreeMap<String, Vec<lb_runtime::EffectiveRouteDestinationPolicy>>,
) -> Result<
    BTreeMap<String, BTreeMap<String, lb_runtime::ExternalAuthPolicyRuntime>>,
    DynError,
> {
    route_backend_policy_diagnostics
        .iter()
        .map(|(route_name, diagnostics)| {
            let destination_runtime = diagnostics
                .iter()
                .filter_map(|diagnostic| {
                    diagnostic.external_auth_policy.as_deref().map(|policy_name| {
                        (diagnostic.upstream_cluster.clone(), policy_name.to_string())
                    })
                })
                .map(|(upstream_cluster, policy_name)| {
                    let policy = config
                        .policies
                        .external_auth_policies
                        .iter()
                        .find(|policy| policy.name == policy_name)
                        .ok_or_else(|| {
                            to_dyn_error(format!("unknown external auth policy {policy_name}"))
                        })?;
                    let runtime = lb_runtime::ExternalAuthPolicyRuntime::from_config(&policy.spec)
                        .map_err(to_dyn_error)?;
                    Ok((upstream_cluster, runtime))
                })
                .collect::<Result<BTreeMap<_, _>, DynError>>()?;
            Ok((route_name.clone(), destination_runtime))
        })
        .collect()
}

fn compile_route_destination_authorization_runtime(
    config: &lb_config_model::WorkspaceConfig,
    route_backend_policy_diagnostics: &BTreeMap<String, Vec<lb_runtime::EffectiveRouteDestinationPolicy>>,
) -> Result<
    BTreeMap<String, BTreeMap<String, lb_runtime::AuthorizationPolicyRuntime>>,
    DynError,
> {
    route_backend_policy_diagnostics
        .iter()
        .map(|(route_name, diagnostics)| {
            let destination_runtime = diagnostics
                .iter()
                .filter_map(|diagnostic| {
                    diagnostic.authorization_policy.as_deref().map(|policy_name| {
                        (diagnostic.upstream_cluster.clone(), policy_name.to_string())
                    })
                })
                .map(|(upstream_cluster, policy_name)| {
                    let policy = config
                        .policies
                        .authorization_policies
                        .iter()
                        .find(|policy| policy.name == policy_name)
                        .ok_or_else(|| {
                            to_dyn_error(format!("unknown authorization policy {policy_name}"))
                        })?;
                    let runtime = lb_runtime::AuthorizationPolicyRuntime::from_config(&policy.spec);
                    Ok((upstream_cluster, runtime))
                })
                .collect::<Result<BTreeMap<_, _>, DynError>>()?;
            Ok((route_name.clone(), destination_runtime))
        })
        .collect()
}

fn compile_route_destination_upstream_identity_runtime(
    config: &lb_config_model::WorkspaceConfig,
    route_backend_policy_diagnostics: &BTreeMap<String, Vec<lb_runtime::EffectiveRouteDestinationPolicy>>,
) -> Result<
    BTreeMap<String, BTreeMap<String, lb_runtime::UpstreamIdentityPolicyRuntime>>,
    DynError,
> {
    route_backend_policy_diagnostics
        .iter()
        .map(|(route_name, diagnostics)| {
            let destination_runtime = diagnostics
                .iter()
                .filter_map(|diagnostic| {
                    diagnostic.upstream_identity_policy.as_deref().map(|policy_name| {
                        (diagnostic.upstream_cluster.clone(), policy_name.to_string())
                    })
                })
                .map(|(upstream_cluster, policy_name)| {
                    let policy = config
                        .policies
                        .upstream_identity_policies
                        .iter()
                        .find(|policy| policy.name == policy_name)
                        .ok_or_else(|| {
                            to_dyn_error(format!(
                                "unknown upstream identity policy {policy_name}"
                            ))
                        })?;
                    let runtime = lb_runtime::UpstreamIdentityPolicyRuntime::from_config(&policy.spec)
                        .map_err(to_dyn_error)?;
                    Ok((upstream_cluster, runtime))
                })
                .collect::<Result<BTreeMap<_, _>, DynError>>()?;
            Ok((route_name.clone(), destination_runtime))
        })
        .collect()
}

fn resolve_named_local_rate_limiter(
    config: &lb_config_model::WorkspaceConfig,
    cache: &mut BTreeMap<String, Arc<lb_runtime::LocalRateLimiter>>,
    policy_name: &str,
) -> Result<Arc<lb_runtime::LocalRateLimiter>, DynError> {
    if let Some(limiter) = cache.get(policy_name) {
        return Ok(Arc::clone(limiter));
    }

    let policy = config
        .policies
        .local_rate_limits
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| to_dyn_error(format!("unknown local rate-limit policy {policy_name}")))?;
    let limiter = Arc::new(
        lb_runtime::LocalRateLimiter::new(lb_runtime::LocalRateLimitConfig {
            scope: compile_local_limit_scope(&policy.spec.scope),
            key_kind: compile_local_limit_key_kind(policy.spec.key_kind),
            requests_per_window: policy.spec.requests_per_window,
            window: Duration::from_millis(policy.spec.window_ms),
            max_tracked_keys: policy.spec.max_tracked_keys,
        })
        .map_err(to_dyn_error)?,
    );
    cache.insert(policy_name.to_string(), Arc::clone(&limiter));
    Ok(limiter)
}

fn resolve_destination_failure_manager(
    config: &lb_config_model::WorkspaceConfig,
    cache: &mut BTreeMap<String, Arc<lb_runtime::FailureManager>>,
    diagnostic: &lb_runtime::EffectiveRouteDestinationPolicy,
) -> Result<Option<Arc<lb_runtime::FailureManager>>, DynError> {
    if diagnostic.retry_budget.is_none()
        && diagnostic.timeout_hierarchy.is_none()
        && diagnostic.circuit_breaker.is_none()
    {
        return Ok(None);
    }

    let key = format!(
        "retry={:?}|timeout={:?}|breaker={:?}",
        diagnostic.retry_budget, diagnostic.timeout_hierarchy, diagnostic.circuit_breaker
    );
    if let Some(manager) = cache.get(&key) {
        return Ok(Some(Arc::clone(manager)));
    }

    let retry_budget = diagnostic
        .retry_budget
        .as_deref()
        .map(|policy_name| resolve_named_retry_budget_policy(config, policy_name))
        .transpose()?
        .unwrap_or_else(default_retry_budget_policy);
    let timeout_hierarchy = diagnostic
        .timeout_hierarchy
        .as_deref()
        .map(|policy_name| resolve_named_timeout_hierarchy(config, policy_name))
        .transpose()?
        .unwrap_or_else(default_timeout_hierarchy);
    let circuit_breaker = diagnostic
        .circuit_breaker
        .as_deref()
        .map(|policy_name| resolve_named_circuit_breaker_policy(config, policy_name))
        .transpose()?
        .unwrap_or_else(default_circuit_breaker_policy);

    let manager = Arc::new(
        lb_runtime::FailureManager::new(retry_budget, timeout_hierarchy, circuit_breaker)
            .map_err(to_dyn_error)?,
    );
    cache.insert(key, Arc::clone(&manager));
    Ok(Some(manager))
}

fn resolve_named_retry_budget_policy(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
) -> Result<lb_runtime::RetryBudgetPolicy, DynError> {
    let policy = config
        .policies
        .retry_budgets
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| to_dyn_error(format!("unknown retry-budget policy {policy_name}")))?;
    Ok(lb_runtime::RetryBudgetPolicy {
        min_retry_tokens: policy.spec.min_retry_tokens,
        retry_percent: policy.spec.retry_percent,
        window: Duration::from_millis(policy.spec.window_ms),
    })
}

fn resolve_named_timeout_hierarchy(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
) -> Result<lb_runtime::TimeoutHierarchy, DynError> {
    let policy = config
        .policies
        .timeout_hierarchies
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| to_dyn_error(format!("unknown timeout hierarchy policy {policy_name}")))?;
    let per_try_timeout_ms = policy.spec.per_try_timeout_ms.unwrap_or(policy.spec.attempt_timeout_ms);
    Ok(lb_runtime::TimeoutHierarchy {
        request_timeout: Duration::from_millis(policy.spec.request_timeout_ms),
        attempt_timeout: Duration::from_millis(per_try_timeout_ms),
        connect_timeout: Duration::from_millis(policy.spec.connect_timeout_ms),
        idle_timeout: Duration::from_millis(policy.spec.idle_timeout_ms),
    })
}

fn resolve_named_circuit_breaker_policy(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
) -> Result<lb_runtime::CircuitBreakerPolicy, DynError> {
    let policy = config
        .policies
        .circuit_breakers
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| to_dyn_error(format!("unknown circuit-breaker policy {policy_name}")))?;
    Ok(lb_runtime::CircuitBreakerPolicy {
        open_failure_threshold: policy.spec.open_failure_threshold,
        open_duration: Duration::from_millis(policy.spec.open_duration_ms),
        half_open_success_threshold: policy.spec.half_open_success_threshold,
    })
}

fn default_retry_budget_policy() -> lb_runtime::RetryBudgetPolicy {
    lb_runtime::RetryBudgetPolicy::default()
}

fn default_timeout_hierarchy() -> lb_runtime::TimeoutHierarchy {
    let defaults = lb_net_core::ConnectionTimeouts::default();
    let attempt_timeout = defaults.idle_timeout.max(defaults.connect_timeout);
    lb_runtime::TimeoutHierarchy {
        request_timeout: attempt_timeout,
        attempt_timeout,
        connect_timeout: defaults.connect_timeout,
        idle_timeout: defaults.idle_timeout.min(attempt_timeout),
    }
}

fn default_circuit_breaker_policy() -> lb_runtime::CircuitBreakerPolicy {
    lb_runtime::CircuitBreakerPolicy::default()
}

fn resolve_named_local_concurrency_limiter(
    config: &lb_config_model::WorkspaceConfig,
    cache: &mut BTreeMap<String, Arc<lb_runtime::LocalConcurrencyLimiter>>,
    policy_name: &str,
) -> Result<Arc<lb_runtime::LocalConcurrencyLimiter>, DynError> {
    if let Some(limiter) = cache.get(policy_name) {
        return Ok(Arc::clone(limiter));
    }

    let policy = config
        .policies
        .local_concurrency_limits
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!("unknown local concurrency-limit policy {policy_name}"))
        })?;
    let limiter = Arc::new(
        lb_runtime::LocalConcurrencyLimiter::new(lb_runtime::LocalConcurrencyLimitConfig {
            scope: compile_local_limit_scope(&policy.spec.scope),
            key_kind: compile_local_limit_key_kind(policy.spec.key_kind),
            max_concurrent: policy.spec.max_concurrent,
            max_tracked_keys: policy.spec.max_tracked_keys,
        })
        .map_err(to_dyn_error)?,
    );
    cache.insert(policy_name.to_string(), Arc::clone(&limiter));
    Ok(limiter)
}

fn compile_local_limit_scope(
    scope: &lb_config_model::LocalLimitScopeConfig,
) -> lb_runtime::LocalLimitScope {
    match scope {
        lb_config_model::LocalLimitScopeConfig::Listener { name } => {
            lb_runtime::LocalLimitScope::Listener { name: name.clone() }
        }
        lb_config_model::LocalLimitScopeConfig::Route { name } => {
            lb_runtime::LocalLimitScope::Route { name: name.clone() }
        }
        lb_config_model::LocalLimitScopeConfig::RouteDestination {
            route,
            upstream_cluster,
        } => lb_runtime::LocalLimitScope::RouteDestination {
            route: route.clone(),
            upstream_cluster: upstream_cluster.clone(),
        },
        lb_config_model::LocalLimitScopeConfig::UpstreamCluster { name } => {
            lb_runtime::LocalLimitScope::UpstreamCluster { name: name.clone() }
        }
    }
}

fn compile_local_limit_key_kind(
    key_kind: lb_config_model::LocalLimitKeyKindConfig,
) -> lb_runtime::LocalLimitKeyKind {
    match key_kind {
        lb_config_model::LocalLimitKeyKindConfig::Global => lb_runtime::LocalLimitKeyKind::Global,
        lb_config_model::LocalLimitKeyKindConfig::SourceIp => {
            lb_runtime::LocalLimitKeyKind::SourceIp
        }
        lb_config_model::LocalLimitKeyKindConfig::RouteName => {
            lb_runtime::LocalLimitKeyKind::RouteName
        }
        lb_config_model::LocalLimitKeyKindConfig::UpstreamCluster => {
            lb_runtime::LocalLimitKeyKind::UpstreamCluster
        }
    }
}

fn merge_request_transform_layers(
    listener: Option<&lb_config_model::RequestTransformConfig>,
    route: Option<&lb_config_model::RequestTransformConfig>,
    destination: Option<&lb_config_model::RequestTransformConfig>,
) -> Option<lb_config_model::RequestTransformConfig> {
    let mut merged = listener.cloned().unwrap_or_default();
    let mut has_any = listener.is_some();

    for layer in [route, destination].into_iter().flatten() {
        has_any = true;
        if layer.path_rewrite.is_some() {
            merged.path_rewrite = layer.path_rewrite.clone();
        }
        if layer.host_rewrite.is_some() {
            merged.host_rewrite = layer.host_rewrite.clone();
        }
        merged.header_mutations.extend(layer.header_mutations.clone());
    }

    has_any.then_some(merged)
}

fn merge_response_transform_layers(
    listener: Option<&lb_config_model::ResponseTransformConfig>,
    route: Option<&lb_config_model::ResponseTransformConfig>,
    destination: Option<&lb_config_model::ResponseTransformConfig>,
) -> Option<lb_config_model::ResponseTransformConfig> {
    let mut merged = listener.cloned().unwrap_or_default();
    let mut has_any = listener.is_some();

    for layer in [route, destination].into_iter().flatten() {
        has_any = true;
        merged.header_mutations.extend(layer.header_mutations.clone());
    }

    has_any.then_some(merged)
}

fn pick_effective_policy_name(
    listener: Option<&String>,
    route: Option<&String>,
    destination: Option<&String>,
) -> Option<String> {
    destination
        .cloned()
        .or_else(|| route.cloned())
        .or_else(|| listener.cloned())
}

fn merge_effective_policy_refs(
    listener: &[String],
    route: &[String],
    destination: &[String],
) -> Vec<String> {
    listener
        .iter()
        .chain(route.iter())
        .chain(destination.iter())
        .cloned()
        .collect()
}

fn resolve_effective_route_backend_policy_diagnostics(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<BTreeMap<String, Vec<lb_runtime::EffectiveRouteDestinationPolicy>>, DynError> {
    let listener_transform_name = listener.policies.transform_policy.as_deref();
    let listener_request_transform = listener_transform_name
        .map(|policy_name| resolve_named_request_transform(config, policy_name, &listener.name))
        .transpose()?;
    let listener_response_transform = listener_transform_name
        .map(|policy_name| resolve_named_response_transform(config, policy_name, &listener.name))
        .transpose()?;

    listener
        .routes
        .iter()
        .map(|route_name| {
            let route = config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .ok_or_else(|| {
                    to_dyn_error(format!(
                        "listener {} references unknown route {}",
                        listener.name, route_name
                    ))
                })?;

            let route_transform_name = route.policies.transform_policy.as_deref();
            let route_request_transform = route_transform_name
                .map(|policy_name| resolve_named_request_transform(config, policy_name, &route.name))
                .transpose()?;
            let route_response_transform = route_transform_name
                .map(|policy_name| resolve_named_response_transform(config, policy_name, &route.name))
                .transpose()?;

            let diagnostics = route
                .normalized_destinations()
                .into_iter()
                .map(|destination| {
                    let upstream_cluster = config
                        .upstream_clusters
                        .iter()
                        .find(|entry| entry.name == destination.upstream_cluster)
                        .ok_or_else(|| {
                            to_dyn_error(format!(
                                "route {} references unknown upstream cluster {}",
                                route.name, destination.upstream_cluster
                            ))
                        })?;
                    let destination_transform_name = destination.policies.transform_policy.as_deref();
                    let destination_request_transform = destination_transform_name
                        .map(|policy_name| {
                            resolve_named_request_transform(
                                config,
                                policy_name,
                                &format!("{}->{}", route.name, destination.upstream_cluster),
                            )
                        })
                        .transpose()?;
                    let destination_response_transform = destination_transform_name
                        .map(|policy_name| {
                            resolve_named_response_transform(
                                config,
                                policy_name,
                                &format!("{}->{}", route.name, destination.upstream_cluster),
                            )
                        })
                        .transpose()?;

                    Ok(lb_runtime::EffectiveRouteDestinationPolicy {
                        upstream_cluster: destination.upstream_cluster.clone(),
                        retry_budget: pick_effective_policy_name(
                            listener.policies.retry_budget.as_ref(),
                            route.policies.retry_budget.as_ref(),
                            destination.policies.retry_budget.as_ref(),
                        ),
                        timeout_hierarchy: pick_effective_policy_name(
                            listener.policies.timeout_hierarchy.as_ref(),
                            route.policies.timeout_hierarchy.as_ref(),
                            destination.policies.timeout_hierarchy.as_ref(),
                        ),
                        circuit_breaker: pick_effective_policy_name(
                            listener.policies.circuit_breaker.as_ref(),
                            route.policies.circuit_breaker.as_ref(),
                            destination.policies.circuit_breaker.as_ref(),
                        ),
                        jwt_auth_policy: pick_effective_policy_name(
                            listener.policies.jwt_auth_policy.as_ref(),
                            route.policies.jwt_auth_policy.as_ref(),
                            destination.policies.jwt_auth_policy.as_ref(),
                        ),
                        external_auth_policy: pick_effective_policy_name(
                            listener.policies.external_auth_policy.as_ref(),
                            route.policies.external_auth_policy.as_ref(),
                            destination.policies.external_auth_policy.as_ref(),
                        ),
                        authorization_policy: pick_effective_policy_name(
                            listener.policies.authorization_policy.as_ref(),
                            route.policies.authorization_policy.as_ref(),
                            destination.policies.authorization_policy.as_ref(),
                        ),
                        upstream_identity_policy: destination
                            .policies
                            .upstream_identity_policy
                            .clone()
                            .or_else(|| upstream_cluster.policies.upstream_identity_policy.clone()),
                        transform_policy: pick_effective_policy_name(
                            listener.policies.transform_policy.as_ref(),
                            route.policies.transform_policy.as_ref(),
                            destination.policies.transform_policy.as_ref(),
                        ),
                        traffic_mirror: pick_effective_policy_name(
                            listener.policies.traffic_mirror.as_ref(),
                            route.policies.traffic_mirror.as_ref(),
                            destination.policies.traffic_mirror.as_ref(),
                        ),
                        fault_injection: pick_effective_policy_name(
                            listener.policies.fault_injection.as_ref(),
                            route.policies.fault_injection.as_ref(),
                            destination.policies.fault_injection.as_ref(),
                        ),
                        local_rate_limits: merge_effective_policy_refs(
                            &listener.policies.local_rate_limits,
                            &route.policies.local_rate_limits,
                            &destination.policies.local_rate_limits,
                        ),
                        local_concurrency_limits: merge_effective_policy_refs(
                            &listener.policies.local_concurrency_limits,
                            &route.policies.local_concurrency_limits,
                            &destination.policies.local_concurrency_limits,
                        ),
                        effective_request_transform: merge_request_transform_layers(
                            listener_request_transform.as_ref(),
                            route_request_transform.as_ref(),
                            destination_request_transform.as_ref(),
                        ),
                        effective_response_transform: merge_response_transform_layers(
                            listener_response_transform.as_ref(),
                            route_response_transform.as_ref(),
                            destination_response_transform.as_ref(),
                        ),
                    })
                })
                .collect::<Result<Vec<_>, DynError>>()?;

            Ok((route.name.clone(), diagnostics))
        })
        .collect()
}

fn resolve_listener_upgrade_policies(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> (
    Vec<lb_config_model::UpgradeProtocolConfig>,
    Vec<(String, Vec<lb_config_model::UpgradeProtocolConfig>)>,
) {
    let route_upgrade_protocols = listener
        .routes
        .iter()
        .filter_map(|route_name| {
            config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .filter(|route| !route.upgrade.protocols.is_empty())
                .map(|route| (route.name.clone(), route.upgrade.protocols.clone()))
        })
        .collect::<Vec<_>>();

    (listener.upgrade.protocols.clone(), route_upgrade_protocols)
}


fn compile_listener_overload_policy(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<Option<CompiledListenerOverloadPolicy>, DynError> {
    let Some(policy_name) = listener.policies.overload_response.as_deref() else {
        return Ok(None);
    };

    let policy = config
        .policies
        .overload_responses
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!(
                "listener {} references unknown overload response policy {policy_name}",
                listener.name,
            ))
        })?;

    Ok(Some(CompiledListenerOverloadPolicy {
        signal_window: Duration::from_millis(policy.spec.signal_window_ms),
        constrained_signal_threshold: policy.spec.constrained_signal_threshold,
        shedding_signal_threshold: policy.spec.shedding_signal_threshold,
        brownout_signal_threshold: policy.spec.brownout_signal_threshold,
        brownout_features: policy
            .spec
            .brownout_features
            .iter()
            .map(|feature| CompiledBrownoutFeature {
                name: feature.name.clone(),
                priority: match feature.priority {
                    lb_config_model::TrafficClassConfig::Critical => {
                        lb_runtime::TrafficClass::Critical
                    }
                    lb_config_model::TrafficClassConfig::Default => {
                        lb_runtime::TrafficClass::Default
                    }
                    lb_config_model::TrafficClassConfig::BestEffort => {
                        lb_runtime::TrafficClass::BestEffort
                    }
                },
            })
            .collect(),
    }))
}

fn compile_listener_abuse_protection_policy(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<Option<CompiledListenerAbuseProtectionPolicy>, DynError> {
    let Some(policy_name) = listener.policies.hostile_edge_protection.as_deref() else {
        return Ok(None);
    };

    let policy = config
        .policies
        .hostile_edge_protections
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!(
                "listener {} references unknown hostile-edge protection policy {policy_name}",
                listener.name,
            ))
        })?;

    Ok(Some(CompiledListenerAbuseProtectionPolicy {
        source_quota: policy.spec.source_quota.as_ref().map(|source_quota| {
            CompiledSourceQuotaPolicy {
                aggregation: match source_quota.aggregation {
                    lb_config_model::HostileEdgeSourceAggregationConfig::ExactIp => {
                        lb_runtime::SourceAggregation::ExactIp
                    }
                    lb_config_model::HostileEdgeSourceAggregationConfig::Ipv4Subnet24 => {
                        lb_runtime::SourceAggregation::Ipv4Subnet24
                    }
                    lb_config_model::HostileEdgeSourceAggregationConfig::Ipv6Subnet64 => {
                        lb_runtime::SourceAggregation::Ipv6Subnet64
                    }
                },
                max_active_per_source: source_quota.max_active_per_source,
                max_tracked_sources: source_quota.max_tracked_sources,
            }
        }),
        handshake_guard: policy.spec.handshake_guard.as_ref().map(|handshake_guard| {
            CompiledHandshakeGuardPolicy {
                max_inflight: handshake_guard.max_inflight,
                timeout: Duration::from_millis(handshake_guard.timeout_ms),
            }
        }),
    }))
}

