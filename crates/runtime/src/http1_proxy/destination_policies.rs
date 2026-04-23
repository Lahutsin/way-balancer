fn route_destination_policy_runtime<'a>(
    config: &'a Http1ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
    selected_upstream: &SelectedUpstream,
) -> Option<&'a RouteDestinationPolicyRuntime> {
    let route = route?;
    let route_backend = selected_upstream.route_backend.as_ref()?;
    config
        .route_destination_policies
        .get(&route.label)
        .and_then(|policies| policies.get(&route_backend.cluster_name().to_string()))
}


fn enforce_destination_local_limits(
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
    request: &lb_proto_http::Http1RequestHead,
    selected_upstream: &SelectedUpstream,
    effective_client_ip: IpAddr,
) -> Result<Vec<crate::LocalConcurrencyLease>, (StatusCode, &'static str)> {
    let Some(destination_policy) = destination_policy else {
        return Ok(Vec::new());
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let context = crate::LimitContext {
        source_ip: Some(effective_client_ip),
        route_name: request.route.as_ref().map(|route| route.label.clone()),
        upstream_cluster: selected_upstream
            .route_backend
            .as_ref()
            .map(|route_backend| route_backend.cluster_name().to_string()),
    };

    for limiter in &destination_policy.rate_limiters {
        match limiter.check(now, &context) {
            Ok(decision) if decision.allowed => {}
            Ok(_) | Err(_) => {
                return Err((StatusCode::TOO_MANY_REQUESTS, "route destination rate limited\n"));
            }
        }
    }

    let mut leases = Vec::with_capacity(destination_policy.concurrency_limiters.len());
    for limiter in &destination_policy.concurrency_limiters {
        match limiter.try_acquire(&context) {
            Ok(lease) => leases.push(lease),
            Err(_) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route destination concurrency limited\n",
                ));
            }
        }
    }

    Ok(leases)
}

fn destination_failure_manager(
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
) -> Option<&crate::FailureManager> {
    destination_policy.and_then(|policy| policy.failure_manager.as_deref())
}

fn failure_policy_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

fn effective_destination_upstream_timeouts(
    base: &lb_net_core::ConnectionTimeouts,
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
) -> lb_net_core::ConnectionTimeouts {
    let Some(destination_policy) = destination_policy else {
        return *base;
    };
    if !destination_policy.enforce_timeout_hierarchy {
        return *base;
    }
    let Some(manager) = destination_failure_manager(Some(destination_policy)) else {
        return *base;
    };

    lb_net_core::ConnectionTimeouts {
        connect_timeout: manager.effective_timeout(crate::TimeoutCategory::Connect),
        preface_timeout: base.preface_timeout,
        idle_timeout: manager.effective_timeout(crate::TimeoutCategory::Idle),
    }
}

fn bounded_dispatch_timeout(
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
    base_category: crate::TimeoutCategory,
    base_timeout: Duration,
    request_started: Instant,
    attempt_started: Instant,
) -> Result<(Duration, crate::TimeoutCategory), crate::TimeoutCategory> {
    let Some(destination_policy) = destination_policy else {
        return Ok((base_timeout, base_category));
    };
    if !destination_policy.enforce_timeout_hierarchy {
        return Ok((base_timeout, base_category));
    }
    let Some(manager) = destination_failure_manager(Some(destination_policy)) else {
        return Ok((base_timeout, base_category));
    };

    let mut selected = (base_timeout, base_category);
    for (category, started_at) in [
        (crate::TimeoutCategory::Request, request_started),
        (crate::TimeoutCategory::Attempt, attempt_started),
    ] {
        let allowed = manager.effective_timeout(category);
        let elapsed = started_at.elapsed();
        if elapsed >= allowed {
            return Err(category);
        }
        let remaining = allowed.saturating_sub(elapsed);
        if remaining < selected.0 {
            selected = (remaining, category);
        }
    }

    Ok(selected)
}

fn record_destination_timeout(
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
    category: crate::TimeoutCategory,
) {
    if let Some(policy) = destination_policy.filter(|policy| policy.enforce_timeout_hierarchy) {
        if let Some(manager) = destination_failure_manager(Some(policy)) {
            manager.record_timeout(category);
            manager.record_failure(failure_policy_now(), crate::UpstreamFailureClass::Timeout);
        }
    }
}

fn record_destination_failure(
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
    class: crate::UpstreamFailureClass,
) {
    if let Some(policy) = destination_policy.filter(|policy| policy.enforce_circuit_breaker) {
        if let Some(manager) = destination_failure_manager(Some(policy)) {
            manager.record_failure(failure_policy_now(), class);
        }
    }
}

fn record_destination_success(destination_policy: Option<&RouteDestinationPolicyRuntime>) {
    if let Some(policy) = destination_policy.filter(|policy| policy.enforce_circuit_breaker) {
        if let Some(manager) = destination_failure_manager(Some(policy)) {
            manager.record_success();
        }
    }
}

fn allow_destination_retry(
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
    class: crate::UpstreamFailureClass,
) -> bool {
    let Some(policy) = destination_policy else {
        return true;
    };
    if !policy.enforce_retry_budget {
        return true;
    }
    destination_failure_manager(Some(policy))
        .is_some_and(|manager| manager.allow_retry(failure_policy_now(), class).allowed)
}

fn classify_http1_response_failure(status: u16) -> Option<crate::UpstreamFailureClass> {
    match status {
        503 => Some(crate::UpstreamFailureClass::Overloaded),
        500 | 502 | 504 => Some(crate::UpstreamFailureClass::Temporary),
        501 | 505 => Some(crate::UpstreamFailureClass::Permanent),
        500..=599 => Some(crate::UpstreamFailureClass::Temporary),
        _ => None,
    }
}
