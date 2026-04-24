fn maybe_spawn_shadow_http1_request(
    config: &Http1ProxyConfig,
    request: &lb_proto_http::Http1RequestHead,
    effective_client_ip: IpAddr,
    requested_upgrade: Option<lb_config_model::UpgradeProtocolConfig>,
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
    metrics: &mut Http1ConnectionMetrics,
) {
    let Some(mirror_policy) = destination_policy.and_then(|policy| policy.traffic_mirror.as_ref()) else {
        return;
    };
    if !shadow_request_selected(mirror_policy, request) {
        metrics.mirror_skip_count += 1;
        return;
    }
    if requested_upgrade.is_some() || !matches!(request.body_kind, lb_proto_http::BodyKind::None) {
        metrics.mirror_skip_count += 1;
        return;
    }
    let Some(target) = resolve_shadow_upstream(config, request, mirror_policy) else {
        metrics.mirror_dispatch_failure_count += 1;
        return;
    };

    metrics.mirror_dispatch_count += 1;
    let request = request.clone();
    let limits = config.limits.clone();
    let timeouts = config.timeouts;
    tokio::spawn(async move {
        let _ = dispatch_shadow_http1_request(target, request, effective_client_ip, timeouts, limits).await;
    });
}

fn shadow_request_selected(
    mirror_policy: &lb_config_model::TrafficMirrorPolicyConfig,
    request: &lb_proto_http::Http1RequestHead,
) -> bool {
    if !mirror_method_allowed(mirror_policy, &request.method) {
        return false;
    }
    fault_injection_action_selected("mirror", mirror_policy.percentage, request)
}

fn mirror_method_allowed(
    mirror_policy: &lb_config_model::TrafficMirrorPolicyConfig,
    method: &str,
) -> bool {
    mirror_policy.methods.is_empty()
        || mirror_policy
            .methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method))
}

fn resolve_shadow_upstream(
    config: &Http1ProxyConfig,
    request: &lb_proto_http::Http1RequestHead,
    mirror_policy: &lb_config_model::TrafficMirrorPolicyConfig,
) -> Option<lb_net_core::UpstreamTarget> {
    let pool = config
        .mirror_backend_pools
        .get(&mirror_policy.target_upstream_cluster)?;
    pool.select_backend_with_context(&selection_context_for_request(request, pool.affinity_policy()))
        .ok()
        .map(|selected| selected.into_upstream())
}

async fn dispatch_shadow_http1_request(
    target: lb_net_core::UpstreamTarget,
    request: lb_proto_http::Http1RequestHead,
    effective_client_ip: IpAddr,
    timeouts: lb_net_core::ConnectionTimeouts,
    limits: lb_proto_http::Http1Limits,
) -> Result<(), Http1ProxyError> {
    let mut stream = time::timeout(timeouts.connect_timeout, TcpStream::connect(target.address))
        .await
        .map_err(|_| Http1ProxyError::ConnectTimeout { target: target.address })?
        .map_err(|source| Http1ProxyError::Connect { target: target.address, source })?;

    let normalized_request_headers = lb_proto_http::normalize_request_headers(
        &request.headers,
        effective_client_ip,
        request.keep_alive,
        &request.body_kind,
    );
    let request_head = lb_proto_http::encode_request_head(
        &request.method,
        &request.target,
        request.version,
        &normalized_request_headers,
    );
    stream
        .write_all(&request_head)
        .await
        .map_err(Http1ProxyError::RequestIo)?;

    let mut upstream_buffer = Vec::new();
    let response = time::timeout(
        timeouts.idle_timeout,
        lb_proto_http::read_response_head(&mut stream, &mut upstream_buffer, &limits, &request.method),
    )
    .await
    .map_err(|_| Http1ProxyError::IdleTimeout("shadow response head"))?
    .map_err(Http1ProxyError::ParseResponse)?;

    let mut sink = tokio::io::sink();
    relay_body(
        &mut stream,
        &mut upstream_buffer,
        &mut sink,
        &response.body_kind,
        limits.max_body_bytes,
        timeouts.idle_timeout,
        RelayDirection::Response,
    )
    .await?;
    Ok(())
}

