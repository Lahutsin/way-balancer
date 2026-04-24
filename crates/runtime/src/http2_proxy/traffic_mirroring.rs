fn maybe_spawn_shadow_http2_request(
    config: &Http2ProxyConfig,
    request: &Request<RecvStream>,
    effective_client_ip: IpAddr,
    authority_override: Option<&str>,
    destination_policy: Option<&crate::RouteDestinationPolicyRuntime>,
    upstream_clients: UpstreamClientRegistry,
    metrics: &MetricsState,
) {
    let Some(mirror_policy) = destination_policy.and_then(|policy| policy.traffic_mirror.as_ref()) else {
        return;
    };
    if !shadow_http2_request_selected(mirror_policy, request) {
        metrics.increment_mirror_skip_count();
        return;
    }
    if !request.body().is_end_stream() {
        metrics.increment_mirror_skip_count();
        return;
    }
    let Some(target) = resolve_shadow_http2_upstream(config, request, mirror_policy) else {
        metrics.increment_mirror_dispatch_failure_count();
        return;
    };
    let request_template = match prepare_upstream_request_template(
        request,
        authority_override,
        effective_client_ip,
        target.address,
    ) {
        Ok(template) => template,
        Err(_) => {
            metrics.increment_mirror_dispatch_failure_count();
            return;
        }
    };
    metrics.increment_mirror_dispatch_count();
    let timeouts = config.timeouts;
    tokio::spawn(async move {
        let _ = dispatch_shadow_http2_request(upstream_clients, target, request_template, timeouts).await;
    });
}

fn shadow_http2_request_selected(
    mirror_policy: &lb_config_model::TrafficMirrorPolicyConfig,
    request: &Request<RecvStream>,
) -> bool {
    if !mirror_method_allowed(mirror_policy, request.method().as_str()) {
        return false;
    }
    fault_injection_http2_action_selected("mirror", mirror_policy.percentage, request)
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


fn resolve_shadow_http2_upstream(
    config: &Http2ProxyConfig,
    request: &Request<RecvStream>,
    mirror_policy: &lb_config_model::TrafficMirrorPolicyConfig,
) -> Option<lb_net_core::UpstreamTarget> {
    let pool = config
        .mirror_backend_pools
        .get(&mirror_policy.target_upstream_cluster)?;
    pool.select_backend_with_context(&selection_context_for_request(
        request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        request.headers(),
        pool.affinity_policy(),
    ))
    .ok()
    .map(|selected| selected.into_upstream())
}


async fn dispatch_shadow_http2_request(
    upstream_clients: UpstreamClientRegistry,
    target: lb_net_core::UpstreamTarget,
    request_template: UpstreamRequestTemplate,
    timeouts: lb_net_core::ConnectionTimeouts,
) -> Result<(), StreamForwardError> {
    let (upstream_client, _) = upstream_clients
        .ensure_client(&target, &timeouts)
        .await
        .map_err(|error| match error {
            UpstreamClientConnectError::ConnectTimeout { .. } => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)
            }
            UpstreamClientConnectError::Connect { .. }
            | UpstreamClientConnectError::Handshake(_) => StreamForwardError::UpstreamRequest,
        })?;

    let request = request_template.into_request()?;
    let mut send_request = upstream_client.send_request.lock().await;
    poll_fn(|cx| send_request.poll_ready(cx))
        .await
        .map_err(|_| StreamForwardError::UpstreamReady)?;
    let (response_future, send_stream) = send_request
        .send_request(request, true)
        .map_err(|_| StreamForwardError::UpstreamRequest)?;
    drop(send_request);
    drop(send_stream);

    let response = time::timeout(timeouts.idle_timeout, response_future)
        .await
        .map_err(|_| StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse))?
        .map_err(|_| StreamForwardError::UpstreamResponse)?;
    discard_recv_stream_body(response.into_body(), timeouts.idle_timeout).await?;
    upstream_client.note_completed_stream();
    Ok(())
}

