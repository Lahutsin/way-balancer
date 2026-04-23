pub async fn proxy_http1_connection(
    downstream: TcpStream,
    config: &Http1ProxyConfig,
) -> Result<Http1ConnectionReport, Http1ProxyError> {
    let downstream_addr = downstream.peer_addr().map_err(Http1ProxyError::RequestIo)?;
    proxy_http1_connection_with_downstream_addr(downstream, downstream_addr, config).await
}

/// Proxies one or more sequential HTTP/1.1 requests over an arbitrary downstream stream.
pub async fn proxy_http1_connection_with_downstream_addr<S>(
    mut downstream: S,
    downstream_addr: SocketAddr,
    config: &Http1ProxyConfig,
) -> Result<Http1ConnectionReport, Http1ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = None;
    let mut active_upstream: Option<lb_net_core::UpstreamTarget> = None;
    let mut last_upstream_activity = None;
    let mut upstream_connected_at = None;
    let mut connect_duration = Duration::ZERO;
    let mut upstream_addr = config.upstream.address;

    let mut downstream_buffer = Vec::new();
    let mut upstream_buffer = Vec::new();
    let mut metrics = Http1ConnectionMetrics::default();

    loop {
        let request = time::timeout(
            config.timeouts.idle_timeout,
            lb_proto_http::read_request_head(
                &mut downstream,
                &mut downstream_buffer,
                &config.limits,
                &config.routes,
            ),
        )
        .await
        .map_err(|_| Http1ProxyError::IdleTimeout("request head"))?
        .map_err(Http1ProxyError::ParseRequest)?;

        let Some(mut request) = request else {
            break;
        };

        let effective_client_ip =
            match resolve_effective_client_ip(config, downstream_addr, &request) {
                Ok(ip) => ip,
                Err(_) => {
                    write_local_response(
                        &mut downstream,
                        false,
                        StatusCode::BAD_REQUEST,
                        "invalid forwarding headers\n",
                    )
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                    metrics.request_count += 1;
                    *metrics
                        .response_status_counts
                        .entry(StatusCode::BAD_REQUEST.as_u16())
                        .or_insert(0) += 1;
                    break;
                }
            };
        request.route = lb_proto_http::match_route_request_with_context(
            &lb_proto_http::RouteMatchInput {
                target: request.target.clone(),
                host: request_authority(&request).map(String::from),
                method: Some(request.method.clone()),
                headers: request.headers.clone(),
                source_ip: Some(effective_client_ip),
            },
            &config.routes,
        );
        let effective_downstream_addr =
            SocketAddr::new(effective_client_ip, downstream_addr.port());

        if anonymous_source_blocked(config, effective_client_ip) {
            write_local_response(
                &mut downstream,
                false,
                StatusCode::FORBIDDEN,
                "anonymous source blocked\n",
            )
            .await
            .map_err(Http1ProxyError::ResponseIo)?;
            metrics.request_count += 1;
            *metrics.response_status_counts.entry(StatusCode::FORBIDDEN.as_u16()).or_insert(0) += 1;
            break;
        }

        if route_enumeration_source_blocked(config, effective_downstream_addr) {
            write_local_response(
                &mut downstream,
                false,
                StatusCode::FORBIDDEN,
                "source temporarily blocked\n",
            )
            .await
            .map_err(Http1ProxyError::ResponseIo)?;
            metrics.request_count += 1;
            *metrics.response_status_counts.entry(StatusCode::FORBIDDEN.as_u16()).or_insert(0) += 1;
            break;
        }

        if request.route.is_some()
            && record_query_probe(
                config,
                effective_downstream_addr,
                request_authority(&request),
                &request.target,
            )
        {
            write_local_response(
                &mut downstream,
                false,
                StatusCode::FORBIDDEN,
                "source temporarily blocked\n",
            )
            .await
            .map_err(Http1ProxyError::ResponseIo)?;
            metrics.request_count += 1;
            *metrics.response_status_counts.entry(StatusCode::FORBIDDEN.as_u16()).or_insert(0) += 1;
            break;
        }

        let original_request = request.clone();
        if let Some(transform) = effective_request_transform(config, request.route.as_ref()) {
            if apply_request_transform(&mut request, &transform).is_err() {
                write_local_response(
                    &mut downstream,
                    request.keep_alive,
                    StatusCode::BAD_REQUEST,
                    "invalid transformed request target\n",
                )
                .await
                .map_err(Http1ProxyError::ResponseIo)?;
                metrics.request_count += 1;
                *metrics
                    .response_status_counts
                    .entry(StatusCode::BAD_REQUEST.as_u16())
                    .or_insert(0) += 1;
                if !request.keep_alive {
                    break;
                }
                continue;
            }
        }

        let requested_upgrade = match classify_requested_upgrade(&request) {
            Ok(requested_upgrade) => requested_upgrade,
            Err(error) => {
                record_upgrade_telemetry(
                    config,
                    HttpUpgradeResult::Rejected,
                    error.telemetry_reason(),
                    error.message().trim_end(),
                );
                write_local_response(&mut downstream, false, StatusCode::BAD_REQUEST, error.message())
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                metrics.request_count += 1;
                *metrics
                    .response_status_counts
                    .entry(StatusCode::BAD_REQUEST.as_u16())
                    .or_insert(0) += 1;
                break;
            }
        };
        if requested_upgrade.is_some() && !route_allows_requested_upgrade(config, request.route.as_ref())
        {
            record_upgrade_telemetry(
                config,
                HttpUpgradeResult::Rejected,
                "policy_denied",
                "route upgrade policy denied the requested protocol",
            );
            write_local_response(
                &mut downstream,
                false,
                StatusCode::BAD_REQUEST,
                "upgrade not allowed for the selected route\n",
            )
            .await
            .map_err(Http1ProxyError::ResponseIo)?;
            metrics.request_count += 1;
            *metrics
                .response_status_counts
                .entry(StatusCode::BAD_REQUEST.as_u16())
                .or_insert(0) += 1;
            break;
        }

        let selected_upstream = match resolve_request_upstream(config, &request) {
            RequestUpstreamResolution::Selected(upstream) => upstream,
            RequestUpstreamResolution::Reject(status, reason) => {
                let blocked = status == StatusCode::FORBIDDEN
                    && record_unmatched_route(config, effective_downstream_addr);
                let response_reason = if blocked { "source temporarily blocked\n" } else { reason };
                write_local_response(
                    &mut downstream,
                    request.keep_alive && !blocked,
                    status,
                    response_reason,
                )
                .await
                .map_err(Http1ProxyError::ResponseIo)?;
                metrics.request_count += 1;
                *metrics.response_status_counts.entry(status.as_u16()).or_insert(0) += 1;
                if blocked || !request.keep_alive {
                    break;
                }
                continue;
            }
        };

        let destination_policy =
            route_destination_policy_runtime(config, request.route.as_ref(), &selected_upstream);
        if let Some(transform) = destination_policy.and_then(|policy| policy.request_transform.as_ref())
        {
            request = original_request;
            if apply_request_transform(&mut request, transform).is_err() {
                write_local_response(
                    &mut downstream,
                    request.keep_alive,
                    StatusCode::BAD_REQUEST,
                    "invalid transformed request target\n",
                )
                .await
                .map_err(Http1ProxyError::ResponseIo)?;
                metrics.request_count += 1;
                *metrics
                    .response_status_counts
                    .entry(StatusCode::BAD_REQUEST.as_u16())
                    .or_insert(0) += 1;
                if !request.keep_alive {
                    break;
                }
                continue;
            }
        }
        let destination_response_transform = effective_destination_response_transform(
            config,
            request.route.as_ref(),
            destination_policy,
        );
        let _destination_concurrency_leases = match enforce_destination_local_limits(
            destination_policy,
            &request,
            &selected_upstream,
            effective_client_ip,
        ) {
            Ok(leases) => leases,
            Err((status, body)) => {
                write_local_response(&mut downstream, request.keep_alive, status, body)
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                metrics.request_count += 1;
                *metrics.response_status_counts.entry(status.as_u16()).or_insert(0) += 1;
                if !request.keep_alive {
                    break;
                }
                continue;
            }
        };

        if let Some(status) = maybe_inject_http1_fault(
            &request,
            &mut downstream,
            destination_policy,
            &mut metrics,
        )
        .await
        .map_err(Http1ProxyError::ResponseIo)?
        {
            metrics.request_count += 1;
            *metrics.response_status_counts.entry(status.as_u16()).or_insert(0) += 1;
            if !request.keep_alive {
                break;
            }
            continue;
        }

        maybe_spawn_shadow_http1_request(
            config,
            &request,
            effective_client_ip,
            requested_upgrade,
            destination_policy,
            &mut metrics,
        );

        let now = config
            .response_cache
            .as_ref()
            .map_or(Duration::ZERO, |response_cache| response_cache.store.now());
        if let Some(cache_result) = resolve_cache_request(config.response_cache.as_ref(), &request, now)
        {
            match cache_result {
                CacheRequestOutcome::CacheHit { entry, outcome, reason } => {
                    write_cached_response(
                        &mut downstream,
                        &request.method,
                        request.keep_alive,
                        entry.as_ref(),
                        destination_response_transform.as_ref(),
                    )
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                    metrics.request_count += 1;
                    metrics.cache_hit_count += 1;
                    record_cache_request_telemetry(
                        config.response_cache.as_ref(),
                        outcome,
                        reason,
                        &format!(
                            "served cached response with status {}",
                            entry.metadata.status.as_u16()
                        ),
                    );
                    *metrics
                        .response_status_counts
                        .entry(entry.metadata.status.as_u16())
                        .or_insert(0) += 1;
                    if !request.keep_alive {
                        break;
                    }
                    continue;
                }
                CacheRequestOutcome::Fetch { key, stale_fallback, revalidation_entry, reason } => {
                    metrics.cache_miss_count += 1;
                    record_cache_request_telemetry(
                        config.response_cache.as_ref(),
                        HttpCacheRequestOutcome::Miss,
                        reason,
                        "cache lookup required origin fetch",
                    );
                    let result = process_uncached_request(
                        &mut upstream,
                        &mut active_upstream,
                        &mut last_upstream_activity,
                        &mut upstream_connected_at,
                        &mut upstream_addr,
                        &mut connect_duration,
                        &mut downstream,
                        &mut downstream_buffer,
                        &mut upstream_buffer,
                        effective_client_ip,
                        config,
                        &selected_upstream.target,
                        &request,
                        requested_upgrade,
                        destination_policy,
                        destination_response_transform.as_ref(),
                        key,
                        stale_fallback.as_deref(),
                        revalidation_entry.as_deref(),
                        &mut metrics,
                        now,
                    )
                    .await;
                    record_passive_health_result(&selected_upstream, &result);
                    match result {
                        Err(error)
                            if stale_fallback.is_some() && error_allows_stale_if_error(&error) =>
                        {
                            let stale_entry = stale_fallback.unwrap_or_else(|| unreachable!());
                            let _ = upstream.take();
                            write_cached_response(
                                &mut downstream,
                                &request.method,
                                request.keep_alive,
                                &stale_entry,
                                destination_response_transform.as_ref(),
                            )
                            .await
                            .map_err(Http1ProxyError::ResponseIo)?;
                            metrics.request_count += 1;
                            metrics.cache_hit_count += 1;
                            record_cache_request_telemetry(
                                config.response_cache.as_ref(),
                                HttpCacheRequestOutcome::StaleHit,
                                "stale_if_error",
                                "served stale cached response after upstream failure",
                            );
                            *metrics
                                .response_status_counts
                                .entry(stale_entry.metadata.status.as_u16())
                                .or_insert(0) += 1;
                        }
                        Err(error) => return Err(error),
                        Ok(status) if status == StatusCode::SWITCHING_PROTOCOLS.as_u16() => break,
                        Ok(_) => {}
                    }
                }
                CacheRequestOutcome::Bypass(reason) => {
                    metrics.cache_bypass_count += 1;
                    record_cache_request_telemetry(
                        config.response_cache.as_ref(),
                        HttpCacheRequestOutcome::Bypass,
                        reason,
                        "request bypassed shared cache",
                    );
                    let result = process_uncached_request(
                        &mut upstream,
                        &mut active_upstream,
                        &mut last_upstream_activity,
                        &mut upstream_connected_at,
                        &mut upstream_addr,
                        &mut connect_duration,
                        &mut downstream,
                        &mut downstream_buffer,
                        &mut upstream_buffer,
                        effective_client_ip,
                        config,
                        &selected_upstream.target,
                        &request,
                        requested_upgrade,
                        destination_policy,
                        destination_response_transform.as_ref(),
                        None,
                        None,
                        None,
                        &mut metrics,
                        now,
                    )
                    .await;
                    record_passive_health_result(&selected_upstream, &result);
                    if result? == StatusCode::SWITCHING_PROTOCOLS.as_u16() {
                        break;
                    }
                }
            }
        } else {
            let result = process_uncached_request(
                &mut upstream,
                &mut active_upstream,
                &mut last_upstream_activity,
                &mut upstream_connected_at,
                &mut upstream_addr,
                &mut connect_duration,
                &mut downstream,
                &mut downstream_buffer,
                &mut upstream_buffer,
                effective_client_ip,
                config,
                &selected_upstream.target,
                &request,
                requested_upgrade,
                destination_policy,
                destination_response_transform.as_ref(),
                None,
                None,
                None,
                &mut metrics,
                now,
            )
            .await;
            record_passive_health_result(&selected_upstream, &result);
            if result? == StatusCode::SWITCHING_PROTOCOLS.as_u16() {
                break;
            }
        }
        if !request.keep_alive {
            break;
        }
    }

    Ok(Http1ConnectionReport {
        downstream_addr,
        upstream_addr,
        upstream_name: active_upstream
            .as_ref()
            .map(|upstream| upstream.name.clone())
            .unwrap_or_else(|| config.upstream.name.clone()),
        connect_duration,
        metrics,
        route_selection_metrics: route_selection_metrics(&config.route_backend_pools),
    })
}
