#[allow(clippy::too_many_arguments)]
async fn process_uncached_request<S>(
    upstream: &mut Option<TcpStream>,
    active_upstream: &mut Option<lb_net_core::UpstreamTarget>,
    last_upstream_activity: &mut Option<Instant>,
    upstream_connected_at: &mut Option<Instant>,
    upstream_addr: &mut SocketAddr,
    connect_duration: &mut Duration,
    downstream: &mut S,
    downstream_buffer: &mut Vec<u8>,
    upstream_buffer: &mut Vec<u8>,
    effective_client_ip: IpAddr,
    config: &Http1ProxyConfig,
    selected_upstream: &lb_net_core::UpstreamTarget,
    request: &lb_proto_http::Http1RequestHead,
    requested_upgrade: Option<lb_config_model::UpgradeProtocolConfig>,
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
    response_transform: Option<&lb_config_model::ResponseTransformConfig>,
    cache_lookup_key: Option<HttpCacheKey>,
    stale_fallback: Option<&HttpCacheEntry>,
    revalidation_entry: Option<&HttpCacheEntry>,
    metrics: &mut Http1ConnectionMetrics,
    now: Duration,
) -> Result<u16, Http1ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(policy) = destination_policy.filter(|policy| policy.enforce_retry_budget) {
        if let Some(manager) = destination_failure_manager(Some(policy)) {
            manager.record_base_request(failure_policy_now());
        }
    }

    let effective_timeouts =
        effective_destination_upstream_timeouts(&config.timeouts, destination_policy);
    let request_started = Instant::now();
    let mut retried_stale_reuse = false;
    let mut close_upstream = false;
    loop {
        let attempt_started = Instant::now();
        if let Some(policy) = destination_policy.filter(|policy| policy.enforce_circuit_breaker) {
            if let Some(manager) = destination_failure_manager(Some(policy)) {
                if !manager.allow_request(failure_policy_now()) {
                    write_local_response(
                        downstream,
                        request.keep_alive,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "route destination circuit open\n",
                    )
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                    metrics.request_count += 1;
                    *metrics
                        .response_status_counts
                        .entry(StatusCode::SERVICE_UNAVAILABLE.as_u16())
                        .or_insert(0) += 1;
                    break Ok(StatusCode::SERVICE_UNAVAILABLE.as_u16());
                }
            }
        }

        let reused_existing_connection = ensure_upstream_connection(
            upstream,
            active_upstream,
            last_upstream_activity,
            upstream_connected_at,
            upstream_addr,
            connect_duration,
            selected_upstream,
            &effective_timeouts,
        )
        .await
        .map_err(|error| {
            match &error {
                Http1ProxyError::ConnectTimeout { .. } => {
                    record_destination_timeout(destination_policy, crate::TimeoutCategory::Connect);
                }
                Http1ProxyError::Connect { .. } => {
                    record_destination_failure(destination_policy, crate::UpstreamFailureClass::Connect);
                }
                _ => {}
            }
            error
        })?;
        let retry_stale_reuse = reused_existing_connection
            && !retried_stale_reuse
            && request_is_safe_stale_reuse_retry_candidate(request);

        {
            let Some(upstream_stream) = upstream.as_mut() else {
                break Err(Http1ProxyError::ConnectTimeout { target: selected_upstream.address });
            };

            let normalized_request_headers = lb_proto_http::normalize_request_headers(
                &request.headers,
                effective_client_ip,
                request.keep_alive,
                &request.body_kind,
            );
            let mut normalized_request_headers = append_conditional_revalidation_headers(
                normalized_request_headers,
                revalidation_entry,
            );
            if requested_upgrade.is_some() {
                append_upgrade_headers(&mut normalized_request_headers, &request.headers);
            }
            let request_head = lb_proto_http::encode_request_head(
                &request.method,
                &request.target,
                request.version,
                &normalized_request_headers,
            );
            if let Err(source) = upstream_stream.write_all(&request_head).await {
                drop_upstream_connection(upstream, last_upstream_activity, upstream_connected_at);
                record_destination_failure(destination_policy, crate::UpstreamFailureClass::Connect);
                if retry_stale_reuse
                    && allow_destination_retry(
                        destination_policy,
                        crate::UpstreamFailureClass::Connect,
                    )
                {
                    retried_stale_reuse = true;
                    continue;
                }
                break Err(Http1ProxyError::RequestIo(source));
            }
            let (request_body_timeout, request_body_timeout_category) =
                match bounded_dispatch_timeout(
                    destination_policy,
                    crate::TimeoutCategory::Idle,
                    effective_timeouts.idle_timeout,
                    request_started,
                    attempt_started,
                ) {
                    Ok(value) => value,
                    Err(category) => {
                        record_destination_timeout(destination_policy, category);
                        write_local_response(
                            downstream,
                            request.keep_alive,
                            StatusCode::GATEWAY_TIMEOUT,
                            "route destination timed out\n",
                        )
                        .await
                        .map_err(Http1ProxyError::ResponseIo)?;
                        metrics.request_count += 1;
                        *metrics
                            .response_status_counts
                            .entry(StatusCode::GATEWAY_TIMEOUT.as_u16())
                            .or_insert(0) += 1;
                        break Ok(StatusCode::GATEWAY_TIMEOUT.as_u16());
                    }
                };
            relay_body(
                downstream,
                downstream_buffer,
                upstream_stream,
                &request.body_kind,
                config.limits.max_body_bytes,
                request_body_timeout,
                RelayDirection::Request,
            )
            .await
            .map_err(|error| {
                if matches!(error, Http1ProxyError::IdleTimeout(_)) {
                    record_destination_timeout(destination_policy, request_body_timeout_category);
                } else {
                    record_destination_failure(
                        destination_policy,
                        crate::UpstreamFailureClass::Temporary,
                    );
                }
                error
            })?;

            let (response_head_timeout, response_head_timeout_category) =
                match bounded_dispatch_timeout(
                    destination_policy,
                    crate::TimeoutCategory::Idle,
                    effective_timeouts.idle_timeout,
                    request_started,
                    attempt_started,
                ) {
                    Ok(value) => value,
                    Err(category) => {
                        record_destination_timeout(destination_policy, category);
                        write_local_response(
                            downstream,
                            request.keep_alive,
                            StatusCode::GATEWAY_TIMEOUT,
                            "route destination timed out\n",
                        )
                        .await
                        .map_err(Http1ProxyError::ResponseIo)?;
                        metrics.request_count += 1;
                        *metrics
                            .response_status_counts
                            .entry(StatusCode::GATEWAY_TIMEOUT.as_u16())
                            .or_insert(0) += 1;
                        break Ok(StatusCode::GATEWAY_TIMEOUT.as_u16());
                    }
                };

            let response = match time::timeout(
                response_head_timeout,
                lb_proto_http::read_response_head(
                    upstream_stream,
                    upstream_buffer,
                    &config.limits,
                    &request.method,
                ),
            )
            .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(source)) => {
                    let error = Http1ProxyError::ParseResponse(source);
                    drop_upstream_connection(
                        upstream,
                        last_upstream_activity,
                        upstream_connected_at,
                    );
                    record_destination_failure(
                        destination_policy,
                        crate::UpstreamFailureClass::Temporary,
                    );
                    if retry_stale_reuse
                        && http1_stale_reuse_retryable_response_error(&error)
                        && allow_destination_retry(
                            destination_policy,
                            crate::UpstreamFailureClass::Temporary,
                        )
                    {
                        retried_stale_reuse = true;
                        continue;
                    }
                    break Err(error);
                }
                Err(_) => {
                    record_destination_timeout(destination_policy, response_head_timeout_category);
                    drop_upstream_connection(
                        upstream,
                        last_upstream_activity,
                        upstream_connected_at,
                    );
                    break Err(Http1ProxyError::IdleTimeout("response head"));
                }
            };

            let normalized_response_headers = lb_proto_http::normalize_response_headers(
                &response.headers,
                response.keep_alive,
                &response.body_kind,
            );
            let mut normalized_response_headers = normalized_response_headers;
            if let Some(requested_upgrade) = requested_upgrade {
                if response.status == StatusCode::SWITCHING_PROTOCOLS.as_u16() {
                    if !response_accepts_requested_upgrade(&response, requested_upgrade) {
                        record_upgrade_telemetry(
                            config,
                            HttpUpgradeResult::Failed,
                            "malformed_101",
                            "upstream returned 101 without valid upgrade response headers",
                        );
                        drop_upstream_connection(
                            upstream,
                            last_upstream_activity,
                            upstream_connected_at,
                        );
                        break Err(Http1ProxyError::ParseResponse(
                            lb_proto_http::Http1ParseError::Invalid(
                                "invalid upgrade response headers",
                            ),
                        ));
                    }
                    append_upgrade_headers(&mut normalized_response_headers, &response.headers);
                    let response_head = lb_proto_http::encode_response_head(
                        response.version,
                        response.status,
                        &response.reason,
                        &normalized_response_headers,
                    );
                    downstream
                        .write_all(&response_head)
                        .await
                        .map_err(Http1ProxyError::ResponseIo)?;
                    record_upgrade_telemetry(
                        config,
                        HttpUpgradeResult::Accepted,
                        "websocket",
                        "upgrade tunnel established",
                    );
                    if let Err(error) = relay_upgraded_streams(
                        downstream,
                        downstream_buffer,
                        upstream_stream,
                        upstream_buffer,
                        effective_timeouts.idle_timeout,
                    )
                    .await
                    {
                        let reason = match &error {
                            Http1ProxyError::IdleTimeout("upgrade tunnel") => {
                                "tunnel_idle_timeout"
                            }
                            _ => "tunnel_io",
                        };
                        record_upgrade_telemetry(
                            config,
                            HttpUpgradeResult::Failed,
                            reason,
                            "upgrade tunnel terminated before clean shutdown",
                        );
                        if matches!(error, Http1ProxyError::IdleTimeout(_)) {
                            record_destination_timeout(
                                destination_policy,
                                crate::TimeoutCategory::Idle,
                            );
                        } else {
                            record_destination_failure(
                                destination_policy,
                                crate::UpstreamFailureClass::Temporary,
                            );
                        }
                        return Err(error);
                    }
                    metrics.request_count += 1;
                    *metrics.response_status_counts.entry(response.status).or_insert(0) += 1;
                    record_destination_success(destination_policy);
                    drop_upstream_connection(
                        upstream,
                        last_upstream_activity,
                        upstream_connected_at,
                    );
                    break Ok(response.status);
                }
                record_upgrade_telemetry(
                    config,
                    HttpUpgradeResult::Failed,
                    "upstream_refused",
                    "upstream declined the requested protocol upgrade",
                );
            }
            let upstream_response_status = response.status;
            let use_stale_if_error_response =
                stale_fallback.is_some() && is_stale_if_error_response_status(response.status);
            let use_not_modified_revalidation =
                response.status == 304 && revalidation_entry.is_some();
            if use_not_modified_revalidation {
                if let Some(stale_entry) = revalidation_entry {
                    let refreshed_entry = refresh_revalidated_entry(
                        config.response_cache.as_ref().map(|response_cache| &response_cache.policy),
                        stale_entry,
                        &normalized_response_headers,
                        now,
                    )
                    .unwrap_or_else(|| stale_entry.clone());
                    if let Some(response_cache) = config.response_cache.as_ref() {
                        if let Some(cache_lookup_key) = cache_lookup_key.clone() {
                            if response_cache
                                .store
                                .insert(now, cache_lookup_key, refreshed_entry.clone())
                                .is_ok()
                            {
                                metrics.cache_fill_count += 1;
                                record_cache_revalidation_telemetry(
                                    Some(response_cache),
                                    HttpCacheRevalidationResult::NotModified,
                                    "origin returned 304 Not Modified",
                                );
                            }
                        }
                    }
                    write_cached_response(
                        downstream,
                        &request.method,
                        request.keep_alive,
                        &refreshed_entry,
                        response_transform,
                    )
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                    metrics.request_count += 1;
                    *metrics
                        .response_status_counts
                        .entry(refreshed_entry.metadata.status.as_u16())
                        .or_insert(0) += 1;
                    record_destination_success(destination_policy);
                    close_upstream = !response.keep_alive;
                    if close_upstream {
                        drop_upstream_connection(
                            upstream,
                            last_upstream_activity,
                            upstream_connected_at,
                        );
                    } else {
                        *last_upstream_activity = Some(Instant::now());
                    }
                    break Ok(upstream_response_status);
                }
            } else if use_stale_if_error_response {
                if let Some(stale_entry) = stale_fallback {
                    write_cached_response(
                        downstream,
                        &request.method,
                        request.keep_alive,
                        stale_entry,
                        response_transform,
                    )
                    .await
                    .map_err(Http1ProxyError::ResponseIo)?;
                    metrics.request_count += 1;
                    metrics.cache_hit_count += 1;
                    record_cache_request_telemetry(
                        config.response_cache.as_ref(),
                        HttpCacheRequestOutcome::StaleHit,
                        "stale_if_error_response",
                        "served stale cached response after upstream error status",
                    );
                    *metrics
                        .response_status_counts
                        .entry(stale_entry.metadata.status.as_u16())
                        .or_insert(0) += 1;
                    record_destination_success(destination_policy);
                    close_upstream = true;
                    if close_upstream {
                        drop_upstream_connection(
                            upstream,
                            last_upstream_activity,
                            upstream_connected_at,
                        );
                    }
                    break Ok(upstream_response_status);
                }
            } else {
                let mut downstream_response_headers = normalized_response_headers.clone();
                if let Some(transform) = response_transform {
                    apply_http1_header_mutations(
                        &mut downstream_response_headers,
                        &transform.header_mutations,
                    );
                }
                let response_head = lb_proto_http::encode_response_head(
                    response.version,
                    response.status,
                    &response.reason,
                    &downstream_response_headers,
                );
                downstream.write_all(&response_head).await.map_err(Http1ProxyError::ResponseIo)?;

                let mut filled_cache = false;
                if let Some(response_cache) = config.response_cache.as_ref() {
                    if let Some(cache_lookup_key) = cache_lookup_key {
                        if let Some(entry) = build_cacheable_response_entry(
                            response_cache,
                            request,
                            &response,
                            &normalized_response_headers,
                            upstream_stream,
                            upstream_buffer,
                            downstream,
                            config,
                            now,
                        )
                        .await?
                        {
                            if response_cache.store.insert(now, cache_lookup_key, entry).is_ok() {
                                metrics.cache_fill_count += 1;
                                record_cache_request_telemetry(
                                    Some(response_cache),
                                    HttpCacheRequestOutcome::Fill,
                                    if revalidation_entry.is_some() {
                                        "revalidation_replace"
                                    } else {
                                        "origin_response"
                                    },
                                    "stored response in shared cache",
                                );
                                if revalidation_entry.is_some() {
                                    record_cache_revalidation_telemetry(
                                        Some(response_cache),
                                        HttpCacheRevalidationResult::Replaced,
                                        "origin returned replacement response for revalidation",
                                    );
                                }
                                filled_cache = true;
                            } else {
                                metrics.cache_bypass_count += 1;
                                record_cache_request_telemetry(
                                    Some(response_cache),
                                    HttpCacheRequestOutcome::Bypass,
                                    "store_reject",
                                    "cache store rejected response insertion",
                                );
                            }
                        }
                    }
                }
                if !filled_cache {
                    let (response_body_timeout, response_body_timeout_category) =
                        match bounded_dispatch_timeout(
                            destination_policy,
                            crate::TimeoutCategory::Idle,
                            effective_timeouts.idle_timeout,
                            request_started,
                            attempt_started,
                        ) {
                            Ok(value) => value,
                            Err(category) => {
                                record_destination_timeout(destination_policy, category);
                                write_local_response(
                                    downstream,
                                    request.keep_alive,
                                    StatusCode::GATEWAY_TIMEOUT,
                                    "route destination timed out\n",
                                )
                                .await
                                .map_err(Http1ProxyError::ResponseIo)?;
                                metrics.request_count += 1;
                                *metrics
                                    .response_status_counts
                                    .entry(StatusCode::GATEWAY_TIMEOUT.as_u16())
                                    .or_insert(0) += 1;
                                break Ok(StatusCode::GATEWAY_TIMEOUT.as_u16());
                            }
                        };
                    relay_body(
                        upstream_stream,
                        upstream_buffer,
                        downstream,
                        &response.body_kind,
                        config.limits.max_body_bytes,
                        response_body_timeout,
                        RelayDirection::Response,
                    )
                    .await
                    .map_err(|error| {
                        if matches!(error, Http1ProxyError::IdleTimeout(_)) {
                            record_destination_timeout(
                                destination_policy,
                                response_body_timeout_category,
                            );
                        } else {
                            record_destination_failure(
                                destination_policy,
                                crate::UpstreamFailureClass::Temporary,
                            );
                        }
                        error
                    })?;
                }

                metrics.request_count += 1;
                *metrics.response_status_counts.entry(response.status).or_insert(0) += 1;
                match classify_http1_response_failure(response.status) {
                    Some(class) => record_destination_failure(destination_policy, class),
                    None => record_destination_success(destination_policy),
                }
                if !response.keep_alive {
                    close_upstream = true;
                }
                if close_upstream {
                    drop_upstream_connection(
                        upstream,
                        last_upstream_activity,
                        upstream_connected_at,
                    );
                } else {
                    *last_upstream_activity = Some(Instant::now());
                }
                break Ok(upstream_response_status);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]

async fn write_cached_response<W>(
    downstream: &mut W,
    request_method: &str,
    keep_alive: bool,
    entry: &HttpCacheEntry,
    response_transform: Option<&lb_config_model::ResponseTransformConfig>,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    let mut headers = entry
        .headers
        .iter()
        .map(|header| lb_proto_http::HttpHeader {
            name: header.name.as_str().to_string(),
            value: header
                .value
                .to_str()
                .map_or_else(|_| String::new(), std::string::ToString::to_string),
        })
        .collect::<Vec<_>>();
    if let Some(transform) = response_transform {
        apply_http1_header_mutations(&mut headers, &transform.header_mutations);
    }
    if !keep_alive {
        headers.push(lb_proto_http::HttpHeader {
            name: String::from("connection"),
            value: String::from("close"),
        });
    }
    let response_head = lb_proto_http::encode_response_head(
        lb_proto_http::SupportedHttpVersion::Http1,
        entry.metadata.status.as_u16(),
        "",
        &headers,
    );
    downstream.write_all(&response_head).await?;
    if !request_method.eq_ignore_ascii_case("HEAD") {
        downstream.write_all(&entry.body).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn build_cacheable_response_entry<W>(
    response_cache: &Http1ResponseCacheConfig,
    request: &lb_proto_http::Http1RequestHead,
    response: &lb_proto_http::Http1ResponseHead,
    normalized_response_headers: &[lb_proto_http::HttpHeader],
    upstream: &mut TcpStream,
    upstream_buffer: &mut Vec<u8>,
    downstream: &mut W,
    config: &Http1ProxyConfig,
    now: Duration,
) -> Result<Option<HttpCacheEntry>, Http1ProxyError>
where
    W: AsyncWrite + Unpin,
{
    if !request.method.eq_ignore_ascii_case("GET")
        || !response_is_cacheable(&response_cache.policy, response, normalized_response_headers)
    {
        return Ok(None);
    }

    let status = StatusCode::from_u16(response.status).map_err(|_| {
        parse_side_error(
            RelayDirection::Response,
            lb_proto_http::Http1ParseError::Invalid("invalid status code"),
        )
    })?;
    let metadata = match derive_cache_metadata(
        &response_cache.policy,
        normalized_response_headers,
        status,
        now,
    ) {
        Some(metadata) => metadata,
        None => return Ok(None),
    };

    let body = match response.body_kind {
        lb_proto_http::BodyKind::None => bytes::Bytes::new(),
        lb_proto_http::BodyKind::ContentLength(length) => {
            if length > response_cache.policy.max_object_bytes {
                return Ok(None);
            }
            relay_content_length_collect(
                upstream,
                upstream_buffer,
                downstream,
                length,
                config.timeouts.idle_timeout,
                RelayDirection::Response,
            )
            .await?
        }
        lb_proto_http::BodyKind::Chunked => return Ok(None),
    };

    let headers = match to_cache_headers(normalized_response_headers) {
        Some(headers) => headers,
        None => return Ok(None),
    };

    Ok(Some(HttpCacheEntry { metadata, headers, body }))
}

