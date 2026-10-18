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

    if selected_upstream.transport == lb_net_core::UpstreamTransport::Http3 {
        drop_upstream_connection(upstream, last_upstream_activity, upstream_connected_at);
        *active_upstream = Some(selected_upstream.clone());
        *upstream_addr = selected_upstream.address;

        let normalized_request_headers = lb_proto_http::normalize_request_headers(
            &request.headers,
            effective_client_ip,
            request.keep_alive,
            &request.body_kind,
        );

        // HTTP/3 carries its own framing, so the HTTP/1.1 chunked encoding must be removed.
        let request_body = collect_decoded_body(
            downstream,
            downstream_buffer,
            &request.body_kind,
            config.limits.max_body_bytes,
            effective_timeouts.idle_timeout,
            RelayDirection::Request,
        )
        .await?;

        let h3_response = match crate::http3_upstream::dispatch_http3_upstream_request(
            selected_upstream,
            &request.method,
            &request.target,
            &normalized_request_headers,
            &request_body,
            effective_client_ip,
            effective_timeouts.connect_timeout,
            effective_timeouts.idle_timeout,
            config.limits.max_body_bytes,
        )
        .await
        {
            Ok(response) => response,
            Err(crate::http3_upstream::Http3UpstreamError::GracefulDrain) => {
                write_local_response(
                    downstream,
                    request.keep_alive,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "upstream draining\n",
                )
                .await
                .map_err(Http1ProxyError::ResponseIo)?;
                metrics.request_count += 1;
                *metrics
                    .response_status_counts
                    .entry(StatusCode::SERVICE_UNAVAILABLE.as_u16())
                    .or_insert(0) += 1;
                return Ok(StatusCode::SERVICE_UNAVAILABLE.as_u16());
            }
            Err(source) => {
                return Err(Http1ProxyError::ResponseIo(std::io::Error::other(source)));
            }
        };

        let body_kind = lb_proto_http::BodyKind::ContentLength(h3_response.body.len() as u64);
        let mut normalized_response_headers = lb_proto_http::normalize_response_headers(
            &h3_response.headers,
            request.keep_alive,
            &body_kind,
        );
        if !normalized_response_headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-length"))
        {
            normalized_response_headers.push(lb_proto_http::HttpHeader {
                name: String::from("content-length"),
                value: h3_response.body.len().to_string(),
            });
        }
        if let Some(transform) = response_transform {
            apply_http1_header_mutations(
                &mut normalized_response_headers,
                &transform.header_mutations,
            );
        }
        let response_head = lb_proto_http::encode_response_head(
            lb_proto_http::SupportedHttpVersion::Http1,
            h3_response.status,
            &h3_response.reason,
            &normalized_response_headers,
        );
        downstream.write_all(&response_head).await.map_err(Http1ProxyError::ResponseIo)?;
        if !h3_response.body.is_empty() {
            downstream.write_all(&h3_response.body).await.map_err(Http1ProxyError::ResponseIo)?;
        }

        metrics.request_count += 1;
        *metrics.response_status_counts.entry(h3_response.status).or_insert(0) += 1;
        match classify_http1_response_failure(h3_response.status) {
            Some(class) => record_destination_failure(destination_policy, class),
            None => record_destination_success(destination_policy),
        }

        return Ok(h3_response.status);
    }

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
        .inspect_err(|error| match error {
            Http1ProxyError::ConnectTimeout { .. } => {
                record_destination_timeout(destination_policy, crate::TimeoutCategory::Connect);
            }
            Http1ProxyError::Connect { .. } => {
                record_destination_failure(
                    destination_policy,
                    crate::UpstreamFailureClass::Connect,
                );
            }
            _ => {}
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
                record_destination_failure(
                    destination_policy,
                    crate::UpstreamFailureClass::Connect,
                );
                if retry_stale_reuse
                    && allow_destination_retry(
                        destination_policy,
                        crate::UpstreamFailureClass::Connect,
                        None,
                        config.request_telemetry.as_ref(),
                        request.route.as_ref().map(|route| route.label.as_str()),
                        Some(selected_upstream.name.as_str()),
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
                            None,
                            config.request_telemetry.as_ref(),
                            request.route.as_ref().map(|route| route.label.as_str()),
                            Some(selected_upstream.name.as_str()),
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

            // Connection management is hop-by-hop: the downstream `connection` header is
            // derived from the downstream request, never from the upstream response, and
            // must not leak into cache entries.
            let normalized_response_headers = lb_proto_http::normalize_response_headers(
                &response.headers,
                true,
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
                            Http1ProxyError::IdleTimeout("upgrade tunnel") => "tunnel_idle_timeout",
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
                if request.http10
                    && lb_proto_http::has_non_chunked_transfer_coding(&response.headers)
                {
                    // HTTP/1.0 has no transfer codings; such a body cannot be delivered intact.
                    drop_upstream_connection(
                        upstream,
                        last_upstream_activity,
                        upstream_connected_at,
                    );
                    break Err(Http1ProxyError::ParseResponse(
                        lb_proto_http::Http1ParseError::Invalid(
                            "unsupported response transfer coding for HTTP/1.0 client",
                        ),
                    ));
                }
                let mut downstream_response_headers = normalized_response_headers.clone();
                if let Some(transform) = response_transform {
                    apply_http1_header_mutations(
                        &mut downstream_response_headers,
                        &transform.header_mutations,
                    );
                }
                let reframe_for_http10 = request.http10
                    && matches!(
                        response.body_kind,
                        lb_proto_http::BodyKind::Chunked | lb_proto_http::BodyKind::CloseDelimited
                    );
                if reframe_for_http10 {
                    downstream_response_headers.retain(|header| {
                        !header.name.eq_ignore_ascii_case("transfer-encoding")
                            && !header.name.eq_ignore_ascii_case("trailer")
                    });
                }
                if !request.keep_alive {
                    downstream_response_headers.push(lb_proto_http::HttpHeader {
                        name: String::from("connection"),
                        value: String::from("close"),
                    });
                }
                let response_head = lb_proto_http::encode_response_head(
                    response.version,
                    response.status,
                    &response.reason,
                    &downstream_response_headers,
                );
                downstream.write_all(&response_head).await.map_err(Http1ProxyError::ResponseIo)?;

                let mut body_relayed = false;
                if let Some(response_cache) = config.response_cache.as_ref() {
                    if let Some(cache_lookup_key) = cache_lookup_key {
                        let fill = build_cacheable_response_entry(
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
                        .await
                        .map_err(|error| response_started_error(error, stale_fallback.is_some()))?;
                        body_relayed = fill.body_relayed;
                        if let Some(entry) = fill.entry {
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
                if !body_relayed {
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
                                // The response head was already sent downstream, so a local
                                // 504 would corrupt the stream; abort the exchange instead.
                                record_destination_timeout(destination_policy, category);
                                drop_upstream_connection(
                                    upstream,
                                    last_upstream_activity,
                                    upstream_connected_at,
                                );
                                break Err(Http1ProxyError::IdleTimeout("response body"));
                            }
                        };
                    let relayed = if reframe_for_http10 {
                        relay_response_body_for_http10(
                            upstream_stream,
                            upstream_buffer,
                            downstream,
                            &response.body_kind,
                            config.limits.max_body_bytes,
                            response_body_timeout,
                        )
                        .await
                    } else {
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
                    };
                    relayed.map_err(|error| {
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
                        response_started_error(error, stale_fallback.is_some())
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

/// Once a response head has been streamed downstream, a stale cached response can no longer
/// be substituted. Re-label errors that would otherwise trigger `stale-if-error` so the
/// connection is aborted instead of emitting a second response on the same stream.
fn response_started_error(error: Http1ProxyError, stale_fallback_armed: bool) -> Http1ProxyError {
    if stale_fallback_armed && error_allows_stale_if_error(&error) {
        Http1ProxyError::ResponseIo(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        ))
    } else {
        error
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

struct CacheFillAttempt {
    entry: Option<HttpCacheEntry>,
    /// Whether the response body was already relayed downstream while collecting it.
    body_relayed: bool,
}

impl CacheFillAttempt {
    const fn skipped() -> Self {
        Self { entry: None, body_relayed: false }
    }
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
) -> Result<CacheFillAttempt, Http1ProxyError>
where
    W: AsyncWrite + Unpin,
{
    if !request.method.eq_ignore_ascii_case("GET")
        || !response_is_cacheable(&response_cache.policy, response, normalized_response_headers)
    {
        return Ok(CacheFillAttempt::skipped());
    }

    let Ok(status) = StatusCode::from_u16(response.status) else {
        return Ok(CacheFillAttempt::skipped());
    };
    let Some(metadata) =
        derive_cache_metadata(&response_cache.policy, normalized_response_headers, status, now)
    else {
        return Ok(CacheFillAttempt::skipped());
    };
    let Some(headers) = to_cache_headers(normalized_response_headers) else {
        return Ok(CacheFillAttempt::skipped());
    };

    let body = match response.body_kind {
        lb_proto_http::BodyKind::None => bytes::Bytes::new(),
        lb_proto_http::BodyKind::ContentLength(length) => {
            if length > response_cache.policy.max_object_bytes
                || length > config.limits.max_body_bytes
            {
                return Ok(CacheFillAttempt::skipped());
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
        lb_proto_http::BodyKind::Chunked | lb_proto_http::BodyKind::CloseDelimited => {
            return Ok(CacheFillAttempt::skipped());
        }
    };

    Ok(CacheFillAttempt {
        entry: Some(HttpCacheEntry { metadata, headers, body }),
        body_relayed: true,
    })
}

#[cfg(test)]
mod cache_fill_coverage_tests {
    use std::io;

    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn entry() -> HttpCacheEntry {
        HttpCacheEntry {
            metadata: HttpCacheMetadata {
                status: StatusCode::OK,
                stored_at: Duration::ZERO,
                fresh_until: Duration::from_secs(10),
                stale_while_revalidate_until: None,
                stale_if_error_until: None,
                etag: None,
                last_modified: None,
            },
            headers: vec![HttpCacheHeader::new(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("text/plain"),
            )],
            body: bytes::Bytes::from_static(b"cached body"),
        }
    }

    #[test]
    fn skipped_attempt_and_started_response_error_have_explicit_semantics() {
        let skipped = CacheFillAttempt::skipped();
        assert!(skipped.entry.is_none());
        assert!(!skipped.body_relayed);
        assert!(matches!(
            response_started_error(Http1ProxyError::UpstreamGracefulDrain, true),
            Http1ProxyError::ResponseIo(error) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            response_started_error(Http1ProxyError::UpstreamGracefulDrain, false),
            Http1ProxyError::UpstreamGracefulDrain
        ));
    }

    #[tokio::test]
    async fn cached_head_is_bodyless_and_cached_get_writes_body(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cached = entry();
        let (mut writer, mut reader) = tokio::io::duplex(256);
        write_cached_response(&mut writer, "HEAD", false, &cached, None).await?;
        drop(writer);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await?;
        let output = String::from_utf8(output)?;
        assert!(output.contains("connection: close\r\n"));
        assert!(output.ends_with("\r\n\r\n"));
        assert!(!output.contains("cached body"));

        let (mut writer, mut reader) = tokio::io::duplex(256);
        write_cached_response(&mut writer, "GET", true, &cached, None).await?;
        drop(writer);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await?;
        assert!(output.ends_with(b"\r\n\r\ncached body"));
        Ok(())
    }

    #[tokio::test]
    async fn cache_fill_skips_non_get_and_non_cacheable_responses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut upstream = TcpStream::connect(address).await?;
        let (_accepted, _) = listener.accept().await?;
        let mut upstream_buffer = Vec::new();
        let (mut downstream, _reader) = tokio::io::duplex(128);
        let config = Http1ProxyConfig::new(lb_net_core::UpstreamTarget::new("cache", address));
        let cache = Http1ResponseCacheConfig::new(
            lb_config_model::HttpCachePolicyConfig::default(),
            Arc::new(HttpCacheStore::new(crate::HttpCacheStoreConfig {
                max_entries: 4,
                max_bytes: 4 * 1024,
                max_object_bytes: 1024,
            })?),
        );
        let response = lb_proto_http::Http1ResponseHead {
            version: lb_proto_http::SupportedHttpVersion::Http1,
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            reason: String::from("Internal Server Error"),
            headers: Vec::new(),
            body_kind: lb_proto_http::BodyKind::None,
            keep_alive: false,
        };
        let request = |method: &str| lb_proto_http::Http1RequestHead {
            method: method.to_string(),
            target: String::from("/"),
            version: lb_proto_http::SupportedHttpVersion::Http1,
            headers: Vec::new(),
            body_kind: lb_proto_http::BodyKind::None,
            keep_alive: true,
            route: None,
            http10: false,
        };

        for method in ["POST", "GET"] {
            let attempt = build_cacheable_response_entry(
                &cache,
                &request(method),
                &response,
                &[],
                &mut upstream,
                &mut upstream_buffer,
                &mut downstream,
                &config,
                Duration::ZERO,
            )
            .await?;
            assert!(attempt.entry.is_none());
            assert!(!attempt.body_relayed);
        }
        Ok(())
    }
}
