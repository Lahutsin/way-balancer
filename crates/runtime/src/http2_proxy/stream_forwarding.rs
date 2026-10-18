async fn proxy_one_http2_stream(
    mut request: Request<RecvStream>,
    respond: &mut SendResponse<Bytes>,
    downstream_addr: SocketAddr,
    upstream_clients: UpstreamClientRegistry,
    metrics: &MetricsState,
    config: &Http2ProxyConfig,
) -> Result<(), StreamForwardError> {
    let effective_client_ip =
        match resolve_effective_client_ip(config, downstream_addr, request.headers()) {
            Ok(ip) => ip,
            Err(_) => {
                send_local_response(respond, StatusCode::BAD_REQUEST)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.increment_hardening_rejection_count();
                metrics.record_anomaly(ProtocolAnomalyCategory::MalformedMessage);
                metrics.record_response_status(StatusCode::BAD_REQUEST.as_u16());
                return Ok(());
            }
        };
    let effective_downstream_addr = SocketAddr::new(effective_client_ip, downstream_addr.port());

    if anonymous_source_blocked(config, effective_client_ip) {
        send_local_response(respond, StatusCode::FORBIDDEN)
            .map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(StatusCode::FORBIDDEN.as_u16());
        return Ok(());
    }

    if route_enumeration_source_blocked(config, effective_downstream_addr) {
        send_local_response(respond, StatusCode::FORBIDDEN)
            .map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(StatusCode::FORBIDDEN.as_u16());
        return Ok(());
    }

    let authority = request.uri().authority().map(|authority| authority.as_str()).or_else(|| {
        request.headers().get(http::header::HOST).and_then(|value| value.to_str().ok())
    });
    let request_headers = header_map_to_http_headers(request.headers());
    let route_input = lb_proto_http::RouteMatchInput {
        target: request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/").to_string(),
        host: authority.map(String::from),
        method: Some(request.method().as_str().to_string()),
        headers: request_headers.clone(),
        source_ip: Some(effective_client_ip),
    };
    let canonical_route_input = lb_proto_http::canonicalize_route_match_input(&route_input).ok();
    let is_grpc = lb_proto_http::is_grpc_request(
        request.method().as_str(),
        lb_proto_http::SupportedHttpVersion::Http2,
        &request_headers,
    );
    if is_grpc {
        metrics.increment_grpc_request_count();
        if let Some(canonical_input) = canonical_route_input.as_ref() {
            if let Some(service) = canonical_input.grpc_service.as_deref() {
                metrics.record_grpc_service(service);
                if let Some(method) = canonical_input.grpc_method.as_deref() {
                    metrics.record_grpc_method(service, method);
                }
            }
        }
    }
    let route_match = lb_proto_http::match_route_request_with_context(
        &route_input,
        &config.routes,
    );
    let route_label = route_match.as_ref().map(|route| route.label.as_str());
    if route_match.is_some()
        && record_query_probe(
            config,
            effective_downstream_addr,
            authority,
            request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        )
    {
        send_local_response(respond, StatusCode::FORBIDDEN)
            .map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(StatusCode::FORBIDDEN.as_u16());
        return Ok(());
    }

    let original_uri = request.uri().clone();
    let original_headers = request.headers().clone();
    let mut request_host_override = if let Some(transform) = effective_request_transform(config, route_match.as_ref()) {
        match apply_request_transform(&mut request, &transform) {
            Ok(host_override) => host_override,
            Err(_) => {
                send_local_response(respond, StatusCode::BAD_REQUEST)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::BAD_REQUEST.as_u16());
                return Ok(());
            }
        }
    } else {
        None
    };

    let route_selection_started = Instant::now();
    let upstream_resolution = resolve_stream_upstream(
        config,
        route_match.as_ref(),
        request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        request.headers(),
    );
    if let (Some(request_telemetry), Some(route)) =
        (config.request_telemetry.as_ref(), route_match.as_ref())
    {
        let _ = request_telemetry.telemetry.record_route_latency(
            &request_telemetry.scope,
            &route.label,
            lb_observability::TraceHookPhase::UpstreamSelected,
            route_selection_started.elapsed(),
        );
    }
    record_route_selection_decision(config, route_match.as_ref(), &upstream_resolution);

    let selected_upstream = match upstream_resolution {
        RequestUpstreamResolution::Selected(upstream) => upstream,
        RequestUpstreamResolution::Reject(status) => {
            let _blocked = status == StatusCode::FORBIDDEN
                && record_unmatched_route(config, effective_downstream_addr);
            send_local_response(respond, status).map_err(|_| StreamForwardError::SendResponse)?;
            metrics.record_response_status(status.as_u16());
            return Ok(());
        }
    };

    let destination_policy =
        route_destination_policy_runtime(config, route_match.as_ref(), &selected_upstream);
    if verify_route_destination_jwt_auth(config, &request, route_match.as_ref(), &selected_upstream)
        .is_err()
    {
        send_local_response(respond, StatusCode::UNAUTHORIZED)
            .map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(StatusCode::UNAUTHORIZED.as_u16());
        return Ok(());
    }
    if let Some(transform) = destination_policy.and_then(|policy| policy.request_transform.as_ref()) {
        *request.uri_mut() = original_uri.clone();
        *request.headers_mut() = original_headers.clone();
        request_host_override = match apply_request_transform(&mut request, transform) {
            Ok(host_override) => host_override,
            Err(_) => {
                send_local_response(respond, StatusCode::BAD_REQUEST)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::BAD_REQUEST.as_u16());
                return Ok(());
            }
        };
    }
    if let Err(outcome) = enforce_route_destination_external_auth(
        config,
        &mut request,
        route_match.as_ref(),
        &selected_upstream,
    )
    .await
    {
        let status = match outcome {
            ExternalAuthEnforcementOutcome::Denied => StatusCode::FORBIDDEN,
            ExternalAuthEnforcementOutcome::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ExternalAuthEnforcementOutcome::InvalidResponse => StatusCode::BAD_GATEWAY,
        };
        send_local_response(respond, status).map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(status.as_u16());
        return Ok(());
    }
    if let Err(outcome) = enforce_route_destination_upstream_identity(
        config,
        &request,
        route_match.as_ref(),
        &selected_upstream,
    ) {
        let status = match outcome {
            UpstreamIdentityEnforcementOutcome::ServiceUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        send_local_response(respond, status).map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(status.as_u16());
        return Ok(());
    }
    if let Err(outcome) = enforce_route_destination_authorization(
        config,
        &request,
        route_match.as_ref(),
        &selected_upstream,
    ) {
        let status = match outcome {
            AuthorizationEnforcementOutcome::Denied => StatusCode::FORBIDDEN,
        };
        send_local_response(respond, status).map_err(|_| StreamForwardError::SendResponse)?;
        metrics.record_response_status(status.as_u16());
        return Ok(());
    }
    let destination_response_transform = effective_destination_response_transform(
        config,
        route_match.as_ref(),
        destination_policy,
    );
    let _destination_latency = DestinationLatencyRecorder::new(
        config.request_telemetry.as_ref(),
        route_label,
        selected_destination_label(&selected_upstream),
    );
    let _destination_concurrency_leases = match enforce_destination_local_limits(
        config,
        destination_policy,
        route_match.as_ref(),
        &selected_upstream,
        effective_client_ip,
    ) {
        Ok(leases) => leases,
        Err(status) => {
            send_local_response(respond, status).map_err(|_| StreamForwardError::SendResponse)?;
            metrics.record_response_status(status.as_u16());
            return Ok(());
        }
    };
    if let Some(status) = maybe_inject_http2_fault(
        &request,
        respond,
        destination_policy,
        metrics,
    )
    .await
    .map_err(|_| StreamForwardError::SendResponse)?
    {
        metrics.record_response_status(status.as_u16());
        return Ok(());
    }
    maybe_spawn_shadow_http2_request(
        config,
        &request,
        effective_client_ip,
        request_host_override.as_deref(),
        destination_policy,
        upstream_clients.clone(),
        metrics,
    );
    if let Some(policy) = destination_policy.filter(|policy| policy.enforce_retry_budget) {
        if let Some(manager) = destination_failure_manager(Some(policy)) {
            manager.record_base_request(failure_policy_now());
        }
    }
    let effective_timeouts =
        effective_destination_upstream_timeouts(&config.timeouts, destination_policy);
    let request_started = Instant::now();

    let request_end_stream = request.body().is_end_stream();
    let safe_stale_reuse_retry =
        request_end_stream && request_is_safe_stale_reuse_retry_candidate(&request);
    let replayable_grpc_retry = is_grpc;
    let replayable_request = safe_stale_reuse_retry || replayable_grpc_retry;
    let retryable_upstream_request = if replayable_request {
        Some(
            prepare_upstream_request_template(
                &request,
                request_host_override.as_deref(),
                effective_client_ip,
                selected_upstream.target.address,
            )
            .inspect_err(|_| {
                let _ = send_local_response(respond, StatusCode::BAD_GATEWAY);
                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
            })?,
        )
    } else {
        None
    };
    let mut buffered_request_payload = None;
    let (
        upstream_client,
        had_prior_successful_stream,
        retried_stale_client,
        attempt_started,
        response_future,
        mut upstream_send_stream,
    ) = {
        let mut retried_stale_client = false;
        loop {
            let attempt_started = Instant::now();
            if let Some(policy) = destination_policy.filter(|policy| policy.enforce_circuit_breaker)
            {
                if let Some(manager) = destination_failure_manager(Some(policy)) {
                    if !manager.allow_request(failure_policy_now()) {
                        send_local_response(respond, StatusCode::SERVICE_UNAVAILABLE)
                            .map_err(|_| StreamForwardError::SendResponse)?;
                        metrics.record_response_status(StatusCode::SERVICE_UNAVAILABLE.as_u16());
                        return Ok(());
                    }
                }
            }
            let (upstream_client, had_prior_successful_stream) = match upstream_clients
                .ensure_client(&selected_upstream.target, &effective_timeouts)
                .await
            {
                Ok(client) => client,
                Err(UpstreamClientConnectError::ConnectTimeout { .. }) => {
                    record_destination_timeout(destination_policy, crate::TimeoutCategory::Connect);
                    send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                        .map_err(|_| StreamForwardError::SendResponse)?;
                    metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                    record_passive_health_result(
                        config,
                        &selected_upstream,
                        route_label,
                        &Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)),
                    );
                    return Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse));
                }
                Err(_) => {
                    record_destination_failure(destination_policy, crate::UpstreamFailureClass::Connect);
                    send_local_response(respond, StatusCode::BAD_GATEWAY)
                        .map_err(|_| StreamForwardError::SendResponse)?;
                    metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                    record_passive_health_result(
                        config,
                        &selected_upstream,
                        route_label,
                        &Err(StreamForwardError::UpstreamRequest),
                    );
                    return Err(StreamForwardError::UpstreamRequest);
                }
            };

            let upstream_request =
                if let Some(upstream_request) = retryable_upstream_request.clone() {
                    upstream_request.into_request()?
                } else {
                    match build_upstream_request(
                        &request,
                        request_host_override.as_deref(),
                        effective_client_ip,
                        selected_upstream.target.address,
                    ) {
                        Ok(upstream_request) => upstream_request,
                        Err(error) => {
                            send_local_response(respond, StatusCode::BAD_GATEWAY)
                                .map_err(|_| StreamForwardError::SendResponse)?;
                            metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                            return Err(error);
                        }
                    }
                };
            let retry_stale_reuse =
                had_prior_successful_stream && safe_stale_reuse_retry && !retried_stale_client;

            let mut send_request = upstream_client.send_request.lock().await;
            if let Err(error) = poll_fn(|cx| send_request.poll_ready(cx)).await {
                drop(send_request);
                upstream_clients.remove_client(&selected_upstream.target).await;
                record_destination_failure(destination_policy, crate::UpstreamFailureClass::Temporary);
                if retry_stale_reuse
                    && http2_stale_reuse_retryable_error(&error)
                    && allow_destination_retry(
                        destination_policy,
                        crate::UpstreamFailureClass::Temporary,
                        Some(&selected_upstream),
                        config.request_telemetry.as_ref(),
                        route_label,
                        Some(selected_destination_label(&selected_upstream)),
                    )
                {
                    retried_stale_client = true;
                    continue;
                }
                send_local_response(respond, StatusCode::BAD_GATEWAY)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                let classified_error =
                    classify_http2_upstream_error(&error, StreamForwardError::UpstreamReady);
                record_passive_health_result(
                    config,
                    &selected_upstream,
                    route_label,
                    &Err(classified_error),
                );
                return Err(classified_error);
            }

            match send_request.send_request(upstream_request, request_end_stream) {
                Ok((response_future, upstream_send_stream)) => {
                    drop(send_request);
                    break (
                        upstream_client,
                        had_prior_successful_stream,
                        retried_stale_client,
                        attempt_started,
                        response_future,
                        upstream_send_stream,
                    );
                }
                Err(error) => {
                    drop(send_request);
                    upstream_clients.remove_client(&selected_upstream.target).await;
                    record_destination_failure(destination_policy, crate::UpstreamFailureClass::Temporary);
                    if retry_stale_reuse
                        && http2_stale_reuse_retryable_error(&error)
                        && allow_destination_retry(
                            destination_policy,
                            crate::UpstreamFailureClass::Temporary,
                            Some(&selected_upstream),
                            config.request_telemetry.as_ref(),
                            route_label,
                            Some(selected_destination_label(&selected_upstream)),
                        )
                    {
                        retried_stale_client = true;
                        continue;
                    }
                    send_local_response(respond, StatusCode::BAD_GATEWAY)
                        .map_err(|_| StreamForwardError::SendResponse)?;
                    metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                    let classified_error =
                        classify_http2_upstream_error(&error, StreamForwardError::UpstreamRequest);
                    record_passive_health_result(
                        config,
                        &selected_upstream,
                        route_label,
                        &Err(classified_error),
                    );
                    return Err(classified_error);
                }
            }
        }
    };

    if !request_end_stream {
        let (request_body_timeout, request_body_timeout_category) = match bounded_dispatch_timeout(
            destination_policy,
            crate::TimeoutCategory::Idle,
            effective_timeouts.idle_timeout,
            request_started,
            attempt_started,
        ) {
            Ok(value) => value,
            Err(category) => {
                record_destination_timeout(destination_policy, category);
                send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                return Ok(());
            }
        };
        match if replayable_request {
            relay_recv_body_to_send_stream_buffered(
                request.into_body(),
                &mut upstream_send_stream,
                config.limits.max_body_bytes,
                request_body_timeout,
                StreamBodyDirection::Request,
            )
            .await
            .map(Some)
        } else {
            relay_recv_body_to_send_stream(
                request.into_body(),
                &mut upstream_send_stream,
                config.limits.max_body_bytes,
                request_body_timeout,
                StreamBodyDirection::Request,
            )
            .await
            .map(|_| None)
        } {
            Ok(payload) => {
                buffered_request_payload = payload;
            }
            Err(StreamForwardError::RequestBodyLimitExceeded) => {
                metrics.increment_body_limit_violation_count();
                metrics.record_anomaly(ProtocolAnomalyCategory::BodySizeLimitExceeded);
                upstream_send_stream.send_reset(Reason::CANCEL);
                send_local_response(respond, StatusCode::PAYLOAD_TOO_LARGE)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::PAYLOAD_TOO_LARGE.as_u16());
                return Ok(());
            }
            Err(error) => {
                if matches!(error, StreamForwardError::IdleTimeout(_)) {
                    record_destination_timeout(destination_policy, request_body_timeout_category);
                } else {
                    record_destination_failure(
                        destination_policy,
                        crate::UpstreamFailureClass::Temporary,
                    );
                }
                upstream_send_stream.send_reset(Reason::INTERNAL_ERROR);
                let status = if matches!(
                    error,
                    StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
                ) {
                    StatusCode::REQUEST_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                };
                send_local_response(respond, status)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(status.as_u16());
                return Err(error);
            }
        }
    }

    drop(upstream_send_stream);

    let (response_timeout, response_timeout_category) = match bounded_dispatch_timeout(
        destination_policy,
        crate::TimeoutCategory::Idle,
        effective_timeouts.idle_timeout,
        request_started,
        attempt_started,
    ) {
        Ok(value) => value,
        Err(category) => {
            record_destination_timeout(destination_policy, category);
            send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                .map_err(|_| StreamForwardError::SendResponse)?;
            metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
            return Ok(());
        }
    };

    let response = match time::timeout(response_timeout, response_future).await {
        Err(_) => {
            upstream_clients.remove_client(&selected_upstream.target).await;
            record_destination_timeout(destination_policy, response_timeout_category);
            send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                .map_err(|_| StreamForwardError::SendResponse)?;
            metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
            record_passive_health_result(
                config,
                &selected_upstream,
                route_label,
                &Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)),
            );
            return Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse));
        }
        Ok(response) => response,
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            upstream_clients.remove_client(&selected_upstream.target).await;
            if had_prior_successful_stream
                && safe_stale_reuse_retry
                && !retried_stale_client
                && http2_stale_reuse_retryable_error(&error)
                && allow_destination_retry(
                    destination_policy,
                    crate::UpstreamFailureClass::Temporary,
                    Some(&selected_upstream),
                    config.request_telemetry.as_ref(),
                    route_label,
                    Some(selected_destination_label(&selected_upstream)),
                )
            {
                let Some(retry_request_template) = retryable_upstream_request.clone() else {
                    return Err(StreamForwardError::UpstreamResponse);
                };
                match dispatch_retry_response_with_optional_hedge(
                    upstream_clients.clone(),
                    selected_upstream.target.clone(),
                    effective_timeouts,
                    destination_policy.cloned(),
                    retry_request_template,
                    request_started,
                    attempt_started,
                    config.request_hedging_policy,
                )
                .await
                {
                    Ok((retry_response, _)) => retry_response,
                    Err(retry_error) => {
                        let status = if matches!(
                            retry_error,
                            StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)
                        ) {
                            StatusCode::GATEWAY_TIMEOUT
                        } else {
                            StatusCode::BAD_GATEWAY
                        };
                        send_local_response(respond, status)
                            .map_err(|_| StreamForwardError::SendResponse)?;
                        metrics.record_response_status(status.as_u16());
                        record_passive_health_result(
                            config,
                            &selected_upstream,
                            route_label,
                            &Err(retry_error),
                        );
                        return Err(StreamForwardError::UpstreamResponse);
                    }
                }
            } else {
                record_destination_failure(destination_policy, crate::UpstreamFailureClass::Temporary);
                let _ = error;
                send_local_response(respond, StatusCode::BAD_GATEWAY)
                    .map_err(|_| StreamForwardError::SendResponse)?;
                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                record_passive_health_result(
                    config,
                    &selected_upstream,
                    route_label,
                    &Err(StreamForwardError::UpstreamResponse),
                );
                return Err(StreamForwardError::UpstreamResponse);
            }
        }
    };

    if is_grpc {
        let mut response = response;
        let mut response_status = response.status();
        let mut response_headers = response.headers().clone();
        let mut buffered_response_payload = if response.body().is_end_stream() {
            BufferedStreamPayload::default()
        } else {
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
                        send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                            .map_err(|_| StreamForwardError::SendResponse)?;
                        metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                        return Ok(());
                    }
                };
            match read_recv_body_to_buffer(
                response.into_body(),
                config.limits.max_body_bytes,
                response_body_timeout,
                StreamBodyDirection::Response,
            )
            .await
            {
                Ok(payload) => payload,
                Err(StreamForwardError::ResponseBodyLimitExceeded) => {
                    metrics.increment_body_limit_violation_count();
                    metrics.record_anomaly(ProtocolAnomalyCategory::BodySizeLimitExceeded);
                    send_local_response(respond, StatusCode::BAD_GATEWAY)
                        .map_err(|_| StreamForwardError::SendResponse)?;
                    metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                    return Ok(());
                }
                Err(error) => {
                    if matches!(error, StreamForwardError::IdleTimeout(_)) {
                        record_destination_timeout(destination_policy, response_body_timeout_category);
                    } else {
                        record_destination_failure(
                            destination_policy,
                            crate::UpstreamFailureClass::Temporary,
                        );
                    }
                    return Err(error);
                }
            }
        };
        let mut grpc_status = grpc_status_from_header_map(&response_headers)
            .or_else(|| buffered_response_payload.trailers.as_ref().and_then(grpc_status_from_header_map));
        if let Some(status) = grpc_status {
            metrics.record_grpc_status(status);
        }

        let unary_grpc_retry_safe = buffered_request_payload
            .as_ref()
            .map_or(true, |payload| grpc_payload_has_at_most_one_message(payload.body.as_ref()))
            && grpc_payload_has_at_most_one_message(buffered_response_payload.body.as_ref());

        let grpc_failure_policy =
            grpc_failure_policy_for_destination(config, route_match.as_ref(), &selected_upstream);
        if let Some(class) =
            grpc_status.and_then(|status| classify_grpc_response_failure_with_policy(grpc_failure_policy, status))
        {
            if unary_grpc_retry_safe
                && allow_destination_retry(
                    destination_policy,
                    class,
                    Some(&selected_upstream),
                    config.request_telemetry.as_ref(),
                    route_label,
                    Some(selected_destination_label(&selected_upstream)),
                )
            {
                record_destination_failure(destination_policy, class);
                let Some(retry_request_template) = retryable_upstream_request.clone() else {
                    return Err(StreamForwardError::UpstreamResponse);
                };
                let retry_request = retry_request_template.into_request()?;
                let retry_attempt_started = Instant::now();
                let retry_response = {
                    let mut retry_send_request = upstream_client.send_request.lock().await;
                    if poll_fn(|cx| retry_send_request.poll_ready(cx)).await.is_err() {
                        drop(retry_send_request);
                        upstream_clients.remove_client(&selected_upstream.target).await;
                        record_destination_failure(
                            destination_policy,
                            crate::UpstreamFailureClass::Temporary,
                        );
                        send_local_response(respond, StatusCode::BAD_GATEWAY)
                            .map_err(|_| StreamForwardError::SendResponse)?;
                        metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                        record_passive_health_result(
                            config,
                            &selected_upstream,
                            route_label,
                            &Err(StreamForwardError::UpstreamReady),
                        );
                        return Err(StreamForwardError::UpstreamReady);
                    }

                    let (retry_response_future, mut retry_upstream_send_stream) =
                        match retry_send_request.send_request(
                            retry_request,
                            request_end_stream && buffered_request_payload.is_none(),
                        ) {
                            Ok(result) => result,
                            Err(_) => {
                                drop(retry_send_request);
                                upstream_clients.remove_client(&selected_upstream.target).await;
                                record_destination_failure(
                                    destination_policy,
                                    crate::UpstreamFailureClass::Temporary,
                                );
                                send_local_response(respond, StatusCode::BAD_GATEWAY)
                                    .map_err(|_| StreamForwardError::SendResponse)?;
                                metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                                record_passive_health_result(
                                    config,
                                    &selected_upstream,
                                    route_label,
                                    &Err(StreamForwardError::UpstreamRequest),
                                );
                                return Err(StreamForwardError::UpstreamRequest);
                            }
                        };
                    // Release the shared connection handle before streaming the body so
                    // other streams multiplexed on this connection are not serialized.
                    drop(retry_send_request);
                    if let Some(payload) = buffered_request_payload.as_ref() {
                        send_buffered_stream_payload(
                            &mut retry_upstream_send_stream,
                            payload,
                            effective_timeouts.idle_timeout,
                            StreamBodyDirection::Request,
                        )
                        .await?;
                    }
                    drop(retry_upstream_send_stream);

                    let (retry_response_timeout, retry_response_timeout_category) =
                        match bounded_dispatch_timeout(
                            destination_policy,
                            crate::TimeoutCategory::Idle,
                            effective_timeouts.idle_timeout,
                            request_started,
                            retry_attempt_started,
                        ) {
                            Ok(value) => value,
                            Err(category) => {
                                record_destination_timeout(destination_policy, category);
                                send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                                    .map_err(|_| StreamForwardError::SendResponse)?;
                                metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                                return Ok(());
                            }
                        };

                    match time::timeout(retry_response_timeout, retry_response_future).await {
                        Err(_) => {
                            upstream_clients.remove_client(&selected_upstream.target).await;
                            record_destination_timeout(
                                destination_policy,
                                retry_response_timeout_category,
                            );
                            send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                                .map_err(|_| StreamForwardError::SendResponse)?;
                            metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                            record_passive_health_result(
                                config,
                                &selected_upstream,
                                route_label,
                                &Err(StreamForwardError::IdleTimeout(
                                    StreamIdlePhase::UpstreamResponse,
                                )),
                            );
                            return Err(StreamForwardError::IdleTimeout(
                                StreamIdlePhase::UpstreamResponse,
                            ));
                        }
                        Ok(Ok(response)) => response,
                        Ok(Err(_)) => {
                            upstream_clients.remove_client(&selected_upstream.target).await;
                            record_destination_failure(
                                destination_policy,
                                crate::UpstreamFailureClass::Temporary,
                            );
                            send_local_response(respond, StatusCode::BAD_GATEWAY)
                                .map_err(|_| StreamForwardError::SendResponse)?;
                            metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                            record_passive_health_result(
                                config,
                                &selected_upstream,
                                route_label,
                                &Err(StreamForwardError::UpstreamResponse),
                            );
                            return Err(StreamForwardError::UpstreamResponse);
                        }
                    }
                };

                response = retry_response;
                response_status = response.status();
                response_headers = response.headers().clone();
                buffered_response_payload = if response.body().is_end_stream() {
                    BufferedStreamPayload::default()
                } else {
                    let (retry_response_body_timeout, retry_response_body_timeout_category) =
                        match bounded_dispatch_timeout(
                            destination_policy,
                            crate::TimeoutCategory::Idle,
                            effective_timeouts.idle_timeout,
                            request_started,
                            retry_attempt_started,
                        ) {
                            Ok(value) => value,
                            Err(category) => {
                                record_destination_timeout(destination_policy, category);
                                send_local_response(respond, StatusCode::GATEWAY_TIMEOUT)
                                    .map_err(|_| StreamForwardError::SendResponse)?;
                                metrics.record_response_status(StatusCode::GATEWAY_TIMEOUT.as_u16());
                                return Ok(());
                            }
                        };
                    match read_recv_body_to_buffer(
                        response.into_body(),
                        config.limits.max_body_bytes,
                        retry_response_body_timeout,
                        StreamBodyDirection::Response,
                    )
                    .await
                    {
                        Ok(payload) => payload,
                        Err(StreamForwardError::ResponseBodyLimitExceeded) => {
                            metrics.increment_body_limit_violation_count();
                            metrics.record_anomaly(ProtocolAnomalyCategory::BodySizeLimitExceeded);
                            send_local_response(respond, StatusCode::BAD_GATEWAY)
                                .map_err(|_| StreamForwardError::SendResponse)?;
                            metrics.record_response_status(StatusCode::BAD_GATEWAY.as_u16());
                            return Ok(());
                        }
                        Err(error) => {
                            if matches!(error, StreamForwardError::IdleTimeout(_)) {
                                record_destination_timeout(
                                    destination_policy,
                                    retry_response_body_timeout_category,
                                );
                            } else {
                                record_destination_failure(
                                    destination_policy,
                                    crate::UpstreamFailureClass::Temporary,
                                );
                            }
                            return Err(error);
                        }
                    }
                };
                grpc_status = grpc_status_from_header_map(&response_headers).or_else(|| {
                    buffered_response_payload
                        .trailers
                        .as_ref()
                        .and_then(grpc_status_from_header_map)
                });
                if let Some(status) = grpc_status {
                    metrics.record_grpc_status(status);
                }
            }
        }

        let response_end_stream =
            buffered_response_payload.body.is_empty() && buffered_response_payload.trailers.is_none();
        let downstream_response =
            build_downstream_response_from_parts(response_status, &response_headers, destination_response_transform.as_ref())?;
        let mut downstream_send_stream = respond
            .send_response(downstream_response, response_end_stream)
            .map_err(|_| StreamForwardError::SendResponse)?;
        if !response_end_stream {
            send_buffered_stream_payload(
                &mut downstream_send_stream,
                &buffered_response_payload,
                effective_timeouts.idle_timeout,
                StreamBodyDirection::Response,
            )
            .await?;
        }

        metrics.record_response_status(response_status.as_u16());
        let grpc_failure_policy =
            grpc_failure_policy_for_destination(config, route_match.as_ref(), &selected_upstream);
        match grpc_status
            .and_then(|status| {
                classify_grpc_response_failure_with_policy(grpc_failure_policy, status)
            })
            .or_else(|| classify_http2_response_failure(response_status))
        {
            Some(class) => record_destination_failure(destination_policy, class),
            None => record_destination_success(destination_policy),
        }

        upstream_client.mark_used(Instant::now());
        upstream_client.note_completed_stream();
        record_passive_health_result(
            config,
            &selected_upstream,
            route_label,
            &Ok(response_status.as_u16()),
        );
        return Ok(());
    }

    let response_status = response.status();
    let response_end_stream = response.body().is_end_stream();
    let response_headers = response.headers().clone();
    let downstream_response = build_downstream_response(
        &response,
        destination_response_transform.as_ref(),
    )?;
    let mut downstream_send_stream = respond
        .send_response(downstream_response, response_end_stream)
        .map_err(|_| StreamForwardError::SendResponse)?;
    metrics.record_response_status(response_status.as_u16());
    match classify_http2_response_failure(response_status) {
        Some(class) => record_destination_failure(destination_policy, class),
        None => record_destination_success(destination_policy),
    }

    if !response_end_stream {
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
                    downstream_send_stream.send_reset(Reason::INTERNAL_ERROR);
                    metrics.increment_stream_reset_count();
                    return Ok(());
                }
            };
        let response_trailers = relay_recv_body_to_send_stream(
            response.into_body(),
            &mut downstream_send_stream,
            config.limits.max_body_bytes,
            response_body_timeout,
            StreamBodyDirection::Response,
        )
        .await;
        match response_trailers {
            Ok(trailers) => {
                if is_grpc {
                    if let Some(grpc_status) = grpc_status_from_header_map(&response_headers)
                        .or_else(|| trailers.as_ref().and_then(grpc_status_from_header_map))
                    {
                        metrics.record_grpc_status(grpc_status);
                    }
                }
            }
            Err(StreamForwardError::ResponseBodyLimitExceeded) => {
                metrics.increment_body_limit_violation_count();
                metrics.record_anomaly(ProtocolAnomalyCategory::BodySizeLimitExceeded);
                downstream_send_stream.send_reset(Reason::ENHANCE_YOUR_CALM);
                metrics.increment_stream_reset_count();
            }
            Err(error) => {
                if matches!(error, StreamForwardError::IdleTimeout(_)) {
                    record_destination_timeout(destination_policy, response_body_timeout_category);
                } else {
                    record_destination_failure(
                        destination_policy,
                        crate::UpstreamFailureClass::Temporary,
                    );
                }
                downstream_send_stream.send_reset(Reason::INTERNAL_ERROR);
                metrics.increment_stream_reset_count();
                return Err(error);
            }
        }
    } else if is_grpc {
        if let Some(grpc_status) = grpc_status_from_header_map(&response_headers) {
            metrics.record_grpc_status(grpc_status);
        }
    }

    upstream_client.mark_used(Instant::now());
    upstream_client.note_completed_stream();
    record_passive_health_result(
        config,
        &selected_upstream,
        route_label,
        &Ok(response_status.as_u16()),
    );

    Ok(())
}

struct DestinationLatencyRecorder<'a> {
    request_telemetry: Option<&'a HttpRequestTelemetryConfig>,
    route_label: Option<&'a str>,
    destination: &'a str,
    started_at: Instant,
}

impl<'a> DestinationLatencyRecorder<'a> {
    fn new(
        request_telemetry: Option<&'a HttpRequestTelemetryConfig>,
        route_label: Option<&'a str>,
        destination: &'a str,
    ) -> Self {
        Self {
            request_telemetry,
            route_label,
            destination,
            started_at: Instant::now(),
        }
    }
}

impl Drop for DestinationLatencyRecorder<'_> {
    fn drop(&mut self) {
        let (Some(request_telemetry), Some(route_label)) = (self.request_telemetry, self.route_label)
        else {
            return;
        };
        let elapsed = self.started_at.elapsed();
        let _ = request_telemetry.telemetry.record_destination_latency(
            &request_telemetry.scope,
            self.destination,
            lb_observability::TraceHookPhase::ResponseCompleted,
            elapsed,
        );
        let _ = request_telemetry.telemetry.record_route_latency(
            &request_telemetry.scope,
            route_label,
            lb_observability::TraceHookPhase::ResponseCompleted,
            elapsed,
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_retry_response_with_optional_hedge(
    upstream_clients: UpstreamClientRegistry,
    target: lb_net_core::UpstreamTarget,
    effective_timeouts: lb_net_core::ConnectionTimeouts,
    destination_policy: Option<crate::http1_proxy::RouteDestinationPolicyRuntime>,
    retry_request_template: UpstreamRequestTemplate,
    request_started: Instant,
    attempt_started: Instant,
    hedging_policy: Option<crate::RequestHedgingPolicy>,
) -> Result<(Response<RecvStream>, crate::HedgeOutcome), StreamForwardError> {
    let Some(policy) = hedging_policy else {
        let response = dispatch_retry_response_attempt(
            upstream_clients,
            target,
            effective_timeouts,
            destination_policy,
            retry_request_template,
            request_started,
            attempt_started,
            false,
        )
        .await?;
        return Ok((
            response,
            crate::HedgeOutcome {
                hedge_launched: false,
                winner_attempt: 1,
            },
        ));
    };

    crate::execute_with_hedge(
        policy,
        || true,
        {
            let upstream_clients = upstream_clients.clone();
            let target = target.clone();
            let destination_policy = destination_policy.clone();
            let retry_request_template = retry_request_template.clone();
            move || {
                dispatch_retry_response_attempt(
                    upstream_clients,
                    target,
                    effective_timeouts,
                    destination_policy,
                    retry_request_template,
                    request_started,
                    attempt_started,
                    true,
                )
            }
        },
        {
            let upstream_clients = upstream_clients.clone();
            let target = target.clone();
            let destination_policy = destination_policy.clone();
            let retry_request_template = retry_request_template.clone();
            move || {
                dispatch_retry_response_attempt(
                    upstream_clients,
                    target,
                    effective_timeouts,
                    destination_policy,
                    retry_request_template,
                    request_started,
                    attempt_started,
                    true,
                )
            }
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_retry_response_attempt(
    upstream_clients: UpstreamClientRegistry,
    target: lb_net_core::UpstreamTarget,
    effective_timeouts: lb_net_core::ConnectionTimeouts,
    destination_policy: Option<crate::http1_proxy::RouteDestinationPolicyRuntime>,
    retry_request_template: UpstreamRequestTemplate,
    request_started: Instant,
    attempt_started: Instant,
    force_fresh_client: bool,
) -> Result<Response<RecvStream>, StreamForwardError> {
    if force_fresh_client {
        upstream_clients.remove_client(&target).await;
    }
    let (retry_upstream_client, _) = match upstream_clients
        .ensure_client(&target, &effective_timeouts)
        .await
    {
        Ok(client) => client,
        Err(UpstreamClientConnectError::ConnectTimeout { .. }) => {
            record_destination_timeout(destination_policy.as_ref(), crate::TimeoutCategory::Connect);
            return Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse));
        }
        Err(_) => {
            record_destination_failure(destination_policy.as_ref(), crate::UpstreamFailureClass::Connect);
            return Err(StreamForwardError::UpstreamResponse);
        }
    };

    let retry_request = retry_request_template.into_request()?;
    let mut retry_send_request = retry_upstream_client.send_request.lock().await;
    if let Err(error) = poll_fn(|cx| retry_send_request.poll_ready(cx)).await {
        drop(retry_send_request);
        upstream_clients.remove_client(&target).await;
        record_destination_failure(destination_policy.as_ref(), crate::UpstreamFailureClass::Temporary);
        return Err(classify_http2_upstream_error(
            &error,
            StreamForwardError::UpstreamReady,
        ));
    }

    let (retry_response_future, retry_upstream_send_stream) =
        match retry_send_request.send_request(retry_request, true) {
            Ok(result) => result,
            Err(error) => {
                drop(retry_send_request);
                upstream_clients.remove_client(&target).await;
                record_destination_failure(
                    destination_policy.as_ref(),
                    crate::UpstreamFailureClass::Temporary,
                );
                return Err(classify_http2_upstream_error(
                    &error,
                    StreamForwardError::UpstreamRequest,
                ));
            }
        };
    drop(retry_send_request);
    drop(retry_upstream_send_stream);

    let (retry_response_timeout, retry_response_timeout_category) = bounded_dispatch_timeout(
        destination_policy.as_ref(),
        crate::TimeoutCategory::Idle,
        effective_timeouts.idle_timeout,
        request_started,
        attempt_started,
    )
    .map_err(|category| {
        record_destination_timeout(destination_policy.as_ref(), category);
        StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse)
    })?;

    let response = match time::timeout(retry_response_timeout, retry_response_future).await {
        Err(_) => {
            upstream_clients.remove_client(&target).await;
            record_destination_timeout(destination_policy.as_ref(), retry_response_timeout_category);
            return Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse));
        }
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            upstream_clients.remove_client(&target).await;
            record_destination_failure(destination_policy.as_ref(), crate::UpstreamFailureClass::Temporary);
            return Err(classify_http2_upstream_error(
                &error,
                StreamForwardError::UpstreamResponse,
            ));
        }
    };

    retry_upstream_client.mark_used(Instant::now());
    Ok(response)
}

#[cfg(test)]
mod retry_dispatch_coverage_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_external_auth_service(
        body: &'static str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await.expect("read external auth request");
                assert_ne!(read, 0, "external auth request ended before its body");
                request.extend_from_slice(&chunk[..read]);

                let Some(head_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = std::str::from_utf8(&request[..head_end])
                    .expect("external auth request headers are ASCII");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("valid content length"))
                    })
                    .expect("external auth request has content length");
                if request.len() >= head_end + 4 + content_length {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write external auth response");
            stream.shutdown().await.expect("close external auth connection");
        });
        Ok(format!("http://{address}/authz"))
    }

    async fn spawn_upstream(
        respond_to_requests: bool,
    ) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            if respond_to_requests {
                while let Some(Ok((_, mut respond))) = connection.accept().await {
                    let Ok(response) = Response::builder().status(StatusCode::OK).body(()) else {
                        return;
                    };
                    if let Ok(mut send) = respond.send_response(response, false) {
                        let _ = send.send_data(Bytes::from_static(b"upstream"), true);
                    }
                }
            } else if let Some(Ok((_, respond))) = connection.accept().await {
                let _respond = respond;
                std::future::pending::<()>().await;
            }
        });
        Ok(address)
    }

    async fn spawn_empty_status_upstream(
        status: StatusCode,
        grpc_status: Option<&'static str>,
    ) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            while let Some(Ok((_, mut respond))) = connection.accept().await {
                let mut response_builder = Response::builder().status(status);
                if let Some(grpc_status) = grpc_status {
                    response_builder = response_builder
                        .header("content-type", "application/grpc")
                        .header("grpc-status", grpc_status);
                }
                let Ok(response) = response_builder.body(()) else {
                    return;
                };
                if respond.send_response(response, true).is_err() {
                    return;
                }
            }
        });
        Ok(address)
    }

    async fn spawn_grpc_retry_upstream(
        retry_response_body: &'static [u8],
    ) -> Result<(SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_attempts = attempts.clone();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            let mut attempt = 0;
            while let Some(Ok((_, mut respond))) = connection.accept().await {
                observed_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/grpc");
                if attempt > 0 {
                    builder = builder.header("grpc-status", "0");
                }
                let Ok(response) = builder.body(()) else {
                    return;
                };
                let Ok(mut send) = respond.send_response(response, false) else {
                    return;
                };
                if attempt == 0 {
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", http::HeaderValue::from_static("14"));
                    if send.send_trailers(trailers).is_err() {
                        return;
                    }
                } else if send
                    .send_data(Bytes::from_static(retry_response_body), true)
                    .is_err()
                {
                    return;
                }
                attempt += 1;
            }
        });
        Ok((address, attempts))
    }

    fn template() -> Result<UpstreamRequestTemplate, http::uri::InvalidUri> {
        Ok(UpstreamRequestTemplate {
            method: http::Method::GET,
            uri: "http://127.0.0.1/retry".parse()?,
            headers: Vec::new(),
        })
    }

    async fn dispatch(
        address: SocketAddr,
        hedging_policy: Option<crate::RequestHedgingPolicy>,
    ) -> Result<(Response<RecvStream>, crate::HedgeOutcome), StreamForwardError> {
        dispatch_with_timeouts(
            address,
            hedging_policy,
            lb_net_core::ConnectionTimeouts::default(),
        )
        .await
    }

    async fn dispatch_with_timeouts(
        address: SocketAddr,
        hedging_policy: Option<crate::RequestHedgingPolicy>,
        effective_timeouts: lb_net_core::ConnectionTimeouts,
    ) -> Result<(Response<RecvStream>, crate::HedgeOutcome), StreamForwardError> {
        let target = lb_net_core::UpstreamTarget::new("retry-target", address);
        let now = Instant::now();
        dispatch_retry_response_with_optional_hedge(
            UpstreamClientRegistry::default(),
            target,
            effective_timeouts,
            None,
            template().expect("valid URI"),
            now,
            now,
            hedging_policy,
        )
        .await
    }

    #[tokio::test]
    async fn retries_dispatch_with_and_without_optional_hedging(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let address = spawn_upstream(true).await?;
        let (response, outcome) = dispatch(address, None).await.expect("retry succeeds");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!outcome.hedge_launched);
        assert_eq!(outcome.winner_attempt, 1);

        let address = spawn_upstream(true).await?;
        let (response, outcome) = dispatch(
            address,
            Some(crate::RequestHedgingPolicy {
                hedge_delay: Duration::from_secs(1),
                max_attempts: 2,
            }),
        )
        .await
        .expect("hedged retry succeeds");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!outcome.hedge_launched);
        Ok(())
    }

    #[tokio::test]
    async fn retry_dispatch_reports_upstream_connection_failure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        drop(listener);
        assert!(matches!(dispatch(address, None).await, Err(StreamForwardError::UpstreamResponse)));

        let address = spawn_upstream(false).await?;
        let timeouts = lb_net_core::ConnectionTimeouts {
            connect_timeout: Duration::from_secs(1),
            preface_timeout: Duration::from_millis(100),
            idle_timeout: Duration::from_millis(25),
        };
        assert!(matches!(
            dispatch_with_timeouts(address, None, timeouts).await,
            Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse))
        ));
        Ok(())
    }

    async fn run_stream(
        config: &Http2ProxyConfig,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Result<(StatusCode, Result<(), StreamForwardError>), Box<dyn std::error::Error>> {
        run_stream_with_body(config, path, headers, Bytes::new()).await
    }

    async fn run_stream_with_body(
        config: &Http2ProxyConfig,
        path: &str,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<(StatusCode, Result<(), StreamForwardError>), Box<dyn std::error::Error>> {
        let (response, result) =
            run_stream_with_body_result(config, path, headers, body).await?;
        Ok((response?, result))
    }

    async fn run_stream_with_body_result(
        config: &Http2ProxyConfig,
        path: &str,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<
        (
            Result<StatusCode, h2::Error>,
            Result<(), StreamForwardError>,
        ),
        Box<dyn std::error::Error>,
    > {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server, client) =
            tokio::join!(h2::server::handshake(server_io), h2::client::handshake(client_io));
        let mut server = server?;
        let (mut client, client_connection) = client?;
        tokio::spawn(async move {
            let _ = client_connection.await;
        });

        let is_grpc = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value.starts_with("application/grpc")
        });
        let mut request = Request::builder()
            .method(if is_grpc { "POST" } else { "GET" })
            .uri(format!("https://example.test{path}"))
            .body(())?;
        for (name, value) in headers {
            request.headers_mut().insert(
                http::header::HeaderName::from_bytes(name.as_bytes())?,
                http::HeaderValue::from_str(value)?,
            );
        }
        let (response, mut request_body) = client.send_request(request, false)?;
        let (request, mut respond) = time::timeout(Duration::from_secs(1), server.accept())
            .await?
            .ok_or("HTTP/2 request was not accepted")??;
        tokio::spawn(async move {
            while let Some(result) = server.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let body_sender = tokio::spawn(async move {
            tokio::task::yield_now().await;
            request_body.send_data(body, true)
        });
        assert!(!request.body().is_end_stream(), "request body should still be open");

        let result = proxy_one_http2_stream(
            request,
            &mut respond,
            "127.0.0.1:40000".parse()?,
            UpstreamClientRegistry::default(),
            &MetricsState::new(),
            config,
        )
        .await;
        body_sender.await??;
        let response = time::timeout(Duration::from_secs(1), response).await?;
        Ok((response.map(|response| response.status()), result))
    }

    #[tokio::test]
    async fn request_policy_rejections_return_specific_local_statuses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let upstream = lb_net_core::UpstreamTarget::new(
            "blocked",
            "127.0.0.1:1".parse()?,
        );
        let trusted = Http2ProxyConfig::new(upstream.clone()).with_trusted_client_ip(
            crate::TrustedClientIpPolicy {
                enabled: true,
                trusted_proxy_cidrs: vec!["127.0.0.0/8".parse()?],
            },
        );
        let (status, result) =
            run_stream(&trusted, "/", &[("forwarded", "for=not-an-ip")]).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(result.is_ok());

        let anonymous = Http2ProxyConfig::new(upstream.clone()).with_anonymous_source_filter(
            crate::AnonymousSourceFilterPolicy {
                enabled: true,
                deny_cidrs: vec!["127.0.0.0/8".parse()?],
                deny_vpn: false,
                deny_proxy: false,
                deny_socks: false,
                deny_tor: false,
                vpn_cidrs: Vec::new(),
                proxy_cidrs: Vec::new(),
                socks_cidrs: Vec::new(),
                tor_exit_cidrs: Vec::new(),
            },
        );
        let (status, result) = run_stream(&anonymous, "/", &[]).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(result.is_ok());

        let mut unmatched = Http2ProxyConfig::new(upstream.clone()).with_route_upstreams([
            Http2RouteUpstream { route_label: String::from("known"), upstream: upstream.clone() },
        ]);
        unmatched.reject_unmatched_routes = true;
        let (status, result) = run_stream(&unmatched, "/unmatched", &[]).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(result.is_ok());

        let (status, result) = run_stream(&Http2ProxyConfig::new(upstream), "/", &[]).await?;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(matches!(result, Err(StreamForwardError::UpstreamRequest)));

        let invalid_transform = lb_config_model::RequestTransformConfig {
            path_rewrite: None,
            host_rewrite: None,
            header_mutations: vec![lb_config_model::HeaderMutationConfig::Set {
                name: String::from("invalid header"),
                value: String::from("value"),
            }],
        };
        let config = Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new(
            "transform",
            "127.0.0.1:1".parse()?,
        ))
        .with_request_transforms(Some(invalid_transform), []);
        let (status, result) = run_stream(&config, "/", &[]).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn forwards_stream_request_and_response_bodies() -> Result<(), Box<dyn std::error::Error>> {
        let address = spawn_upstream(true).await?;
        let config =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("body-upstream", address));
        let (status, result) = run_stream_with_body(
            &config,
            "/body",
            &[],
            Bytes::from_static(b"request"),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "proxy result: {result:?}");
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn forwards_empty_http_errors_without_opening_a_response_body(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let address =
            spawn_empty_status_upstream(StatusCode::SERVICE_UNAVAILABLE, None).await?;
        let config =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("empty-error", address));
        let (status, result) = run_stream(&config, "/empty-error", &[]).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn records_grpc_status_from_an_empty_response_header(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let address = spawn_empty_status_upstream(StatusCode::OK, Some("0")).await?;
        let config = Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new(
            "empty-grpc",
            address,
        ));
        let (status, result) = run_stream(
            &config,
            "/grpc.health.v1.Health/Check",
            &[("content-type", "application/grpc")],
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn classifies_grpc_streams_and_proxies_the_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let address = spawn_upstream(true).await?;
        let config =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("grpc-upstream", address));
        let (status, result) = run_stream(
            &config,
            "/grpc.health.v1.Health/Check",
            &[("content-type", "application/grpc")],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "proxy result: {result:?}");
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn retries_unary_grpc_responses_with_retryable_statuses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response_body = &[0, 0, 0, 0, 0];
        let (address, attempts) = spawn_grpc_retry_upstream(response_body).await?;
        let config =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("grpc-retry", address));
        let (status, result) = run_stream(
            &config,
            "/grpc.health.v1.Health/Check",
            &[("content-type", "application/grpc")],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "proxy result: {result:?}");
        assert!(result.is_ok());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 2);

        let (address, attempts) = spawn_grpc_retry_upstream(response_body).await?;
        let mut limited =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("grpc-retry-limited", address));
        limited.limits.max_body_bytes = 1;
        let (status, result) = run_stream(
            &limited,
            "/grpc.health.v1.Health/Check",
            &[("content-type", "application/grpc")],
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(result.is_ok());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 2);

        let (address, attempts) = spawn_grpc_retry_upstream(response_body).await?;
        let config =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("grpc-stream", address));
        let multi_message_request =
            Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (status, result) = run_stream_with_body(
            &config,
            "/grpc.health.v1.Health/Check",
            &[("content-type", "application/grpc")],
            multi_message_request,
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert!(result.is_ok());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn request_limits_and_upstream_timeouts_are_reported(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let address = spawn_upstream(true).await?;
        let mut limited =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("limited", address));
        limited.limits.max_body_bytes = 1;
        let (status, result) = run_stream_with_body(
            &limited,
            "/limited",
            &[],
            Bytes::from_static(b"request"),
        )
        .await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(result.is_ok());

        let address = spawn_upstream(true).await?;
        let mut response_limited =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("response-limited", address));
        response_limited.limits.max_body_bytes = 1;
        let (response, result) =
            run_stream_with_body_result(&response_limited, "/response-limited", &[], Bytes::new())
                .await?;
        assert_eq!(response.unwrap_err().reason(), Some(Reason::ENHANCE_YOUR_CALM));
        assert!(result.is_ok());

        let address = spawn_upstream(false).await?;
        let mut slow =
            Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new("slow", address));
        slow.timeouts.idle_timeout = Duration::from_millis(1);
        let (status, result) = run_stream(&slow, "/slow", &[]).await?;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert!(matches!(
            result,
            Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse))
        ));

        let target =
            lb_net_core::UpstreamTarget::new("connect-timeout", "127.0.0.1:1".parse()?);
        let mut connect_timeout = Http2ProxyConfig::new(target);
        connect_timeout.timeouts.connect_timeout = Duration::ZERO;
        let (status, result) = run_stream(&connect_timeout, "/timeout", &[]).await?;
        match status {
            StatusCode::BAD_GATEWAY => {
                assert!(matches!(result, Err(StreamForwardError::UpstreamRequest)));
            }
            StatusCode::GATEWAY_TIMEOUT => {
                assert!(matches!(
                    result,
                    Err(StreamForwardError::IdleTimeout(StreamIdlePhase::UpstreamResponse))
                ));
            }
            status => panic!("unexpected connect failure status: {status}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn route_authentication_failures_map_to_local_http2_responses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let route_label = String::from("secure-api");
        let cluster_name = String::from("secure-cluster");
        let pool = crate::RouteBackendPool::from_cluster(
            lb_net_core::UpstreamCluster::new(
                lb_net_core::UpstreamClusterName::new(cluster_name.clone())?,
                vec![lb_net_core::UpstreamEndpoint::new(
                    lb_net_core::UpstreamEndpointId::new("secure-endpoint")?,
                    "127.0.0.1:1".parse()?,
                    lb_net_core::EndpointState::Ready,
                    lb_net_core::EndpointMetadata { zone: None, locality: None, weight: 1 },
                )?],
            )?,
            crate::EndpointHealthPolicy::default(),
            crate::UpstreamSelectionPolicy::default(),
        )?;
        let upstream = pool.select_upstream(0)?;
        let route_config = |target: lb_net_core::UpstreamTarget| {
            let mut config = Http2ProxyConfig::new(target)
                .with_route_backend_pools([(route_label.clone(), pool.clone())]);
            config.routes = vec![lb_proto_http::RoutePrefixRule::new(&route_label, "/")];
            config
        };

        let jwt = crate::JwtAuthPolicyRuntime::from_config(
            &lb_config_model::JwtAuthPolicyConfig {
                issuers: vec![String::from("https://issuer.example")],
                audiences: vec![String::from("edge-api")],
                jwks: Some(lb_config_model::JwtJwksSourceConfig::Inline {
                    jwks_json: String::from(
                        r#"{"keys":[{"kty":"oct","k":"c2VjcmV0","alg":"HS256","kid":"key"}]}"#,
                    ),
                }),
                required_claims: Vec::new(),
                clock_skew_secs: 30,
            },
        )?;
        let jwt_config = route_config(upstream.clone())
            .with_route_destination_jwt_auth_policies([(
                route_label.clone(),
                BTreeMap::from([(cluster_name.clone(), jwt)]),
            )]);
        let (status, result) = run_stream(&jwt_config, "/secure", &[]).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(result.is_ok());

        let external = crate::ExternalAuthPolicyRuntime::from_config(
            &lb_config_model::ExternalAuthPolicyConfig {
                endpoint: String::from("http://127.0.0.1:9/authz"),
                protocol: lb_config_model::ExternalAuthProtocolConfig::Http,
                timeout_ms: 1_000,
                fail_open: false,
                include_headers: Vec::new(),
                context_mappings: Vec::new(),
            },
        )?;
        let external_config = route_config(upstream.clone())
            .with_route_destination_external_auth_policies([(
                route_label.clone(),
                BTreeMap::from([(cluster_name.clone(), external)]),
            )]);
        let (status, result) = run_stream(&external_config, "/secure", &[]).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(result.is_ok());

        for (body, expected_status) in [
            (r#"{"allow":false}"#, StatusCode::FORBIDDEN),
            ("not-json", StatusCode::BAD_GATEWAY),
        ] {
            let endpoint = spawn_external_auth_service(body).await?;
            let external = crate::ExternalAuthPolicyRuntime::from_config(
                &lb_config_model::ExternalAuthPolicyConfig {
                    endpoint,
                    protocol: lb_config_model::ExternalAuthProtocolConfig::Http,
                    timeout_ms: 1_000,
                    fail_open: false,
                    include_headers: Vec::new(),
                    context_mappings: Vec::new(),
                },
            )?;
            let config = route_config(upstream.clone())
                .with_route_destination_external_auth_policies([(
                    route_label.clone(),
                    BTreeMap::from([(cluster_name.clone(), external)]),
                )]);
            let (status, result) = run_stream(&config, "/secure", &[]).await?;
            assert_eq!(status, expected_status);
            assert!(result.is_ok());
        }

        let authorization = crate::AuthorizationPolicyRuntime::from_config(
            &lb_config_model::AuthorizationPolicyConfig {
                rules: Vec::new(),
                default_decision: lb_config_model::AuthorizationDecisionConfig::Deny,
            },
        );
        let authorization_config = route_config(upstream.clone())
            .with_route_destination_authorization_policies([(
                route_label.clone(),
                BTreeMap::from([(cluster_name.clone(), authorization)]),
            )]);
        let (status, result) = run_stream(&authorization_config, "/secure", &[]).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(result.is_ok());

        let certified = rcgen::generate_simple_self_signed(vec![String::from("localhost")])?;
        let identity = crate::UpstreamIdentityPolicyRuntime::from_config(
            &lb_config_model::UpstreamIdentityPolicyConfig {
                mode: lb_config_model::UpstreamIdentityModeConfig::Spiffe,
                trust_bundle: lb_config_model::IdentityTrustBundleSourceConfig::InlinePem {
                    pem: certified.cert.pem(),
                },
                allowed_spiffe_ids: Vec::new(),
                allowed_trust_domains: Vec::new(),
            },
        )?;
        let identity_config = route_config(upstream)
            .with_route_destination_upstream_identity_policies([(
                route_label.clone(),
                BTreeMap::from([(cluster_name.clone(), identity)]),
            )]);
        let (status, result) = run_stream(&identity_config, "/secure", &[]).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(result.is_ok());

        let invalid_destination_transform = crate::http1_proxy::RouteDestinationPolicyRuntime {
            request_transform: Some(lb_config_model::RequestTransformConfig {
                path_rewrite: None,
                host_rewrite: None,
                header_mutations: vec![lb_config_model::HeaderMutationConfig::Set {
                    name: String::from("invalid header"),
                    value: String::from("value"),
                }],
            }),
            ..crate::http1_proxy::RouteDestinationPolicyRuntime::default()
        };
        let transform_config = route_config(pool.select_upstream(0)?)
            .with_route_destination_policies([(
                route_label,
                BTreeMap::from([(cluster_name, invalid_destination_transform)]),
            )]);
        let (status, result) = run_stream(&transform_config, "/secure", &[]).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(result.is_ok());
        Ok(())
    }
}
