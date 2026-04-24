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
            .is_none_or(|payload| grpc_payload_has_at_most_one_message(payload.body.as_ref()))
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
                    if let Some(payload) = buffered_request_payload.as_ref() {
                        send_buffered_stream_payload(
                            &mut retry_upstream_send_stream,
                            payload,
                            StreamBodyDirection::Request,
                        )
                        .await?;
                    }
                    drop(retry_send_request);
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

