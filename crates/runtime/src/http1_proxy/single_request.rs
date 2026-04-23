pub async fn proxy_http1_request_with_downstream_addr(
    config: &Http1ProxyConfig,
    downstream_addr: SocketAddr,
    mut request: lb_proto_http::Http1RequestHead,
    request_body: &[u8],
) -> Result<Http1SingleRequestResponse, Http1ProxyError> {
    let original_request = request.clone();
    if let Some(transform) = effective_request_transform(config, request.route.as_ref()) {
        if apply_request_transform(&mut request, &transform).is_err() {
            return Ok(local_http1_response(
                request.keep_alive,
                StatusCode::BAD_REQUEST,
                "invalid transformed request target\n",
            ));
        }
    }

    let selected_upstream = match resolve_request_upstream(config, &request) {
        RequestUpstreamResolution::Selected(upstream) => upstream,
        RequestUpstreamResolution::Reject(status, reason) => {
            return Ok(local_http1_response(request.keep_alive, status, reason));
        }
    };

    let destination_policy =
        route_destination_policy_runtime(config, request.route.as_ref(), &selected_upstream);
    if let Some(transform) = destination_policy.and_then(|policy| policy.request_transform.as_ref()) {
        request = original_request;
        if apply_request_transform(&mut request, transform).is_err() {
            return Ok(local_http1_response(
                request.keep_alive,
                StatusCode::BAD_REQUEST,
                "invalid transformed request target\n",
            ));
        }
    }

    let effective_client_ip = downstream_addr.ip();
    let _destination_concurrency_leases = match enforce_destination_local_limits(
        destination_policy,
        &request,
        &selected_upstream,
        effective_client_ip,
    ) {
        Ok(leases) => leases,
        Err((status, body)) => return Ok(local_http1_response(request.keep_alive, status, body)),
    };
    let response_transform =
        effective_destination_response_transform(config, request.route.as_ref(), destination_policy);
    let effective_timeouts =
        effective_destination_upstream_timeouts(&config.timeouts, destination_policy);

    let mut stream = time::timeout(
        effective_timeouts.connect_timeout,
        TcpStream::connect(selected_upstream.target.address),
    )
    .await
    .map_err(|_| Http1ProxyError::ConnectTimeout {
        target: selected_upstream.target.address,
    })?
    .map_err(|source| Http1ProxyError::Connect {
        target: selected_upstream.target.address,
        source,
    })?;

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
    if !request_body.is_empty() {
        stream
            .write_all(request_body)
            .await
            .map_err(Http1ProxyError::RequestIo)?;
    }

    let mut upstream_buffer = Vec::new();
    let response = time::timeout(
        effective_timeouts.idle_timeout,
        lb_proto_http::read_response_head(
            &mut stream,
            &mut upstream_buffer,
            &config.limits,
            &request.method,
        ),
    )
    .await
    .map_err(|_| Http1ProxyError::IdleTimeout("response head"))?
    .map_err(Http1ProxyError::ParseResponse)?;

    let mut body_writer = VecAsyncWriter::default();
    relay_body(
        &mut stream,
        &mut upstream_buffer,
        &mut body_writer,
        &response.body_kind,
        config.limits.max_body_bytes,
        effective_timeouts.idle_timeout,
        RelayDirection::Response,
    )
    .await?;

    let mut normalized_response_headers = lb_proto_http::normalize_response_headers(
        &response.headers,
        false,
        &response.body_kind,
    );
    if let Some(transform) = response_transform {
        apply_http1_header_mutations(&mut normalized_response_headers, &transform.header_mutations);
    }
    match classify_http1_response_failure(response.status) {
        Some(class) => record_destination_failure(destination_policy, class),
        None => record_destination_success(destination_policy),
    }

    Ok(Http1SingleRequestResponse {
        head: lb_proto_http::Http1ResponseHead {
            version: response.version,
            status: response.status,
            reason: response.reason,
            headers: normalized_response_headers,
            body_kind: response.body_kind,
            keep_alive: false,
        },
        body: body_writer.into_inner(),
    })
}

