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
    if verify_route_destination_jwt_auth(config, &request, &selected_upstream).is_err() {
        return Ok(local_http1_response(
            request.keep_alive,
            StatusCode::UNAUTHORIZED,
            "unauthorized\n",
        ));
    }
    if let Some(transform) = destination_policy.and_then(|policy| policy.request_transform.as_ref())
    {
        request = original_request;
        if apply_request_transform(&mut request, transform).is_err() {
            return Ok(local_http1_response(
                request.keep_alive,
                StatusCode::BAD_REQUEST,
                "invalid transformed request target\n",
            ));
        }
    }
    if let Err(outcome) =
        enforce_route_destination_external_auth(config, &mut request, &selected_upstream).await
    {
        let (status, body) = match outcome {
            ExternalAuthEnforcementOutcome::Denied => (StatusCode::FORBIDDEN, "forbidden\n"),
            ExternalAuthEnforcementOutcome::ServiceUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "auth service unavailable\n")
            }
            ExternalAuthEnforcementOutcome::InvalidResponse => {
                (StatusCode::BAD_GATEWAY, "auth service invalid response\n")
            }
        };
        return Ok(local_http1_response(request.keep_alive, status, body));
    }
    if let Err(outcome) =
        enforce_route_destination_upstream_identity(config, &request, &selected_upstream)
    {
        let (status, body) = match outcome {
            UpstreamIdentityEnforcementOutcome::ServiceUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "upstream identity unavailable\n")
            }
        };
        return Ok(local_http1_response(request.keep_alive, status, body));
    }
    if let Err(outcome) =
        enforce_route_destination_authorization(config, &request, &selected_upstream)
    {
        let (status, body) = match outcome {
            AuthorizationEnforcementOutcome::Denied => (StatusCode::FORBIDDEN, "forbidden\n"),
        };
        return Ok(local_http1_response(request.keep_alive, status, body));
    }

    let effective_client_ip = downstream_addr.ip();
    let _destination_concurrency_leases = match enforce_destination_local_limits(
        config,
        destination_policy,
        &request,
        &selected_upstream,
        effective_client_ip,
    ) {
        Ok(leases) => leases,
        Err((status, body)) => return Ok(local_http1_response(request.keep_alive, status, body)),
    };
    let response_transform = effective_destination_response_transform(
        config,
        request.route.as_ref(),
        destination_policy,
    );
    let effective_timeouts =
        effective_destination_upstream_timeouts(&config.timeouts, destination_policy);
    let normalized_request_headers = lb_proto_http::normalize_request_headers(
        &request.headers,
        effective_client_ip,
        request.keep_alive,
        &request.body_kind,
    );

    if selected_upstream.target.transport == lb_net_core::UpstreamTransport::Http3 {
        let h3_response = match crate::http3_upstream::dispatch_http3_upstream_request(
            &selected_upstream.target,
            &request.method,
            &request.target,
            &normalized_request_headers,
            request_body,
            effective_client_ip,
            effective_timeouts.connect_timeout,
            effective_timeouts.idle_timeout,
            config.limits.max_body_bytes,
        )
        .await
        {
            Ok(response) => response,
            Err(crate::http3_upstream::Http3UpstreamError::GracefulDrain) => {
                return Ok(local_http1_response(
                    request.keep_alive,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "upstream draining\n",
                ));
            }
            Err(source) => {
                return Err(Http1ProxyError::ResponseIo(std::io::Error::other(source)));
            }
        };

        let body_kind = lb_proto_http::BodyKind::ContentLength(h3_response.body.len() as u64);
        let mut normalized_response_headers =
            lb_proto_http::normalize_response_headers(&h3_response.headers, true, &body_kind);
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
        match classify_http1_response_failure(h3_response.status) {
            Some(class) => record_destination_failure(destination_policy, class),
            None => record_destination_success(destination_policy),
        }

        return Ok(Http1SingleRequestResponse {
            head: lb_proto_http::Http1ResponseHead {
                version: lb_proto_http::SupportedHttpVersion::Http1,
                status: h3_response.status,
                reason: h3_response.reason,
                headers: normalized_response_headers,
                body_kind,
                keep_alive: false,
            },
            body: h3_response.body,
        });
    }

    let mut stream = time::timeout(
        effective_timeouts.connect_timeout,
        TcpStream::connect(selected_upstream.target.address),
    )
    .await
    .map_err(|_| Http1ProxyError::ConnectTimeout { target: selected_upstream.target.address })?
    .map_err(|source| Http1ProxyError::Connect {
        target: selected_upstream.target.address,
        source,
    })?;
    let request_head = lb_proto_http::encode_request_head(
        &request.method,
        &request.target,
        request.version,
        &normalized_request_headers,
    );
    stream.write_all(&request_head).await.map_err(Http1ProxyError::RequestIo)?;
    if !request_body.is_empty() {
        stream.write_all(request_body).await.map_err(Http1ProxyError::RequestIo)?;
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

    // The caller receives a fully buffered body, so transfer framing is removed and the
    // response is surfaced with an explicit content-length. Codings such as `gzip` applied
    // as transfer codings cannot be removed and are rejected instead of corrupting the body.
    if lb_proto_http::has_non_chunked_transfer_coding(&response.headers) {
        return Err(Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::Invalid(
            "unsupported response transfer coding",
        )));
    }
    let body = collect_decoded_body(
        &mut stream,
        &mut upstream_buffer,
        &response.body_kind,
        config.limits.max_body_bytes,
        effective_timeouts.idle_timeout,
        RelayDirection::Response,
    )
    .await?;

    let mut normalized_response_headers =
        lb_proto_http::normalize_response_headers(&response.headers, true, &response.body_kind);
    let body_kind = match response.body_kind {
        lb_proto_http::BodyKind::None => lb_proto_http::BodyKind::None,
        _ => {
            reframe_buffered_headers(&mut normalized_response_headers, body.len());
            lb_proto_http::BodyKind::ContentLength(body.len() as u64)
        }
    };
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
            body_kind,
            keep_alive: false,
        },
        body,
    })
}

#[cfg(test)]
mod single_request_coverage_tests {
    use std::net::SocketAddr;

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn request() -> lb_proto_http::Http1RequestHead {
        lb_proto_http::Http1RequestHead {
            method: String::from("GET"),
            target: String::from("/"),
            version: lb_proto_http::SupportedHttpVersion::Http1,
            headers: Vec::new(),
            body_kind: lb_proto_http::BodyKind::None,
            keep_alive: true,
            route: None,
            http10: false,
        }
    }

    fn source_addr() -> SocketAddr {
        "127.0.0.1:40000".parse().expect("valid test peer")
    }

    #[tokio::test]
    async fn rejects_unmatched_route_before_connecting_upstream(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let target = lb_net_core::UpstreamTarget::new("static", "127.0.0.1:1".parse()?);
        let mut config = Http1ProxyConfig::new(target);
        config.route_upstreams.insert(
            String::from("known-route"),
            vec![lb_net_core::UpstreamTarget::new("route", "127.0.0.1:2".parse()?)],
        );
        config.reject_unmatched_routes = true;
        let response =
            proxy_http1_request_with_downstream_addr(&config, source_addr(), request(), &[])
                .await?;
        assert_eq!(response.head.status, http::StatusCode::FORBIDDEN.as_u16());
        assert_eq!(response.body, b"route not allowed\n");
        Ok(())
    }

    #[tokio::test]
    async fn connect_failure_is_returned_as_a_typed_upstream_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        drop(listener);
        let config = Http1ProxyConfig::new(lb_net_core::UpstreamTarget::new("closed", addr));
        let error =
            proxy_http1_request_with_downstream_addr(&config, source_addr(), request(), &[])
                .await
                .expect_err("closed upstream port must fail");
        assert!(matches!(error, Http1ProxyError::Connect { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn buffers_and_normalizes_a_valid_upstream_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut bytes = [0_u8; 1024];
            let _ = stream.read(&mut bytes).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await?;
            Ok::<(), std::io::Error>(())
        });
        let config = Http1ProxyConfig::new(lb_net_core::UpstreamTarget::new("healthy", addr));
        let response =
            proxy_http1_request_with_downstream_addr(&config, source_addr(), request(), &[])
                .await?;
        upstream.await??;
        assert_eq!(response.head.status, http::StatusCode::OK.as_u16());
        assert_eq!(response.head.body_kind, lb_proto_http::BodyKind::ContentLength(2));
        assert_eq!(response.body, b"ok");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_non_chunked_transfer_coding_from_upstream(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut bytes = [0_u8; 1024];
            let _ = stream.read(&mut bytes).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n",
                )
                .await?;
            Ok::<(), std::io::Error>(())
        });
        let config = Http1ProxyConfig::new(lb_net_core::UpstreamTarget::new("bad-framing", addr));
        let error =
            proxy_http1_request_with_downstream_addr(&config, source_addr(), request(), &[])
                .await
                .expect_err("non-chunked transfer encoding must fail closed");
        upstream.await??;
        assert!(matches!(
            error,
            Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::Invalid(
                "unsupported response transfer coding"
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn reports_http3_upstream_failure_without_fabricating_a_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut target = lb_net_core::UpstreamTarget::new("unavailable-h3", "127.0.0.1:1".parse()?);
        target.transport = lb_net_core::UpstreamTransport::Http3;
        let mut config = Http1ProxyConfig::new(target);
        config.timeouts.connect_timeout = std::time::Duration::from_millis(25);

        let error = proxy_http1_request_with_downstream_addr(
            &config,
            source_addr(),
            request(),
            &[],
        )
        .await
        .expect_err("unavailable HTTP/3 upstream must be surfaced");
        assert!(matches!(error, Http1ProxyError::ResponseIo(_)));
        Ok(())
    }

    #[tokio::test]
    async fn returns_local_statuses_for_route_destination_auth_failures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = crate::RouteBackendPool::from_cluster(
            lb_net_core::UpstreamCluster::new(
                lb_net_core::UpstreamClusterName::new("secure-cluster")?,
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
        let selected_target = pool.select_upstream(0)?;
        let route = lb_proto_http::RouteMatch {
            label: String::from("secure-api"),
            prefix: String::from("/"),
        };
        let route_request = || {
            let mut request = request();
            request.route = Some(route.clone());
            request
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
        let jwt_config = Http1ProxyConfig::new(selected_target.clone())
            .with_route_backend_pools([(String::from("secure-api"), pool.clone())])
            .with_route_destination_jwt_auth_policies([(
                String::from("secure-api"),
                std::collections::BTreeMap::from([(String::from("secure-cluster"), jwt)]),
            )]);
        let response = proxy_http1_request_with_downstream_addr(
            &jwt_config,
            source_addr(),
            route_request(),
            &[],
        )
        .await?;
        assert_eq!(response.head.status, http::StatusCode::UNAUTHORIZED.as_u16());

        let authorization = crate::AuthorizationPolicyRuntime::from_config(
            &lb_config_model::AuthorizationPolicyConfig {
                rules: Vec::new(),
                default_decision: lb_config_model::AuthorizationDecisionConfig::Deny,
            },
        );
        let authorization_config = Http1ProxyConfig::new(selected_target.clone())
            .with_route_backend_pools([(String::from("secure-api"), pool.clone())])
            .with_route_destination_authorization_policies([(
                String::from("secure-api"),
                std::collections::BTreeMap::from([(
                    String::from("secure-cluster"),
                    authorization,
                )]),
            )]);
        let response = proxy_http1_request_with_downstream_addr(
            &authorization_config,
            source_addr(),
            route_request(),
            &[],
        )
        .await?;
        assert_eq!(response.head.status, http::StatusCode::FORBIDDEN.as_u16());

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
        let external_config = Http1ProxyConfig::new(selected_target)
            .with_route_backend_pools([(String::from("secure-api"), pool)])
            .with_route_destination_external_auth_policies([(
                String::from("secure-api"),
                std::collections::BTreeMap::from([(String::from("secure-cluster"), external)]),
            )]);
        let response = proxy_http1_request_with_downstream_addr(
            &external_config,
            source_addr(),
            route_request(),
            &[],
        )
        .await?;
        assert_eq!(response.head.status, http::StatusCode::SERVICE_UNAVAILABLE.as_u16());
        Ok(())
    }
}
