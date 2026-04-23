async fn run_public_http3_listener_loop(
    socket: UdpSocket,
    listener_name: String,
    proxy: ManagedProxyConfig,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
    counters: Arc<ListenerRuntimeCounters>,
    state: Arc<WorkspaceServeState>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
    ready_tx: oneshot::Sender<()>,
) -> io::Result<ListenerDrainOutcome> {
    let ManagedProxyConfig::Http3(proxy) = proxy else {
        return Err(io::Error::other("http3 listener requires http3 proxy config"));
    };
    let runtime = quinn::TokioRuntime;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some((*proxy.quic_server_config).clone()),
        socket.into_std()?,
        Arc::new(runtime),
    )
    .map_err(io::Error::other)?;

    *counters.state.write().await = String::from("running");
    let _ = ready_tx.send(());
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                counters.accepted_connections.fetch_add(1, Ordering::SeqCst);
                if !try_acquire_listener_slot(&counters, &admission_limit) {
                    counters.shed_connections.fetch_add(1, Ordering::SeqCst);
                    state.record_overload_event(
                        &listener_name,
                        lb_observability::OverloadEventKind::RequestShed,
                        format!(
                            "listener shed http3 connection at capacity {}",
                            admission_limit.load(Ordering::SeqCst)
                        ),
                    );
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        true,
                    );
                    continue;
                }
                state.sync_listener_overload_snapshot(
                    &listener_name,
                    &counters,
                    admission_limit.load(Ordering::SeqCst),
                    &overload_runtime,
                    false,
                );

                let counters = Arc::clone(&counters);
                let state = Arc::clone(&state);
                let abuse_protection = Arc::clone(&abuse_protection);
                let overload_runtime = Arc::clone(&overload_runtime);
                let admission_limit = Arc::clone(&admission_limit);
                let listener_name = listener_name.clone();
                let proxy = proxy.clone();

                tasks.spawn(async move {
                    let result = handle_http3_connecting(
                        incoming,
                        &listener_name,
                        proxy,
                        &state,
                        Arc::clone(&abuse_protection),
                    )
                    .await;
                    if let Ok(request_count) = result {
                        state.proxied_connections.fetch_add(1, Ordering::SeqCst);
                        state.proxied_requests.fetch_add(request_count, Ordering::SeqCst);
                    }
                    counters.active_connections.fetch_sub(1, Ordering::SeqCst);
                    counters.completed_connections.fetch_add(1, Ordering::SeqCst);
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        false,
                    );
                    state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                });
            }
        }
    }

    endpoint.close(0u32.into(), b"server shutdown");
    *counters.state.write().await = String::from("draining");
    let drain_outcome =
        if time::timeout(drain_timeout, async { while tasks.join_next().await.is_some() {} })
            .await
            .is_ok()
        {
            *counters.state.write().await = String::from("stopped");
            ListenerDrainOutcome::Completed
        } else {
            *counters.state.write().await = String::from("drain_timeout_expired");
            ListenerDrainOutcome::TimedOut
        };
    Ok(drain_outcome)
}

async fn handle_http3_connecting(
    connecting: quinn::Incoming,
    listener_name: &str,
    proxy: ManagedHttp3ProxyConfig,
    state: &WorkspaceServeState,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
) -> io::Result<u64> {
    let connecting = connecting.accept().map_err(io::Error::other)?;
    let connection = connecting.await.map_err(io::Error::other)?;
    let remote_addr = connection.remote_address();
    let _source_lease = {
        let protection = abuse_protection.read().await;
        protection.try_acquire_source(remote_addr).map_err(|reason| io::Error::other(reason.detail()))?
    };
    let mut h3_conn = h3::server::builder()
        .build(H3Connection::new(connection))
        .await
        .map_err(io::Error::other)?;
    let mut request_count = 0_u64;

    while let Some(resolver) = h3_conn.accept().await.map_err(io::Error::other)? {
        let (request, mut stream) = resolver.resolve_request().await.map_err(io::Error::other)?;
        request_count += 1;
        handle_http3_request(listener_name, state, &proxy, remote_addr, request, &mut stream)
            .await?;
    }

    Ok(request_count)
}

async fn handle_http3_request(
    listener_name: &str,
    state: &WorkspaceServeState,
    proxy: &ManagedHttp3ProxyConfig,
    downstream_addr: SocketAddr,
    request: http1::Request<()>,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> io::Result<()> {
    let mut headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| lb_proto_http::HttpHeader {
                name: name.as_str().to_ascii_lowercase(),
                value: value.to_string(),
            })
        })
        .collect::<Vec<_>>();
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    let route_input = lb_proto_http::RouteMatchInput {
        target: target.clone(),
        host: request.uri().authority().map(|authority| authority.as_str().to_string()),
        method: Some(request.method().as_str().to_string()),
        headers: headers.clone(),
        source_ip: Some(downstream_addr.ip()),
    };
    let route = lb_proto_http::match_route_request_with_context(&route_input, &proxy.http1.routes);

    let mut request_body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(io::Error::other)? {
        let chunk_bytes = chunk.copy_to_bytes(chunk.remaining());
        request_body.extend_from_slice(&chunk_bytes);
    }
    if !request_body.is_empty() {
        headers.retain(|header| !header.name.eq_ignore_ascii_case("content-length"));
        headers.push(lb_proto_http::HttpHeader {
            name: String::from("content-length"),
            value: request_body.len().to_string(),
        });
    }

    let response = lb_runtime::proxy_http1_request_with_downstream_addr(
        &proxy.http1,
        downstream_addr,
        lb_proto_http::Http1RequestHead {
            method: request.method().as_str().to_string(),
            target,
            version: lb_proto_http::SupportedHttpVersion::Http1,
            headers,
            body_kind: if request_body.is_empty() {
                lb_proto_http::BodyKind::None
            } else {
                lb_proto_http::BodyKind::ContentLength(request_body.len() as u64)
            },
            keep_alive: false,
            route,
        },
        &request_body,
    )
    .await
    .map_err(|error| {
        state.record_http3_request(listener_name, "failed", "bridge_failed");
        io::Error::other(error)
    })?;

    let status_reason = match response.head.status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    };

    let mut response_builder = http1::Response::builder().status(response.head.status);
    for header in &response.head.headers {
        response_builder = response_builder.header(&header.name, &header.value);
    }
    let response_head = response_builder.body(()).map_err(|error| {
        state.record_http3_request(listener_name, "failed", "response_build_failed");
        io::Error::other(error)
    })?;
    stream.send_response(response_head).await.map_err(|error| {
        state.record_http3_request(listener_name, "failed", "response_head_write_failed");
        io::Error::other(error)
    })?;
    if !response.body.is_empty() {
        stream.send_data(Bytes::from(response.body)).await.map_err(|error| {
            state.record_http3_request(listener_name, "failed", "response_body_write_failed");
            io::Error::other(error)
        })?;
    }
    stream.finish().await.map_err(|error| {
        state.record_http3_request(listener_name, "failed", "response_finish_failed");
        io::Error::other(error)
    })?;
    state.record_http3_request(listener_name, "served", status_reason);
    Ok(())
}

