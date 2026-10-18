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
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
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
        protection
            .try_acquire_source(remote_addr)
            .map_err(|reason| io::Error::other(reason.detail()))?
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
    let target =
        request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/").to_string();
    let route_input = lb_proto_http::RouteMatchInput {
        target: target.clone(),
        host: request.uri().authority().map(|authority| authority.as_str().to_string()),
        method: Some(request.method().as_str().to_string()),
        headers: headers.clone(),
        source_ip: Some(downstream_addr.ip()),
    };
    let route = lb_proto_http::match_route_request_with_context(&route_input, &proxy.http1.routes);

    // HTTP/1.1 upstreams require Host; HTTP/3 carries it in the :authority pseudo-header.
    if !headers.iter().any(|header| header.name.eq_ignore_ascii_case("host")) {
        if let Some(authority) = request.uri().authority() {
            headers.push(lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: authority.as_str().to_string(),
            });
        }
    }

    let max_body_bytes = proxy.http1.limits.max_body_bytes;
    let idle_timeout = proxy.http1.timeouts.idle_timeout;
    let mut request_body = Vec::new();
    loop {
        let chunk = match time::timeout(idle_timeout, stream.recv_data()).await {
            Ok(chunk) => chunk.map_err(io::Error::other)?,
            Err(_) => {
                state.record_http3_request(listener_name, "failed", "request_body_timeout");
                return send_http3_local_response(stream, http1::StatusCode::REQUEST_TIMEOUT).await;
            }
        };
        let Some(mut chunk) = chunk else {
            break;
        };
        if (request_body.len() as u64).saturating_add(chunk.remaining() as u64) > max_body_bytes {
            state.record_http3_request(listener_name, "failed", "request_body_too_large");
            return send_http3_local_response(stream, http1::StatusCode::PAYLOAD_TOO_LARGE).await;
        }
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
            http10: false,
        },
        &request_body,
    )
    .await;
    let response = match response {
        Ok(response) => response,
        Err(_) => {
            state.record_http3_request(listener_name, "failed", "bridge_failed");
            return send_http3_local_response(stream, http1::StatusCode::BAD_GATEWAY).await;
        }
    };

    let status_reason = match response.head.status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    };

    let mut response_builder = http1::Response::builder().status(response.head.status);
    for header in
        response.head.headers.iter().filter(|header| !is_http3_forbidden_header(&header.name))
    {
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

/// Connection-specific fields are malformed in HTTP/3 (RFC 9114 §4.2).
fn is_http3_forbidden_header(name: &str) -> bool {
    ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te"]
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

async fn send_http3_local_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: http1::StatusCode,
) -> io::Result<()> {
    let response = http1::Response::builder().status(status).body(()).map_err(io::Error::other)?;
    stream.send_response(response).await.map_err(io::Error::other)?;
    stream.finish().await.map_err(io::Error::other)
}

#[cfg(test)]
mod http3_tests {
    use super::{
        build_listener_abuse_protection_state, build_quic_server_config, is_http3_forbidden_header,
        run_public_http3_listener_loop, ListenerDrainOutcome, ListenerRuntimeCounters,
        ManagedHttp3ProxyConfig, ManagedProxyConfig, WorkspaceServeState,
    };
    use std::io;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::net::UdpSocket;
    use tokio::sync::{watch, RwLock};

    #[test]
    fn filters_connection_specific_fields_but_keeps_end_to_end_headers() {
        for name in
            ["connection", "Keep-Alive", "PROXY-CONNECTION", "transfer-encoding", "Upgrade", "TE"]
        {
            assert!(is_http3_forbidden_header(name));
        }
        for name in ["content-type", "cache-control", "x-request-id"] {
            assert!(!is_http3_forbidden_header(name));
        }
    }

    #[tokio::test]
    async fn rejects_tcp_proxy_configuration_before_marking_http3_listener_ready() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let state = Arc::new(WorkspaceServeState::new(String::from("unused-test-config")).unwrap());
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let counters = Arc::new(ListenerRuntimeCounters::new());
        let error = run_public_http3_listener_loop(
            socket,
            String::from("test"),
            ManagedProxyConfig::Http1(lb_runtime::Http1ProxyConfig::new(
                lb_net_core::UpstreamTarget::new(
                    "test-upstream",
                    SocketAddr::from(([127, 0, 0, 1], 8080)),
                ),
            )),
            Arc::new(AtomicUsize::new(1)),
            Arc::new(StdMutex::new(None)),
            Arc::new(RwLock::new(build_listener_abuse_protection_state(None))),
            counters,
            state,
            shutdown_rx,
            std::time::Duration::from_secs(1),
            ready_tx,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("requires http3 proxy config"));
        assert!(ready_rx.await.is_err());
    }

    #[tokio::test]
    async fn http3_listener_signals_ready_and_drains_cleanly_on_shutdown(
    ) -> Result<(), Box<dyn std::error::Error>> {
        super::ensure_rustls_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec![String::from("localhost")])?;
        let cert_der = certified.cert.der().to_vec();
        let cert = rustls::pki_types::CertificateDer::from(cert_der.clone());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut tls =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_server_config = Arc::new(build_quic_server_config(Arc::new(tls)).unwrap());
        let proxy = ManagedProxyConfig::Http3(ManagedHttp3ProxyConfig {
            http1: lb_runtime::Http1ProxyConfig::new(lb_net_core::UpstreamTarget::new(
                "test-upstream",
                {
                    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                    unused.local_addr()?
                },
            )),
            quic_server_config,
        });
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = socket.local_addr()?;
        let state = Arc::new(WorkspaceServeState::new(String::from("unused-test-config")).unwrap());
        let counters = Arc::new(ListenerRuntimeCounters::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_public_http3_listener_loop(
            socket,
            String::from("http3-test"),
            proxy,
            Arc::new(AtomicUsize::new(4)),
            Arc::new(StdMutex::new(None)),
            Arc::new(RwLock::new(build_listener_abuse_protection_state(None))),
            Arc::clone(&counters),
            state,
            shutdown_rx,
            std::time::Duration::from_secs(1),
            ready_tx,
        ));
        ready_rx.await?;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(rustls::pki_types::CertificateDer::from(cert_der))?;
        let mut client_tls =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls))?;
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_config)));
        let connection = endpoint.connect(server_addr, "localhost")?.await?;
        let (_driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;
        let request = http1::Request::builder().method("GET").uri("https://localhost/").body(())?;
        let mut request_stream = send_request.send_request(request).await?;
        request_stream.finish().await?;
        let response = request_stream.recv_response().await?;
        assert_eq!(response.status(), http1::StatusCode::BAD_GATEWAY);
        endpoint.close(0u32.into(), b"test complete");

        shutdown_tx.send(true)?;
        assert_eq!(task.await??, ListenerDrainOutcome::Completed);
        assert_eq!(*counters.state.read().await, "stopped");
        Ok(())
    }
}
