#[derive(Debug)]
struct ManagedServeListener {
    name: String,
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
    configured_bind: SocketAddr,
    bind_mode: lb_net_core::ListenerBindMode,
    local_addr: SocketAddr,
    drain_timeout: Duration,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    abuse_policy: Arc<RwLock<Option<CompiledListenerAbuseProtectionPolicy>>>,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
    counters: Arc<ListenerRuntimeCounters>,
    kind: ManagedListenerKind,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<io::Result<ListenerDrainOutcome>>,
    probe_task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerDrainOutcome {
    Completed,
    TimedOut,
}

async fn start_managed_listener(
    name: String,
    spec: CompiledServeListener,
    state: Arc<WorkspaceServeState>,
    supervisor: ServeSupervisor,
) -> Result<ManagedServeListener, DynError> {
    let drain_timeout = spec.drain_timeout();
    let admission_limit = Arc::new(AtomicUsize::new(spec.max_connections()));
    let overload_runtime =
        Arc::new(StdMutex::new(build_listener_overload_runtime(spec.overload_policy())?));
    let abuse_policy = Arc::new(RwLock::new(spec.abuse_protection_policy().cloned()));
    let abuse_protection = Arc::new(RwLock::new(build_listener_abuse_protection_state(
        spec.abuse_protection_policy(),
    )));
    let counters = Arc::new(ListenerRuntimeCounters::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    match spec {
        CompiledServeListener::Public {
            class,
            protocol,
            proxy_protocol,
            bind_address,
            bind_mode,
            proxy,
            ..
        } => {
            if let ManagedProxyConfig::Http3(proxy) = proxy.clone() {
                let socket = lb_runtime::bind_udp_socket(bind_address, bind_mode)?;
                let local_addr = socket.local_addr()?;
                let (ready_tx, ready_rx) = oneshot::channel();
                let shared_proxy = Arc::new(RwLock::new(ManagedProxyConfig::Http3(proxy)));
                let task = tokio::spawn(run_public_http3_listener_loop(
                    socket,
                    name.clone(),
                    shared_proxy.read().await.clone(),
                    Arc::clone(&admission_limit),
                    Arc::clone(&overload_runtime),
                    Arc::clone(&abuse_protection),
                    Arc::clone(&counters),
                    Arc::clone(&state),
                    shutdown_rx,
                    drain_timeout,
                    ready_tx,
                ));
                return await_managed_listener_ready(
                    ManagedServeListener {
                        name,
                        class,
                        protocol,
                        proxy_protocol,
                        configured_bind: bind_address,
                        bind_mode,
                        local_addr,
                        drain_timeout,
                        admission_limit,
                        overload_runtime,
                        abuse_policy,
                        abuse_protection,
                        counters,
                        kind: ManagedListenerKind::Public { shared_proxy },
                        shutdown_tx,
                        task,
                        probe_task: None,
                    },
                    ready_rx,
                )
                .await;
            }

            let listener = lb_runtime::bind_tcp_listener(bind_address, bind_mode)?;
            let local_addr = listener.local_addr()?;
            let (ready_tx, ready_rx) = oneshot::channel();
            let shared_proxy = Arc::new(RwLock::new(proxy));
            let task = tokio::spawn(run_public_listener_loop(
                listener,
                name.clone(),
                proxy_protocol,
                Arc::clone(&shared_proxy),
                Arc::clone(&admission_limit),
                Arc::clone(&overload_runtime),
                Arc::clone(&abuse_protection),
                Arc::clone(&counters),
                Arc::clone(&state),
                shutdown_rx,
                drain_timeout,
                ready_tx,
            ));
            let probe_task = Some(tokio::spawn(run_active_health_probe_loop(
                Arc::clone(&shared_proxy),
                shutdown_tx.subscribe(),
            )));
            await_managed_listener_ready(
                ManagedServeListener {
                    name,
                    class,
                    protocol,
                    proxy_protocol,
                    configured_bind: bind_address,
                    bind_mode,
                    local_addr,
                    drain_timeout,
                    admission_limit,
                    overload_runtime,
                    abuse_policy,
                    abuse_protection,
                    counters,
                    kind: ManagedListenerKind::Public { shared_proxy },
                    shutdown_tx,
                    task,
                    probe_task,
                },
                ready_rx,
            )
            .await
        }
        CompiledServeListener::Admin {
            protocol,
            proxy_protocol,
            bind_address,
            bind_mode,
            admin_policy,
            tls,
            ..
        } => {
            let listener = lb_runtime::bind_tcp_listener(bind_address, bind_mode)?;
            let local_addr = listener.local_addr()?;
            let (ready_tx, ready_rx) = oneshot::channel();
            let admin_runtime = AdminRuntimeHandles {
                shared_policy: Arc::new(RwLock::new(admin_policy)),
                rate_limit_state: Arc::new(StdMutex::new(AdminRateLimitState::default())),
                replay_state: Arc::new(StdMutex::new(AdminReplayState::default())),
            };
            let task = tokio::spawn(run_admin_listener_loop(
                listener,
                name.clone(),
                Arc::clone(&admission_limit),
                Arc::clone(&overload_runtime),
                Arc::clone(&abuse_protection),
                Arc::clone(&counters),
                Arc::clone(&state),
                shutdown_rx,
                drain_timeout,
                admin_runtime.clone(),
                tls.clone(),
                Arc::clone(&supervisor.shared.admin_secret),
                supervisor,
                ready_tx,
            ));
            await_managed_listener_ready(
                ManagedServeListener {
                    name,
                    class: lb_config_model::ListenerClassConfig::Admin,
                    protocol,
                    proxy_protocol,
                    configured_bind: bind_address,
                    bind_mode,
                    local_addr,
                    drain_timeout,
                    admission_limit,
                    overload_runtime,
                    abuse_policy,
                    abuse_protection,
                    counters,
                    kind: ManagedListenerKind::Admin {
                        runtime: admin_runtime,
                        tls_status: tls.as_ref().map(|config| config.tls_status.clone()),
                    },
                    shutdown_tx,
                    task,
                    probe_task: None,
                },
                ready_rx,
            )
            .await
        }
    }
}

fn proxy_preface_timeout(proxy: &ManagedProxyConfig) -> Duration {
    match proxy {
        ManagedProxyConfig::Http1(config) => config.timeouts.preface_timeout,
        ManagedProxyConfig::Http2(config) => config.timeouts.preface_timeout,
        ManagedProxyConfig::Https(config) => config.http1.timeouts.preface_timeout,
        ManagedProxyConfig::Http3(_) => Duration::from_secs(5),
    }
}


async fn run_public_listener_loop(
    listener: TcpListener,
    listener_name: String,
    proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
    shared_proxy: Arc<RwLock<ManagedProxyConfig>>,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
    counters: Arc<ListenerRuntimeCounters>,
    state: Arc<WorkspaceServeState>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
    ready_tx: oneshot::Sender<()>,
) -> io::Result<ListenerDrainOutcome> {
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
            accepted = listener.accept() => {
                let (mut stream, peer_addr) = accepted?;
                let proxy = shared_proxy.read().await.clone();
                let downstream_addr = match resolve_downstream_addr_from_proxy_protocol(
                    &mut stream,
                    peer_addr,
                    proxy_protocol,
                    proxy_preface_timeout(&proxy),
                )
                .await
                {
                    Ok(downstream_addr) => downstream_addr,
                    Err(_) => continue,
                };
                let source_lease = {
                    let protection = abuse_protection.read().await;
                    match protection.try_acquire_source(downstream_addr) {
                        Ok(source_lease) => source_lease,
                        Err(reason) => {
                            state.record_listener_abuse_rejection(&listener_name, reason);
                            state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                            if matches!(&proxy, ManagedProxyConfig::Http1(_)) {
                                let _ = write_abuse_rejection_response(&mut stream, reason).await;
                            }
                            continue;
                        }
                    }
                };
                let mut handshake_permit = {
                    let protection = abuse_protection.read().await;
                    match protection.try_acquire_handshake() {
                        Ok(handshake_permit) => handshake_permit,
                        Err(reason) => {
                            drop(source_lease);
                            state.record_listener_abuse_rejection(&listener_name, reason);
                            state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                            if matches!(&proxy, ManagedProxyConfig::Http1(_)) {
                                let _ = write_abuse_rejection_response(&mut stream, reason).await;
                            }
                            continue;
                        }
                    }
                };
                if !matches!(&proxy, ManagedProxyConfig::Https(_)) {
                    if let Some(handshake_permit) = handshake_permit.as_mut() {
                        handshake_permit.release();
                    }
                }
                state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                counters.accepted_connections.fetch_add(1, Ordering::SeqCst);
                if !try_acquire_listener_slot(&counters, &admission_limit) {
                    drop(source_lease);
                    drop(handshake_permit);
                    counters.shed_connections.fetch_add(1, Ordering::SeqCst);
                    state.record_overload_event(
                        &listener_name,
                        lb_observability::OverloadEventKind::RequestShed,
                        format!(
                            "listener shed public connection at capacity {}",
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
                    if matches!(&proxy, ManagedProxyConfig::Http1(_)) {
                        let _ = write_overload_response(&mut stream).await;
                    }
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
                let listener_name = listener_name.clone();
                let admission_limit = Arc::clone(&admission_limit);
                let overload_runtime = Arc::clone(&overload_runtime);
                let abuse_protection = Arc::clone(&abuse_protection);
                tasks.spawn(async move {
                    let _source_lease = source_lease;
                    let result: io::Result<u64> = match proxy {
                        ManagedProxyConfig::Http1(config) => {
                            lb_runtime::proxy_http1_connection_with_downstream_addr(
                                stream,
                                downstream_addr,
                                &config,
                            )
                            .await
                            .map(|report| report.metrics.request_count)
                            .map_err(|error| io::Error::other(error.to_string()))
                        }
                        ManagedProxyConfig::Http2(config) => {
                            lb_runtime::proxy_http2_connection_with_downstream_addr(
                                stream,
                                downstream_addr,
                                &config,
                            )
                            .await
                            .map(|report| report.metrics.request_count)
                            .map_err(|error| io::Error::other(error.to_string()))
                        }
                        ManagedProxyConfig::Https(config) => {
                            proxy_https_connection(stream, downstream_addr, config, handshake_permit)
                                .await
                        }
                        ManagedProxyConfig::Http3(_) => {
                            Err(io::Error::other("http3 proxy config cannot run on tcp listener loop"))
                        }
                    };
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

async fn run_admin_listener_loop(
    listener: TcpListener,
    listener_name: String,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
    counters: Arc<ListenerRuntimeCounters>,
    state: Arc<WorkspaceServeState>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
    admin_runtime: AdminRuntimeHandles,
    admin_tls: Option<ManagedAdminTlsConfig>,
    admin_secret: Arc<String>,
    supervisor: ServeSupervisor,
    ready_tx: oneshot::Sender<()>,
) -> io::Result<ListenerDrainOutcome> {
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
            accepted = listener.accept() => {
                let (mut stream, peer_addr) = accepted?;
                let source_lease = {
                    let protection = abuse_protection.read().await;
                    match protection.try_acquire_source(peer_addr) {
                        Ok(source_lease) => source_lease,
                        Err(reason) => {
                            state.record_listener_abuse_rejection(&listener_name, reason);
                            state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                            if admin_tls.is_none() {
                                let _ = write_abuse_rejection_response(&mut stream, reason).await;
                            }
                            continue;
                        }
                    }
                };
                let mut handshake_permit = {
                    let protection = abuse_protection.read().await;
                    match protection.try_acquire_handshake() {
                        Ok(handshake_permit) => handshake_permit,
                        Err(reason) => {
                            drop(source_lease);
                            state.record_listener_abuse_rejection(&listener_name, reason);
                            state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                            if admin_tls.is_none() {
                                let _ = write_abuse_rejection_response(&mut stream, reason).await;
                            }
                            continue;
                        }
                    }
                };
                if admin_tls.is_none() {
                    if let Some(handshake_permit) = handshake_permit.as_mut() {
                        handshake_permit.release();
                    }
                }
                state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                counters.accepted_connections.fetch_add(1, Ordering::SeqCst);
                if !try_acquire_listener_slot(&counters, &admission_limit) {
                    drop(source_lease);
                    drop(handshake_permit);
                    counters.shed_connections.fetch_add(1, Ordering::SeqCst);
                    state.record_overload_event(
                        &listener_name,
                        lb_observability::OverloadEventKind::RequestShed,
                        format!(
                            "listener shed admin connection at capacity {}",
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
                    if admin_tls.is_none() {
                        let _ = write_overload_response(&mut stream).await;
                    }
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
                let admin_runtime = admin_runtime.clone();
                let admin_secret = Arc::clone(&admin_secret);
                let supervisor = supervisor.clone();
                let listener_name = listener_name.clone();
                let admission_limit = Arc::clone(&admission_limit);
                let overload_runtime = Arc::clone(&overload_runtime);
                let abuse_protection = Arc::clone(&abuse_protection);
                let admin_tls = admin_tls.clone();
                tasks.spawn(async move {
                    let _source_lease = source_lease;
                    let state_for_connection = Arc::clone(&state);
                    let _ = match admin_tls {
                        Some(config) => {
                            handle_workspace_admin_tls_connection(
                                stream,
                                peer_addr,
                                listener_name.clone(),
                                state_for_connection,
                                admin_runtime,
                                admin_secret,
                                supervisor,
                                config,
                                handshake_permit,
                            )
                            .await
                        }
                        None => {
                            handle_workspace_admin_connection(
                                stream,
                                peer_addr,
                                listener_name.clone(),
                                state_for_connection,
                                admin_runtime,
                                admin_secret,
                                supervisor,
                            )
                            .await
                        }
                    };
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

async fn handle_workspace_admin_tls_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    listener_name: String,
    state: Arc<WorkspaceServeState>,
    admin_runtime: AdminRuntimeHandles,
    admin_secret: Arc<String>,
    supervisor: ServeSupervisor,
    config: ManagedAdminTlsConfig,
    mut handshake_permit: Option<lb_runtime::HandshakePermit>,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::clone(&config.tls_server_config));
    let tls_stream =
        acceptor.accept(stream).await.map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(handshake_permit) = handshake_permit.as_mut() {
        handshake_permit.release();
    }

    handle_workspace_admin_connection(
        tls_stream,
        peer_addr,
        listener_name,
        state,
        admin_runtime,
        admin_secret,
        supervisor,
    )
    .await
}


fn try_acquire_listener_slot(
    counters: &ListenerRuntimeCounters,
    admission_limit: &AtomicUsize,
) -> bool {
    loop {
        let active = counters.active_connections.load(Ordering::SeqCst);
        let limit = admission_limit.load(Ordering::SeqCst);
        if active >= limit {
            return false;
        }

        if counters
            .active_connections
            .compare_exchange(active, active + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return true;
        }
    }
}

async fn write_overload_response(stream: &mut TcpStream) -> io::Result<()> {
    crate::write_http_response(
        stream,
        "503 Service Unavailable",
        "text/plain; charset=utf-8",
        b"listener overloaded\n",
    )
    .await?;
    stream.shutdown().await
}


async fn proxy_https_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: ManagedHttpsProxyConfig,
    mut handshake_permit: Option<lb_runtime::HandshakePermit>,
) -> io::Result<u64> {
    let acceptor = TlsAcceptor::from(Arc::clone(&config.tls_server_config));
    let tls_stream =
        acceptor.accept(stream).await.map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(handshake_permit) = handshake_permit.as_mut() {
        handshake_permit.release();
    }
    let negotiated_h2 =
        tls_stream.get_ref().1.alpn_protocol().is_some_and(|protocol| protocol == b"h2");

    if negotiated_h2 {
        lb_runtime::proxy_http2_connection_with_downstream_addr(
            tls_stream,
            peer_addr,
            &config.http2,
        )
        .await
        .map(|report| report.metrics.request_count)
        .map_err(|error| io::Error::other(error.to_string()))
    } else {
        lb_runtime::proxy_http1_connection_with_downstream_addr(
            tls_stream,
            peer_addr,
            &config.http1,
        )
        .await
        .map(|report| report.metrics.request_count)
        .map_err(|error| io::Error::other(error.to_string()))
    }
}

