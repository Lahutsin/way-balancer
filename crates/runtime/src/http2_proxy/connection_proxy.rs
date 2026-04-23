pub async fn proxy_http2_connection(
    downstream: TcpStream,
    config: &Http2ProxyConfig,
) -> Result<Http2ConnectionReport, Http2ProxyError> {
    let downstream_addr = downstream
        .peer_addr()
        .map_err(|source| Http2ProxyError::Connect { target: config.upstream.address, source })?;

    proxy_http2_connection_with_downstream_addr(downstream, downstream_addr, config).await
}

/// Proxies an HTTP/2 connection with bounded concurrent streams over an arbitrary downstream stream.
pub async fn proxy_http2_connection_with_downstream_addr<S>(
    downstream: S,
    downstream_addr: SocketAddr,
    config: &Http2ProxyConfig,
) -> Result<Http2ConnectionReport, Http2ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let downstream_builder = server::Builder::new();
    let mut downstream_connection = downstream_builder
        .handshake(downstream)
        .await
        .map_err(Http2ProxyError::DownstreamHandshake)?;

    let upstream_clients = UpstreamClientRegistry::default();
    if config.route_upstreams.is_empty() && config.route_backend_pools.is_empty() {
        upstream_clients
            .ensure_client(&config.upstream, &config.timeouts)
            .await
            .map(|_| ())
            .map_err(map_upstream_client_connect_error)?;
    }

    let metrics = Arc::new(MetricsState::new());
    let semaphore = Arc::new(Semaphore::new(config.limits.max_concurrent_streams));
    let shared_config = Arc::new(config.clone());
    let mut stream_tasks = JoinSet::new();

    while let Some(result) = downstream_connection.accept().await {
        let (request, respond) = match result {
            Ok(stream) => stream,
            Err(error) => {
                let had_traffic = metrics.request_count.load(Ordering::SeqCst) > 0;
                let no_active_streams = metrics.active_streams.load(Ordering::SeqCst) == 0;
                if had_traffic && no_active_streams {
                    break;
                }
                return Err(Http2ProxyError::DownstreamConnection(error));
            }
        };
        let metrics = Arc::clone(&metrics);
        let semaphore = Arc::clone(&semaphore);
        let config = Arc::clone(&shared_config);
        let upstream_clients = upstream_clients.clone();

        stream_tasks.spawn(async move {
            handle_http2_stream(
                request,
                respond,
                downstream_addr,
                upstream_clients,
                metrics,
                semaphore,
                config,
            )
            .await;
        });
    }

    while let Some(result) = stream_tasks.join_next().await {
        result.map_err(Http2ProxyError::StreamTask)?;
    }

    let active_upstream = upstream_clients.active_summary().await;
    Ok(Http2ConnectionReport {
        downstream_addr,
        upstream_addr: active_upstream
            .as_ref()
            .map(|client| client.upstream_addr)
            .unwrap_or(config.upstream.address),
        upstream_name: active_upstream
            .as_ref()
            .map(|client| client.target.name.clone())
            .unwrap_or_else(|| config.upstream.name.clone()),
        connect_duration: active_upstream
            .as_ref()
            .map(|client| client.connect_duration)
            .unwrap_or(Duration::ZERO),
        metrics: metrics.snapshot(),
        route_selection_metrics: route_selection_metrics(&config.route_backend_pools),
    })
}

fn route_selection_metrics(
    route_backend_pools: &BTreeMap<String, crate::RouteBackendPool>,
) -> Option<crate::UpstreamSelectionMetrics> {
    if route_backend_pools.is_empty() {
        return None;
    }

    Some(route_backend_pools.values().fold(
        crate::UpstreamSelectionMetrics::default(),
        |mut aggregate, pool| {
            let metrics = pool.selection_metrics();
            aggregate.round_robin_selection_count += metrics.round_robin_selection_count;
            aggregate.weighted_round_robin_selection_count +=
                metrics.weighted_round_robin_selection_count;
            aggregate.weighted_route_selection_count += metrics.weighted_route_selection_count;
            aggregate.power_of_two_selection_count += metrics.power_of_two_selection_count;
            aggregate.locality_preference_hit_count += metrics.locality_preference_hit_count;
            aggregate.no_healthy_endpoint_count += metrics.no_healthy_endpoint_count;
            aggregate.unhealthy_fallback_selection_count +=
                metrics.unhealthy_fallback_selection_count;
            aggregate.affinity_hit_count += metrics.affinity_hit_count;
            aggregate.affinity_fallback_count += metrics.affinity_fallback_count;
            aggregate.route_destination_fallback_count += metrics.route_destination_fallback_count;
            for (destination_name, count) in metrics.route_destination_selection_counts {
                *aggregate
                    .route_destination_selection_counts
                    .entry(destination_name)
                    .or_default() += count;
            }
            aggregate
        },
    ))
}

fn map_upstream_client_connect_error(error: UpstreamClientConnectError) -> Http2ProxyError {
    match error {
        UpstreamClientConnectError::ConnectTimeout { target } => {
            Http2ProxyError::ConnectTimeout { target }
        }
        UpstreamClientConnectError::Connect { target, source } => {
            Http2ProxyError::Connect { target, source }
        }
        UpstreamClientConnectError::Handshake(source) => Http2ProxyError::UpstreamHandshake(source),
    }
}

