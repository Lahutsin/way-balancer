async fn ensure_upstream_connection(
    upstream: &mut Option<TcpStream>,
    active_upstream: &mut Option<lb_net_core::UpstreamTarget>,
    last_upstream_activity: &mut Option<Instant>,
    upstream_connected_at: &mut Option<Instant>,
    upstream_addr: &mut SocketAddr,
    connect_duration: &mut Duration,
    target: &lb_net_core::UpstreamTarget,
    timeouts: &lb_net_core::ConnectionTimeouts,
) -> Result<bool, Http1ProxyError> {
    let now = Instant::now();
    if upstream.is_some()
        && active_upstream
            .as_ref()
            .is_some_and(|active| active.address == target.address && active.name == target.name)
    {
        if !upstream_connection_reuse_expired(
            now,
            *last_upstream_activity,
            *upstream_connected_at,
            timeouts.idle_timeout,
        ) {
            return Ok(true);
        }

        drop_upstream_connection(upstream, last_upstream_activity, upstream_connected_at);
    }

    let _ = upstream.take();
    let connect_started = Instant::now();
    let stream = time::timeout(timeouts.connect_timeout, TcpStream::connect(target.address))
        .await
        .map_err(|_| Http1ProxyError::ConnectTimeout { target: target.address })?
        .map_err(|source| Http1ProxyError::Connect { target: target.address, source })?;
    *connect_duration = connect_started.elapsed();
    *upstream_addr = stream
        .peer_addr()
        .map_err(|source| Http1ProxyError::Connect { target: target.address, source })?;
    *active_upstream = Some(target.clone());
    let connected_at = Instant::now();
    *last_upstream_activity = Some(connected_at);
    *upstream_connected_at = Some(connected_at);
    *upstream = Some(stream);
    Ok(false)
}

fn upstream_connection_reuse_expired(
    now: Instant,
    last_upstream_activity: Option<Instant>,
    upstream_connected_at: Option<Instant>,
    reuse_timeout: Duration,
) -> bool {
    last_upstream_activity
        .map_or(true, |last_used_at| now.saturating_duration_since(last_used_at) >= reuse_timeout)
        || upstream_connected_at.map_or(true, |connected_at| {
            now.saturating_duration_since(connected_at) >= reuse_timeout
        })
}

fn drop_upstream_connection(
    upstream: &mut Option<TcpStream>,
    last_upstream_activity: &mut Option<Instant>,
    upstream_connected_at: &mut Option<Instant>,
) {
    *last_upstream_activity = None;
    *upstream_connected_at = None;
    let _ = upstream.take();
}
