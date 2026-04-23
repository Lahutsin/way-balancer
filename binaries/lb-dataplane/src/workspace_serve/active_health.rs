async fn run_active_health_probe_loop(
    shared_proxy: Arc<RwLock<ManagedProxyConfig>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = time::interval(ACTIVE_HEALTH_PROBE_INTERVAL);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    ticker.tick().await;
    let mut last_tick = Instant::now();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(last_tick);
                last_tick = now;
                let pools = {
                    let proxy = shared_proxy.read().await.clone();
                    collect_active_probe_pools(&proxy)
                };

                for pool in pools {
                    pool.advance_time(elapsed);
                    let probe_targets = match pool.active_probe_targets() {
                        Ok(probe_targets) => probe_targets,
                        Err(_) => continue,
                    };
                    for probe_target in probe_targets {
                        let probe_result = time::timeout(
                            ACTIVE_HEALTH_PROBE_TIMEOUT,
                            TcpStream::connect(probe_target.address),
                        )
                        .await;
                        match probe_result {
                            Ok(Ok(stream)) => {
                                drop(stream);
                                let _ = pool.note_active_success(&probe_target.endpoint_id);
                            }
                            _ => {
                                let _ = pool.note_active_failure(&probe_target.endpoint_id);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn collect_active_probe_pools(proxy: &ManagedProxyConfig) -> Vec<lb_runtime::RouteBackendPool> {
    let mut pools_by_scope = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();
    let mut insert_pool = |pool: &lb_runtime::RouteBackendPool| {
        let key = pool
            .cluster_names()
            .into_iter()
            .map(|cluster_name| cluster_name.to_string())
            .collect::<Vec<_>>()
            .join(",");
        pools_by_scope.entry(key).or_insert_with(|| pool.clone());
    };

    match proxy {
        ManagedProxyConfig::Http1(config) => {
            for pool in config.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
        ManagedProxyConfig::Http2(config) => {
            for pool in config.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
        ManagedProxyConfig::Https(config) => {
            for pool in config.http1.route_backend_pools.values() {
                insert_pool(pool);
            }
            for pool in config.http2.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
        ManagedProxyConfig::Http3(_) => {}
    }

    pools_by_scope.into_values().collect()
}

