#[derive(Debug, Clone)]
struct UpstreamClientHandle {
    target: lb_net_core::UpstreamTarget,
    upstream_addr: SocketAddr,
    connect_duration: Duration,
    send_request: Arc<AsyncMutex<SendRequest<Bytes>>>,
    connected_at: Arc<Mutex<Instant>>,
    last_used_at: Arc<Mutex<Instant>>,
    completed_streams: Arc<Mutex<u64>>,
}

impl UpstreamClientHandle {
    fn mark_used(&self, at: Instant) {
        *self.last_used_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = at;
    }

    fn idle_expired(&self, now: Instant, idle_timeout: Duration) -> bool {
        now.saturating_duration_since(
            *self.last_used_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()),
        ) >= idle_timeout
    }

    fn age_expired(&self, now: Instant, max_age: Duration) -> bool {
        now.saturating_duration_since(
            *self.connected_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()),
        ) >= max_age
    }

    fn reuse_expired(&self, now: Instant, reuse_timeout: Duration) -> bool {
        self.idle_expired(now, reuse_timeout) || self.age_expired(now, reuse_timeout)
    }

    fn had_completed_streams(&self) -> bool {
        *self.completed_streams.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) > 0
    }

    fn note_completed_stream(&self) {
        *self.completed_streams.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
    }
}

#[derive(Debug, Clone, Default)]
struct UpstreamClientRegistry {
    clients: Arc<AsyncMutex<BTreeMap<String, UpstreamClientHandle>>>,
    last_active: Arc<AsyncMutex<Option<UpstreamClientHandle>>>,
}

#[derive(Debug)]
enum UpstreamClientConnectError {
    ConnectTimeout { target: SocketAddr },
    Connect { target: SocketAddr, source: std::io::Error },
    Handshake(h2::Error),
}

impl UpstreamClientRegistry {
    async fn ensure_client(
        &self,
        target: &lb_net_core::UpstreamTarget,
        timeouts: &lb_net_core::ConnectionTimeouts,
    ) -> Result<(UpstreamClientHandle, bool), UpstreamClientConnectError> {
        let key = upstream_client_key(target);
        let now = Instant::now();
        let cached_client = self.clients.lock().await.get(&key).cloned();
        if let Some(client) = cached_client {
            if client.reuse_expired(now, timeouts.idle_timeout) {
                self.remove_client(target).await;
            } else {
                let had_completed_streams = client.had_completed_streams();
                client.mark_used(now);
                self.record_active(&client).await;
                return Ok((client, had_completed_streams));
            }
        }

        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(&key) {
            if client.reuse_expired(now, timeouts.idle_timeout) {
                clients.remove(&key);
            } else {
                let client = client.clone();
                let had_completed_streams = client.had_completed_streams();
                client.mark_used(now);
                drop(clients);
                self.record_active(&client).await;
                return Ok((client, had_completed_streams));
            }
        }

        let connect_started = Instant::now();
        let upstream_stream =
            time::timeout(timeouts.connect_timeout, TcpStream::connect(target.address))
                .await
                .map_err(|_| UpstreamClientConnectError::ConnectTimeout { target: target.address })?
                .map_err(|source| UpstreamClientConnectError::Connect {
                    target: target.address,
                    source,
                })?;
        let connect_duration = connect_started.elapsed();
        let upstream_addr = upstream_stream.peer_addr().map_err(|source| {
            UpstreamClientConnectError::Connect { target: target.address, source }
        })?;

        let upstream_builder = client::Builder::new();
        let (send_request, upstream_connection) = upstream_builder
            .handshake(upstream_stream)
            .await
            .map_err(UpstreamClientConnectError::Handshake)?;
        tokio::spawn(async move {
            let _ = upstream_connection.await;
        });

        let connected_at = Instant::now();
        let client = UpstreamClientHandle {
            target: target.clone(),
            upstream_addr,
            connect_duration,
            send_request: Arc::new(AsyncMutex::new(send_request)),
            connected_at: Arc::new(Mutex::new(connected_at)),
            last_used_at: Arc::new(Mutex::new(connected_at)),
            completed_streams: Arc::new(Mutex::new(0)),
        };
        clients.insert(key, client.clone());
        drop(clients);
        self.record_active(&client).await;
        Ok((client, false))
    }

    async fn remove_client(&self, target: &lb_net_core::UpstreamTarget) {
        self.clients.lock().await.remove(&upstream_client_key(target));
    }

    async fn record_active(&self, client: &UpstreamClientHandle) {
        *self.last_active.lock().await = Some(client.clone());
    }

    async fn active_summary(&self) -> Option<UpstreamClientHandle> {
        self.last_active.lock().await.clone()
    }
}

fn upstream_client_key(target: &lb_net_core::UpstreamTarget) -> String {
    format!("{}@{}", target.name, target.address)
}
