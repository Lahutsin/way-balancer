#[derive(Debug, Clone)]
struct CompiledListenerAbuseProtectionPolicy {
    source_quota: Option<CompiledSourceQuotaPolicy>,
    handshake_guard: Option<CompiledHandshakeGuardPolicy>,
}

#[derive(Debug, Clone, Copy)]
struct CompiledSourceQuotaPolicy {
    aggregation: lb_runtime::SourceAggregation,
    max_active_per_source: usize,
    max_tracked_sources: usize,
}

#[derive(Debug, Clone, Copy)]
struct CompiledHandshakeGuardPolicy {
    max_inflight: usize,
    timeout: Duration,
}

async fn write_abuse_rejection_response(
    stream: &mut TcpStream,
    reason: lb_runtime::AbuseRejectionReason,
) -> io::Result<()> {
    let body = format!("listener rejected connection: {}\n", reason.code());
    let response = format!(
        concat!(
            "HTTP/1.1 503 Service Unavailable\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n",
            "X-LB-Abuse-Reason: {}\r\n\r\n",
            "{}"
        ),
        body.len(),
        reason.code(),
        body,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn build_listener_abuse_protection_state(
    policy: Option<&CompiledListenerAbuseProtectionPolicy>,
) -> lb_runtime::ListenerAbuseProtectionState {
    lb_runtime::ListenerAbuseProtectionState::new(policy.map_or_else(
        lb_runtime::ListenerAbuseProtectionPolicy::default,
        |policy| lb_runtime::ListenerAbuseProtectionPolicy {
            source_quota: policy.source_quota.map(|source_quota| {
                lb_runtime::SourceQuotaPolicy::new(
                    source_quota.aggregation,
                    source_quota.max_active_per_source,
                    source_quota.max_tracked_sources,
                )
            }),
            handshake_guard: policy.handshake_guard.map(|handshake_guard| {
                lb_runtime::HandshakeGuardPolicy::new(
                    handshake_guard.max_inflight,
                    handshake_guard.timeout,
                )
            }),
        },
    ))
}

