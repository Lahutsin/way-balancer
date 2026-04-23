async fn handle_http2_stream(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    downstream_addr: SocketAddr,
    upstream_clients: UpstreamClientRegistry,
    metrics: Arc<MetricsState>,
    semaphore: Arc<Semaphore>,
    config: Arc<Http2ProxyConfig>,
) {
    let Ok(permit) = semaphore.try_acquire_owned() else {
        metrics.increment_stream_limit_violation_count();
        metrics.record_anomaly(ProtocolAnomalyCategory::StreamConcurrencyLimitExceeded);
        metrics.increment_stream_reset_count();
        respond.send_reset(Reason::REFUSED_STREAM);
        return;
    };

    metrics.increment_request_count();
    metrics.increment_active_streams();
    let stream_result = proxy_one_http2_stream(
        request,
        &mut respond,
        downstream_addr,
        upstream_clients,
        &metrics,
        &config,
    )
    .await;

    if matches!(stream_result, Err(StreamForwardError::ResponseBody)) {
        metrics.increment_stream_reset_count();
    }
    if let Err(error) = stream_result {
        if matches!(error, StreamForwardError::InvalidRequest) {
            metrics.increment_hardening_rejection_count();
            metrics.record_anomaly(ProtocolAnomalyCategory::MalformedMessage);
        }
        if let StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody) = error {
            metrics.increment_slow_client_trigger_count();
            metrics.record_slow_client(SlowClientStage::RequestBody);
        }
        if !matches!(error, StreamForwardError::RequestBodyLimitExceeded) {
            metrics.increment_stream_error_count();
        }
    }

    drop(permit);
    metrics.decrement_active_streams();
}

#[derive(Debug, Clone, Copy)]
enum StreamForwardError {
    InvalidRequest,
    IdleTimeout(StreamIdlePhase),
    UpstreamGracefulDrain,
    UpstreamReady,
    UpstreamRequest,
    UpstreamResponse,
    SendResponse,
    RequestBody,
    ResponseBody,
    RequestBodyLimitExceeded,
    ResponseBodyLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamIdlePhase {
    RequestBody,
    UpstreamResponse,
    ResponseBody,
}

#[derive(Clone, Copy)]
enum StreamBodyDirection {
    Request,
    Response,
}

