async fn maybe_inject_http2_fault(
    request: &Request<RecvStream>,
    respond: &mut SendResponse<Bytes>,
    destination_policy: Option<&crate::RouteDestinationPolicyRuntime>,
    metrics: &MetricsState,
) -> Result<Option<StatusCode>, h2::Error> {
    let Some(fault_policy) = destination_policy.and_then(|policy| policy.fault_injection.as_ref()) else {
        return Ok(None);
    };

    if let Some(delay) = fault_policy.delay.as_ref().filter(|delay| {
        fault_injection_http2_action_selected("delay", delay.percentage, request)
    }) {
        metrics.increment_fault_injection_delay_count();
        time::sleep(Duration::from_millis(delay.fixed_delay_ms)).await;
    }

    let Some(abort) = fault_policy.abort.as_ref().filter(|abort| {
        fault_injection_http2_action_selected("abort", abort.percentage, request)
    }) else {
        return Ok(None);
    };
    metrics.increment_fault_injection_abort_count();
    let status = StatusCode::from_u16(abort.http_status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    send_local_response(respond, status)?;
    Ok(Some(status))
}

fn fault_injection_http2_action_selected(
    action: &str,
    percentage: u8,
    request: &Request<RecvStream>,
) -> bool {
    if percentage >= 100 {
        return true;
    }
    let authority = request
        .uri()
        .authority()
        .map(|value| value.as_str())
        .or_else(|| request.headers().get(http::header::HOST).and_then(|value| value.to_str().ok()))
        .unwrap_or_default();
    let key = format!(
        "{action} {} {} {}",
        request.method(),
        request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        authority,
    );
    stable_request_hash(key.as_bytes()) % 100 < u64::from(percentage)
}

