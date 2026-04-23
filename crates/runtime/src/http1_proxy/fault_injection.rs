async fn maybe_inject_http1_fault<W>(
    request: &lb_proto_http::Http1RequestHead,
    downstream: &mut W,
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
    metrics: &mut Http1ConnectionMetrics,
) -> Result<Option<StatusCode>, std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    let Some(fault_policy) = destination_policy.and_then(|policy| policy.fault_injection.as_ref()) else {
        return Ok(None);
    };

    if let Some(delay) = fault_policy.delay.as_ref().filter(|delay| {
        fault_injection_action_selected("delay", delay.percentage, request)
    }) {
        metrics.fault_injection_delay_count += 1;
        time::sleep(Duration::from_millis(delay.fixed_delay_ms)).await;
    }

    let Some(abort) = fault_policy.abort.as_ref().filter(|abort| {
        fault_injection_action_selected("abort", abort.percentage, request)
    }) else {
        return Ok(None);
    };
    metrics.fault_injection_abort_count += 1;
    let status = StatusCode::from_u16(abort.http_status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    write_local_response(downstream, request.keep_alive, status, "fault injection abort\n").await?;
    Ok(Some(status))
}

fn fault_injection_action_selected(
    action: &str,
    percentage: u8,
    request: &lb_proto_http::Http1RequestHead,
) -> bool {
    if percentage >= 100 {
        return true;
    }

    let authority = request_authority(request).unwrap_or_default();
    let key = format!("{action} {} {} {}", request.method, request.target, authority);
    stable_request_hash(key.as_bytes()) % 100 < u64::from(percentage)
}
