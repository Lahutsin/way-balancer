fn record_passive_health_result(
    config: &Http1ProxyConfig,
    selected_upstream: &SelectedUpstream,
    route_label: Option<&str>,
    result: &Result<u16, Http1ProxyError>,
) {
    let Some(route_backend) = selected_upstream.route_backend.as_ref() else {
        return;
    };

    let feedback_result = match result {
        Ok(status) if *status < 500 => route_backend.note_passive_success(),
        Err(error) if error_is_upstream_passive_failure(error) => {
            route_backend.note_passive_failure()
        }
        _ => return,
    };

    if let (Some(request_telemetry), Ok(snapshot)) = (config.request_telemetry.as_ref(), &feedback_result)
    {
        if matches!(snapshot.status, crate::EndpointHealthStatus::Ejected) {
            let _ = request_telemetry.telemetry.record_decision_trace(
                &request_telemetry.scope,
                lb_observability::DecisionTraceKind::HealthEjection,
                "ejected",
                route_label,
                Some(route_backend.cluster_name().as_str()),
                Some("passive_health"),
                None,
                "passive health manager ejected destination after upstream failure",
            );
        }
    }
    let _ = feedback_result;
}

fn error_is_upstream_passive_failure(error: &Http1ProxyError) -> bool {
    matches!(
        error,
        Http1ProxyError::ConnectTimeout { .. }
            | Http1ProxyError::Connect { .. }
            | Http1ProxyError::RequestIo(_)
            | Http1ProxyError::ParseResponse(_)
            | Http1ProxyError::IdleTimeout("response head")
    )
}

