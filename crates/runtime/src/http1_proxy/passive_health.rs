fn record_passive_health_result(
    selected_upstream: &SelectedUpstream,
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

