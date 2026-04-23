fn validate_workspace_basics(config: &WorkspaceConfig, report: &mut ValidationReport) {
    if config.name.trim().is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::EmptyWorkspaceName,
            "name",
            "workspace name must not be empty",
        ));
    }
}

fn validate_defaults(config: &WorkspaceConfig, report: &mut ValidationReport) {
    let listener = &config.defaults.listener;
    if listener.max_connections == 0
        || listener.backlog == 0
        || listener.idle_timeout_ms == 0
        || listener.drain_timeout_ms == 0
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerDefaults,
            "defaults.listener",
            "listener defaults must use non-zero max_connections, backlog, idle_timeout_ms, and drain_timeout_ms",
        ));
    }

    let http1 = &config.defaults.http.http1;
    if http1.max_head_bytes == 0 || http1.max_header_count == 0 || http1.max_body_bytes == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidHttp1Defaults,
            "defaults.http.http1",
            "http1 defaults must use non-zero max_head_bytes, max_header_count, and max_body_bytes",
        ));
    }

    let http2 = &config.defaults.http.http2;
    if http2.max_concurrent_streams == 0 || http2.max_body_bytes == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidHttp2Defaults,
            "defaults.http.http2",
            "http2 defaults must use non-zero max_concurrent_streams and max_body_bytes",
        ));
    }
}

