fn route_enumeration_source_blocked(
    config: &Http2ProxyConfig,
    downstream_addr: SocketAddr,
) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.is_blocked(downstream_addr))
}

fn record_unmatched_route(config: &Http2ProxyConfig, downstream_addr: SocketAddr) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.record_unmatched_route(downstream_addr))
}

fn record_query_probe(
    config: &Http2ProxyConfig,
    downstream_addr: SocketAddr,
    authority: Option<&str>,
    target: &str,
) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.record_query_probe(downstream_addr, authority, target))
}

fn resolve_effective_client_ip(
    config: &Http2ProxyConfig,
    downstream_addr: SocketAddr,
    headers: &http::HeaderMap,
) -> Result<IpAddr, crate::TrustedClientIpError> {
    config.trusted_client_ip.as_ref().map_or(Ok(downstream_addr.ip()), |policy| {
        policy
            .resolve_resolution_from_http2_headers(downstream_addr.ip(), headers)
            .map(|resolution| resolution.client_ip)
    })
}

fn anonymous_source_blocked(config: &Http2ProxyConfig, client_ip: IpAddr) -> bool {
    config
        .anonymous_source_filter
        .as_ref()
        .is_some_and(|filter| filter.classify_and_record(client_ip).is_some())
}

