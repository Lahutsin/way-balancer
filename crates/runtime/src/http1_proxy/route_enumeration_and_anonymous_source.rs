fn route_enumeration_source_blocked(
    config: &Http1ProxyConfig,
    downstream_addr: SocketAddr,
) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.is_blocked(downstream_addr))
}

fn record_unmatched_route(config: &Http1ProxyConfig, downstream_addr: SocketAddr) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.record_unmatched_route(downstream_addr))
}

fn record_query_probe(
    config: &Http1ProxyConfig,
    downstream_addr: SocketAddr,
    authority: Option<&str>,
    target: &str,
) -> bool {
    config
        .route_enumeration_protection
        .as_ref()
        .is_some_and(|protection| protection.record_query_probe(downstream_addr, authority, target))
}

fn anonymous_source_blocked(config: &Http1ProxyConfig, client_ip: IpAddr) -> bool {
    config
        .anonymous_source_filter
        .as_ref()
        .is_some_and(|filter| filter.classify_and_record(client_ip).is_some())
}

