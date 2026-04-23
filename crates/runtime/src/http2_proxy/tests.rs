#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use http::{HeaderMap, HeaderValue, StatusCode};
    use ipnet::IpNet;

    use super::{
        anonymous_source_blocked, error_is_upstream_passive_failure,
        grpc_payload_has_at_most_one_message, header_value,
        record_query_probe, record_unmatched_route, resolve_effective_client_ip,
        resolve_stream_upstream, route_enumeration_source_blocked, select_http2_route_upstream,
        selection_context_for_request, should_skip_http2_header, stable_request_hash,
        Http2ProxyConfig, Http2ProxyError, Http2RouteUpstream, MetricsState,
        RequestUpstreamResolution, StreamForwardError, StreamIdlePhase,
    };
    use crate::{
        AnonymousSourceFilterPolicy, ProtocolAnomalyCategory, RouteEnumerationProtectionPolicy,
        SlowClientStage, SourceAggregation, TrustedClientIpPolicy,
    };

    fn localhost_socket(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn http2_errors_expose_anomaly_and_sources() {
        let connect = Http2ProxyError::Connect {
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            source: io::Error::other("connect failed"),
        };
        let handshake =
            Http2ProxyError::DownstreamHandshake(h2::Error::from(h2::Reason::PROTOCOL_ERROR));

        assert!(connect.to_string().contains("failed to connect HTTP/2 upstream"));
        assert!(std::error::Error::source(&connect).is_some());
        assert_eq!(handshake.anomaly_category(), Some(ProtocolAnomalyCategory::MalformedPreface));
    }

    #[test]
    fn metrics_state_snapshot_accumulates_all_counters() {
        let metrics = MetricsState::new();
        metrics.increment_request_count();
        metrics.increment_active_streams();
        metrics.increment_active_streams();
        metrics.decrement_active_streams();
        metrics.increment_stream_reset_count();
        metrics.increment_stream_error_count();
        metrics.increment_stream_limit_violation_count();
        metrics.increment_body_limit_violation_count();
        metrics.increment_fault_injection_delay_count();
        metrics.increment_fault_injection_abort_count();
        metrics.increment_grpc_request_count();
        metrics.record_grpc_service("grpc.health.v1.Health");
        metrics.record_grpc_method("grpc.health.v1.Health", "Check");
        metrics.record_grpc_status(0);
        metrics.increment_hardening_rejection_count();
        metrics.increment_slow_client_trigger_count();
        metrics.record_anomaly(ProtocolAnomalyCategory::BodySizeLimitExceeded);
        metrics.record_slow_client(SlowClientStage::RequestBody);
        metrics.record_response_status(200);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.active_streams, 1);
        assert_eq!(snapshot.peak_active_streams, 2);
        assert_eq!(snapshot.request_count, 1);
        assert_eq!(snapshot.stream_reset_count, 1);
        assert_eq!(snapshot.stream_error_count, 1);
        assert_eq!(snapshot.stream_limit_violation_count, 1);
        assert_eq!(snapshot.body_limit_violation_count, 1);
        assert_eq!(snapshot.fault_injection_delay_count, 1);
        assert_eq!(snapshot.fault_injection_abort_count, 1);
        assert_eq!(snapshot.grpc_request_count, 1);
        assert_eq!(
            snapshot.grpc_service_counts.get("grpc.health.v1.Health"),
            Some(&1)
        );
        assert_eq!(
            snapshot.grpc_method_counts.get("grpc.health.v1.Health/Check"),
            Some(&1)
        );
        assert_eq!(snapshot.grpc_status_counts.get(&0), Some(&1));
        assert_eq!(snapshot.hardening_rejection_count, 1);
        assert_eq!(snapshot.slow_client_trigger_count, 1);
        assert_eq!(
            snapshot.anomaly_counts.get(&ProtocolAnomalyCategory::BodySizeLimitExceeded),
            Some(&1)
        );
        assert_eq!(snapshot.slow_client_counts.get(&SlowClientStage::RequestBody), Some(&1));
        assert_eq!(snapshot.response_status_counts.get(&200), Some(&1));
    }

    #[test]
    fn selection_context_trims_hints_and_uses_stable_hash() {
        let mut headers = HeaderMap::new();
        headers.insert("x-lb-locality", HeaderValue::from_static(" edge-west "));
        headers.insert("x-lb-zone", HeaderValue::from_static(" zone-west "));
        headers.insert("x-empty", HeaderValue::from_static("   "));

        let context = selection_context_for_request("/api?q=1", &headers, None);

        assert_eq!(context.preferred_locality.as_deref(), Some("edge-west"));
        assert_eq!(context.preferred_zone.as_deref(), Some("zone-west"));
        assert_eq!(context.request_hash, stable_request_hash(b"/api?q=1"));
        assert_eq!(header_value(&headers, "x-empty"), None);
    }

    #[test]
    fn grpc_payload_retry_shape_is_limited_to_unary_frames() {
        assert!(grpc_payload_has_at_most_one_message(&[]));
        assert!(grpc_payload_has_at_most_one_message(&[0, 0, 0, 0, 4, 1, 2, 3, 4]));
        assert!(!grpc_payload_has_at_most_one_message(&[
            0, 0, 0, 0, 1, 9,
            0, 0, 0, 0, 1, 8,
        ]));
        assert!(!grpc_payload_has_at_most_one_message(&[0, 0, 0]));
    }

    #[test]
    fn route_upstream_selection_rotates_and_resolves_fallbacks() {
        let upstream_a = lb_net_core::UpstreamTarget::new("a", localhost_socket(9001));
        let upstream_b = lb_net_core::UpstreamTarget::new("b", localhost_socket(9002));
        let fallback = lb_net_core::UpstreamTarget::new("fallback", localhost_socket(9000));
        let mut config = Http2ProxyConfig::new(fallback.clone()).with_route_upstreams([
            Http2RouteUpstream { route_label: String::from("api"), upstream: upstream_a.clone() },
            Http2RouteUpstream { route_label: String::from("api"), upstream: upstream_b.clone() },
        ]);
        config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

        let route = lb_proto_http::match_route_request_with_method("/api", None, Some("GET"), &config.routes)
            .expect("route should match");
        let selected_one =
            match resolve_stream_upstream(&config, Some(&route), "/api", &HeaderMap::new()) {
                RequestUpstreamResolution::Selected(selected) => selected.target,
                RequestUpstreamResolution::Reject(status) => panic!("unexpected reject: {status}"),
            };
        let selected_two =
            match resolve_stream_upstream(&config, Some(&route), "/api", &HeaderMap::new()) {
                RequestUpstreamResolution::Selected(selected) => selected.target,
                RequestUpstreamResolution::Reject(status) => panic!("unexpected reject: {status}"),
            };
        let selected_three = select_http2_route_upstream(
            &config,
            "api",
            config.route_upstreams.get("api").expect("route upstreams"),
        );

        assert_eq!(selected_one.address, upstream_a.address);
        assert_eq!(selected_two.address, upstream_b.address);
        assert_eq!(selected_three.address, upstream_a.address);

        let matched_none = match resolve_stream_upstream(&config, None, "/", &HeaderMap::new()) {
            RequestUpstreamResolution::Selected(selected) => selected.target,
            RequestUpstreamResolution::Reject(status) => panic!("unexpected reject: {status}"),
        };
        assert_eq!(matched_none.address, fallback.address);

        let rejecting = Http2ProxyConfig::new(fallback)
            .with_route_upstreams([Http2RouteUpstream {
                route_label: String::from("api"),
                upstream: upstream_a,
            }])
            .rejecting_unmatched_routes();
        assert!(matches!(
            resolve_stream_upstream(&rejecting, None, "/", &HeaderMap::new()),
            RequestUpstreamResolution::Reject(StatusCode::FORBIDDEN)
        ));
    }

    #[test]
    fn source_filter_and_enumeration_helpers_block_sources() {
        let filtered = Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new(
            "upstream",
            localhost_socket(9000),
        ))
        .with_anonymous_source_filter(AnonymousSourceFilterPolicy {
            enabled: true,
            deny_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("cidr")],
            deny_vpn: false,
            deny_proxy: false,
            deny_socks: false,
            deny_tor: false,
            vpn_cidrs: Vec::new(),
            proxy_cidrs: Vec::new(),
            socks_cidrs: Vec::new(),
            tor_exit_cidrs: Vec::new(),
        });
        assert!(anonymous_source_blocked(&filtered, IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let enumerating = Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new(
            "upstream",
            localhost_socket(9000),
        ))
        .with_route_enumeration_protection(RouteEnumerationProtectionPolicy {
            source_aggregation: SourceAggregation::ExactIp,
            evaluation_window: Duration::from_secs(60),
            max_unmatched_route_events: 0,
            max_distinct_query_signatures_per_route: 0,
            base_ban_duration: Duration::from_secs(5),
            max_ban_duration: Duration::from_secs(30),
            max_tracked_sources: 32,
        });
        let source = localhost_socket(40000);

        assert!(record_unmatched_route(&enumerating, source));
        assert!(route_enumeration_source_blocked(&enumerating, source));
        assert!(record_query_probe(&enumerating, source, Some("example.test"), "/api?debug=1"));
    }

    #[test]
    fn trusted_client_ip_and_header_filtering_helpers_match_runtime_policy() {
        let config = Http2ProxyConfig::new(lb_net_core::UpstreamTarget::new(
            "upstream",
            localhost_socket(9000),
        ))
        .with_trusted_client_ip(TrustedClientIpPolicy {
            enabled: true,
            trusted_proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("cidr")],
        });
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));

        let effective = resolve_effective_client_ip(&config, localhost_socket(8080), &headers)
            .expect("trusted forwarded client ip should resolve");
        assert_eq!(effective, "198.51.100.7".parse::<IpAddr>().expect("ip"));

        assert!(should_skip_http2_header(
            &http::header::HOST,
            &HeaderValue::from_static("example.test")
        ));
        assert!(should_skip_http2_header(&http::header::TE, &HeaderValue::from_static("gzip")));
        assert!(!should_skip_http2_header(
            &http::header::TE,
            &HeaderValue::from_static("trailers")
        ));
    }

    #[test]
    fn passive_failure_classifier_stays_narrow() {
        assert!(error_is_upstream_passive_failure(&StreamForwardError::UpstreamReady));
        assert!(error_is_upstream_passive_failure(&StreamForwardError::UpstreamRequest));
        assert!(error_is_upstream_passive_failure(&StreamForwardError::UpstreamResponse));
        assert!(error_is_upstream_passive_failure(&StreamForwardError::IdleTimeout(
            StreamIdlePhase::UpstreamResponse,
        )));
        assert!(!error_is_upstream_passive_failure(&StreamForwardError::UpstreamGracefulDrain));
        assert!(!error_is_upstream_passive_failure(&StreamForwardError::InvalidRequest));
        assert!(!error_is_upstream_passive_failure(&StreamForwardError::RequestBodyLimitExceeded));
    }
}
