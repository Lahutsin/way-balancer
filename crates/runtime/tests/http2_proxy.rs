use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h2::{client, server, Reason};
use http::{Request, Response, StatusCode};
use ipnet::IpNet;
use lb_net_core::{
    EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName, UpstreamEndpoint,
    UpstreamEndpointId, UpstreamTarget,
};
use lb_runtime::{
    proxy_http2_connection, AnonymousSourceFilterPolicy, EndpointHealthPolicy,
    Http2ConnectionReport, Http2ProxyConfig, Http2ProxyError, Http2RouteUpstream,
    LoadBalancingAlgorithm, LocalityRoutingPolicy, NoHealthyFallback,
    ProtocolAnomalyCategory, RouteBackendPool, RouteEnumerationProtectionPolicy,
    SourceAggregation, TrustedClientIpPolicy, UpstreamSelectionPolicy,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxies_multiplexed_http2_streams() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_basic_h2_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response_one = send_h2_request(&mut client, "/slow", None).await?;
    let response_two = send_h2_request(&mut client, "/fast", None).await?;

    let (body_one, body_two) =
        tokio::try_join!(receive_h2_response(response_one), receive_h2_response(response_two),)?;
    assert_eq!(body_one.0, StatusCode::OK);
    assert_eq!(body_one.1, "slow");
    assert_eq!(body_two.0, StatusCode::OK);
    assert_eq!(body_two.1, "fast");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&2));
    assert!(report.metrics.peak_active_streams >= 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enforces_http2_stream_limit() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_basic_h2_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_concurrent_streams = 1;
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let hold_response = send_h2_request(&mut client, "/slow", None).await?;
    time::sleep(Duration::from_millis(25)).await;
    let refused_response = send_h2_request(&mut client, "/fast", None).await?;
    drop(refused_response);

    let hold = receive_h2_response(hold_response).await?;
    assert_eq!(hold.0, StatusCode::OK);
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.stream_limit_violation_count, 1);
    assert_eq!(report.metrics.stream_reset_count, 1);
    assert_eq!(
        report.metrics.anomaly_counts.get(&ProtocolAnomalyCategory::StreamConcurrencyLimitExceeded),
        Some(&1)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_large_http2_request_body() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_body_counting_h2_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_body_bytes = 256 * 1024;
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let body = Bytes::from(vec![b'b'; 32 * 1024]);
    let response = send_h2_request(&mut client, "/upload", Some(body)).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, "received=32768");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evicts_idle_http2_upstream_clients_before_reuse(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_connection_indexed_h2_upstream(false).await?;
    let mut config = proxy_config(upstream_addr);
    config.timeouts.idle_timeout = Duration::from_millis(40);
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let first_response = send_h2_request(&mut client, "/one", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::OK);
    assert_eq!(first_received.1, "conn-1");

    time::sleep(Duration::from_millis(80)).await;

    let second_response = send_h2_request(&mut client, "/two", None).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::OK);
    assert_eq!(second_received.1, "conn-2");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&2));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_safe_http2_request_once_after_reused_upstream_client_closes(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_connection_indexed_h2_upstream(true).await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let first_response = send_h2_request(&mut client, "/first", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::OK);
    assert_eq!(first_received.1, "conn-1");

    let second_response = send_h2_request(&mut client, "/second", None).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::OK);
    assert_eq!(second_received.1, "conn-2");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&2));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn does_not_retry_unsafe_http2_request_after_reused_upstream_client_graceful_drain(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_connection_indexed_h2_upstream(true).await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let first_response = send_h2_request(&mut client, "/first", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::OK);
    assert_eq!(first_received.1, "conn-1");

    let second_response =
        send_h2_request(&mut client, "/second", Some(Bytes::from_static(b"payload"))).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::BAD_GATEWAY);
    assert_eq!(second_received.1, "");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    assert_eq!(report.metrics.response_status_counts.get(&502), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_http2_reconnects_stay_bounded_on_safe_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_connection_indexed_h2_upstream(true).await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    for request_index in 1..=5 {
        let response = send_h2_request(&mut client, &format!("/req-{request_index}"), None).await?;
        let received = receive_h2_response(response).await?;
        assert_eq!(received.0, StatusCode::OK);
        assert_eq!(received.1, format!("conn-{request_index}"));
    }
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 5);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&5));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotates_http2_upstream_client_after_reuse_age_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_connection_indexed_h2_upstream(false).await?;
    let mut config = proxy_config(upstream_addr);
    config.timeouts.idle_timeout = Duration::from_millis(40);
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let first_response = send_h2_request(&mut client, "/age-1", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::OK);
    assert_eq!(first_received.1, "conn-1");

    time::sleep(Duration::from_millis(20)).await;

    let second_response = send_h2_request(&mut client, "/age-2", None).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::OK);
    assert_eq!(second_received.1, "conn-1");

    time::sleep(Duration::from_millis(30)).await;

    let third_response = send_h2_request(&mut client, "/age-3", None).await?;
    let third_received = receive_h2_response(third_response).await?;
    assert_eq!(third_received.0, StatusCode::OK);
    assert_eq!(third_received.1, "conn-2");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 3);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&3));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_reset_becomes_bad_gateway() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_resetting_h2_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/reset", None).await?;
    let result = receive_h2_response(response).await?;
    assert_eq!(result.0, StatusCode::BAD_GATEWAY);
    assert_eq!(result.1, "");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.stream_error_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&502), Some(&1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_malformed_http2_preface() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_basic_h2_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    tokio::io::AsyncWriteExt::write_all(&mut client, b"GET / HTTP/1.1\r\n\r\n").await?;
    drop(client);

    let result = receive_proxy_result(report_rx).await;
    assert!(matches!(
        result,
        Err(Http2ProxyError::DownstreamHandshake(_))
            | Err(Http2ProxyError::DownstreamConnection(_))
    ));
    if let Err(error) = result {
        assert_eq!(error.anomaly_category(), Some(ProtocolAnomalyCategory::MalformedPreface));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_body_limit_violation_is_categorized() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_body_counting_h2_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_body_bytes = 8;
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response =
        send_h2_request(&mut client, "/upload", Some(Bytes::from_static(b"0123456789"))).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::PAYLOAD_TOO_LARGE);
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.body_limit_violation_count, 1);
    assert_eq!(
        report.metrics.anomaly_counts.get(&ProtocolAnomalyCategory::BodySizeLimitExceeded),
        Some(&1)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routes_http2_requests_by_host_and_path() -> Result<(), Box<dyn std::error::Error>> {
    let api_upstream_addr = spawn_tagged_h2_upstream("api-route").await?;
    let fallback_upstream_addr = spawn_tagged_h2_upstream("fallback-route").await?;
    let mut config = proxy_config(fallback_upstream_addr)
        .with_route_upstreams([
            Http2RouteUpstream {
                route_label: String::from("api"),
                upstream: UpstreamTarget::new("api-h2-upstream", api_upstream_addr),
            },
            Http2RouteUpstream {
                route_label: String::from("fallback"),
                upstream: UpstreamTarget::new("fallback-h2-upstream", fallback_upstream_addr),
            },
        ])
        .rejecting_unmatched_routes();
    config.routes = vec![
        lb_proto_http::RoutePrefixRule::new("api", "/api")
            .with_hostnames(vec![String::from("example.com")]),
        lb_proto_http::RoutePrefixRule::new("fallback", "/"),
    ];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "http://example.com/api?auth=user", None).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, "api-route");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unmatched_http2_host_filtered_routes_return_forbidden(
) -> Result<(), Box<dyn std::error::Error>> {
    let fallback_upstream_addr = spawn_tagged_h2_upstream("fallback-route").await?;
    let mut config = proxy_config(fallback_upstream_addr)
        .with_route_upstreams([Http2RouteUpstream {
            route_label: String::from("api"),
            upstream: UpstreamTarget::new("api-h2-upstream", fallback_upstream_addr),
        }])
        .rejecting_unmatched_routes();
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")
        .with_hostnames(vec![String::from("example.com")])];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "http://other.example/api?auth=user", None).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::FORBIDDEN);
    assert_eq!(received.1, "");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&403), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn progressive_ban_blocks_query_shape_enumeration(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_tagged_h2_upstream("search-route").await?;
    let mut config = proxy_config(upstream_addr)
        .with_route_upstreams([Http2RouteUpstream {
            route_label: String::from("search"),
            upstream: UpstreamTarget::new("search-h2-upstream", upstream_addr),
        }])
        .with_route_enumeration_protection(RouteEnumerationProtectionPolicy {
            source_aggregation: SourceAggregation::ExactIp,
            evaluation_window: Duration::from_secs(60),
            max_unmatched_route_events: 8,
            max_distinct_query_signatures_per_route: 1,
            base_ban_duration: Duration::from_secs(5),
            max_ban_duration: Duration::from_secs(30),
            max_tracked_sources: 32,
        })
        .rejecting_unmatched_routes();
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("search", "/search")
        .with_hostnames(vec![String::from("example.com")])];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let first_response = send_h2_request(&mut client, "http://example.com/search?q=one", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::OK);
    assert_eq!(first_received.1, "search-route");

    let second_response =
        send_h2_request(&mut client, "http://example.com/search?debug=1&q=two", None).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::FORBIDDEN);
    assert_eq!(second_received.1, "");

    let third_response = send_h2_request(&mut client, "http://example.com/search?q=three", None).await?;
    let third_received = receive_h2_response(third_response).await?;
    assert_eq!(third_received.0, StatusCode::FORBIDDEN);
    assert_eq!(third_received.1, "");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 3);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    assert_eq!(report.metrics.response_status_counts.get(&403), Some(&2));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocks_http2_requests_from_configured_anonymous_sources(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_tagged_h2_upstream("blocked").await?;
    let config = proxy_config(upstream_addr).with_anonymous_source_filter(
        AnonymousSourceFilterPolicy {
            enabled: true,
            deny_cidrs: Vec::new(),
            deny_vpn: false,
            deny_proxy: false,
            deny_socks: false,
            deny_tor: true,
            vpn_cidrs: Vec::new(),
            proxy_cidrs: Vec::new(),
            socks_cidrs: Vec::new(),
            tor_exit_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("tor cidr")],
        },
    );
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/", None).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::FORBIDDEN);
    assert_eq!(received.1, "");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&403), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trusted_proxy_headers_affect_http2_source_filtering(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_tagged_h2_upstream("trusted").await?;
    let config = proxy_config(upstream_addr)
        .with_trusted_client_ip(TrustedClientIpPolicy {
            enabled: true,
            trusted_proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("proxy cidr")],
        })
        .with_anonymous_source_filter(AnonymousSourceFilterPolicy {
            enabled: true,
            deny_cidrs: vec!["198.51.100.0/24".parse::<IpNet>().expect("client cidr")],
            deny_vpn: false,
            deny_proxy: false,
            deny_socks: false,
            deny_tor: false,
            vpn_cidrs: Vec::new(),
            proxy_cidrs: Vec::new(),
            socks_cidrs: Vec::new(),
            tor_exit_cidrs: Vec::new(),
        });
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request_with_headers(
        &mut client,
        "/",
        None,
        &[("x-forwarded-for", "198.51.100.7")],
    )
    .await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::FORBIDDEN);
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&403), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untrusted_http2_forwarding_headers_return_bad_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_tagged_h2_upstream("trusted").await?;
    let config = proxy_config(upstream_addr).with_trusted_client_ip(TrustedClientIpPolicy {
        enabled: true,
        trusted_proxy_cidrs: vec!["10.0.0.0/8".parse::<IpNet>().expect("proxy cidr")],
    });
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request_with_headers(
        &mut client,
        "/",
        None,
        &[("forwarded", "for=198.51.100.7")],
    )
    .await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::BAD_REQUEST);
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&400), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_backend_pool_passive_failures_keep_failed_http2_endpoint_out_of_rotation(
) -> Result<(), Box<dyn std::error::Error>> {
    let failed_upstream = reserve_unused_addr().await?;
    let healthy_upstream = spawn_multi_tagged_h2_upstream("healthy-h2-route", 2).await?;
    let pool = route_backend_pool(
        "api",
        vec![
            ("a", failed_upstream, 1, None, None),
            ("b", healthy_upstream, 1, None, None),
        ],
        EndpointHealthPolicy {
            degraded_failure_threshold: 1,
            unhealthy_failure_threshold: 1,
            ejection_failure_threshold: 3,
            recovery_success_threshold: 1,
            ejection_duration: Duration::from_secs(30),
            warmup_duration: Duration::ZERO,
        },
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
        },
    )?;
    let mut config = proxy_config(healthy_upstream).with_route_backend_pools([(
        String::from("api"),
        pool,
    )]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    let (first_proxy_addr, first_report_rx) = spawn_one_shot_http2_proxy_listener(config.clone()).await?;
    let mut first_client = connect_h2_client(first_proxy_addr).await?;
    let first_response = send_h2_request(&mut first_client, "/api", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::BAD_GATEWAY);
    drop(first_client);
    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.response_status_counts.get(&502), Some(&1));

    let (second_proxy_addr, second_report_rx) = spawn_one_shot_http2_proxy_listener(config.clone()).await?;
    let mut second_client = connect_h2_client(second_proxy_addr).await?;
    let second_response = send_h2_request(&mut second_client, "/api", None).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::OK);
    assert_eq!(second_received.1, "healthy-h2-route");
    drop(second_client);
    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.response_status_counts.get(&200), Some(&1));

    let (third_proxy_addr, third_report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;
    let mut third_client = connect_h2_client(third_proxy_addr).await?;
    let third_response = send_h2_request(&mut third_client, "/api", None).await?;
    let third_received = receive_h2_response(third_response).await?;
    assert_eq!(third_received.0, StatusCode::OK);
    assert_eq!(third_received.1, "healthy-h2-route");
    drop(third_client);
    let third_report = receive_proxy_result(third_report_rx).await?;
    assert_eq!(third_report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_http2_drain_does_not_mark_route_backend_unhealthy(
) -> Result<(), Box<dyn std::error::Error>> {
    let draining_upstream = spawn_connection_indexed_h2_upstream(true).await?;
    let pool = route_backend_pool(
        "api",
        vec![("drain", draining_upstream, 1, None, None)],
        EndpointHealthPolicy {
            degraded_failure_threshold: 1,
            unhealthy_failure_threshold: 1,
            ejection_failure_threshold: 1,
            recovery_success_threshold: 1,
            ejection_duration: Duration::from_secs(30),
            warmup_duration: Duration::ZERO,
        },
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
        },
    )?;
    let mut config = proxy_config(draining_upstream).with_route_backend_pools([(
        String::from("api"),
        pool,
    )]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    let (first_proxy_addr, first_report_rx) = spawn_one_shot_http2_proxy_listener(config.clone()).await?;
    let mut first_client = connect_h2_client(first_proxy_addr).await?;
    let first_response = send_h2_request(&mut first_client, "/api", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::OK);
    assert_eq!(first_received.1, "conn-1");

    let second_response =
        send_h2_request(&mut first_client, "/api", Some(Bytes::from_static(b"payload"))).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::BAD_GATEWAY);
    assert_eq!(second_received.1, "");
    drop(first_client);

    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.response_status_counts.get(&200), Some(&1));
    assert_eq!(first_report.metrics.response_status_counts.get(&502), Some(&1));

    let (second_proxy_addr, second_report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;
    let mut second_client = connect_h2_client(second_proxy_addr).await?;
    let recovery_response = send_h2_request(&mut second_client, "/api", None).await?;
    let recovery_received = receive_h2_response(recovery_response).await?;
    assert_eq!(recovery_received.0, StatusCode::OK);
    assert_eq!(recovery_received.1, "conn-2");
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_graceful_http2_drains_do_not_accumulate_route_backend_failures(
) -> Result<(), Box<dyn std::error::Error>> {
    let draining_upstream = spawn_connection_indexed_h2_upstream(true).await?;
    let pool = route_backend_pool(
        "api",
        vec![("drain", draining_upstream, 1, None, None)],
        EndpointHealthPolicy {
            degraded_failure_threshold: 1,
            unhealthy_failure_threshold: 1,
            ejection_failure_threshold: 1,
            recovery_success_threshold: 1,
            ejection_duration: Duration::from_secs(30),
            warmup_duration: Duration::ZERO,
        },
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
        },
    )?;
    let mut config = proxy_config(draining_upstream).with_route_backend_pools([(
        String::from("api"),
        pool,
    )]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    for cycle in 1..=3 {
        let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config.clone()).await?;
        let mut client = connect_h2_client(proxy_addr).await?;

        let ok_response = send_h2_request(&mut client, "/api", None).await?;
        let ok_received = receive_h2_response(ok_response).await?;
        assert_eq!(ok_received.0, StatusCode::OK);
        assert_eq!(ok_received.1, format!("conn-{cycle}"));

        let drained_response =
            send_h2_request(&mut client, "/api", Some(Bytes::from_static(b"payload"))).await?;
        let drained_received = receive_h2_response(drained_response).await?;
        assert_eq!(drained_received.0, StatusCode::BAD_GATEWAY);
        assert_eq!(drained_received.1, "");
        drop(client);

        let report = receive_proxy_result(report_rx).await?;
        assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
        assert_eq!(report.metrics.response_status_counts.get(&502), Some(&1));
    }

    let (recovery_proxy_addr, recovery_report_rx) =
        spawn_one_shot_http2_proxy_listener(config).await?;
    let mut recovery_client = connect_h2_client(recovery_proxy_addr).await?;
    let recovery_response = send_h2_request(&mut recovery_client, "/api", None).await?;
    let recovery_received = receive_h2_response(recovery_response).await?;
    assert_eq!(recovery_received.0, StatusCode::OK);
    assert_eq!(recovery_received.1, "conn-4");
    drop(recovery_client);

    let recovery_report = receive_proxy_result(recovery_report_rx).await?;
    assert_eq!(recovery_report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_backend_pool_honors_http2_locality_hint_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let west_upstream = spawn_tagged_h2_upstream("west-h2-route").await?;
    let east_upstream = spawn_tagged_h2_upstream("east-h2-route").await?;
    let pool = route_backend_pool(
        "api",
        vec![
            ("west", west_upstream, 1, Some("zone-west"), Some("edge-west")),
            ("east", east_upstream, 1, Some("zone-east"), Some("edge-east")),
        ],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::PreferLocalityThenZone,
            no_healthy_fallback: NoHealthyFallback::Fail,
        },
    )?;
    let mut config = proxy_config(west_upstream).with_route_backend_pools([(
        String::from("api"),
        pool,
    )]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request_with_headers(
        &mut client,
        "/api",
        None,
        &[("x-lb-locality", "edge-west")],
    )
    .await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, "west-h2-route");
    drop(client);
    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_backend_pool_include_unhealthy_fallback_keeps_http2_backend_reachable(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_tagged_h2_upstream("fallback-h2-route").await?;
    let pool = route_backend_pool(
        "api",
        vec![("a", upstream_addr, 1, None, None)],
        EndpointHealthPolicy {
            degraded_failure_threshold: 1,
            unhealthy_failure_threshold: 2,
            ejection_failure_threshold: 3,
            recovery_success_threshold: 2,
            ejection_duration: Duration::from_secs(30),
            warmup_duration: Duration::ZERO,
        },
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::IncludeUnhealthy,
        },
    )?;
    let endpoint_id = pool.active_probe_targets()?[0].endpoint_id.clone();
    pool.note_active_failure(&endpoint_id)?;
    pool.note_active_failure(&endpoint_id)?;

    let fail_closed_pool = route_backend_pool(
        "api",
        vec![("a", upstream_addr, 1, None, None)],
        EndpointHealthPolicy {
            degraded_failure_threshold: 1,
            unhealthy_failure_threshold: 2,
            ejection_failure_threshold: 3,
            recovery_success_threshold: 2,
            ejection_duration: Duration::from_secs(30),
            warmup_duration: Duration::ZERO,
        },
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
        },
    )?;
    let fail_closed_endpoint_id = fail_closed_pool.active_probe_targets()?[0].endpoint_id.clone();
    fail_closed_pool.note_active_failure(&fail_closed_endpoint_id)?;
    fail_closed_pool.note_active_failure(&fail_closed_endpoint_id)?;

    let mut fail_closed_config = proxy_config(upstream_addr).with_route_backend_pools([(
        String::from("api"),
        fail_closed_pool,
    )]);
    fail_closed_config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (fail_closed_addr, fail_closed_report_rx) =
        spawn_one_shot_http2_proxy_listener(fail_closed_config).await?;
    let mut fail_closed_client = connect_h2_client(fail_closed_addr).await?;
    let fail_closed_response = send_h2_request(&mut fail_closed_client, "/api", None).await?;
    let fail_closed_received = receive_h2_response(fail_closed_response).await?;
    assert_eq!(fail_closed_received.0, StatusCode::BAD_GATEWAY);
    drop(fail_closed_client);
    let fail_closed_report = receive_proxy_result(fail_closed_report_rx).await?;
    assert_eq!(fail_closed_report.metrics.response_status_counts.get(&502), Some(&1));

    let mut include_unhealthy_config = proxy_config(upstream_addr).with_route_backend_pools([(
        String::from("api"),
        pool,
    )]);
    include_unhealthy_config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(include_unhealthy_config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/api", None).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, "fallback-h2-route");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

async fn spawn_basic_h2_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut connection = match server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let mut tasks = JoinSet::new();

            while let Some(result) = connection.accept().await {
                let Ok((request, mut respond)) = result else {
                    break;
                };
                tasks.spawn(async move {
                    let path = request.uri().path().to_string();
                    if path == "/slow" {
                        time::sleep(Duration::from_millis(150)).await;
                    }
                    let body = if path == "/fast" { "fast" } else { "slow" };
                    let response = Response::builder().status(StatusCode::OK).body(());
                    if let Ok(response) = response {
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from(body.to_string()), true);
                        }
                    }
                });
            }

            while tasks.join_next().await.is_some() {}
        }
    });

    Ok(address)
}

async fn spawn_body_counting_h2_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut connection = match server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };

            while let Some(result) = connection.accept().await {
                let Ok((request, mut respond)) = result else {
                    break;
                };
                let mut body = request.into_body();
                let mut total = 0_usize;
                while let Some(chunk) = body.data().await {
                    let Ok(chunk) = chunk else {
                        return;
                    };
                    if body.flow_control().release_capacity(chunk.len()).is_err() {
                        return;
                    }
                    total += chunk.len();
                }
                let response = Response::builder().status(StatusCode::OK).body(());
                if let Ok(response) = response {
                    if let Ok(mut send) = respond.send_response(response, false) {
                        let payload = Bytes::from(format!("received={total}"));
                        let _ = send.send_data(payload, true);
                    }
                }
            }
        }
    });

    Ok(address)
}

async fn spawn_resetting_h2_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut connection = match server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };

            while let Some(result) = connection.accept().await {
                let Ok((_request, mut respond)) = result else {
                    break;
                };
                respond.send_reset(Reason::CANCEL);
            }
        }
    });

    Ok(address)
}

async fn spawn_tagged_h2_upstream(body: &'static str) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut connection = match server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };

            while let Some(result) = connection.accept().await {
                let Ok((_request, mut respond)) = result else {
                    break;
                };
                let response = Response::builder().status(StatusCode::OK).body(());
                if let Ok(response) = response {
                    if let Ok(mut send) = respond.send_response(response, false) {
                        let _ = send.send_data(Bytes::from(body.to_string()), true);
                    }
                }
            }
        }
    });

    Ok(address)
}

async fn spawn_connection_indexed_h2_upstream(
    close_after_first_request: bool,
) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        let mut next_connection_id = 1_usize;
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let connection_id = next_connection_id;
            next_connection_id += 1;

            tokio::spawn(async move {
                let mut connection = match server::handshake(stream).await {
                    Ok(connection) => connection,
                    Err(_) => return,
                };
                let mut served_requests = 0_usize;

                while let Some(result) = connection.accept().await {
                    let Ok((_request, mut respond)) = result else {
                        break;
                    };
                    served_requests += 1;
                    let response = Response::builder().status(StatusCode::OK).body(());
                    if let Ok(response) = response {
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send
                                .send_data(Bytes::from(format!("conn-{connection_id}")), true);
                        }
                    }

                    if close_after_first_request && served_requests == 1 {
                        connection.graceful_shutdown();
                    }
                }
            });
        }
    });

    Ok(address)
}

async fn spawn_multi_tagged_h2_upstream(body: &'static str, max_connections: usize) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        for _ in 0..max_connections {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let mut connection = match server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => break,
            };

            while let Some(result) = connection.accept().await {
                let Ok((_request, mut respond)) = result else {
                    break;
                };
                let response = Response::builder().status(StatusCode::OK).body(());
                if let Ok(response) = response {
                    if let Ok(mut send) = respond.send_response(response, false) {
                        let _ = send.send_data(Bytes::from(body.to_string()), true);
                    }
                }
            }
        }
    });

    Ok(address)
}

async fn spawn_one_shot_http2_proxy_listener(
    config: Http2ProxyConfig,
) -> io::Result<(SocketAddr, oneshot::Receiver<Result<Http2ConnectionReport, Http2ProxyError>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = match listener.accept().await {
            Ok((downstream, _)) => proxy_http2_connection(downstream, &config).await,
            Err(error) => {
                Err(Http2ProxyError::Connect { target: config.upstream.address, source: error })
            }
        };
        let _ = result_tx.send(result);
    });

    Ok((address, result_rx))
}

async fn connect_h2_client(
    proxy_addr: SocketAddr,
) -> Result<client::SendRequest<Bytes>, Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(proxy_addr).await?;
    let (client, connection) = client::handshake(stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn send_h2_request(
    client: &mut client::SendRequest<Bytes>,
    path: &str,
    body: Option<Bytes>,
) -> Result<h2::client::ResponseFuture, h2::Error> {
    send_h2_request_with_headers(client, path, body, &[]).await
}

async fn send_h2_request_with_headers(
    client: &mut client::SendRequest<Bytes>,
    path: &str,
    body: Option<Bytes>,
    headers: &[(&str, &str)],
) -> Result<h2::client::ResponseFuture, h2::Error> {
    poll_fn(|cx| client.poll_ready(cx)).await?;
    let mut builder = Request::builder().method("GET").uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).map_err(|_| Reason::INTERNAL_ERROR)?;
    let end_stream = body.is_none();
    let (response, mut send_stream) = client.send_request(request, end_stream)?;
    if let Some(body) = body {
        let mut body = body;
        const MAX_FRAME_CHUNK: usize = 16 * 1024;
        while body.remaining() != 0 {
            let next_len = body.remaining().min(MAX_FRAME_CHUNK);
            let capacity = loop {
                send_stream.reserve_capacity(next_len);
                let capacity = poll_fn(|cx| match send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity)),
                    Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
                    Poll::Ready(None) => Poll::Ready(Err(h2::Error::from(Reason::INTERNAL_ERROR))),
                    Poll::Pending => Poll::Pending,
                })
                .await?;
                if capacity != 0 {
                    break capacity;
                }
                tokio::task::yield_now().await;
            };
            let chunk = body.split_to(body.remaining().min(next_len).min(capacity));
            let end = body.remaining() == 0;
            send_stream.send_data(chunk, end)?;
        }
    }
    Ok(response)
}

async fn receive_h2_response(
    response: h2::client::ResponseFuture,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let response = response.await?;
    let status = response.status();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8(bytes)?;
    Ok((status, body))
}

async fn receive_proxy_result(
    result_rx: oneshot::Receiver<Result<Http2ConnectionReport, Http2ProxyError>>,
) -> Result<Http2ConnectionReport, Http2ProxyError> {
    match time::timeout(Duration::from_secs(2), result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            Err(Http2ProxyError::DownstreamConnection(h2::Error::from(Reason::INTERNAL_ERROR)))
        }
        Err(_) => {
            Err(Http2ProxyError::DownstreamConnection(h2::Error::from(Reason::INTERNAL_ERROR)))
        }
    }
}

fn proxy_config(upstream_addr: SocketAddr) -> Http2ProxyConfig {
    Http2ProxyConfig::new(UpstreamTarget::new("http2-upstream", upstream_addr))
}

async fn reserve_unused_addr() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

fn route_backend_pool(
    cluster_name: &str,
    endpoints: Vec<(&str, SocketAddr, u16, Option<&str>, Option<&str>)>,
    health_policy: EndpointHealthPolicy,
    selection_policy: UpstreamSelectionPolicy,
) -> Result<RouteBackendPool, Box<dyn std::error::Error>> {
    let cluster_name = UpstreamClusterName::new(cluster_name)?;
    let endpoints = endpoints
        .into_iter()
        .map(|(id, address, weight, zone, locality)| {
            UpstreamEndpoint::new(
                UpstreamEndpointId::new(id)?,
                address,
                EndpointState::Ready,
                EndpointMetadata {
                    zone: zone.map(str::to_string),
                    locality: locality.map(str::to_string),
                    weight,
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RouteBackendPool::from_cluster(
        UpstreamCluster::new(cluster_name, endpoints)?,
        health_policy,
        selection_policy,
    )?)
}
