#![allow(clippy::expect_used, clippy::type_complexity)]

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h2::{client, server, Reason};
use http::{Request, Response, StatusCode};
use ipnet::IpNet;
use lb_config_model::{
    FaultInjectionAbortConfig, FaultInjectionDelayConfig, FaultInjectionPolicyConfig,
    HeaderMutationConfig, PathRewriteTransformConfig, RequestTransformConfig,
    ResponseTransformConfig, TrafficMirrorPolicyConfig,
};
use lb_net_core::{
    EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName, UpstreamEndpoint,
    UpstreamEndpointId, UpstreamTarget,
};
use lb_runtime::{
    proxy_http2_connection, AffinityFallbackPolicy, AffinityPolicy, AnonymousSourceFilterPolicy,
    CircuitBreakerPolicy, EndpointHealthPolicy, FailureManager, Http2ConnectionReport,
    Http2ProxyConfig, Http2ProxyError, Http2RouteUpstream, LoadBalancingAlgorithm,
    LocalLimitKeyKind, LocalLimitScope, LocalRateLimitConfig, LocalRateLimiter,
    LocalityRoutingPolicy, NoHealthyFallback, ProtocolAnomalyCategory, RetryBudgetPolicy,
    RouteBackendPool, RouteDestinationPolicyRuntime, RouteEnumerationProtectionPolicy,
    SourceAggregation, TimeoutCategory, TimeoutHierarchy, TrustedClientIpPolicy,
    UpstreamSelectionPolicy, WeightedRouteDestination,
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
    config.timeouts.idle_timeout = Duration::from_secs(90);
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let body_len = (16 * 1024) + 1;
    let body = Bytes::from(vec![b'b'; body_len]);
    let response = send_h2_request(&mut client, "/upload", Some(body)).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, format!("received={body_len}"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evicts_idle_http2_upstream_clients_before_reuse() -> Result<(), Box<dyn std::error::Error>>
{
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
async fn applies_request_transforms_before_http2_upstream_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_request_capture_h2_upstream().await?;
    let mut config = proxy_config(upstream_addr).with_request_transforms(
        Some(RequestTransformConfig {
            path_rewrite: None,
            host_rewrite: None,
            header_mutations: vec![HeaderMutationConfig::Set {
                name: String::from("x-listener-env"),
                value: String::from("demo"),
            }],
        }),
        [(String::from("api"), RequestTransformConfig {
            path_rewrite: Some(PathRewriteTransformConfig::ReplacePrefix {
                match_prefix: String::from("/edge"),
                replacement: String::from("/v1"),
            }),
            host_rewrite: Some(String::from("backend.internal")),
            header_mutations: vec![
                HeaderMutationConfig::Set {
                    name: String::from("x-route"),
                    value: String::from("api"),
                },
                HeaderMutationConfig::Remove {
                    name: String::from("x-remove-me"),
                },
            ],
        })],
    );
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/edge")];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let request = Request::builder()
        .method("GET")
        .uri("/edge/orders?expand=true")
        .header("x-remove-me", "true")
        .body(())?;
    let (response, _) = client.send_request(request, true)?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    drop(client);

    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    let expected_authority = format!("backend.internal:{}", upstream_addr.port());
    assert_eq!(capture.path_and_query, "/v1/orders?expand=true");
    assert_eq!(capture.authority.as_deref(), Some(expected_authority.as_str()));
    assert!(capture.headers.iter().any(|(name, value)| name == "x-listener-env" && value == "demo"));
    assert!(capture.headers.iter().any(|(name, value)| name == "x-route" && value == "api"));
    assert!(!capture.headers.iter().any(|(name, _)| name == "x-remove-me"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enforces_destination_local_http2_transform_and_rate_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_request_capture_h2_upstream().await?;
    let pool = route_backend_pool(
        "frontend-primary",
        vec![("primary-a", upstream_addr, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        },
    )?;
    let destination_rate_limiter = Arc::new(LocalRateLimiter::new(LocalRateLimitConfig {
        scope: LocalLimitScope::RouteDestination {
            route: String::from("api"),
            upstream_cluster: String::from("frontend-primary"),
        },
        key_kind: LocalLimitKeyKind::Global,
        requests_per_window: 1,
        window: Duration::from_secs(60),
        max_tracked_keys: 8,
    })?);

    let mut config = proxy_config(upstream_addr)
        .with_route_backend_pools([(String::from("api"), pool)])
        .with_route_destination_policies([(String::from("api"), std::collections::BTreeMap::from([(
            String::from("frontend-primary"),
            RouteDestinationPolicyRuntime {
                request_transform: Some(RequestTransformConfig {
                    path_rewrite: Some(PathRewriteTransformConfig::ReplacePrefix {
                        match_prefix: String::from("/edge"),
                        replacement: String::from("/dest"),
                    }),
                    host_rewrite: Some(String::from("frontend.internal")),
                    header_mutations: vec![HeaderMutationConfig::Set {
                        name: String::from("x-destination"),
                        value: String::from("primary"),
                    }],
                }),
                response_transform: Some(ResponseTransformConfig {
                    header_mutations: vec![HeaderMutationConfig::Set {
                        name: String::from("x-destination-response"),
                        value: String::from("primary"),
                    }],
                }),
                traffic_mirror: None,
                fault_injection: None,
                rate_limiters: vec![destination_rate_limiter],
                concurrency_limiters: Vec::new(),
                failure_manager: None,
                enforce_retry_budget: false,
                enforce_timeout_hierarchy: false,
                enforce_circuit_breaker: false,
            },
        )]))]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/edge")];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let first = send_h2_request(&mut client, "/edge/orders", None).await?;
    let first = first.await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first.headers().get("x-destination-response").and_then(|value| value.to_str().ok()),
        Some("primary")
    );
    let mut first_body = first.into_body();
    while let Some(frame) = first_body.data().await {
        let _ = frame?;
    }

    let second = send_h2_request(&mut client, "/edge/orders", None).await?;
    let second = receive_h2_response(second).await?;
    assert_eq!(second.0, StatusCode::TOO_MANY_REQUESTS);
    drop(client);

    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    let expected_authority = format!("frontend.internal:{}", upstream_addr.port());
    assert_eq!(capture.path_and_query, "/dest/orders");
    assert_eq!(capture.authority.as_deref(), Some(expected_authority.as_str()));
    assert!(capture.headers.iter().any(|(name, value)| name == "x-destination" && value == "primary"));

    drop(report_rx);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mirrors_bodyless_http2_request_without_affecting_primary_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let (primary_upstream_addr, primary_capture_rx) = spawn_request_capture_h2_upstream().await?;
    let (shadow_upstream_addr, shadow_capture_rx) = spawn_request_capture_h2_upstream().await?;
    let primary_pool = route_backend_pool(
        "frontend-primary",
        vec![("primary-a", primary_upstream_addr, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        },
    )?;
    let shadow_pool = route_backend_pool(
        "frontend-shadow",
        vec![("shadow-a", shadow_upstream_addr, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        },
    )?;

    let mut config = proxy_config(primary_upstream_addr)
        .with_route_backend_pools([(String::from("api"), primary_pool)])
        .with_mirror_backend_pools([(String::from("frontend-shadow"), shadow_pool)])
        .with_route_destination_policies([(String::from("api"), std::collections::BTreeMap::from([(
            String::from("frontend-primary"),
            RouteDestinationPolicyRuntime {
                request_transform: None,
                response_transform: None,
                traffic_mirror: Some(TrafficMirrorPolicyConfig {
                    percentage: 100,
                    target_upstream_cluster: String::from("frontend-shadow"),
                }),
                fault_injection: None,
                rate_limiters: Vec::new(),
                concurrency_limiters: Vec::new(),
                failure_manager: None,
                enforce_retry_budget: false,
                enforce_timeout_hierarchy: false,
                enforce_circuit_breaker: false,
            },
        )]))]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/api/orders", None).await?;
    let response = receive_h2_response(response).await?;
    assert_eq!(response.0, StatusCode::OK);
    drop(client);

    let primary_capture = time::timeout(Duration::from_secs(2), primary_capture_rx).await??;
    let shadow_capture = time::timeout(Duration::from_secs(2), shadow_capture_rx).await??;
    assert_eq!(primary_capture.path_and_query, "/api/orders");
    assert_eq!(shadow_capture.path_and_query, "/api/orders");

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.mirror_dispatch_count, 1);
    assert_eq!(report.metrics.mirror_skip_count, 0);
    assert_eq!(report.metrics.mirror_dispatch_failure_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delays_http2_request_before_primary_upstream_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_request_capture_h2_upstream().await?;
    let primary_pool = route_backend_pool(
        "frontend-primary",
        vec![("primary-a", upstream_addr, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        },
    )?;

    let mut config = proxy_config(upstream_addr)
        .with_route_backend_pools([(String::from("api"), primary_pool)])
        .with_route_destination_policies([(String::from("api"), std::collections::BTreeMap::from([(
            String::from("frontend-primary"),
            RouteDestinationPolicyRuntime {
                request_transform: None,
                response_transform: None,
                traffic_mirror: None,
                fault_injection: Some(FaultInjectionPolicyConfig {
                    delay: Some(FaultInjectionDelayConfig {
                        percentage: 100,
                        fixed_delay_ms: 60,
                    }),
                    abort: None,
                }),
                rate_limiters: Vec::new(),
                concurrency_limiters: Vec::new(),
                failure_manager: None,
                enforce_retry_budget: false,
                enforce_timeout_hierarchy: false,
                enforce_circuit_breaker: false,
            },
        )]))]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let started = time::Instant::now();
    let response = send_h2_request(&mut client, "/api/orders", None).await?;
    let response = receive_h2_response(response).await?;
    let elapsed = started.elapsed();
    assert_eq!(response.0, StatusCode::OK);
    assert!(elapsed >= Duration::from_millis(40), "elapsed={elapsed:?}");
    drop(client);

    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    assert_eq!(capture.path_and_query, "/api/orders");

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.fault_injection_delay_count, 1);
    assert_eq!(report.metrics.fault_injection_abort_count, 0);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborts_http2_request_locally_without_contacting_primary_upstream(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_request_capture_h2_upstream().await?;
    let primary_pool = route_backend_pool(
        "frontend-primary",
        vec![("primary-a", upstream_addr, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        },
    )?;

    let mut config = proxy_config(upstream_addr)
        .with_route_backend_pools([(String::from("api"), primary_pool)])
        .with_route_destination_policies([(String::from("api"), std::collections::BTreeMap::from([(
            String::from("frontend-primary"),
            RouteDestinationPolicyRuntime {
                request_transform: None,
                response_transform: None,
                traffic_mirror: None,
                fault_injection: Some(FaultInjectionPolicyConfig {
                    delay: None,
                    abort: Some(FaultInjectionAbortConfig {
                        percentage: 100,
                        http_status: 503,
                    }),
                }),
                rate_limiters: Vec::new(),
                concurrency_limiters: Vec::new(),
                failure_manager: None,
                enforce_retry_budget: false,
                enforce_timeout_hierarchy: false,
                enforce_circuit_breaker: false,
            },
        )]))]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/api/orders", None).await?;
    let response = receive_h2_response(response).await?;
    assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
    drop(client);

    assert!(time::timeout(Duration::from_millis(100), capture_rx).await.is_err());

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.fault_injection_delay_count, 0);
    assert_eq!(report.metrics.fault_injection_abort_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&503), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn applies_response_transforms_before_http2_downstream_write(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_transformable_h2_upstream().await?;
    let mut config = proxy_config(upstream_addr).with_response_transforms(
        Some(ResponseTransformConfig {
            header_mutations: vec![HeaderMutationConfig::Set {
                name: String::from("x-listener-response"),
                value: String::from("demo"),
            }],
        }),
        [(String::from("api"), ResponseTransformConfig {
            header_mutations: vec![
                HeaderMutationConfig::Set {
                    name: String::from("x-route-response"),
                    value: String::from("api"),
                },
                HeaderMutationConfig::Remove {
                    name: String::from("x-remove-me"),
                },
            ],
        })],
    );
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/edge")];
    let (proxy_addr, _report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/edge/orders", None).await?;
    let response = response.await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("x-origin").and_then(|value| value.to_str().ok()), Some("true"));
    assert_eq!(
        response
            .headers()
            .get("x-listener-response")
            .and_then(|value| value.to_str().ok()),
        Some("demo")
    );
    assert_eq!(
        response
            .headers()
            .get("x-route-response")
            .and_then(|value| value.to_str().ok()),
        Some("api")
    );
    assert!(response.headers().get("x-remove-me").is_none());

    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        bytes.extend_from_slice(&chunk);
    }
    assert_eq!(String::from_utf8(bytes)?, "ok");
    drop(client);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destination_retry_budget_blocks_http2_stale_reuse_retry(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_connection_indexed_h2_upstream(true).await?;
    let pool = route_backend_pool(
        "frontend-primary",
        vec![("primary-a", upstream_addr, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        },
    )?;
    let failure_manager = Arc::new(FailureManager::new(
        RetryBudgetPolicy {
            min_retry_tokens: 0,
            retry_percent: 0,
            window: Duration::from_secs(60),
        },
        TimeoutHierarchy {
            request_timeout: Duration::from_secs(2),
            attempt_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_millis(250),
            idle_timeout: Duration::from_secs(2),
        },
        CircuitBreakerPolicy::default(),
    )?);

    let mut config = proxy_config(upstream_addr)
        .with_route_backend_pools([(String::from("api"), pool)])
        .with_route_destination_policies([(String::from("api"), std::collections::BTreeMap::from([(
            String::from("frontend-primary"),
            RouteDestinationPolicyRuntime {
                request_transform: None,
                response_transform: None,
                traffic_mirror: None,
                fault_injection: None,
                rate_limiters: Vec::new(),
                concurrency_limiters: Vec::new(),
                failure_manager: Some(failure_manager.clone()),
                enforce_retry_budget: true,
                enforce_timeout_hierarchy: false,
                enforce_circuit_breaker: false,
            },
        )]))]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/")];

    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;
    let mut client = connect_h2_client(proxy_addr).await?;

    let first_response = send_h2_request(&mut client, "/first", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::OK);
    assert_eq!(first_received.1, "conn-1");

    let second_response = send_h2_request(&mut client, "/second", None).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::BAD_GATEWAY);
    assert_eq!(second_received.1, "");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    assert_eq!(report.metrics.response_status_counts.get(&502), Some(&1));

    let metrics = failure_manager.metrics();
    assert_eq!(metrics.retry_budget_exhausted_count, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destination_timeout_hierarchy_returns_gateway_timeout_for_http2(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_basic_h2_upstream().await?;
    let pool = route_backend_pool(
        "frontend-primary",
        vec![("primary-a", upstream_addr, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        },
    )?;
    let failure_manager = Arc::new(FailureManager::new(
        RetryBudgetPolicy::default(),
        TimeoutHierarchy {
            request_timeout: Duration::from_millis(50),
            attempt_timeout: Duration::from_millis(50),
            connect_timeout: Duration::from_millis(25),
            idle_timeout: Duration::from_millis(50),
        },
        CircuitBreakerPolicy::default(),
    )?);

    let mut config = proxy_config(upstream_addr)
        .with_route_backend_pools([(String::from("api"), pool)])
        .with_route_destination_policies([(String::from("api"), std::collections::BTreeMap::from([(
            String::from("frontend-primary"),
            RouteDestinationPolicyRuntime {
                request_transform: None,
                response_transform: None,
                traffic_mirror: None,
                fault_injection: None,
                rate_limiters: Vec::new(),
                concurrency_limiters: Vec::new(),
                failure_manager: Some(failure_manager.clone()),
                enforce_retry_budget: false,
                enforce_timeout_hierarchy: true,
                enforce_circuit_breaker: false,
            },
        )]))]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/")];

    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;
    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/slow", None).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(received.1, "");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&504), Some(&1));

    let metrics = failure_manager.metrics();
    assert_eq!(metrics.timeout_category_counts.get(&TimeoutCategory::Request), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_http2_client_accepts_rewritten_absolute_uri_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_request_capture_h2_upstream().await?;
    let mut client = connect_h2_client(upstream_addr).await?;
    let rewritten_uri = format!("http://backend.internal:{}/v1/orders?expand=true", upstream_addr.port());
    let request = Request::builder().method("GET").uri(rewritten_uri).body(())?;

    let (response, _) = client.send_request(request, true)?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);

    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    let expected_authority = format!("backend.internal:{}", upstream_addr.port());
    assert_eq!(capture.path_and_query, "/v1/orders?expand=true");
    assert_eq!(capture.authority.as_deref(), Some(expected_authority.as_str()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_http2_client_accepts_path_only_uri_with_rewritten_host_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_request_capture_h2_upstream().await?;
    let mut client = connect_h2_client(upstream_addr).await?;
    let request = Request::builder()
        .method("GET")
        .uri("/v1/orders?expand=true")
        .header("host", "backend.internal")
        .body(())?;

    let (response, _) = client.send_request(request, true)?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);

    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    assert_eq!(capture.path_and_query, "/v1/orders?expand=true");
    assert!(capture.headers.iter().any(|(name, value)| name == "host" && value == "backend.internal"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_http2_client_accepts_capture_upstream_baseline_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_request_capture_h2_upstream().await?;
    let mut client = connect_h2_client(upstream_addr).await?;
    let request = Request::builder().method("GET").uri("/v1/orders?expand=true").body(())?;

    let (response, _) = client.send_request(request, true)?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);

    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    assert_eq!(capture.path_and_query, "/v1/orders?expand=true");
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
async fn http2_routes_can_filter_by_method() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_tagged_h2_upstream("writes-route").await?;
    let mut config = proxy_config(upstream_addr)
        .with_route_upstreams([Http2RouteUpstream {
            route_label: String::from("writes"),
            upstream: UpstreamTarget::new("writes-h2-upstream", upstream_addr),
        }])
        .rejecting_unmatched_routes();
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("writes", "/api")
        .with_methods(vec![String::from("POST")])];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request_with_method(&mut client, "POST", "http://example.com/api", None).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, "writes-route");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_routes_can_filter_by_header_query_content_type_and_source(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_tagged_h2_upstream("target-route").await?;
    let mut config = proxy_config(upstream_addr)
        .with_route_upstreams([Http2RouteUpstream {
            route_label: String::from("target"),
            upstream: UpstreamTarget::new("target-h2-upstream", upstream_addr),
        }])
        .with_trusted_client_ip(TrustedClientIpPolicy {
            enabled: true,
            trusted_proxy_cidrs: vec!["127.0.0.0/8".parse()?],
        })
        .rejecting_unmatched_routes();
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("target", "/api")
        .with_methods(vec![String::from("POST")])
        .with_header_matches(vec![lb_proto_http::RouteHeaderMatch::Exact {
            name: String::from("x-tenant"),
            value: String::from("beta"),
        }])
        .with_query_matches(vec![lb_proto_http::RouteQueryMatch::Exact {
            name: String::from("auth"),
            value: String::from("user"),
        }])
        .with_content_types(vec![String::from("application/json")])
        .with_source_cidrs(vec!["198.51.100.0/24".parse()?])];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request_with_method_and_headers(
        &mut client,
        "POST",
        "http://example.test/api?auth=user",
        None,
        &[
            ("x-tenant", "beta"),
            ("content-type", "application/json; charset=utf-8"),
            ("x-forwarded-for", "198.51.100.7"),
        ],
    )
    .await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, "target-route");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn progressive_ban_blocks_query_shape_enumeration() -> Result<(), Box<dyn std::error::Error>>
{
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
    let first_response =
        send_h2_request(&mut client, "http://example.com/search?q=one", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::OK);
    assert_eq!(first_received.1, "search-route");

    let second_response =
        send_h2_request(&mut client, "http://example.com/search?debug=1&q=two", None).await?;
    let second_received = receive_h2_response(second_response).await?;
    assert_eq!(second_received.0, StatusCode::FORBIDDEN);
    assert_eq!(second_received.1, "");

    let third_response =
        send_h2_request(&mut client, "http://example.com/search?q=three", None).await?;
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
    let config =
        proxy_config(upstream_addr).with_anonymous_source_filter(AnonymousSourceFilterPolicy {
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
        });
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
    let response =
        send_h2_request_with_headers(&mut client, "/", None, &[("forwarded", "for=198.51.100.7")])
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
        vec![("a", failed_upstream, 1, None, None), ("b", healthy_upstream, 1, None, None)],
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
            affinity: None,
        },
    )?;
    let mut config =
        proxy_config(healthy_upstream).with_route_backend_pools([(String::from("api"), pool)]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    let (first_proxy_addr, first_report_rx) =
        spawn_one_shot_http2_proxy_listener(config.clone()).await?;
    let mut first_client = connect_h2_client(first_proxy_addr).await?;
    let first_response = send_h2_request(&mut first_client, "/api", None).await?;
    let first_received = receive_h2_response(first_response).await?;
    assert_eq!(first_received.0, StatusCode::BAD_GATEWAY);
    drop(first_client);
    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.response_status_counts.get(&502), Some(&1));

    let (second_proxy_addr, second_report_rx) =
        spawn_one_shot_http2_proxy_listener(config.clone()).await?;
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
            affinity: None,
        },
    )?;
    let mut config =
        proxy_config(draining_upstream).with_route_backend_pools([(String::from("api"), pool)]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    let (first_proxy_addr, first_report_rx) =
        spawn_one_shot_http2_proxy_listener(config.clone()).await?;
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
            affinity: None,
        },
    )?;
    let mut config =
        proxy_config(draining_upstream).with_route_backend_pools([(String::from("api"), pool)]);
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
            affinity: None,
        },
    )?;
    let mut config =
        proxy_config(west_upstream).with_route_backend_pools([(String::from("api"), pool)]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response =
        send_h2_request_with_headers(&mut client, "/api", None, &[("x-lb-locality", "edge-west")])
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
async fn route_backend_pool_honors_http2_header_affinity() -> Result<(), Box<dyn std::error::Error>>
{
    let first_upstream = spawn_multi_tagged_h2_upstream("sticky-a", 2).await?;
    let second_upstream = spawn_multi_tagged_h2_upstream("sticky-b", 2).await?;
    let pool = route_backend_pool(
        "api",
        vec![("a", first_upstream, 1, None, None), ("b", second_upstream, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: Some(AffinityPolicy::HeaderHash {
                header_name: String::from("x-session-id"),
                fallback: AffinityFallbackPolicy::BalanceHealthy,
            }),
        },
    )?;
    let mut config = proxy_config(first_upstream)
        .with_route_backend_pools([(String::from("api"), pool.clone())]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    let (first_proxy_addr, first_report_rx) =
        spawn_one_shot_http2_proxy_listener(config.clone()).await?;
    let mut first_client = connect_h2_client(first_proxy_addr).await?;
    let first_response = send_h2_request_with_headers(
        &mut first_client,
        "/api",
        None,
        &[("x-session-id", "sticky-user")],
    )
    .await?;
    let first_received = receive_h2_response(first_response).await?;
    drop(first_client);
    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.response_status_counts.get(&200), Some(&1));

    let (second_proxy_addr, second_report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;
    let mut second_client = connect_h2_client(second_proxy_addr).await?;
    let second_response = send_h2_request_with_headers(
        &mut second_client,
        "/api",
        None,
        &[("x-session-id", "sticky-user")],
    )
    .await?;
    let second_received = receive_h2_response(second_response).await?;
    drop(second_client);
    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.response_status_counts.get(&200), Some(&1));

    assert_eq!(first_received, second_received);
    assert!(matches!(first_received.1.as_str(), "sticky-a" | "sticky-b"));
    let metrics = pool.selection_metrics();
    assert_eq!(metrics.affinity_hit_count, 2);
    assert_eq!(metrics.affinity_fallback_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn weighted_route_backend_pool_splits_http2_requests_across_route_destinations(
) -> Result<(), Box<dyn std::error::Error>> {
    let stable_upstream = spawn_multi_tagged_h2_upstream("stable-h2-route", 9).await?;
    let canary_upstream = spawn_multi_tagged_h2_upstream("canary-h2-route", 1).await?;
    let stable_pool = route_backend_pool(
        "stable",
        vec![("stable-a", stable_upstream, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy::default(),
    )?;
    let canary_pool = route_backend_pool(
        "canary",
        vec![("canary-a", canary_upstream, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy::default(),
    )?;
    let weighted_pool = RouteBackendPool::from_weighted_destinations([
        WeightedRouteDestination { weight: 90, pool: stable_pool },
        WeightedRouteDestination { weight: 10, pool: canary_pool },
    ])?;

    let mut config = proxy_config(stable_upstream)
        .with_route_backend_pools([(String::from("api"), weighted_pool)]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    let mut stable_count = 0;
    let mut canary_count = 0;
    for _ in 0..10 {
        let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config.clone()).await?;
        let mut client = connect_h2_client(proxy_addr).await?;
        let response = send_h2_request(&mut client, "/api", None).await?;
        let received = receive_h2_response(response).await?;
        assert_eq!(received.0, StatusCode::OK);
        match received.1.as_str() {
            "stable-h2-route" => stable_count += 1,
            "canary-h2-route" => canary_count += 1,
            other => panic!("unexpected route destination body {other}"),
        }
        drop(client);
        let report = receive_proxy_result(report_rx).await?;
        assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    }

    assert_eq!(stable_count, 9);
    assert_eq!(canary_count, 1);
    let selection_metrics = config
        .route_backend_pools
        .get("api")
        .expect("api weighted pool")
        .selection_metrics();
    assert_eq!(selection_metrics.weighted_route_selection_count, 10);
    assert_eq!(selection_metrics.route_destination_fallback_count, 0);
    assert_eq!(
        selection_metrics.route_destination_selection_counts.get("stable"),
        Some(&9)
    );
    assert_eq!(
        selection_metrics.route_destination_selection_counts.get("canary"),
        Some(&1)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn weighted_route_backend_pool_reports_http2_destination_fallback_metrics(
) -> Result<(), Box<dyn std::error::Error>> {
    let stable_upstream = spawn_tagged_h2_upstream("stable-h2-fallback-route").await?;
    let canary_upstream = reserve_unused_addr().await?;
    let stable_pool = route_backend_pool(
        "stable",
        vec![("stable-a", stable_upstream, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy::default(),
    )?;
    let canary_pool = route_backend_pool(
        "canary",
        vec![("canary-a", canary_upstream, 1, None, None)],
        EndpointHealthPolicy {
            degraded_failure_threshold: 1,
            unhealthy_failure_threshold: 1,
            ejection_failure_threshold: 1,
            recovery_success_threshold: 1,
            ejection_duration: Duration::from_secs(30),
            warmup_duration: Duration::ZERO,
        },
        UpstreamSelectionPolicy::default(),
    )?;
    let canary_endpoint_id = canary_pool.active_probe_targets()?[0].endpoint_id.clone();
    canary_pool.note_active_failure(&canary_endpoint_id)?;
    let weighted_pool = RouteBackendPool::from_weighted_destinations([
        WeightedRouteDestination { weight: 100, pool: canary_pool },
        WeightedRouteDestination { weight: 1, pool: stable_pool },
    ])?;

    let mut config = proxy_config(stable_upstream)
        .with_route_backend_pools([(String::from("api"), weighted_pool)]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;
    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/api", None).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, "stable-h2-fallback-route");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    let selection_metrics = report
        .route_selection_metrics
        .expect("route selection metrics should be present");
    assert_eq!(selection_metrics.weighted_route_selection_count, 1);
    assert_eq!(selection_metrics.route_destination_fallback_count, 1);
    assert_eq!(
        selection_metrics.route_destination_selection_counts.get("stable"),
        Some(&1)
    );
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
            affinity: None,
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
            affinity: None,
        },
    )?;
    let fail_closed_endpoint_id = fail_closed_pool.active_probe_targets()?[0].endpoint_id.clone();
    fail_closed_pool.note_active_failure(&fail_closed_endpoint_id)?;
    fail_closed_pool.note_active_failure(&fail_closed_endpoint_id)?;

    let mut fail_closed_config = proxy_config(upstream_addr)
        .with_route_backend_pools([(String::from("api"), fail_closed_pool)]);
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

    let mut include_unhealthy_config =
        proxy_config(upstream_addr).with_route_backend_pools([(String::from("api"), pool)]);
    include_unhealthy_config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(include_unhealthy_config).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_h2_request(&mut client, "/api", None).await?;
    let received = receive_h2_response(response).await?;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, "fallback-h2-route");
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    let selection_metrics = report
        .route_selection_metrics
        .expect("route selection metrics should be present");
    assert_eq!(selection_metrics.round_robin_selection_count, 1);
    assert_eq!(selection_metrics.unhealthy_fallback_selection_count, 1);
    assert_eq!(selection_metrics.weighted_route_selection_count, 0);
    assert_eq!(selection_metrics.route_destination_fallback_count, 0);
    assert!(selection_metrics.route_destination_selection_counts.is_empty());
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
                            let _ =
                                send.send_data(Bytes::from(format!("conn-{connection_id}")), true);
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

async fn spawn_multi_tagged_h2_upstream(
    body: &'static str,
    max_connections: usize,
) -> io::Result<SocketAddr> {
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

async fn spawn_transformable_h2_upstream() -> io::Result<SocketAddr> {
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
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("x-origin", "true")
                    .header("x-remove-me", "yes")
                    .body(());
                if let Ok(response) = response {
                    if let Ok(mut send) = respond.send_response(response, false) {
                        let _ = send.send_data(Bytes::from_static(b"ok"), true);
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
    send_h2_request_with_method(client, "GET", path, body).await
}

async fn send_h2_request_with_method(
    client: &mut client::SendRequest<Bytes>,
    method: &str,
    path: &str,
    body: Option<Bytes>,
) -> Result<h2::client::ResponseFuture, h2::Error> {
    send_h2_request_with_method_and_headers(client, method, path, body, &[]).await
}

async fn send_h2_request_with_headers(
    client: &mut client::SendRequest<Bytes>,
    path: &str,
    body: Option<Bytes>,
    headers: &[(&str, &str)],
) -> Result<h2::client::ResponseFuture, h2::Error> {
    send_h2_request_with_method_and_headers(client, "GET", path, body, headers).await
}

async fn send_h2_request_with_method_and_headers(
    client: &mut client::SendRequest<Bytes>,
    method: &str,
    path: &str,
    body: Option<Bytes>,
    headers: &[(&str, &str)],
) -> Result<h2::client::ResponseFuture, h2::Error> {
    poll_fn(|cx| client.poll_ready(cx)).await?;
    let mut builder = Request::builder().method(method).uri(path);
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

#[derive(Debug)]
struct Http2RequestCapture {
    path_and_query: String,
    authority: Option<String>,
    headers: Vec<(String, String)>,
}

async fn spawn_request_capture_h2_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Http2RequestCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            let mut connection = match server::handshake(socket).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let mut capture_tx = Some(capture_tx);
            while let Some(result) = connection.accept().await {
                let Ok((request, mut respond)) = result else {
                    break;
                };
                let capture = Http2RequestCapture {
                    path_and_query: request
                        .uri()
                        .path_and_query()
                        .map(|value| value.as_str().to_string())
                        .unwrap_or_else(|| String::from("/")),
                    authority: request.uri().authority().map(|value| value.as_str().to_string()),
                    headers: request
                        .headers()
                        .iter()
                        .filter_map(|(name, value)| {
                            value
                                .to_str()
                                .ok()
                                .map(|value| (name.as_str().to_string(), value.to_string()))
                        })
                        .collect(),
                };
                let response = Response::builder().status(StatusCode::OK).body(()).expect("response");
                if let Ok(mut send_stream) = respond.send_response(response, false) {
                    let _ = send_stream.send_data(Bytes::from_static(b"ok"), true);
                }
                if let Some(capture_tx) = capture_tx.take() {
                    let _ = capture_tx.send(capture);
                }
            }
        }
    });

    Ok((address, capture_rx))
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
