#![allow(clippy::expect_used, clippy::type_complexity)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use lb_config_model::{
    AuthorizationCacheBehaviorConfig, CacheKeyPolicyConfig, HeaderMutationConfig,
    FaultInjectionAbortConfig, FaultInjectionDelayConfig, FaultInjectionPolicyConfig,
    HttpCachePolicyConfig, PathRewriteTransformConfig, RequestTransformConfig,
    ResponseTransformConfig, TrafficMirrorPolicyConfig, UpgradeProtocolConfig,
};
use lb_net_core::{
    EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName, UpstreamEndpoint,
    UpstreamEndpointId, UpstreamTarget,
};
use lb_runtime::{
    build_http_cache_key_material, proxy_http1_connection, AffinityFallbackPolicy, AffinityPolicy,
    AnonymousSourceFilterPolicy, CircuitBreakerPolicy, EndpointHealthPolicy, FailureManager,
    Http1ConnectionReport, Http1ProxyConfig, Http1ProxyError, Http1ResponseCacheConfig,
    Http1RouteUpstream, HttpCacheRequest, HttpCacheStore, HttpCacheStoreConfig,
    HttpCacheStoreError, LoadBalancingAlgorithm, LocalLimitKeyKind, LocalLimitScope,
    LocalRateLimitConfig, LocalRateLimiter, LocalityRoutingPolicy, NoHealthyFallback,
    ProtocolAnomalyCategory, RetryBudgetPolicy, RouteBackendPool,
    RouteDestinationPolicyRuntime, RouteEnumerationProtectionPolicy, RuntimeTelemetry,
    SourceAggregation, TimeoutHierarchy, TrustedClientIpPolicy, UpstreamSelectionPolicy,
    WeightedRouteDestination,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time;

#[derive(Debug)]
struct RequestCapture {
    head: String,
    body: Vec<u8>,
}

#[derive(Debug)]
struct UpgradeCapture {
    head: String,
    tunnel_payload: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_keep_alive_requests_and_normalizes_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, captures_rx) = spawn_keep_alive_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /api/one HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n",
        )
        .await?;
    let first_response = read_http_response(&mut client).await?;
    assert!(first_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_response.ends_with("hello"));

    client
        .write_all(b"GET /api/two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut client).await?;
    assert!(second_response.starts_with("HTTP/1.1 201 Created\r\n"));
    assert!(second_response.ends_with("world"));
    drop(client);

    let captures = receive_capture_list(captures_rx).await?;
    assert_eq!(captures.len(), 2);
    assert!(captures[0].head.contains("GET /api/one HTTP/1.1\r\n"));
    assert!(captures[0].head.contains("x-forwarded-for: 127.0.0.1\r\n"));
    assert!(!captures[0].head.contains("connection: keep-alive\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    assert_eq!(report.metrics.response_status_counts.get(&201), Some(&1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_safe_http1_request_once_after_reused_upstream_connection_closes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, captures_rx) = spawn_reused_connection_close_then_retry_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /first HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n")
        .await?;
    let first_response = read_http_response(&mut client).await?;
    assert!(first_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_response.ends_with("first"));

    client
        .write_all(b"GET /second HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut client).await?;
    assert!(second_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second_response.ends_with("second"));
    drop(client);

    let captures = receive_capture_list(captures_rx).await?;
    assert_eq!(captures.len(), 2);
    assert!(captures[0].head.contains("GET /first HTTP/1.1\r\n"));
    assert!(captures[1].head.contains("GET /second HTTP/1.1\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&2));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_http1_reconnects_stay_bounded_on_safe_keep_alive_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, captures_rx) = spawn_connection_indexed_http1_upstream(5).await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    for request_index in 1..=5 {
        let connection_header = if request_index == 5 { "close" } else { "keep-alive" };
        let request = format!(
            "GET /req-{request_index} HTTP/1.1\r\nHost: example.test\r\nConnection: {connection_header}\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await?;
        let response = read_http_response(&mut client).await?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(&format!("conn-{request_index}")));
    }
    drop(client);

    let captures = receive_capture_list(captures_rx).await?;
    assert_eq!(captures.len(), 5);
    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 5);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&5));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotates_http1_upstream_connection_after_reuse_age_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, captures_rx) =
        spawn_keep_alive_connection_indexed_http1_upstream(2).await?;
    let mut config = proxy_config(upstream_addr);
    config.timeouts.idle_timeout = Duration::from_millis(40);
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /age-1 HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n")
        .await?;
    let first_response = read_http_response(&mut client).await?;
    assert!(first_response.ends_with("conn-1"));

    time::sleep(Duration::from_millis(20)).await;

    client
        .write_all(b"GET /age-2 HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut client).await?;
    assert!(second_response.ends_with("conn-1"));

    time::sleep(Duration::from_millis(30)).await;

    client
        .write_all(b"GET /age-3 HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let third_response = read_http_response(&mut client).await?;
    assert!(third_response.ends_with("conn-2"));
    drop(client);

    let captures = receive_capture_list(captures_rx).await?;
    assert_eq!(captures.len(), 3);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 3);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&3));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applies_request_transforms_before_http1_upstream_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_single_capture_upstream().await?;
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
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /edge/orders?expand=true HTTP/1.1\r\nHost: edge.example\r\nX-Remove-Me: true\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

    let capture = receive_capture(capture_rx).await?;
    assert!(capture.head.contains("GET /v1/orders?expand=true HTTP/1.1\r\n"));
    assert!(capture.head.contains("host: backend.internal\r\n"));
    assert!(capture.head.contains("x-listener-env: demo\r\n"));
    assert!(capture.head.contains("x-route: api\r\n"));
    assert!(!capture.head.contains("x-remove-me:"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforces_destination_local_http1_transform_and_rate_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_keep_alive_single_capture_upstream().await?;
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
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /edge/orders HTTP/1.1\r\nHost: edge.example\r\nConnection: keep-alive\r\n\r\n",
        )
        .await?;
    let first_response = read_http_response(&mut client).await?;
    assert!(first_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_response.contains("x-destination-response: primary\r\n"));

    client
        .write_all(
            b"GET /edge/orders HTTP/1.1\r\nHost: edge.example\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let second_response = read_http_response(&mut client).await?;
    assert!(second_response.starts_with("HTTP/1.1 429"));
    drop(client);

    let capture = receive_capture(capture_rx).await?;
    assert!(capture.head.contains("GET /dest/orders HTTP/1.1\r\n"));
    assert!(capture.head.contains("host: frontend.internal\r\n"));
    assert!(capture.head.contains("x-destination: primary\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    assert_eq!(report.metrics.response_status_counts.get(&429), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirrors_bodyless_http1_request_without_affecting_primary_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let (primary_upstream_addr, primary_capture_rx) = spawn_single_capture_upstream().await?;
    let (shadow_upstream_addr, shadow_capture_rx) = spawn_single_capture_upstream().await?;
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

    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;
    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /api/orders HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    drop(client);

    let primary_capture = receive_capture(primary_capture_rx).await?;
    let shadow_capture = receive_capture(shadow_capture_rx).await?;
    assert!(primary_capture.head.contains("GET /api/orders HTTP/1.1\r\n"));
    assert!(shadow_capture.head.contains("GET /api/orders HTTP/1.1\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.mirror_dispatch_count, 1);
    assert_eq!(report.metrics.mirror_skip_count, 0);
    assert_eq!(report.metrics.mirror_dispatch_failure_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delays_http1_request_before_primary_upstream_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_single_capture_upstream().await?;
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

    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;
    let mut client = TcpStream::connect(proxy_addr).await?;
    let started = time::Instant::now();
    client
        .write_all(b"GET /api/orders HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    let elapsed = started.elapsed();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(elapsed >= Duration::from_millis(40), "elapsed={elapsed:?}");
    drop(client);

    let capture = receive_capture(capture_rx).await?;
    assert!(capture.head.contains("GET /api/orders HTTP/1.1\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.fault_injection_delay_count, 1);
    assert_eq!(report.metrics.fault_injection_abort_count, 0);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborts_http1_request_locally_without_contacting_primary_upstream(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_single_capture_upstream().await?;
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

    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;
    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /api/orders HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 503"));
    drop(client);

    assert!(time::timeout(Duration::from_millis(100), capture_rx).await.is_err());

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.fault_injection_delay_count, 0);
    assert_eq!(report.metrics.fault_injection_abort_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&503), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_allowed_websocket_upgrade_and_relays_tunnel_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_websocket_upgrade_upstream().await?;
    let telemetry = Arc::new(RuntimeTelemetry::new()?);
    let mut config = proxy_config(upstream_addr).with_upgrade_policies(
        Vec::<UpgradeProtocolConfig>::new(),
        [(String::from("ws"), vec![UpgradeProtocolConfig::Websocket])],
    );
    config = config.with_upgrade_telemetry("public-http", Arc::clone(&telemetry));
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("ws", "/ws")];
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /ws/chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test-key\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await?;

    let response_head = read_http_head(&mut client).await?;
    assert!(response_head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response_head.to_ascii_lowercase().contains("connection: upgrade\r\n"));
    assert!(response_head.to_ascii_lowercase().contains("upgrade: websocket\r\n"));

    client.write_all(b"ping").await?;
    let mut tunnel_reply = [0_u8; 4];
    client.read_exact(&mut tunnel_reply).await?;
    assert_eq!(&tunnel_reply, b"pong");
    drop(client);

    let capture = receive_upgrade_capture(capture_rx).await?;
    assert!(capture.head.contains("GET /ws/chat HTTP/1.1\r\n"));
    assert!(capture.head.to_ascii_lowercase().contains("connection: upgrade\r\n"));
    assert!(capture.head.to_ascii_lowercase().contains("upgrade: websocket\r\n"));
    assert_eq!(capture.tunnel_payload, b"ping");

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&101), Some(&1));
    let metrics = telemetry.export_metrics();
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"accepted\",reason=\"websocket\"} 1"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_websocket_upgrade_when_route_policy_does_not_allow_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = reserve_unused_addr().await?;
    let telemetry = Arc::new(RuntimeTelemetry::new()?);
    let mut config = proxy_config(upstream_addr).with_upgrade_telemetry(
        "public-http",
        Arc::clone(&telemetry),
    );
    config.timeouts.connect_timeout = Duration::from_millis(50);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("ws", "/ws")];
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /ws/chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test-key\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await?;

    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("upgrade not allowed for the selected route\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&400), Some(&1));
    let metrics = telemetry.export_metrics();
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"rejected\",reason=\"policy_denied\"} 1"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_malformed_websocket_upgrade_without_upgrade_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = reserve_unused_addr().await?;
    let mut config = proxy_config(upstream_addr).with_upgrade_policies(
        vec![UpgradeProtocolConfig::Websocket],
        Vec::<(String, Vec<UpgradeProtocolConfig>)>::new(),
    );
    config.timeouts.connect_timeout = Duration::from_millis(50);
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /ws/chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nSec-WebSocket-Key: test-key\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await?;

    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("malformed upgrade request: missing Upgrade header\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&400), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_unsupported_http1_upgrade_protocol(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = reserve_unused_addr().await?;
    let mut config = proxy_config(upstream_addr).with_upgrade_policies(
        vec![UpgradeProtocolConfig::Websocket],
        Vec::<(String, Vec<UpgradeProtocolConfig>)>::new(),
    );
    config.timeouts.connect_timeout = Duration::from_millis(50);
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /ws/chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
        )
        .await?;

    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("unsupported upgrade protocol\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&400), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_websocket_upgrade_when_request_includes_body(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = reserve_unused_addr().await?;
    let telemetry = Arc::new(RuntimeTelemetry::new()?);
    let mut config = proxy_config(upstream_addr)
        .with_upgrade_policies(
            vec![UpgradeProtocolConfig::Websocket],
            Vec::<(String, Vec<UpgradeProtocolConfig>)>::new(),
        )
        .with_upgrade_telemetry("public-http", Arc::clone(&telemetry));
    config.timeouts.connect_timeout = Duration::from_millis(50);
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /ws/chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 4\r\n\r\nping",
        )
        .await?;

    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("websocket upgrade requests must not include a body\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&400), Some(&1));
    let metrics = telemetry.export_metrics();
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"rejected\",reason=\"body_not_allowed\"} 1"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_upstream_upgrade_refusal_and_records_failed_upgrade(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_upgrade_refusal_upstream().await?;
    let telemetry = Arc::new(RuntimeTelemetry::new()?);
    let mut config = proxy_config(upstream_addr)
        .with_upgrade_policies(
            Vec::<UpgradeProtocolConfig>::new(),
            [(String::from("ws"), vec![UpgradeProtocolConfig::Websocket])],
        )
        .with_upgrade_telemetry("public-http", Arc::clone(&telemetry));
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("ws", "/ws")];
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /ws/chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test-key\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await?;

    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("nope"));
    drop(client);

    let capture = receive_capture(capture_rx).await?;
    assert!(capture.head.contains("GET /ws/chat HTTP/1.1\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    let metrics = telemetry.export_metrics();
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"failed\",reason=\"upstream_refused\"} 1"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destination_circuit_breaker_rejects_http1_request_after_connect_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = reserve_unused_addr().await?;
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
            request_timeout: Duration::from_secs(2),
            attempt_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_millis(100),
            idle_timeout: Duration::from_secs(2),
        },
        CircuitBreakerPolicy {
            open_failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            half_open_success_threshold: 1,
        },
    )?);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    failure_manager.record_failure(now, lb_runtime::UpstreamFailureClass::Connect);

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
                enforce_timeout_hierarchy: false,
                enforce_circuit_breaker: true,
            },
        )]))]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/")];

    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /blocked HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 503"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&503), Some(&1));

    let metrics = failure_manager.metrics();
    assert_eq!(metrics.breaker_open_rejection_count, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_malformed_101_upgrade_response_and_records_failed_upgrade(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_malformed_websocket_upgrade_upstream().await?;
    let telemetry = Arc::new(RuntimeTelemetry::new()?);
    let mut config = proxy_config(upstream_addr)
        .with_upgrade_policies(
            Vec::<UpgradeProtocolConfig>::new(),
            [(String::from("ws"), vec![UpgradeProtocolConfig::Websocket])],
        )
        .with_upgrade_telemetry("public-http", Arc::clone(&telemetry));
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("ws", "/ws")];
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /ws/chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test-key\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await?;

    match receive_proxy_result(report_rx).await {
        Err(Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::Invalid(message))) => {
            assert_eq!(message, "invalid upgrade response headers");
        }
        other => panic!("unexpected proxy result: {other:?}"),
    }
    let metrics = telemetry.export_metrics();
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"failed\",reason=\"malformed_101\"} 1"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn times_out_idle_upgraded_tunnel_and_records_failed_upgrade(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_websocket_upgrade_upstream().await?;
    let telemetry = Arc::new(RuntimeTelemetry::new()?);
    let mut config = proxy_config(upstream_addr)
        .with_upgrade_policies(
            Vec::<UpgradeProtocolConfig>::new(),
            [(String::from("ws"), vec![UpgradeProtocolConfig::Websocket])],
        )
        .with_upgrade_telemetry("public-http", Arc::clone(&telemetry));
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("ws", "/ws")];
    config.timeouts.idle_timeout = Duration::from_millis(100);
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /ws/chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test-key\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await?;

    let response_head = read_http_head(&mut client).await?;
    assert!(response_head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));

    match receive_proxy_result(report_rx).await {
        Err(Http1ProxyError::IdleTimeout("upgrade tunnel")) => {}
        other => panic!("unexpected proxy result: {other:?}"),
    }
    let metrics = telemetry.export_metrics();
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"accepted\",reason=\"websocket\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"failed\",reason=\"tunnel_idle_timeout\"} 1"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applies_response_transforms_to_live_and_cached_http1_responses(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (upstream_addr, capture_rx) = spawn_transformable_cacheable_upstream().await?;
    let mut first_config = proxy_config(upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)))
        .with_response_transforms(
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
    first_config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/cacheable")];
    let (first_proxy_addr, first_report_rx) =
        spawn_one_shot_http1_proxy_listener(first_config).await?;

    let mut first_client = TcpStream::connect(first_proxy_addr).await?;
    first_client
        .write_all(b"GET /cacheable HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let first_response = read_http_response(&mut first_client).await?;
    assert!(first_response.ends_with("cached"));
    assert!(first_response.contains("x-origin: true\r\n"));
    assert!(first_response.contains("x-listener-response: demo\r\n"));
    assert!(first_response.contains("x-route-response: api\r\n"));
    assert!(!first_response.contains("x-remove-me:"));
    drop(first_client);

    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.cache_miss_count, 1);
    assert_eq!(first_report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);

    let unused_upstream = reserve_unused_addr().await?;
    let mut second_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)))
        .with_response_transforms(
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
    second_config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/cacheable")];
    let (second_proxy_addr, second_report_rx) =
        spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /cacheable HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("cached"));
    assert!(second_response.contains("x-origin: true\r\n"));
    assert!(second_response.contains("x-listener-response: demo\r\n"));
    assert!(second_response.contains("x-route-response: api\r\n"));
    assert!(!second_response.contains("x-remove-me:"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_hit_count, 1);
    assert_eq!(second_report.metrics.cache_miss_count, 0);
    Ok(())
}

async fn spawn_not_modified_revalidation_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\nCache-Control: max-age=5\r\n\r\n",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_short_ttl_not_modified_revalidation_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\nCache-Control: max-age=1\r\n\r\n",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_single_capture_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<RequestCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok",
                    )
                    .await;
                let _ = capture_tx.send(capture);
            }
        }
    });

    Ok((address, capture_rx))
}

async fn spawn_keep_alive_single_capture_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<RequestCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok",
                    )
                    .await;
                let _ = capture_tx.send(capture);
                let mut buffer = [0_u8; 128];
                let _ = stream.read(&mut buffer).await;
            }
        }
    });

    Ok((address, capture_rx))
}

async fn spawn_revalidation_replacement_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\nCache-Control: max-age=5\r\nETag: \"v2\"\r\n\r\nrenewed",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streams_large_request_body() -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_body_echo_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_body_bytes = 256 * 1024;
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let body = vec![b'a'; 64 * 1024];
    let mut request = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(&request).await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.contains("received=65536"));
    drop(client);

    let capture = receive_capture(capture_rx).await?;
    assert_eq!(capture.body.len(), body.len());

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_malformed_http_requests() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(b"GET / HTTP/1.1\r\nHost example.test\r\nConnection: close\r\n\r\n").await?;
    drop(client);

    let result = receive_proxy_result(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::ParseRequest(_))));
    if let Err(error) = result {
        assert_eq!(error.anomaly_category(), Some(ProtocolAnomalyCategory::MalformedMessage));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_unsupported_transfer_encoding_smuggling_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n",
        )
        .await?;
    drop(client);

    let result = receive_proxy_result(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::ParseRequest(_))));
    if let Err(error) = result {
        assert_eq!(error.anomaly_category(), Some(ProtocolAnomalyCategory::MalformedMessage));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_requests_by_host_and_preserves_query_string(
) -> Result<(), Box<dyn std::error::Error>> {
    let (api_upstream_addr, api_capture_rx) = spawn_tagged_upstream("api-route").await?;
    let (fallback_upstream_addr, _fallback_capture_rx) =
        spawn_tagged_upstream("fallback-route").await?;
    let mut config = proxy_config(fallback_upstream_addr)
        .with_route_upstreams([
            Http1RouteUpstream {
                route_label: String::from("api"),
                upstream: UpstreamTarget::new("api-upstream", api_upstream_addr),
            },
            Http1RouteUpstream {
                route_label: String::from("fallback"),
                upstream: UpstreamTarget::new("fallback-upstream", fallback_upstream_addr),
            },
        ])
        .rejecting_unmatched_routes();
    config.routes = vec![
        lb_proto_http::RoutePrefixRule::new("api", "/api")
            .with_hostnames(vec![String::from("example.com")]),
        lb_proto_http::RoutePrefixRule::new("fallback", "/"),
    ];
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /api?auth=user HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("api-route"));
    drop(client);

    let capture = receive_capture(api_capture_rx).await?;
    assert!(capture.head.contains("GET /api?auth=user HTTP/1.1\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unmatched_host_filtered_routes_return_local_forbidden(
) -> Result<(), Box<dyn std::error::Error>> {
    let unused_upstream = reserve_unused_addr().await?;
    let mut config = proxy_config(unused_upstream)
        .with_route_upstreams([Http1RouteUpstream {
            route_label: String::from("api"),
            upstream: UpstreamTarget::new("api-upstream", unused_upstream),
        }])
        .rejecting_unmatched_routes();
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")
        .with_hostnames(vec![String::from("example.com")])];
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /api?auth=user HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("route not allowed\n"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&403), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_routes_can_filter_by_method() -> Result<(), Box<dyn std::error::Error>> {
    let (api_upstream_addr, api_capture_rx) = spawn_tagged_upstream("api-route").await?;
    let mut config = proxy_config(api_upstream_addr)
        .with_route_upstreams([Http1RouteUpstream {
            route_label: String::from("writes"),
            upstream: UpstreamTarget::new("writes-upstream", api_upstream_addr),
        }])
        .rejecting_unmatched_routes();
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("writes", "/api")
        .with_methods(vec![String::from("POST")])];
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"POST /api HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("api-route"));
    drop(client);

    let capture = receive_capture(api_capture_rx).await?;
    assert!(capture.head.contains("POST /api HTTP/1.1\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_routes_can_filter_by_header_query_content_type_and_source(
) -> Result<(), Box<dyn std::error::Error>> {
    let (api_upstream_addr, api_capture_rx) = spawn_tagged_upstream("api-route").await?;
    let mut config = proxy_config(api_upstream_addr)
        .with_route_upstreams([Http1RouteUpstream {
            route_label: String::from("target"),
            upstream: UpstreamTarget::new("target-upstream", api_upstream_addr),
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
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(b"POST /api?auth=user HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json; charset=utf-8\r\nX-Tenant: beta\r\nX-Forwarded-For: 198.51.100.7\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("api-route"));
    drop(client);

    let capture = receive_capture(api_capture_rx).await?;
    assert!(capture.head.contains("POST /api?auth=user HTTP/1.1\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn progressive_ban_blocks_repeated_route_enumeration(
) -> Result<(), Box<dyn std::error::Error>> {
    let (api_upstream_addr, _api_capture_rx) = spawn_tagged_upstream("api-route").await?;
    let mut config = proxy_config(api_upstream_addr)
        .with_route_upstreams([Http1RouteUpstream {
            route_label: String::from("api"),
            upstream: UpstreamTarget::new("api-upstream", api_upstream_addr),
        }])
        .with_route_enumeration_protection(RouteEnumerationProtectionPolicy {
            source_aggregation: SourceAggregation::ExactIp,
            evaluation_window: Duration::from_secs(60),
            max_unmatched_route_events: 1,
            max_distinct_query_signatures_per_route: 8,
            base_ban_duration: Duration::from_secs(5),
            max_ban_duration: Duration::from_secs(30),
            max_tracked_sources: 32,
        })
        .rejecting_unmatched_routes();
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")
        .with_hostnames(vec![String::from("example.com")])];

    let (first_proxy_addr, first_report_rx) =
        spawn_one_shot_http1_proxy_listener(config.clone()).await?;
    let mut first_client = TcpStream::connect(first_proxy_addr).await?;
    first_client
        .write_all(b"GET /missing HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n")
        .await?;
    let first_response = read_http_response(&mut first_client).await?;
    assert!(first_response.ends_with("route not allowed\n"));
    drop(first_client);
    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.response_status_counts.get(&403), Some(&1));

    let (second_proxy_addr, second_report_rx) =
        spawn_one_shot_http1_proxy_listener(config.clone()).await?;
    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(
            b"GET /still-missing HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("source temporarily blocked\n"));
    drop(second_client);
    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.response_status_counts.get(&403), Some(&1));

    let (third_proxy_addr, third_report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;
    let mut third_client = TcpStream::connect(third_proxy_addr).await?;
    third_client
        .write_all(b"GET /api HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;
    let third_response = read_http_response(&mut third_client).await?;
    assert!(third_response.ends_with("source temporarily blocked\n"));
    drop(third_client);

    let third_report = receive_proxy_result(third_report_rx).await?;
    assert_eq!(third_report.metrics.response_status_counts.get(&403), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_backend_pool_passive_failures_keep_failed_http1_endpoint_out_of_rotation(
) -> Result<(), Box<dyn std::error::Error>> {
    let failed_upstream = reserve_unused_addr().await?;
    let (healthy_upstream, healthy_capture_rx) =
        spawn_multi_tagged_upstream("healthy-route", 2).await?;
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
        spawn_one_shot_http1_proxy_listener(config.clone()).await?;
    let mut first_client = TcpStream::connect(first_proxy_addr).await?;
    first_client
        .write_all(b"GET /api HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    drop(first_client);
    let first_result = receive_proxy_result(first_report_rx).await;
    assert!(first_result.is_err());

    let (second_proxy_addr, second_report_rx) =
        spawn_one_shot_http1_proxy_listener(config.clone()).await?;
    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /api HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("healthy-route"));
    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.response_status_counts.get(&200), Some(&1));

    let (third_proxy_addr, third_report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;
    let mut third_client = TcpStream::connect(third_proxy_addr).await?;
    third_client
        .write_all(b"GET /api HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let third_response = read_http_response(&mut third_client).await?;
    assert!(third_response.ends_with("healthy-route"));
    let third_report = receive_proxy_result(third_report_rx).await?;
    assert_eq!(third_report.metrics.response_status_counts.get(&200), Some(&1));

    let captures = receive_capture_list(healthy_capture_rx).await?;
    assert_eq!(captures.len(), 2);
    assert!(captures.iter().all(|capture| capture.head.contains("GET /api HTTP/1.1\r\n")));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_backend_pool_honors_http1_locality_hint_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let (west_upstream, west_capture_rx) = spawn_tagged_upstream("west-route").await?;
    let (east_upstream, _east_capture_rx) = spawn_tagged_upstream("east-route").await?;
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
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /api HTTP/1.1\r\nHost: example.test\r\nX-Lb-Locality: edge-west\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("west-route"));
    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));

    let capture = receive_capture(west_capture_rx).await?;
    assert!(capture.head.contains("GET /api HTTP/1.1\r\n"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_backend_pool_honors_http1_cookie_affinity() -> Result<(), Box<dyn std::error::Error>>
{
    let (first_upstream, _first_capture_rx) = spawn_multi_tagged_upstream("sticky-a", 2).await?;
    let (second_upstream, _second_capture_rx) = spawn_multi_tagged_upstream("sticky-b", 2).await?;
    let pool = route_backend_pool(
        "api",
        vec![("a", first_upstream, 1, None, None), ("b", second_upstream, 1, None, None)],
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: Some(AffinityPolicy::CookieHash {
                cookie_name: String::from("session_id"),
                fallback: AffinityFallbackPolicy::BalanceHealthy,
            }),
        },
    )?;
    let mut config = proxy_config(first_upstream)
        .with_route_backend_pools([(String::from("api"), pool.clone())]);
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];

    let (first_proxy_addr, first_report_rx) =
        spawn_one_shot_http1_proxy_listener(config.clone()).await?;
    let mut first_client = TcpStream::connect(first_proxy_addr).await?;
    first_client
        .write_all(
            b"GET /api HTTP/1.1\r\nHost: example.test\r\nCookie: session_id=sticky-user\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let first_response = read_http_response(&mut first_client).await?;
    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.response_status_counts.get(&200), Some(&1));

    let (second_proxy_addr, second_report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;
    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(
            b"GET /api HTTP/1.1\r\nHost: example.test\r\nCookie: session_id=sticky-user\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.response_status_counts.get(&200), Some(&1));

    assert_eq!(first_response, second_response);
    assert!(first_response.ends_with("sticky-a") || first_response.ends_with("sticky-b"));
    let metrics = pool.selection_metrics();
    assert_eq!(metrics.affinity_hit_count, 2);
    assert_eq!(metrics.affinity_fallback_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn weighted_route_backend_pool_splits_http1_requests_across_route_destinations(
) -> Result<(), Box<dyn std::error::Error>> {
    let (stable_upstream, stable_capture_rx) = spawn_multi_tagged_upstream("stable-route", 9).await?;
    let (canary_upstream, canary_capture_rx) = spawn_multi_tagged_upstream("canary-route", 1).await?;
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

    for _ in 0..10 {
        let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config.clone()).await?;
        let mut client = TcpStream::connect(proxy_addr).await?;
        client
            .write_all(b"GET /api HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await?;
        let response = read_http_response(&mut client).await?;
        assert!(response.ends_with("stable-route") || response.ends_with("canary-route"));
        let report = receive_proxy_result(report_rx).await?;
        assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    }

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

    let stable_captures = receive_capture_list(stable_capture_rx).await?;
    let canary_captures = receive_capture_list(canary_capture_rx).await?;
    assert_eq!(stable_captures.len(), 9);
    assert_eq!(canary_captures.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn weighted_route_backend_pool_reports_http1_destination_fallback_metrics(
) -> Result<(), Box<dyn std::error::Error>> {
    let (stable_upstream, stable_capture_rx) =
        spawn_tagged_upstream("stable-fallback-route").await?;
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

    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;
    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /api HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("stable-fallback-route"));

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
    let capture = receive_capture(stable_capture_rx).await?;
    assert!(capture.head.contains("GET /api HTTP/1.1\r\n"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_backend_pool_include_unhealthy_fallback_keeps_http1_backend_reachable(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_tagged_upstream("fallback-route").await?;
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

    let mut fail_closed_config = proxy_config(upstream_addr).with_route_backend_pools([(
        String::from("api"),
        RouteBackendPool::from_cluster(
            UpstreamCluster::new(
                UpstreamClusterName::new("api")?,
                vec![UpstreamEndpoint::new(
                    UpstreamEndpointId::new("a")?,
                    upstream_addr,
                    EndpointState::Ready,
                    EndpointMetadata { zone: None, locality: None, weight: 1 },
                )?],
            )?,
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
        )?,
    )]);
    fail_closed_config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let fail_closed_pool = fail_closed_config
        .route_backend_pools
        .get("api")
        .ok_or("missing fail-closed pool")?
        .clone();
    let fail_closed_endpoint_id = fail_closed_pool.active_probe_targets()?[0].endpoint_id.clone();
    fail_closed_pool.note_active_failure(&fail_closed_endpoint_id)?;
    fail_closed_pool.note_active_failure(&fail_closed_endpoint_id)?;

    let (fail_closed_addr, fail_closed_report_rx) =
        spawn_one_shot_http1_proxy_listener(fail_closed_config).await?;
    let mut fail_closed_client = TcpStream::connect(fail_closed_addr).await?;
    fail_closed_client
        .write_all(b"GET /api HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let fail_closed_response = read_http_response(&mut fail_closed_client).await?;
    assert!(fail_closed_response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    let fail_closed_report = receive_proxy_result(fail_closed_report_rx).await?;
    assert_eq!(fail_closed_report.metrics.response_status_counts.get(&502), Some(&1));

    let mut include_unhealthy_config =
        proxy_config(upstream_addr).with_route_backend_pools([(String::from("api"), pool)]);
    include_unhealthy_config.routes = vec![lb_proto_http::RoutePrefixRule::new("api", "/api")];
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(include_unhealthy_config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /api HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("fallback-route"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    let capture = receive_capture(capture_rx).await?;
    assert!(capture.head.contains("GET /api HTTP/1.1\r\n"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocks_configured_anonymous_source_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = reserve_unused_addr().await?;
    let config =
        proxy_config(upstream_addr).with_anonymous_source_filter(AnonymousSourceFilterPolicy {
            enabled: true,
            deny_cidrs: Vec::new(),
            deny_vpn: false,
            deny_proxy: true,
            deny_socks: false,
            deny_tor: false,
            vpn_cidrs: Vec::new(),
            proxy_cidrs: vec!["127.0.0.0/8".parse::<IpNet>().expect("proxy cidr")],
            socks_cidrs: Vec::new(),
            tor_exit_cidrs: Vec::new(),
        });
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("anonymous source blocked\n"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&403), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_proxy_uses_forwarded_client_ip_for_filters(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = reserve_unused_addr().await?;
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
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 198.51.100.7\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("anonymous source blocked\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&403), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_peer_forwarding_headers_return_bad_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = reserve_unused_addr().await?;
    let config = proxy_config(upstream_addr).with_trusted_client_ip(TrustedClientIpPolicy {
        enabled: true,
        trusted_proxy_cidrs: vec!["10.0.0.0/8".parse::<IpNet>().expect("proxy cidr")],
    });
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example.test\r\nForwarded: for=198.51.100.7\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid forwarding headers\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.response_status_counts.get(&400), Some(&1));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforces_header_count_limit() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_header_count = 2;
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: test\r\nX-Test: 1\r\nConnection: close\r\n\r\n",
        )
        .await?;
    drop(client);

    let result = receive_proxy_result(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::ParseRequest(_))));
    if let Err(error) = result {
        assert_eq!(
            error.anomaly_category(),
            Some(ProtocolAnomalyCategory::HeaderCountLimitExceeded)
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforces_body_size_limit() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_body_bytes = 16;
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 32\r\nConnection: close\r\n\r\n12345678901234567890123456789012",
        )
        .await?;
    drop(client);

    let result = receive_proxy_result(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::BodyLimitExceeded("request body"))));
    if let Err(error) = result {
        assert_eq!(error.anomaly_category(), Some(ProtocolAnomalyCategory::BodySizeLimitExceeded));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_cache_hits_avoid_upstream_requests() -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (upstream_addr, capture_rx) = spawn_single_cacheable_upstream().await?;
    let first_config = proxy_config(upstream_addr).with_response_cache(
        Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)),
    );
    let (first_proxy_addr, first_report_rx) =
        spawn_one_shot_http1_proxy_listener(first_config).await?;

    let mut first_client = TcpStream::connect(first_proxy_addr).await?;
    first_client
        .write_all(b"GET /cacheable HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let first_response = read_http_response(&mut first_client).await?;
    assert!(first_response.ends_with("cached"));
    drop(first_client);

    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.cache_miss_count, 1);
    assert_eq!(first_report.metrics.cache_fill_count, 1);

    let captures = receive_capture_list(capture_rx).await?;
    assert_eq!(captures.len(), 1);

    let unused_upstream = reserve_unused_addr().await?;
    let second_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (second_proxy_addr, second_report_rx) =
        spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /cacheable HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("cached"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_hit_count, 1);
    assert_eq!(second_report.metrics.cache_miss_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_cacheable_responses_bypass_storage_without_breaking_proxying(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (upstream_addr, capture_rx) = spawn_no_store_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /private HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(
        response.contains("Cache-Control: no-store")
            || response.contains("cache-control: no-store")
    );
    assert!(response.ends_with("private"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_miss_count, 1);
    assert_eq!(report.metrics.cache_fill_count, 0);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookie_bearing_requests_bypass_shared_cache_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (first_upstream_addr, first_capture_rx) = spawn_single_cacheable_upstream().await?;
    let first_config = proxy_config(first_upstream_addr).with_response_cache(
        Http1ResponseCacheConfig::new(HttpCachePolicyConfig::default(), Arc::clone(&shared_store)),
    );
    let (first_proxy_addr, first_report_rx) =
        spawn_one_shot_http1_proxy_listener(first_config).await?;

    let mut first_client = TcpStream::connect(first_proxy_addr).await?;
    first_client
        .write_all(b"GET /cookie-session HTTP/1.1\r\nHost: example.test\r\nCookie: session=alpha\r\nConnection: close\r\n\r\n")
        .await?;
    let first_response = read_http_response(&mut first_client).await?;
    assert!(first_response.ends_with("cached"));
    drop(first_client);

    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.cache_bypass_count, 1);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(first_capture_rx).await?.len(), 1);

    let (second_upstream_addr, second_capture_rx) = spawn_single_cacheable_upstream().await?;
    let second_config = proxy_config(second_upstream_addr).with_response_cache(
        Http1ResponseCacheConfig::new(HttpCachePolicyConfig::default(), Arc::clone(&shared_store)),
    );
    let (second_proxy_addr, second_report_rx) =
        spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /cookie-session HTTP/1.1\r\nHost: example.test\r\nCookie: session=beta\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("cached"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_bypass_count, 1);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(second_capture_rx).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsafe_vary_headers_fail_closed_without_storage() -> Result<(), Box<dyn std::error::Error>>
{
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (upstream_addr, capture_rx) = spawn_vary_cookie_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /vary-cookie HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("unsafe"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 0);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_cache_control_responses_fail_closed_without_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (upstream_addr, capture_rx) = spawn_private_cache_control_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /private-cache-control HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("private"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 0);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_while_revalidate_window_can_serve_stale_entries(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 2,
        stale_if_error_secs: 0,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };
    let (upstream_addr, capture_rx) = spawn_swr_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        policy.clone(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /swr HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("stale"));
    drop(client);
    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);

    time::sleep(Duration::from_millis(1_100)).await;

    let unused_upstream = reserve_unused_addr().await?;
    let second_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (second_proxy_addr, second_report_rx) =
        spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /swr HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("stale"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_hit_count, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_if_error_window_can_fallback_on_upstream_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 0,
        stale_if_error_secs: 3,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };
    let (upstream_addr, capture_rx) = spawn_stale_if_error_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        policy.clone(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /sie HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("backup"));
    drop(client);
    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);

    time::sleep(Duration::from_millis(1_100)).await;

    let unused_upstream = reserve_unused_addr().await?;
    let second_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (second_proxy_addr, second_report_rx) =
        spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /sie HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("backup"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_hit_count, 1);
    assert_eq!(second_report.metrics.cache_miss_count, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditional_revalidation_uses_validators_and_304_refreshes_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 2,
        stale_if_error_secs: 0,
        revalidation_enabled: true,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (seed_upstream_addr, seed_capture_rx) = spawn_revalidation_seed_upstream().await?;
    let seed_config = proxy_config(seed_upstream_addr).with_response_cache(
        Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)),
    );
    let (seed_proxy_addr, seed_report_rx) =
        spawn_one_shot_http1_proxy_listener(seed_config).await?;

    let mut seed_client = TcpStream::connect(seed_proxy_addr).await?;
    seed_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let seed_response = read_http_response(&mut seed_client).await?;
    assert!(seed_response.ends_with("cached"));
    drop(seed_client);

    let seed_report = receive_proxy_result(seed_report_rx).await?;
    assert_eq!(seed_report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(seed_capture_rx).await?.len(), 1);

    time::sleep(Duration::from_millis(1_100)).await;

    let (revalidate_upstream_addr, revalidate_capture_rx) =
        spawn_not_modified_revalidation_upstream().await?;
    let revalidate_config = proxy_config(revalidate_upstream_addr).with_response_cache(
        Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)),
    );
    let (revalidate_proxy_addr, revalidate_report_rx) =
        spawn_one_shot_http1_proxy_listener(revalidate_config).await?;

    let mut revalidate_client = TcpStream::connect(revalidate_proxy_addr).await?;
    revalidate_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let revalidate_response = read_http_response(&mut revalidate_client).await?;
    assert!(revalidate_response.ends_with("cached"));
    drop(revalidate_client);

    let revalidate_report = receive_proxy_result(revalidate_report_rx).await?;
    assert_eq!(revalidate_report.metrics.cache_miss_count, 1);
    assert_eq!(revalidate_report.metrics.cache_fill_count, 1);

    let revalidate_captures = receive_capture_list(revalidate_capture_rx).await?;
    assert_eq!(revalidate_captures.len(), 1);
    assert!(revalidate_captures[0].head.contains("if-none-match: \"v1\"\r\n"));
    assert!(revalidate_captures[0]
        .head
        .contains("if-modified-since: Wed, 21 Oct 2015 07:28:00 GMT\r\n"));

    let unused_upstream = reserve_unused_addr().await?;
    let post_refresh_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (post_refresh_proxy_addr, post_refresh_report_rx) =
        spawn_one_shot_http1_proxy_listener(post_refresh_config).await?;

    let mut post_refresh_client = TcpStream::connect(post_refresh_proxy_addr).await?;
    post_refresh_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let post_refresh_response = read_http_response(&mut post_refresh_client).await?;
    assert!(post_refresh_response.ends_with("cached"));
    drop(post_refresh_client);

    let post_refresh_report = receive_proxy_result(post_refresh_report_rx).await?;
    assert_eq!(post_refresh_report.metrics.cache_hit_count, 1);
    assert_eq!(post_refresh_report.metrics.cache_miss_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditional_revalidation_200_replaces_cached_object(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 2,
        stale_if_error_secs: 0,
        revalidation_enabled: true,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (seed_upstream_addr, seed_capture_rx) = spawn_revalidation_seed_upstream().await?;
    let seed_config = proxy_config(seed_upstream_addr).with_response_cache(
        Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)),
    );
    let (seed_proxy_addr, seed_report_rx) =
        spawn_one_shot_http1_proxy_listener(seed_config).await?;

    let mut seed_client = TcpStream::connect(seed_proxy_addr).await?;
    seed_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let seed_response = read_http_response(&mut seed_client).await?;
    assert!(seed_response.ends_with("cached"));
    drop(seed_client);

    let seed_report = receive_proxy_result(seed_report_rx).await?;
    assert_eq!(seed_report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(seed_capture_rx).await?.len(), 1);

    time::sleep(Duration::from_millis(1_100)).await;

    let (replacement_upstream_addr, replacement_capture_rx) =
        spawn_revalidation_replacement_upstream().await?;
    let replacement_config = proxy_config(replacement_upstream_addr).with_response_cache(
        Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)),
    );
    let (replacement_proxy_addr, replacement_report_rx) =
        spawn_one_shot_http1_proxy_listener(replacement_config).await?;

    let mut replacement_client = TcpStream::connect(replacement_proxy_addr).await?;
    replacement_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let replacement_response = read_http_response(&mut replacement_client).await?;
    assert!(replacement_response.ends_with("renewed"));
    drop(replacement_client);

    let replacement_report = receive_proxy_result(replacement_report_rx).await?;
    assert_eq!(replacement_report.metrics.cache_miss_count, 1);
    assert_eq!(replacement_report.metrics.cache_fill_count, 1);

    let replacement_captures = receive_capture_list(replacement_capture_rx).await?;
    assert_eq!(replacement_captures.len(), 1);
    assert!(replacement_captures[0].head.contains("if-none-match: \"v1\"\r\n"));
    assert!(replacement_captures[0]
        .head
        .contains("if-modified-since: Wed, 21 Oct 2015 07:28:00 GMT\r\n"));

    let unused_upstream = reserve_unused_addr().await?;
    let post_replace_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (post_replace_proxy_addr, post_replace_report_rx) =
        spawn_one_shot_http1_proxy_listener(post_replace_config).await?;

    let mut post_replace_client = TcpStream::connect(post_replace_proxy_addr).await?;
    post_replace_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let post_replace_response = read_http_response(&mut post_replace_client).await?;
    assert!(post_replace_response.ends_with("renewed"));
    drop(post_replace_client);

    let post_replace_report = receive_proxy_result(post_replace_report_rx).await?;
    assert_eq!(post_replace_report.metrics.cache_hit_count, 1);
    assert_eq!(post_replace_report.metrics.cache_miss_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_revalidation_cycles_stay_bounded_under_soak(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 2,
        stale_if_error_secs: 0,
        revalidation_enabled: true,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (seed_upstream_addr, seed_capture_rx) = spawn_revalidation_seed_upstream().await?;
    let seed_config = proxy_config(seed_upstream_addr).with_response_cache(
        Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)),
    );
    let (seed_proxy_addr, seed_report_rx) =
        spawn_one_shot_http1_proxy_listener(seed_config).await?;

    let mut seed_client = TcpStream::connect(seed_proxy_addr).await?;
    seed_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let seed_response = read_http_response(&mut seed_client).await?;
    assert!(seed_response.ends_with("cached"));
    drop(seed_client);

    let seed_report = receive_proxy_result(seed_report_rx).await?;
    assert_eq!(seed_report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(seed_capture_rx).await?.len(), 1);

    for cycle in 0..3 {
        time::sleep(Duration::from_millis(1_100)).await;

        let (revalidate_upstream_addr, revalidate_capture_rx) =
            spawn_short_ttl_not_modified_revalidation_upstream().await?;
        let revalidate_config = proxy_config(revalidate_upstream_addr).with_response_cache(
            Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)),
        );
        let (revalidate_proxy_addr, revalidate_report_rx) =
            spawn_one_shot_http1_proxy_listener(revalidate_config).await?;

        let mut revalidate_client = TcpStream::connect(revalidate_proxy_addr).await?;
        revalidate_client
            .write_all(
                b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let revalidate_response = read_http_response(&mut revalidate_client).await?;
        assert!(revalidate_response.ends_with("cached"));
        drop(revalidate_client);

        let revalidate_report = receive_proxy_result(revalidate_report_rx).await?;
        assert_eq!(revalidate_report.metrics.cache_fill_count, 1);
        assert_eq!(revalidate_report.metrics.cache_miss_count, 1);
        assert_eq!(receive_capture_list(revalidate_capture_rx).await?.len(), 1);

        let metrics = shared_store.metrics();
        assert_eq!(metrics.entry_count, 1, "cycle {cycle} should keep one cached object");
        assert!(metrics.total_bytes <= 64 * 1024, "cycle {cycle} exceeded cache byte budget");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_cache_directives_fail_closed_without_storing(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (upstream_addr, capture_rx) = spawn_invalid_cache_control_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /invalid-cache-control HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("broken"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 0);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);
    Ok(())
}

#[test]
fn equivalent_requests_produce_identical_cache_keys() -> Result<(), Box<dyn std::error::Error>> {
    let policy = HttpCachePolicyConfig {
        authorization: AuthorizationCacheBehaviorConfig::Partition,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            headers: vec![String::from("accept-language")],
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };
    let first = HttpCacheRequest {
        method: "get",
        target: "/items?b=%2f&a=2&a=1",
        headers: &[
            lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: String::from("Example.TEST"),
            },
            lb_proto_http::HttpHeader {
                name: String::from("accept-language"),
                value: String::from(" en-US , en "),
            },
        ],
    };
    let second = HttpCacheRequest {
        method: "GET",
        target: "http://example.test/items?a=1&a=2&b=%2F",
        headers: &[
            lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: String::from("example.test"),
            },
            lb_proto_http::HttpHeader {
                name: String::from("accept-language"),
                value: String::from("en,en-us"),
            },
        ],
    };

    let first_key = build_http_cache_key_material(&policy, &first, &[])?.expect("key").primary;
    let second_key = build_http_cache_key_material(&policy, &second, &[])?.expect("key").primary;
    assert_eq!(first_key, second_key);
    Ok(())
}

#[test]
fn authorization_bypass_skips_cache_key_construction_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = HttpCachePolicyConfig::default();
    let request = HttpCacheRequest {
        method: "GET",
        target: "/profile",
        headers: &[
            lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: String::from("example.test"),
            },
            lb_proto_http::HttpHeader {
                name: String::from("authorization"),
                value: String::from("Bearer top-secret"),
            },
        ],
    };

    assert!(build_http_cache_key_material(&policy, &request, &[])?.is_none());
    Ok(())
}

#[test]
fn malformed_request_shapes_do_not_produce_ambiguous_cache_keys() {
    let policy = HttpCachePolicyConfig::default();
    let request = HttpCacheRequest {
        method: "GET",
        target: "http://other.test/items?x=%zz",
        headers: &[lb_proto_http::HttpHeader {
            name: String::from("host"),
            value: String::from("example.test"),
        }],
    };

    let error = build_http_cache_key_material(&policy, &request, &[]).expect_err("must fail");
    assert!(matches!(
        error,
        HttpCacheStoreError::InvalidRequestTarget(_)
            | HttpCacheStoreError::HostAuthorityMismatch { .. }
    ));
}

async fn spawn_keep_alive_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut captures = Vec::new();
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ =
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
            }
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld",
                    )
                    .await;
            }
            let _ = captures_tx.send(captures);
        }
    });

    Ok((address, captures_rx))
}

async fn spawn_keep_alive_connection_indexed_http1_upstream(
    max_connections: usize,
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        for connection_index in 1..=max_connections {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };

            loop {
                let Ok(capture) = read_http_request_capture(&mut stream).await else {
                    break;
                };
                captures.push(capture);

                let body = format!("conn-{connection_index}");
                let response =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                if stream.write_all(response.as_bytes()).await.is_err() {
                    break;
                }
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_connection_indexed_http1_upstream(
    max_connections: usize,
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        for connection_index in 1..=max_connections {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let Ok(capture) = read_http_request_capture(&mut stream).await else {
                break;
            };
            let body = format!("conn-{connection_index}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            captures.push(capture);
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_reused_connection_close_then_retry_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();

        if let Ok((mut first_stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut first_stream).await {
                captures.push(capture);
                let _ = first_stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
                    .await;
            }
        }

        if let Ok((mut second_stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut second_stream).await {
                captures.push(capture);
                let _ = second_stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
                    )
                    .await;
            }
        }

        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_body_echo_upstream() -> io::Result<(SocketAddr, oneshot::Receiver<RequestCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nreceived={}",
                    capture.body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = capture_tx.send(capture);
            }
        }
    });

    Ok((address, capture_rx))
}

async fn spawn_tagged_upstream(
    body: &'static str,
) -> io::Result<(SocketAddr, oneshot::Receiver<RequestCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = capture_tx.send(capture);
            }
        }
    });

    Ok((address, capture_rx))
}

async fn spawn_multi_tagged_upstream(
    body: &'static str,
    max_requests: usize,
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        for _ in 0..max_requests {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let Ok(capture) = read_http_request_capture(&mut stream).await else {
                break;
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            captures.push(capture);
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_single_cacheable_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nETag: \"v1\"\r\n\r\ncached",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_revalidation_seed_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=1, stale-while-revalidate=2\r\nETag: \"v1\"\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\ncached",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_transformable_cacheable_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=5\r\nX-Origin: true\r\nX-Remove-Me: yes\r\n\r\ncached",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_no_store_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nprivate",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_swr_upstream() -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\nCache-Control: max-age=1, stale-while-revalidate=2\r\n\r\nstale",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_stale_if_error_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=1, stale-if-error=2\r\n\r\nbackup",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_invalid_cache_control_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=bogus\r\n\r\nbroken",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_vary_cookie_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=30\r\nVary: Cookie\r\n\r\nunsafe",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_private_cache_control_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\nCache-Control: private, max-age=30\r\n\r\nprivate",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_websocket_upgrade_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<UpgradeCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let head = match read_http_head(&mut stream).await {
                Ok(head) => head,
                Err(_) => return,
            };
            if stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: test-accept\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            let mut tunnel_payload = vec![0_u8; 4];
            if stream.read_exact(&mut tunnel_payload).await.is_err() {
                return;
            }
            if stream.write_all(b"pong").await.is_err() {
                return;
            }
            let _ = capture_tx.send(UpgradeCapture { head, tunnel_payload });
        }
    });

    Ok((address, capture_rx))
}

async fn spawn_upgrade_refusal_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<RequestCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
                    )
                    .await;
                let _ = capture_tx.send(capture);
            }
        }
    });

    Ok((address, capture_rx))
}

async fn spawn_malformed_websocket_upgrade_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if read_http_head(&mut stream).await.is_ok() {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        }
    });

    Ok(address)
}

async fn spawn_idle_websocket_upgrade_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if read_http_head(&mut stream).await.is_ok() {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: test-accept\r\n\r\n",
                    )
                    .await;
                time::sleep(Duration::from_secs(1)).await;
            }
        }
    });

    Ok(address)
}

async fn spawn_idle_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((_stream, _)) = listener.accept().await {
            time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(address)
}

async fn reserve_unused_addr() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    listener.local_addr()
}

async fn read_http_request_capture(stream: &mut TcpStream) -> io::Result<RequestCapture> {
    let mut buffer = Vec::new();
    let head_end = read_until_sequence(stream, &mut buffer, b"\r\n\r\n").await?;
    let head = String::from_utf8(buffer[..head_end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request head utf8"))?;
    let content_length = parse_content_length(&head)?;
    let mut body = buffer[head_end..].to_vec();

    while body.len() < content_length {
        let mut chunk = vec![0_u8; (content_length - body.len()).min(8192)];
        let bytes_read = stream.read(&mut chunk).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body truncated"));
        }
        body.extend_from_slice(&chunk[..bytes_read]);
    }
    body.truncate(content_length);

    Ok(RequestCapture { head, body })
}

async fn read_http_response(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::new();
    let head_end = read_until_sequence(stream, &mut buffer, b"\r\n\r\n").await?;
    let head = String::from_utf8(buffer[..head_end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response head utf8"))?;
    let content_length = parse_content_length(&head)?;
    let mut body = buffer[head_end..].to_vec();

    while body.len() < content_length {
        let mut chunk = vec![0_u8; (content_length - body.len()).min(8192)];
        let bytes_read = stream.read(&mut chunk).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "response body truncated"));
        }
        body.extend_from_slice(&chunk[..bytes_read]);
    }
    body.truncate(content_length);

    let body_text = String::from_utf8(body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response body utf8"))?;
    Ok(format!("{head}{body_text}"))
}

async fn read_http_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::new();
    let head_end = read_until_sequence(stream, &mut buffer, b"\r\n\r\n").await?;
    String::from_utf8(buffer[..head_end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "http head utf8"))
}

async fn read_until_sequence(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    sequence: &[u8],
) -> io::Result<usize> {
    loop {
        if let Some(position) = buffer.windows(sequence.len()).position(|window| window == sequence)
        {
            return Ok(position + sequence.len());
        }

        let mut chunk = [0_u8; 1024];
        let bytes_read = stream.read(&mut chunk).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "sequence not found"));
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn parse_content_length(head: &str) -> io::Result<usize> {
    let line = head.lines().find(|line| line.to_ascii_lowercase().starts_with("content-length:"));
    let Some(line) = line else {
        return Ok(0);
    };

    let (_, value) = line.split_once(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid content-length header")
    })?;
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid content-length value"))
}

async fn spawn_one_shot_http1_proxy_listener(
    config: Http1ProxyConfig,
) -> io::Result<(SocketAddr, oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = match listener.accept().await {
            Ok((downstream, _)) => proxy_http1_connection(downstream, &config).await,
            Err(error) => Err(Http1ProxyError::RequestIo(error)),
        };
        let _ = result_tx.send(result);
    });

    Ok((address, result_rx))
}

async fn receive_proxy_result(
    result_rx: oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>,
) -> Result<Http1ConnectionReport, Http1ProxyError> {
    match time::timeout(Duration::from_secs(2), result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(Http1ProxyError::IdleTimeout("proxy result channel closed")),
        Err(_) => Err(Http1ProxyError::IdleTimeout("proxy result wait")),
    }
}

async fn receive_capture(
    capture_rx: oneshot::Receiver<RequestCapture>,
) -> Result<RequestCapture, Box<dyn std::error::Error>> {
    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    Ok(capture)
}

async fn receive_capture_list(
    capture_rx: oneshot::Receiver<Vec<RequestCapture>>,
) -> Result<Vec<RequestCapture>, Box<dyn std::error::Error>> {
    let captures = time::timeout(Duration::from_secs(2), capture_rx).await??;
    Ok(captures)
}

async fn receive_upgrade_capture(
    capture_rx: oneshot::Receiver<UpgradeCapture>,
) -> Result<UpgradeCapture, Box<dyn std::error::Error>> {
    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    Ok(capture)
}

fn proxy_config(upstream_addr: SocketAddr) -> Http1ProxyConfig {
    Http1ProxyConfig::new(UpstreamTarget::new("http-upstream", upstream_addr))
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
