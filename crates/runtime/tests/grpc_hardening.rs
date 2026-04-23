use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h2::{client, server, Reason};
use http::{Request, Response, StatusCode};
use lb_net_core::{
    EndpointMetadata, EndpointState, UpstreamCluster, UpstreamClusterName, UpstreamEndpoint,
    UpstreamEndpointId, UpstreamTarget,
};
use lb_runtime::{
    CircuitBreakerPolicy, EndpointHealthPolicy, FailureManager, LoadBalancingAlgorithm,
    LocalityRoutingPolicy, NoHealthyFallback, RetryBudgetPolicy, RouteBackendPool,
    RouteDestinationPolicyRuntime, TimeoutHierarchy, UpstreamSelectionPolicy,
    proxy_http1_connection, proxy_http2_connection, Http1ConnectionReport, Http1ProxyConfig,
    Http1ProxyError, Http2ConnectionReport, Http2ProxyConfig, Http2ProxyError,
    ProtocolAnomalyCategory, SlowClientStage,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time;

#[derive(Debug)]
struct GrpcUpstreamCapture {
    request_id: String,
    body: Vec<u8>,
}

#[derive(Debug)]
struct H2ResponseData {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
    trailers: Option<http::HeaderMap>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_unary_metadata_and_status_are_preserved() -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_grpc_unary_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(proxy_h2_config(upstream_addr)).await?;

    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_grpc_unary_request(&mut client).await?;
    let capture = receive_capture(capture_rx).await?;
    let response = receive_h2_response(response).await?;
    drop(client);

    assert_eq!(capture.request_id, "req-42");
    assert_eq!(capture.body, grpc_frame(b"ping"));

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/grpc")
    );
    assert_eq!(
        response.headers.get("x-response-meta").and_then(|v| v.to_str().ok()),
        Some("upstream")
    );
    assert_eq!(response.headers.get("grpc-status").and_then(|v| v.to_str().ok()), Some("0"));
    assert_eq!(response.headers.get("grpc-message").and_then(|v| v.to_str().ok()), Some("ok"));
    assert_eq!(response.headers.get("x-trailer-meta").and_then(|v| v.to_str().ok()), Some("done"));
    assert_eq!(response.body, grpc_frame(b"pong"));
    assert!(response.trailers.is_none());

    let report = receive_http2_report(report_rx).await?;
    assert_eq!(report.metrics.grpc_request_count, 1);
    assert_eq!(
        report
            .metrics
            .grpc_service_counts
            .get("grpc.test.Echo"),
        Some(&1)
    );
    assert_eq!(
        report
            .metrics
            .grpc_method_counts
            .get("grpc.test.Echo/Unary"),
        Some(&1)
    );
    assert_eq!(report.metrics.grpc_status_counts.get(&0), Some(&1));
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_unary_retry_budget_retries_unavailable_trailers(
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_grpc_retrying_upstream().await?;
    let failure_manager = Arc::new(FailureManager::new(
        RetryBudgetPolicy {
            min_retry_tokens: 1,
            retry_percent: 100,
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
    let pool = single_endpoint_backend_pool("grpc-primary", upstream_addr)?;
    let mut config = Http2ProxyConfig::new(UpstreamTarget::new("grpc-upstream", upstream_addr))
        .with_route_backend_pools([(String::from("grpc-route"), pool)])
        .with_route_destination_policies([(String::from("grpc-route"), std::collections::BTreeMap::from([(
            String::from("grpc-primary"),
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
    config.routes = vec![lb_proto_http::RoutePrefixRule::new("grpc-route", "/")];

    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;
    let mut client = connect_h2_client(proxy_addr).await?;
    let response = send_grpc_unary_request(&mut client).await?;
    let response = receive_h2_response(response).await?;
    drop(client);

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.headers.get("x-upstream-attempt").and_then(|v| v.to_str().ok()),
        Some("2")
    );
    assert_eq!(response.body, grpc_frame(b"pong"));
    assert_eq!(
        response
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-status"))
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );

    let report = receive_http2_report(report_rx).await?;
    assert_eq!(report.metrics.grpc_request_count, 1);
    assert_eq!(report.metrics.grpc_status_counts.get(&14), Some(&1));
    assert_eq!(report.metrics.grpc_status_counts.get(&0), Some(&1));
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_ambiguous_http1_request_framing() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_tcp_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_h1_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
    )
    .await?;
    drop(client);

    let result = receive_http1_report(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::ParseRequest(_))));
    if let Err(error) = result {
        assert_eq!(error.anomaly_category(), Some(ProtocolAnomalyCategory::AmbiguousFraming));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_multiple_host_headers() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_tcp_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_h1_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: one.test\r\nHost: two.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
    drop(client);

    let result = receive_http1_report(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::ParseRequest(_))));
    if let Err(error) = result {
        assert_eq!(error.anomaly_category(), Some(ProtocolAnomalyCategory::AmbiguousFraming));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slowloris_request_head_hits_idle_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_tcp_upstream().await?;
    let mut config = proxy_h1_config(upstream_addr);
    config.timeouts.idle_timeout = Duration::from_millis(75);
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(b"GET / HTTP/1.1\r\nHost: example.test").await?;

    let result = receive_http1_report(report_rx).await;
    drop(client);
    assert!(matches!(result, Err(Http1ProxyError::IdleTimeout("request head"))));
    if let Err(error) = result {
        assert_eq!(error.slow_client_stage(), Some(SlowClientStage::RequestHead));
    }

    Ok(())
}

async fn spawn_grpc_unary_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<GrpcUpstreamCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut connection = match server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let mut tasks = JoinSet::new();
            let mut capture_tx = Some(capture_tx);

            while let Some(result) = connection.accept().await {
                let Ok((request, mut respond)) = result else {
                    break;
                };
                let capture_tx = capture_tx.take();
                tasks.spawn(async move {
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let mut body = request.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let Ok(chunk) = chunk else {
                            return;
                        };
                        if body.flow_control().release_capacity(chunk.len()).is_err() {
                            return;
                        }
                        bytes.extend_from_slice(&chunk);
                    }

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/grpc")
                        .header("x-response-meta", "upstream")
                        .header("grpc-status", "0")
                        .header("grpc-message", "ok")
                        .header("x-trailer-meta", "done")
                        .body(());
                    if let Ok(response) = response {
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from(grpc_frame(b"pong")), true);
                        }
                    }

                    if let Some(capture_tx) = capture_tx {
                        let _ = capture_tx.send(GrpcUpstreamCapture { request_id, body: bytes });
                    }
                });
            }

            while tasks.join_next().await.is_some() {}
        }
    });

    Ok((address, capture_rx))
}

async fn spawn_grpc_retrying_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut connection = match server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let mut attempt = 0_u64;
            let mut tasks = JoinSet::new();

            while let Some(result) = connection.accept().await {
                let Ok((request, mut respond)) = result else {
                    break;
                };
                attempt += 1;
                let this_attempt = attempt;
                tasks.spawn(async move {
                    let mut body = request.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let Ok(chunk) = chunk else {
                            return;
                        };
                        if body.flow_control().release_capacity(chunk.len()).is_err() {
                            return;
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    if bytes != grpc_frame(b"ping") {
                        return;
                    }

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/grpc")
                        .header("x-upstream-attempt", this_attempt.to_string())
                        .body(());
                    let Ok(response) = response else {
                        return;
                    };
                    let Ok(mut send) = respond.send_response(response, false) else {
                        return;
                    };

                    let payload = if this_attempt == 1 {
                        grpc_frame(b"retry")
                    } else {
                        grpc_frame(b"pong")
                    };
                    if send.send_data(Bytes::from(payload), false).is_err() {
                        return;
                    }

                    let mut trailers = http::HeaderMap::new();
                    let status = if this_attempt == 1 { "14" } else { "0" };
                    let message = if this_attempt == 1 { "upstream unavailable" } else { "ok" };
                    let Ok(status_value) = http::HeaderValue::from_str(status) else {
                        return;
                    };
                    let Ok(message_value) = http::HeaderValue::from_str(message) else {
                        return;
                    };
                    trailers.insert("grpc-status", status_value);
                    trailers.insert("grpc-message", message_value);
                    let _ = send.send_trailers(trailers);
                });
            }

            while tasks.join_next().await.is_some() {}
        }
    });

    Ok(address)
}

async fn spawn_idle_tcp_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((_stream, _)) = listener.accept().await {
            time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(address)
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

async fn send_grpc_unary_request(
    client: &mut client::SendRequest<Bytes>,
) -> Result<h2::client::ResponseFuture, h2::Error> {
    poll_fn(|cx| client.poll_ready(cx)).await?;
    let request = Request::builder()
        .method("POST")
        .uri("/grpc.test.Echo/Unary")
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .header("x-request-id", "req-42")
        .body(())
        .map_err(|_| h2::Error::from(Reason::INTERNAL_ERROR))?;
    let (response, mut send_stream) = client.send_request(request, false)?;

    let mut body = Bytes::from(grpc_frame(b"ping"));
    const MAX_FRAME_CHUNK: usize = 16 * 1024;
    while body.remaining() != 0 {
        let next_len = body.remaining().min(MAX_FRAME_CHUNK);
        send_stream.reserve_capacity(next_len);
        let capacity = poll_fn(|cx| match send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity)),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(h2::Error::from(Reason::INTERNAL_ERROR))),
            Poll::Pending => Poll::Pending,
        })
        .await?;
        let chunk = body.split_to(body.remaining().min(next_len).min(capacity));
        let end = body.remaining() == 0;
        send_stream.send_data(chunk, end)?;
    }

    Ok(response)
}

async fn receive_h2_response(
    response: h2::client::ResponseFuture,
) -> Result<H2ResponseData, Box<dyn std::error::Error>> {
    let response = response.await?;
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        bytes.extend_from_slice(&chunk);
    }
    let trailers = body.trailers().await?;

    Ok(H2ResponseData { status, headers, body: bytes, trailers })
}

async fn receive_capture(
    capture_rx: oneshot::Receiver<GrpcUpstreamCapture>,
) -> Result<GrpcUpstreamCapture, Box<dyn std::error::Error>> {
    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    Ok(capture)
}

async fn receive_http1_report(
    result_rx: oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>,
) -> Result<Http1ConnectionReport, Http1ProxyError> {
    match time::timeout(Duration::from_secs(2), result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(Http1ProxyError::IdleTimeout("proxy result channel closed")),
        Err(_) => Err(Http1ProxyError::IdleTimeout("proxy result wait")),
    }
}

async fn receive_http2_report(
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

fn proxy_h1_config(upstream_addr: SocketAddr) -> Http1ProxyConfig {
    Http1ProxyConfig::new(UpstreamTarget::new("http1-upstream", upstream_addr))
}

fn proxy_h2_config(upstream_addr: SocketAddr) -> Http2ProxyConfig {
    Http2ProxyConfig::new(UpstreamTarget::new("grpc-upstream", upstream_addr))
}

fn single_endpoint_backend_pool(
    cluster_name: &str,
    upstream_addr: SocketAddr,
) -> Result<RouteBackendPool, Box<dyn std::error::Error>> {
    let cluster_name = UpstreamClusterName::new(cluster_name)?;
    let endpoint = UpstreamEndpoint::new(
        UpstreamEndpointId::new("grpc-primary-a")?,
        upstream_addr,
        EndpointState::Ready,
        EndpointMetadata {
            zone: None,
            locality: None,
            weight: 1,
        },
    )?;
    Ok(RouteBackendPool::from_cluster(
        UpstreamCluster::new(cluster_name, vec![endpoint])?,
        EndpointHealthPolicy::default(),
        UpstreamSelectionPolicy {
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            locality: LocalityRoutingPolicy::Disabled,
            no_healthy_fallback: NoHealthyFallback::Fail,
            affinity: None,
        },
    )?)
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(5 + payload.len());
    bytes.push(0);
    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
