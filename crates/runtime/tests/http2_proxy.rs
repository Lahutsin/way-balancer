use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h2::{client, server, Reason};
use http::{Request, Response, StatusCode};
use lb_net_core::UpstreamTarget;
use lb_runtime::{
    proxy_http2_connection, Http2ConnectionReport, Http2ProxyConfig, Http2ProxyError,
    ProtocolAnomalyCategory,
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
    poll_fn(|cx| client.poll_ready(cx)).await?;
    let request =
        Request::builder().method("GET").uri(path).body(()).map_err(|_| Reason::INTERNAL_ERROR)?;
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
