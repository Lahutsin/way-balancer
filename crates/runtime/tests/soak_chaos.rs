#![allow(clippy::never_loop)]

use std::fs;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h2::{client, server, Reason};
use http::{Request, Response, StatusCode};
use lb_net_core::UpstreamTarget;
use lb_runtime::{
    proxy_http1_connection, proxy_http2_connection, Http1ConnectionReport, Http1ProxyConfig,
    Http1ProxyError, Http2ConnectionReport, Http2ProxyConfig, Http2ProxyError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time;

const SOAK_IDLE_TIMEOUT: Duration = Duration::from_millis(150);
const SOAK_STALL_DELAY: Duration = Duration::from_millis(300);

#[derive(Clone, Copy, Debug)]
enum Http1ChaosScenario {
    PartialWrite,
    ResetBeforeResponse,
    StallBeforeResponse,
    DegradedResponse,
}

#[derive(Clone, Copy, Debug)]
enum Http2ChaosScenario {
    HealthyResponse,
    ResetStream,
    StallBeforeResponse,
    DegradedResponse,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_upstream_flap_chaos_soak_keeps_fd_growth_bounded(
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline_fds = open_fd_count();
    let mut partial_ok = 0_u64;
    let mut degraded_ok = 0_u64;
    let mut reset_failures = 0_u64;
    let mut stall_failures = 0_u64;

    for iteration in 0..24 {
        let scenario = match iteration % 4 {
            0 => Http1ChaosScenario::PartialWrite,
            1 => Http1ChaosScenario::ResetBeforeResponse,
            2 => Http1ChaosScenario::StallBeforeResponse,
            _ => Http1ChaosScenario::DegradedResponse,
        };
        let upstream_addr = spawn_http1_chaos_upstream(scenario).await?;
        let mut config = http1_proxy_config(upstream_addr);
        config.timeouts.idle_timeout = SOAK_IDLE_TIMEOUT;
        let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

        let mut client = TcpStream::connect(proxy_addr).await?;
        client
            .write_all(b"GET /chaos HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await?;

        match scenario {
            Http1ChaosScenario::PartialWrite => {
                let response = read_http_response(&mut client).await?;
                assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
                assert!(response.ends_with("partial-ok"));
                let report = receive_http1_proxy_result(report_rx).await?;
                assert_eq!(report.metrics.request_count, 1);
                assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
                partial_ok += 1;
            }
            Http1ChaosScenario::DegradedResponse => {
                let response = read_http_response(&mut client).await?;
                assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
                assert!(response.ends_with("degraded"));
                let report = receive_http1_proxy_result(report_rx).await?;
                assert_eq!(report.metrics.request_count, 1);
                assert_eq!(report.metrics.response_status_counts.get(&503), Some(&1));
                degraded_ok += 1;
            }
            Http1ChaosScenario::ResetBeforeResponse => {
                drop(client);
                let result = receive_http1_proxy_result(report_rx).await;
                assert!(matches!(
                    result,
                    Err(Http1ProxyError::ParseResponse(_)) | Err(Http1ProxyError::RequestIo(_))
                ));
                reset_failures += 1;
            }
            Http1ChaosScenario::StallBeforeResponse => {
                drop(client);
                let result = receive_http1_proxy_result(report_rx).await;
                assert!(matches!(result, Err(Http1ProxyError::IdleTimeout("response head"))));
                stall_failures += 1;
            }
        }
    }

    assert_eq!(partial_ok, 6);
    assert_eq!(degraded_ok, 6);
    assert_eq!(reset_failures, 6);
    assert_eq!(stall_failures, 6);

    if let Some(baseline_fds) = baseline_fds {
        time::sleep(Duration::from_millis(50)).await;
        let final_fds = open_fd_count().ok_or("fd counter disappeared")?;
        assert!(
            final_fds <= baseline_fds + 12,
            "fd growth exceeded bound: baseline={baseline_fds} final={final_fds}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_upstream_flap_chaos_soak_keeps_fd_growth_bounded(
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline_fds = open_fd_count();
    let mut ok_count = 0_u64;
    let mut degraded_count = 0_u64;
    let mut reset_count = 0_u64;
    let mut timeout_count = 0_u64;

    for iteration in 0..24 {
        let scenario = match iteration % 4 {
            0 => Http2ChaosScenario::HealthyResponse,
            1 => Http2ChaosScenario::ResetStream,
            2 => Http2ChaosScenario::StallBeforeResponse,
            _ => Http2ChaosScenario::DegradedResponse,
        };
        let upstream_addr = match scenario {
            Http2ChaosScenario::HealthyResponse => spawn_steady_h2_upstream("steady-ok").await?,
            Http2ChaosScenario::DegradedResponse => {
                spawn_status_h2_upstream(StatusCode::SERVICE_UNAVAILABLE, "degraded").await?
            }
            _ => spawn_http2_chaos_upstream(scenario).await?,
        };
        let mut config = http2_proxy_config(upstream_addr);
        config.timeouts.idle_timeout = SOAK_IDLE_TIMEOUT;
        let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(config).await?;

        let mut client = connect_h2_client(proxy_addr).await?;
        let response = send_h2_request(&mut client, "/chaos", None).await?;
        let (status, body) = receive_h2_response(response).await?;
        drop(client);
        let report = receive_http2_proxy_result(report_rx).await?;
        assert_eq!(report.metrics.request_count, 1);
        assert_eq!(report.metrics.active_streams, 0);
        assert!(report.metrics.peak_active_streams <= 1);

        match scenario {
            Http2ChaosScenario::HealthyResponse => {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body, "steady-ok");
                assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
                ok_count += 1;
            }
            Http2ChaosScenario::DegradedResponse => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(body, "degraded");
                assert_eq!(report.metrics.response_status_counts.get(&503), Some(&1));
                degraded_count += 1;
            }
            Http2ChaosScenario::ResetStream => {
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert!(body.is_empty());
                assert_eq!(report.metrics.response_status_counts.get(&502), Some(&1));
                assert!(report.metrics.stream_error_count >= 1);
                reset_count += 1;
            }
            Http2ChaosScenario::StallBeforeResponse => {
                assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
                assert!(body.is_empty());
                assert_eq!(report.metrics.response_status_counts.get(&504), Some(&1));
                assert!(report.metrics.stream_error_count >= 1);
                timeout_count += 1;
            }
        }
    }

    assert_eq!(ok_count, 6);
    assert_eq!(degraded_count, 6);
    assert_eq!(reset_count, 6);
    assert_eq!(timeout_count, 6);

    if let Some(baseline_fds) = baseline_fds {
        time::sleep(Duration::from_millis(50)).await;
        let final_fds = open_fd_count().ok_or("fd counter disappeared")?;
        assert!(
            final_fds <= baseline_fds + 12,
            "fd growth exceeded bound: baseline={baseline_fds} final={final_fds}"
        );
    }

    Ok(())
}

fn open_fd_count() -> Option<usize> {
    ["/dev/fd", "/proc/self/fd"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .and_then(|path| fs::read_dir(path).ok().map(|entries| entries.count()))
}

async fn spawn_http1_chaos_upstream(scenario: Http1ChaosScenario) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let _ = read_http1_request_head(&mut stream).await;
        match scenario {
            Http1ChaosScenario::PartialWrite => {
                let _ = write_http1_in_chunks(
                    &mut stream,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\npartial-ok",
                )
                .await;
            }
            Http1ChaosScenario::ResetBeforeResponse => {
                drop(stream);
            }
            Http1ChaosScenario::StallBeforeResponse => {
                time::sleep(SOAK_STALL_DELAY).await;
            }
            Http1ChaosScenario::DegradedResponse => {
                let _ = write_http1_in_chunks(
                    &mut stream,
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndegraded",
                )
                .await;
            }
        }
    });

    Ok(address)
}

async fn write_http1_in_chunks(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    for chunk in bytes.chunks(7) {
        stream.write_all(chunk).await?;
        time::sleep(Duration::from_millis(3)).await;
    }
    Ok(())
}

async fn read_http1_request_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::new();
    let end = read_until_sequence(stream, &mut buffer, b"\r\n\r\n").await?;
    String::from_utf8(buffer[..end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request head utf8"))
}

async fn spawn_http2_chaos_upstream(scenario: Http2ChaosScenario) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let mut connection = match server::handshake(stream).await {
            Ok(connection) => connection,
            Err(_) => return,
        };
        while let Some(result) = connection.accept().await {
            let Ok((_request, mut respond)) = result else {
                break;
            };
            match scenario {
                Http2ChaosScenario::HealthyResponse => {
                    if let Ok(response) = Response::builder().status(StatusCode::OK).body(()) {
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from_static(b"steady-ok"), true);
                            time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
                Http2ChaosScenario::ResetStream => {
                    respond.send_reset(Reason::CANCEL);
                }
                Http2ChaosScenario::StallBeforeResponse => {
                    time::sleep(SOAK_STALL_DELAY).await;
                }
                Http2ChaosScenario::DegradedResponse => unreachable!("handled by stable helper"),
            }
            break;
        }
    });

    Ok(address)
}

async fn spawn_steady_h2_upstream(body: &'static str) -> io::Result<SocketAddr> {
    spawn_status_h2_upstream(StatusCode::OK, body).await
}

async fn spawn_status_h2_upstream(
    status: StatusCode,
    body: &'static str,
) -> io::Result<SocketAddr> {
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
                let response = Response::builder().status(status).body(());
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

async fn receive_http1_proxy_result(
    result_rx: oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>,
) -> Result<Http1ConnectionReport, Http1ProxyError> {
    match time::timeout(Duration::from_secs(2), result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(Http1ProxyError::IdleTimeout("proxy result channel closed")),
        Err(_) => Err(Http1ProxyError::IdleTimeout("proxy result wait")),
    }
}

fn http1_proxy_config(upstream_addr: SocketAddr) -> Http1ProxyConfig {
    Http1ProxyConfig::new(UpstreamTarget::new("http1-chaos-upstream", upstream_addr))
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
    if let Some(mut body) = body {
        const MAX_FRAME_CHUNK: usize = 16 * 1024;
        while body.remaining() != 0 {
            let next_len = body.remaining().min(MAX_FRAME_CHUNK);
            let capacity = loop {
                send_stream.reserve_capacity(next_len);
                let capacity = poll_fn(|cx| match send_stream.poll_capacity(cx) {
                    std::task::Poll::Ready(Some(Ok(capacity))) => {
                        std::task::Poll::Ready(Ok(capacity))
                    }
                    std::task::Poll::Ready(Some(Err(error))) => std::task::Poll::Ready(Err(error)),
                    std::task::Poll::Ready(None) => {
                        std::task::Poll::Ready(Err(h2::Error::from(Reason::INTERNAL_ERROR)))
                    }
                    std::task::Poll::Pending => std::task::Poll::Pending,
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
    Ok((status, String::from_utf8(bytes)?))
}

async fn receive_http2_proxy_result(
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

fn http2_proxy_config(upstream_addr: SocketAddr) -> Http2ProxyConfig {
    Http2ProxyConfig::new(UpstreamTarget::new("http2-chaos-upstream", upstream_addr))
}
