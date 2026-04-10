#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h2::{client, server, Reason};
use http::{Request, Response, StatusCode};
use lb_net_core::{ListenerClass, ListenerConfig, UpstreamTarget};
use lb_runtime::{
    proxy_http1_connection, proxy_http1_connection_with_downstream_addr,
    proxy_http2_connection, start_listener, Http1ConnectionReport, Http1ProxyConfig,
    Http1ProxyError, Http2ConnectionReport, Http2ProxyConfig, Http2ProxyError,
    ListenerHandle,
};
use rcgen::generate_simple_self_signed;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

const HTTP1_BENCH_BODY: &str = "bench-http1";
const HTTP2_BENCH_BODY: &str = "bench-http2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeMode {
    Smoke,
    Full,
}

impl EnvelopeMode {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "smoke" => Some(Self::Smoke),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    #[must_use]
    pub fn scenario(self) -> ScenarioConfig {
        match self {
            Self::Smoke => ScenarioConfig {
                http1_requests: 64,
                http2_streams: 64,
                mixed_operations: 64,
                idle_connections: 24,
                active_streams: 24,
            },
            Self::Full => ScenarioConfig {
                http1_requests: 256,
                http2_streams: 256,
                mixed_operations: 256,
                idle_connections: 64,
                active_streams: 64,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ScenarioConfig {
    pub http1_requests: usize,
    pub http2_streams: usize,
    pub mixed_operations: usize,
    pub idle_connections: usize,
    pub active_streams: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThroughputMeasurement {
    pub scenario: String,
    pub operations: usize,
    pub elapsed_ms: u128,
    pub operations_per_sec: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencySummary {
    pub scenario: String,
    pub samples: usize,
    pub mean_us: f64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryMeasurement {
    pub scenario: String,
    pub units: usize,
    pub baseline_rss_kib: Option<u64>,
    pub peak_rss_kib: Option<u64>,
    pub delta_rss_kib: Option<u64>,
    pub per_unit_rss_kib: Option<f64>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsOverheadMeasurement {
    pub plain_ops_per_sec: f64,
    pub tls_ops_per_sec: f64,
    pub throughput_penalty_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PerformanceEnvelopeReport {
    pub mode: EnvelopeMode,
    pub scenario: ScenarioConfig,
    pub http1_throughput: ThroughputMeasurement,
    pub http2_throughput: ThroughputMeasurement,
    pub mixed_latency: LatencySummary,
    pub http1_tls_throughput: ThroughputMeasurement,
    pub tls_overhead: TlsOverheadMeasurement,
    pub idle_connection_memory: MemoryMeasurement,
    pub http2_stream_memory: MemoryMeasurement,
    pub assumptions: Vec<String>,
}

#[derive(Clone)]
struct TlsIdentity {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
}

struct H2Client {
    send_request: client::SendRequest<Bytes>,
    connection_task: tokio::task::JoinHandle<()>,
}

pub async fn run_performance_envelope(
    mode: EnvelopeMode,
) -> Result<PerformanceEnvelopeReport, DynError> {
    let scenario = mode.scenario();
    let http1_throughput = measure_http1_throughput(scenario.http1_requests).await?;
    let http2_throughput = measure_http2_throughput(scenario.http2_streams).await?;
    let mixed_latency = measure_mixed_latency(scenario.mixed_operations).await?;
    let http1_tls_throughput = measure_http1_tls_throughput(scenario.http1_requests).await?;
    let idle_connection_memory = measure_idle_connection_memory(scenario.idle_connections).await?;
    let http2_stream_memory = measure_http2_stream_memory(scenario.active_streams).await?;
    let tls_overhead = TlsOverheadMeasurement {
        plain_ops_per_sec: http1_throughput.operations_per_sec,
        tls_ops_per_sec: http1_tls_throughput.operations_per_sec,
        throughput_penalty_pct: percentage_penalty(
            http1_throughput.operations_per_sec,
            http1_tls_throughput.operations_per_sec,
        ),
    };

    Ok(PerformanceEnvelopeReport {
        mode,
        scenario,
        http1_throughput,
        http2_throughput,
        mixed_latency,
        http1_tls_throughput,
        tls_overhead,
        idle_connection_memory,
        http2_stream_memory,
        assumptions: vec![
            String::from("loopback-only proxy measurements; these numbers are for relative regression detection and local capacity planning, not internet-facing SLA claims"),
            String::from("resident-set-size sampling is process-level and most comparable across commits on the same host class"),
            String::from("TLS overhead is measured against the same HTTP/1 batch through a local Rustls-terminated downstream connection"),
        ],
    })
}

pub async fn measure_http1_throughput(
    requests: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let (upstream_addr, captures_rx) = spawn_repeating_http1_upstream(requests, HTTP1_BENCH_BODY).await?;
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(http1_proxy_config(upstream_addr)).await?;
    let mut client = TcpStream::connect(proxy_addr).await?;

    let started_at = Instant::now();
    drive_http1_batch(&mut client, requests).await?;
    let elapsed = started_at.elapsed();
    drop(client);

    let report = receive_http1_proxy_result(report_rx).await?;
    let captures = receive_http1_captures(captures_rx).await?;
    if report.metrics.request_count != requests as u64 || captures.len() != requests {
        return Err(io::Error::other("unexpected HTTP/1 throughput harness counts").into());
    }

    Ok(throughput_measurement("http1_proxy_batch", requests, elapsed))
}

pub async fn measure_http1_tls_throughput(
    requests: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let identity = tls_identity()?;
    let (upstream_addr, captures_rx) = spawn_repeating_http1_upstream(requests, HTTP1_BENCH_BODY).await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_tls_http1_proxy_listener(http1_proxy_config(upstream_addr), identity.clone()).await?;

    let stream = TcpStream::connect(proxy_addr).await?;
    let server_name = ServerName::try_from("localhost")?.to_owned();
    let mut client = TlsConnector::from(identity.client).connect(server_name, stream).await?;

    let started_at = Instant::now();
    drive_http1_batch(&mut client, requests).await?;
    let elapsed = started_at.elapsed();
    drop(client);

    let report = receive_http1_proxy_result(report_rx).await?;
    let captures = receive_http1_captures(captures_rx).await?;
    if report.metrics.request_count != requests as u64 || captures.len() != requests {
        return Err(io::Error::other("unexpected HTTP/1 TLS throughput harness counts").into());
    }

    Ok(throughput_measurement("http1_proxy_batch_tls", requests, elapsed))
}

pub async fn measure_http2_throughput(
    streams: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let upstream_addr = spawn_basic_h2_upstream(HTTP2_BENCH_BODY).await?;
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(http2_proxy_config(upstream_addr)).await?;
    let mut client = connect_h2_client(proxy_addr).await?;

    let started_at = Instant::now();
    let mut responses = Vec::with_capacity(streams);
    for index in 0..streams {
        responses.push(send_h2_request(&mut client, &format!("/stream-{index}"), None).await?);
    }
    for response in responses {
        let received = receive_h2_response(response).await?;
        if received.0 != StatusCode::OK || received.1 != HTTP2_BENCH_BODY {
            return Err(io::Error::other("unexpected HTTP/2 benchmark response").into());
        }
    }
    let elapsed = started_at.elapsed();
    shutdown_h2_client(client).await;
    time::sleep(Duration::from_millis(50)).await;

    let report = receive_http2_proxy_result(report_rx).await?;
    if report.metrics.request_count != streams as u64 {
        return Err(io::Error::other("unexpected HTTP/2 throughput harness counts").into());
    }

    Ok(throughput_measurement("http2_proxy_stream_batch", streams, elapsed))
}

pub async fn measure_mixed_latency(
    operations: usize,
) -> Result<LatencySummary, DynError> {
    let http1_requests = operations / 2;
    let http2_requests = operations - http1_requests;

    let (http1_upstream_addr, http1_captures_rx) =
        spawn_repeating_http1_upstream(http1_requests.max(1), HTTP1_BENCH_BODY).await?;
    let (http1_proxy_addr, http1_report_rx) =
        spawn_one_shot_http1_proxy_listener(http1_proxy_config(http1_upstream_addr)).await?;
    let mut http1_client = TcpStream::connect(http1_proxy_addr).await?;

    let http2_upstream_addr = spawn_basic_h2_upstream(HTTP2_BENCH_BODY).await?;
    let (http2_proxy_addr, http2_report_rx) =
        spawn_one_shot_http2_proxy_listener(http2_proxy_config(http2_upstream_addr)).await?;
    let mut http2_client = connect_h2_client(http2_proxy_addr).await?;

    let mut samples_us = Vec::with_capacity(operations);
    let mut http1_seen = 0usize;
    let mut http2_seen = 0usize;
    for index in 0..operations {
        if index % 2 == 0 && http1_seen < http1_requests {
            let started_at = Instant::now();
            send_one_http1_request(
                &mut http1_client,
                http1_seen + 1 == http1_requests,
                &format!("/mixed-http1-{index}"),
            )
            .await?;
            samples_us.push(duration_to_us(started_at.elapsed()));
            http1_seen += 1;
        }

        if http2_seen < http2_requests {
            let started_at = Instant::now();
            let response = send_h2_request(&mut http2_client, &format!("/mixed-http2-{index}"), None).await?;
            let received = receive_h2_response(response).await?;
            if received.0 != StatusCode::OK || received.1 != HTTP2_BENCH_BODY {
                return Err(io::Error::other("unexpected mixed HTTP/2 response").into());
            }
            samples_us.push(duration_to_us(started_at.elapsed()));
            http2_seen += 1;
        }
    }

    drop(http1_client);
    shutdown_h2_client(http2_client).await;
    time::sleep(Duration::from_millis(50)).await;

    let http1_report = receive_http1_proxy_result(http1_report_rx).await?;
    let http2_report = receive_http2_proxy_result(http2_report_rx).await?;
    let http1_captures = receive_http1_captures(http1_captures_rx).await?;
    if http1_report.metrics.request_count != http1_requests as u64
        || http2_report.metrics.request_count != http2_requests as u64
    {
        return Err(io::Error::other("unexpected mixed latency harness counts").into());
    }
    if http1_captures.len() != http1_requests {
        return Err(io::Error::other("unexpected mixed HTTP/1 capture count").into());
    }

    Ok(latency_summary("mixed_http1_http2_interleaved", samples_us))
}

pub async fn measure_idle_connection_memory(
    connections: usize,
) -> Result<MemoryMeasurement, DynError> {
    let baseline_rss_kib = current_rss_kib();

    let mut config = ListenerConfig::foundation_local("perf-envelope", ListenerClass::Public);
    config.max_connections = connections.max(1) + 8;
    config.idle_timeout = Duration::from_secs(2);
    let handle = start_listener(config).await?;
    let local_addr = handle.local_addr();

    let mut clients = Vec::with_capacity(connections);
    for _ in 0..connections {
        let mut stream = TcpStream::connect(local_addr).await?;
        stream.write_all(b"x").await?;
        clients.push(stream);
    }
    time::sleep(Duration::from_millis(75)).await;
    let snapshot = handle.snapshot();
    let peak_rss_kib = current_rss_kib();

    drop(clients);
    handle.shutdown().await?;

    if snapshot.active_connections < connections {
        return Err(io::Error::other("listener memory harness did not retain all idle connections").into());
    }

    Ok(memory_measurement(
        "idle_listener_connections",
        connections,
        baseline_rss_kib,
        peak_rss_kib,
        String::from("resident-set-size delta while the bounded listener keeps loopback idle connections admitted"),
    ))
}

pub async fn measure_http2_stream_memory(
    streams: usize,
) -> Result<MemoryMeasurement, DynError> {
    let baseline_rss_kib = current_rss_kib();
    let upstream_addr = spawn_delayed_h2_upstream(Duration::from_millis(250), HTTP2_BENCH_BODY).await?;
    let (proxy_addr, report_rx) = spawn_one_shot_http2_proxy_listener(http2_proxy_config(upstream_addr)).await?;
    let mut client = connect_h2_client(proxy_addr).await?;

    let mut responses = Vec::with_capacity(streams);
    for index in 0..streams {
        responses.push(send_h2_request(&mut client, &format!("/hold-{index}"), None).await?);
    }
    time::sleep(Duration::from_millis(75)).await;
    let peak_rss_kib = current_rss_kib();

    for response in responses {
        let received = receive_h2_response(response).await?;
        if received.0 != StatusCode::OK || received.1 != HTTP2_BENCH_BODY {
            return Err(io::Error::other("unexpected HTTP/2 memory response").into());
        }
    }
    shutdown_h2_client(client).await;
    time::sleep(Duration::from_millis(50)).await;

    let report = receive_http2_proxy_result(report_rx).await?;
    if report.metrics.peak_active_streams < streams {
        return Err(io::Error::other("HTTP/2 memory harness did not reach target active stream count").into());
    }

    Ok(memory_measurement(
        "http2_active_streams",
        streams,
        baseline_rss_kib,
        peak_rss_kib,
        String::from("resident-set-size delta while the proxy keeps a single downstream HTTP/2 connection busy with concurrent delayed upstream streams"),
    ))
}

fn throughput_measurement(
    scenario: &str,
    operations: usize,
    elapsed: Duration,
) -> ThroughputMeasurement {
    let operations_per_sec = if elapsed.is_zero() {
        operations as f64
    } else {
        operations as f64 / elapsed.as_secs_f64()
    };

    ThroughputMeasurement {
        scenario: scenario.to_string(),
        operations,
        elapsed_ms: elapsed.as_millis(),
        operations_per_sec,
    }
}

fn latency_summary(scenario: &str, mut samples_us: Vec<u64>) -> LatencySummary {
    samples_us.sort_unstable();
    let samples = samples_us.len();
    let sum: u128 = samples_us.iter().map(|sample| u128::from(*sample)).sum();
    let mean_us = if samples == 0 {
        0.0
    } else {
        sum as f64 / samples as f64
    };

    LatencySummary {
        scenario: scenario.to_string(),
        samples,
        mean_us,
        p50_us: percentile(&samples_us, 0.50),
        p95_us: percentile(&samples_us, 0.95),
        p99_us: percentile(&samples_us, 0.99),
        max_us: samples_us.last().copied().unwrap_or(0),
    }
}

fn memory_measurement(
    scenario: &str,
    units: usize,
    baseline_rss_kib: Option<u64>,
    peak_rss_kib: Option<u64>,
    note: String,
) -> MemoryMeasurement {
    let delta_rss_kib = baseline_rss_kib.zip(peak_rss_kib).map(|(baseline, peak)| peak.saturating_sub(baseline));
    let per_unit_rss_kib = delta_rss_kib.map(|delta| {
        if units == 0 {
            0.0
        } else {
            delta as f64 / units as f64
        }
    });

    MemoryMeasurement {
        scenario: scenario.to_string(),
        units,
        baseline_rss_kib,
        peak_rss_kib,
        delta_rss_kib,
        per_unit_rss_kib,
        note,
    }
}

fn percentage_penalty(baseline: f64, candidate: f64) -> f64 {
    if baseline <= f64::EPSILON {
        0.0
    } else {
        ((baseline - candidate) / baseline) * 100.0
    }
}

fn percentile(samples_us: &[u64], percentile: f64) -> u64 {
    if samples_us.is_empty() {
        return 0;
    }
    let index = ((samples_us.len() - 1) as f64 * percentile).round() as usize;
    samples_us[index.min(samples_us.len() - 1)]
}

fn duration_to_us(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

fn tls_identity() -> Result<TlsIdentity, DynError> {
    let certified = generate_simple_self_signed(vec![String::from("localhost")])?;
    let cert_der_bytes = certified.cert.der().to_vec();
    let cert_der = CertificateDer::from(cert_der_bytes.clone());
    let key_der = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    let server = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_der))?,
    );

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der_bytes))?;
    let client = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    Ok(TlsIdentity { server, client })
}

async fn drive_http1_batch<S>(stream: &mut S, requests: usize) -> Result<(), DynError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for index in 0..requests {
        send_one_http1_request(stream, index + 1 == requests, &format!("/batch-{index}")).await?;
    }
    Ok(())
}

async fn send_one_http1_request<S>(
    stream: &mut S,
    close_connection: bool,
    target: &str,
) -> Result<(), DynError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connection_header = if close_connection { "close" } else { "keep-alive" };
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: example.test\r\nConnection: {connection_header}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let response = read_http_response(stream).await?;
    if !response.starts_with("HTTP/1.1 200 OK\r\n") || !response.ends_with(HTTP1_BENCH_BODY) {
        return Err(io::Error::other("unexpected HTTP/1 benchmark response").into());
    }
    Ok(())
}

async fn spawn_repeating_http1_upstream(
    requests: usize,
    body: &'static str,
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            for _ in 0..requests {
                let capture = match read_http_request_capture(&mut stream).await {
                    Ok(capture) => capture,
                    Err(_) => break,
                };
                captures.push(capture);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    break;
                }
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn read_http_request_capture(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::new();
    let head_end = read_until_sequence(stream, &mut buffer, b"\r\n\r\n").await?;
    String::from_utf8(buffer[..head_end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request head utf8"))
}

async fn read_http_response<S>(stream: &mut S) -> io::Result<String>
where
    S: AsyncRead + Unpin,
{
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

async fn read_until_sequence<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    sequence: &[u8],
) -> io::Result<usize>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(position) = buffer.windows(sequence.len()).position(|window| window == sequence) {
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
    let Some(line) = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
    else {
        return Ok(0);
    };

    let Some((_, value)) = line.split_once(':') else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid content-length header"));
    };
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

async fn spawn_one_shot_tls_http1_proxy_listener(
    config: Http1ProxyConfig,
    identity: TlsIdentity,
) -> io::Result<(SocketAddr, oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = match listener.accept().await {
            Ok((downstream, peer_addr)) => {
                let acceptor = TlsAcceptor::from(identity.server);
                match acceptor.accept(downstream).await {
                    Ok(tls_stream) => {
                        proxy_http1_connection_with_downstream_addr(tls_stream, peer_addr, &config)
                            .await
                    }
                    Err(error) => Err(Http1ProxyError::RequestIo(io::Error::other(error.to_string()))),
                }
            }
            Err(error) => Err(Http1ProxyError::RequestIo(error)),
        };
        let _ = result_tx.send(result);
    });

    Ok((address, result_rx))
}

async fn receive_http1_proxy_result(
    result_rx: oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>,
) -> Result<Http1ConnectionReport, Http1ProxyError> {
    match time::timeout(Duration::from_secs(5), result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(Http1ProxyError::IdleTimeout("proxy result channel closed")),
        Err(_) => Err(Http1ProxyError::IdleTimeout("proxy result wait")),
    }
}

async fn receive_http1_captures(
    capture_rx: oneshot::Receiver<Vec<String>>,
) -> Result<Vec<String>, DynError> {
    match time::timeout(Duration::from_secs(5), capture_rx).await {
        Ok(Ok(captures)) => Ok(captures),
        Ok(Err(_)) => Err(io::Error::other("HTTP/1 capture channel closed").into()),
        Err(_) => Err(io::Error::other("HTTP/1 capture wait timed out").into()),
    }
}

async fn spawn_basic_h2_upstream(body: &'static str) -> io::Result<SocketAddr> {
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
                let Ok(response) = response else {
                    break;
                };
                if let Ok(mut send) = respond.send_response(response, false) {
                    let _ = send.send_data(Bytes::from(body.to_string()), true);
                }
            }
        }
    });

    Ok(address)
}

async fn spawn_delayed_h2_upstream(
    delay: Duration,
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
            let mut tasks = JoinSet::new();
            while let Some(result) = connection.accept().await {
                let Ok((_request, mut respond)) = result else {
                    break;
                };
                tasks.spawn(async move {
                    time::sleep(delay).await;
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

async fn spawn_one_shot_http2_proxy_listener(
    config: Http2ProxyConfig,
) -> io::Result<(SocketAddr, oneshot::Receiver<Result<Http2ConnectionReport, Http2ProxyError>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = match listener.accept().await {
            Ok((downstream, _)) => proxy_http2_connection(downstream, &config).await,
            Err(error) => Err(Http2ProxyError::Connect { target: config.upstream.address, source: error }),
        };
        let _ = result_tx.send(result);
    });

    Ok((address, result_rx))
}

async fn connect_h2_client(
    proxy_addr: SocketAddr,
) -> Result<H2Client, DynError> {
    let stream = TcpStream::connect(proxy_addr).await?;
    let (send_request, connection) = client::handshake(stream).await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(H2Client {
        send_request,
        connection_task,
    })
}

async fn send_h2_request(
    client: &mut H2Client,
    path: &str,
    body: Option<Bytes>,
) -> Result<h2::client::ResponseFuture, h2::Error> {
    poll_h2_ready(&mut client.send_request).await?;
    let request = Request::builder().method("GET").uri(path).body(())
        .map_err(|_| h2::Error::from(Reason::INTERNAL_ERROR))?;
    let end_stream = body.is_none();
    let (response, mut send_stream) = client.send_request.send_request(request, end_stream)?;
    if let Some(mut body) = body {
        const MAX_FRAME_CHUNK: usize = 16 * 1024;
        while body.remaining() != 0 {
            let capacity = poll_h2_capacity(&mut send_stream, body.remaining().min(MAX_FRAME_CHUNK)).await?;
            let chunk = body.split_to(body.remaining().min(MAX_FRAME_CHUNK).min(capacity));
            let end = body.remaining() == 0;
            send_stream.send_data(chunk, end)?;
        }
    }
    Ok(response)
}

async fn shutdown_h2_client(client: H2Client) {
    let H2Client {
        send_request,
        connection_task,
    } = client;
    drop(send_request);
    connection_task.abort();
    let _ = connection_task.await;
}

async fn poll_h2_ready(
    client: &mut client::SendRequest<Bytes>,
) -> Result<(), h2::Error> {
    use std::future::poll_fn;
    poll_fn(|cx| client.poll_ready(cx)).await
}

async fn poll_h2_capacity(
    send_stream: &mut h2::SendStream<Bytes>,
    requested: usize,
) -> Result<usize, h2::Error> {
    use std::future::poll_fn;
    use std::task::Poll;

    loop {
        send_stream.reserve_capacity(requested);
        let capacity = poll_fn(|cx| match send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity)),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(h2::Error::from(Reason::INTERNAL_ERROR))),
            Poll::Pending => Poll::Pending,
        })
        .await?;
        if capacity != 0 {
            return Ok(capacity);
        }
        tokio::task::yield_now().await;
    }
}

async fn receive_h2_response(
    response: h2::client::ResponseFuture,
) -> Result<(StatusCode, String), DynError> {
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
) -> Result<Http2ConnectionReport, DynError> {
    match time::timeout(Duration::from_secs(15), result_rx).await {
        Ok(Ok(result)) => result.map_err(Into::into),
        Ok(Err(_)) => Err(io::Error::other("HTTP/2 proxy result channel closed").into()),
        Err(_) => Err(io::Error::other("HTTP/2 proxy result wait timed out").into()),
    }
}

fn http1_proxy_config(upstream_addr: SocketAddr) -> Http1ProxyConfig {
    Http1ProxyConfig::new(UpstreamTarget::new("http1-upstream", upstream_addr))
}

fn http2_proxy_config(upstream_addr: SocketAddr) -> Http2ProxyConfig {
    Http2ProxyConfig::new(UpstreamTarget::new("http2-upstream", upstream_addr))
}

fn current_rss_kib() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", pid.as_str()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.trim().parse::<u64>().ok()
}

pub fn run_or_exit<T>(result: Result<T, DynError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("performance harness failed: {error}");
            std::process::exit(1);
        }
    }
}

pub async fn shutdown_listener(handle: ListenerHandle) -> Result<(), DynError> {
    handle.shutdown().await?;
    Ok(())
}