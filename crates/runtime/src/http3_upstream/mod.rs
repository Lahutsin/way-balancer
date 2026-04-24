use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client as h3_client;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};

fn test_root_certificates_store() -> &'static Mutex<Vec<Vec<u8>>> {
    static TEST_ROOT_CERTIFICATES: OnceLock<Mutex<Vec<Vec<u8>>>> = OnceLock::new();
    TEST_ROOT_CERTIFICATES.get_or_init(|| Mutex::new(Vec::new()))
}

fn test_root_certificates() -> Vec<Vec<u8>> {
    let guard = test_root_certificates_store()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

#[doc(hidden)]
pub fn set_http3_test_root_certificates(certificates: Vec<Vec<u8>>) {
    let mut guard = test_root_certificates_store()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = certificates;
}

#[doc(hidden)]
pub fn clear_http3_test_root_certificates() {
    let mut guard = test_root_certificates_store()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clear();
}

/// Buffered HTTP response returned by the HTTP/3 upstream bridge path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http3BridgeResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<lb_proto_http::HttpHeader>,
    pub body: Vec<u8>,
}

/// Stable failures for one-shot HTTP/3 upstream dispatch.
#[derive(Debug)]
pub enum Http3UpstreamError {
    InvalidRequestTarget,
    InvalidRequest,
    ConnectTimeout,
    ConnectFailed,
    GracefulDrain,
    HandshakeFailed,
    RequestTimeout,
    RequestFailed,
    ResponseTimeout,
    ResponseFailed,
}

impl std::fmt::Display for Http3UpstreamError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequestTarget => formatter.write_str("invalid HTTP request target"),
            Self::InvalidRequest => formatter.write_str("invalid HTTP/3 upstream request"),
            Self::ConnectTimeout => formatter.write_str("HTTP/3 upstream connect timeout"),
            Self::ConnectFailed => formatter.write_str("HTTP/3 upstream connect failed"),
            Self::GracefulDrain => formatter.write_str("HTTP/3 upstream graceful drain"),
            Self::HandshakeFailed => formatter.write_str("HTTP/3 upstream handshake failed"),
            Self::RequestTimeout => formatter.write_str("HTTP/3 upstream request timeout"),
            Self::RequestFailed => formatter.write_str("HTTP/3 upstream request failed"),
            Self::ResponseTimeout => formatter.write_str("HTTP/3 upstream response timeout"),
            Self::ResponseFailed => formatter.write_str("HTTP/3 upstream response failed"),
        }
    }
}

impl std::error::Error for Http3UpstreamError {}

/// Dispatches one HTTP request to an explicit HTTP/3 upstream and buffers the response.
pub async fn dispatch_http3_upstream_request(
    upstream: &lb_net_core::UpstreamTarget,
    method: &str,
    target: &str,
    headers: &[lb_proto_http::HttpHeader],
    body: &[u8],
    effective_client_ip: IpAddr,
    connect_timeout: Duration,
    idle_timeout: Duration,
) -> Result<Http3BridgeResponse, Http3UpstreamError> {
    dispatch_http3_upstream_request_with_client_config(
        upstream,
        method,
        target,
        headers,
        body,
        effective_client_ip,
        connect_timeout,
        idle_timeout,
        default_quic_client_config(),
    )
    .await
}

async fn dispatch_http3_upstream_request_with_client_config(
    upstream: &lb_net_core::UpstreamTarget,
    method: &str,
    target: &str,
    headers: &[lb_proto_http::HttpHeader],
    body: &[u8],
    effective_client_ip: IpAddr,
    connect_timeout: Duration,
    idle_timeout: Duration,
    client_config: quinn::ClientConfig,
) -> Result<Http3BridgeResponse, Http3UpstreamError> {
    let authority = request_authority(headers).unwrap_or_else(|| upstream.address.to_string());
    let url = compose_upstream_url(target, &authority)?;
    let request = build_http3_request(method, &url, headers)?;
    let bind_addr = if upstream.address.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()
    .map_err(|_| Http3UpstreamError::ConnectFailed)?;

    let mut endpoint =
        quinn::Endpoint::client(bind_addr).map_err(|_| Http3UpstreamError::ConnectFailed)?;
    endpoint.set_default_client_config(client_config);

    let connect = endpoint
        .connect(upstream.address, &server_name_from_authority(&authority))
        .map_err(|_| Http3UpstreamError::ConnectFailed)?;
    let connection = tokio::time::timeout(connect_timeout, connect)
        .await
        .map_err(|_| Http3UpstreamError::ConnectTimeout)?
        .map_err(|_| Http3UpstreamError::ConnectFailed)?;

    let (_driver, mut send_request) = h3_client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|error| classify_http3_transport_error(&error, Http3UpstreamError::HandshakeFailed))?;

    let mut request_stream = tokio::time::timeout(idle_timeout, send_request.send_request(request))
        .await
        .map_err(|_| Http3UpstreamError::RequestTimeout)?
        .map_err(|error| classify_http3_transport_error(&error, Http3UpstreamError::RequestFailed))?;

    if !body.is_empty() {
        tokio::time::timeout(idle_timeout, request_stream.send_data(Bytes::copy_from_slice(body)))
            .await
            .map_err(|_| Http3UpstreamError::RequestTimeout)?
            .map_err(|error| classify_http3_transport_error(&error, Http3UpstreamError::RequestFailed))?;
    }
    tokio::time::timeout(idle_timeout, request_stream.finish())
        .await
        .map_err(|_| Http3UpstreamError::RequestTimeout)?
        .map_err(|error| classify_http3_transport_error(&error, Http3UpstreamError::RequestFailed))?;

    let response = tokio::time::timeout(idle_timeout, request_stream.recv_response())
        .await
        .map_err(|_| Http3UpstreamError::ResponseTimeout)?
        .map_err(|error| classify_http3_transport_error(&error, Http3UpstreamError::ResponseFailed))?;

    let status = response.status();
    let response_headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|raw| lb_proto_http::HttpHeader {
                name: name.as_str().to_ascii_lowercase(),
                value: raw.to_string(),
            })
        })
        .collect::<Vec<_>>();

    let mut response_body = Vec::new();
    loop {
        let chunk = tokio::time::timeout(idle_timeout, request_stream.recv_data())
            .await
            .map_err(|_| Http3UpstreamError::ResponseTimeout)?
            .map_err(|error| classify_http3_transport_error(&error, Http3UpstreamError::ResponseFailed))?;
        let Some(mut chunk) = chunk else {
            break;
        };
        let chunk_bytes = chunk.copy_to_bytes(chunk.remaining());
        response_body.extend_from_slice(&chunk_bytes);
    }

    endpoint.close(0u32.into(), b"done");
    let _ = effective_client_ip;

    Ok(Http3BridgeResponse {
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or("").to_string(),
        headers: response_headers,
        body: response_body,
    })
}

fn classify_http3_transport_error<E: std::fmt::Debug>(
    error: &E,
    fallback: Http3UpstreamError,
) -> Http3UpstreamError {
    if http3_error_is_graceful_drain(&format!("{error:?}")) {
        Http3UpstreamError::GracefulDrain
    } else {
        fallback
    }
}

fn http3_error_is_graceful_drain(debug_repr: &str) -> bool {
    let debug_repr = debug_repr.to_ascii_lowercase();
    debug_repr.contains("h3_no_error")
        || (debug_repr.contains("applicationclose")
            && (debug_repr.contains("error_code: 0")
                || debug_repr.contains("code: 0")
                || debug_repr.contains("no_error")))
        || (debug_repr.contains("goaway") && debug_repr.contains("no_error"))
}

fn build_http3_request(
    method: &str,
    url: &str,
    headers: &[lb_proto_http::HttpHeader],
) -> Result<http1::Request<()>, Http3UpstreamError> {
    let mut builder = http1::Request::builder().method(method).uri(url);
    for header in headers {
        if should_skip_request_header(&header.name) {
            continue;
        }
        builder = builder.header(header.name.as_str(), header.value.as_str());
    }
    builder.body(()).map_err(|_| Http3UpstreamError::InvalidRequest)
}

fn should_skip_request_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
}

fn server_name_from_authority(authority: &str) -> String {
    authority
        .split('@')
        .next_back()
        .unwrap_or(authority)
        .split(':')
        .next()
        .unwrap_or(authority)
        .trim_matches('[')
        .trim_matches(']')
        .to_string()
}

fn ensure_rustls_crypto_provider() {
    static PROVIDER: OnceLock<()> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn default_quic_client_config() -> quinn::ClientConfig {
    ensure_rustls_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let test_roots = test_root_certificates();
    roots.add_parsable_certificates(
        test_roots
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from),
    );

    let mut tls = RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = QuicClientConfig::try_from(Arc::new(tls))
        .expect("valid rustls client config for quic");
    quinn::ClientConfig::new(Arc::new(quic_config))
}

fn compose_upstream_url(target: &str, authority: &str) -> Result<String, Http3UpstreamError> {
    if target.starts_with("https://") {
        return Ok(target.to_string());
    }
    if target.starts_with("http://") || target.starts_with('*') {
        return Err(Http3UpstreamError::InvalidRequestTarget);
    }
    if target.starts_with('/') {
        Ok(format!("https://{authority}{target}"))
    } else {
        Ok(format!("https://{authority}/{target}"))
    }
}

fn request_authority(headers: &[lb_proto_http::HttpHeader]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.clone())
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use h3::server;
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig};
    use tokio::net::UdpSocket;

    use super::{
        classify_http3_transport_error, compose_upstream_url,
        dispatch_http3_upstream_request_with_client_config, ensure_rustls_crypto_provider,
        http3_error_is_graceful_drain, Http3UpstreamError,
    };

    #[test]
    fn compose_upstream_url_rejects_plaintext_and_asterisk_targets() {
        assert!(compose_upstream_url("http://example.com/", "example.com").is_err());
        assert!(compose_upstream_url("*", "example.com").is_err());
    }

    #[test]
    fn compose_upstream_url_builds_https_urls_from_origin_targets() {
        assert_eq!(
            compose_upstream_url("/api", "example.com:8443").expect("url"),
            "https://example.com:8443/api"
        );
        assert_eq!(
            compose_upstream_url("metrics", "example.com").expect("url"),
            "https://example.com/metrics"
        );
    }

    #[test]
    fn graceful_drain_detection_matches_h3_no_error_patterns() {
        assert!(http3_error_is_graceful_drain(
            "ConnectionError(ApplicationClose { error_code: 0, reason: \"H3_NO_ERROR\" })"
        ));
        assert!(http3_error_is_graceful_drain(
            "GoAway received with NO_ERROR from peer"
        ));
        assert!(!http3_error_is_graceful_drain(
            "ConnectionError(ApplicationClose { error_code: 268, reason: \"boom\" })"
        ));
    }

    #[test]
    fn graceful_drain_classification_overrides_fallback_error() {
        let graceful = classify_http3_transport_error(
            &"ConnectionError(ApplicationClose { error_code: 0, reason: \"H3_NO_ERROR\" })",
            Http3UpstreamError::ResponseFailed,
        );
        let ordinary = classify_http3_transport_error(
            &"ConnectionError(ApplicationClose { error_code: 268, reason: \"boom\" })",
            Http3UpstreamError::ResponseFailed,
        );

        assert!(matches!(graceful, Http3UpstreamError::GracefulDrain));
        assert!(matches!(ordinary, Http3UpstreamError::ResponseFailed));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatch_http3_upstream_request_success_roundtrip() -> Result<(), Box<dyn Error>> {
        let (server_addr, cert_der, _server_task) = spawn_test_h3_server().await?;
        let client_config = test_quic_client_config_with_ca(&cert_der)?;
        let upstream = lb_net_core::UpstreamTarget::with_transport(
            "h3-test",
            server_addr,
            lb_net_core::UpstreamTransport::Http3,
        );
        let response = dispatch_http3_upstream_request_with_client_config(
            &upstream,
            "GET",
            "/ready",
            &[lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: format!("localhost:{}", server_addr.port()),
            }],
            &[],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_secs(2),
            Duration::from_secs(2),
            client_config,
        )
        .await?;

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"h3-ok");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatch_http3_upstream_request_connect_failure_is_classified() -> Result<(), Box<dyn Error>> {
        let client_config = test_quic_client_config_with_default_roots();
        let unreachable = SocketAddr::from(([127, 0, 0, 1], 1));
        let upstream = lb_net_core::UpstreamTarget::with_transport(
            "h3-fail",
            unreachable,
            lb_net_core::UpstreamTransport::Http3,
        );

        let result = dispatch_http3_upstream_request_with_client_config(
            &upstream,
            "GET",
            "/ready",
            &[lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: String::from("localhost:1"),
            }],
            &[],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(200),
            Duration::from_millis(200),
            client_config,
        )
        .await;

        assert!(matches!(
            result,
            Err(Http3UpstreamError::ConnectFailed) | Err(Http3UpstreamError::ConnectTimeout)
        ));
        Ok(())
    }

    fn test_quic_client_config_with_default_roots() -> quinn::ClientConfig {
        ensure_rustls_crypto_provider();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls =
            RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).expect("client quic config");
        quinn::ClientConfig::new(Arc::new(quic))
    }

    fn test_quic_client_config_with_ca(
        cert_der: &CertificateDer<'static>,
    ) -> Result<quinn::ClientConfig, Box<dyn Error>> {
        ensure_rustls_crypto_provider();
        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone())?;
        let mut tls =
            RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))?;
        Ok(quinn::ClientConfig::new(Arc::new(quic)))
    }

    async fn spawn_test_h3_server(
    ) -> Result<(SocketAddr, CertificateDer<'static>, tokio::task::JoinHandle<()>), Box<dyn Error>> {
        ensure_rustls_crypto_provider();

        let certified = rcgen::generate_simple_self_signed(vec![String::from("localhost")])?;
        let cert_der = CertificateDer::from(certified.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        ));

        let mut rustls_server = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)?;
        rustls_server.alpn_protocols = vec![b"h3".to_vec()];

        let quic_server = QuicServerConfig::try_from(Arc::new(rustls_server))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = socket.local_addr()?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )?;

        let task = tokio::spawn(async move {
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            let Ok(connecting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = connecting.await else {
                return;
            };
            let Ok(mut h3_conn) = server::builder().build(h3_quinn::Connection::new(connection)).await else {
                return;
            };
            let Ok(Some(resolver)) = h3_conn.accept().await else {
                return;
            };
            let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                return;
            };

            let response = http1::Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(())
                .expect("valid response");
            if stream.send_response(response).await.is_err() {
                return;
            }
            if stream
                .send_data(Bytes::from_static(b"h3-ok"))
                .await
                .is_err()
            {
                return;
            }
            let _ = stream.finish().await;
            // Keep session alive briefly so client can reliably consume response before close.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        Ok((server_addr, cert_der, task))
    }
}