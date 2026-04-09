use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use lb_net_core::{ConnectionTimeouts, UpstreamTarget};
use lb_proto_tls::TlsClientHelloClassification;
use lb_runtime::{proxy_tcp_stream, ProxySessionReport, TcpProxyConfig, TcpProxyError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_tcp_bidirectionally() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_echo_server().await?;
    let (proxy_addr, result_rx) =
        spawn_one_shot_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(b"ping").await?;
    let mut buffer = [0_u8; 4];
    client.read_exact(&mut buffer).await?;
    assert_eq!(&buffer, b"ping");
    drop(client);

    let report = receive_proxy_result(result_rx).await?;
    assert_eq!(report.downstream_to_upstream_bytes, 4);
    assert_eq!(report.upstream_to_downstream_bytes, 4);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preserves_half_close_behavior() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_collect_then_reply_server().await?;
    let (proxy_addr, result_rx) =
        spawn_one_shot_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(b"half-close").await?;
    client.shutdown().await?;

    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    assert_eq!(response, b"half-close");
    drop(client);

    let report = receive_proxy_result(result_rx).await?;
    assert_eq!(report.downstream_to_upstream_bytes, 10);
    assert_eq!(report.upstream_to_downstream_bytes, 10);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_upstream_failure() -> Result<(), Box<dyn std::error::Error>> {
    let target = unused_local_address()?;
    let (proxy_addr, result_rx) = spawn_one_shot_proxy_listener(proxy_config(target)).await?;

    let client = TcpStream::connect(proxy_addr).await?;
    drop(client);

    let result = receive_proxy_result(result_rx).await;
    assert!(matches!(result, Err(TcpProxyError::Connect { .. })));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_timeout_is_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_server().await?;
    let mut config = proxy_config(upstream_addr);
    config.inspect_tls_client_hello = false;
    config.timeouts = ConnectionTimeouts {
        connect_timeout: Duration::from_secs(1),
        preface_timeout: Duration::from_millis(100),
        idle_timeout: Duration::from_millis(100),
    };
    let (proxy_addr, result_rx) = spawn_one_shot_proxy_listener(config).await?;

    let client = TcpStream::connect(proxy_addr).await?;
    let result = receive_proxy_result(result_rx).await;
    drop(client);

    assert!(matches!(result, Err(TcpProxyError::IdleTimeout(_))));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_passthrough_is_classified() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_echo_server().await?;
    let (proxy_addr, result_rx) =
        spawn_one_shot_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(&build_client_hello(Some("example.com"))).await?;
    client.shutdown().await?;
    let mut sink = Vec::new();
    let _ = client.read_to_end(&mut sink).await?;
    drop(client);

    let report = receive_proxy_result(result_rx).await?;
    assert!(matches!(
        report.context.metadata.tls_classification,
        Some(TlsClientHelloClassification::ClientHello(_))
    ));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_churn_smoke_test() -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..12 {
        let upstream_addr = spawn_echo_server().await?;
        let (proxy_addr, result_rx) =
            spawn_one_shot_proxy_listener(proxy_config(upstream_addr)).await?;

        let mut client = TcpStream::connect(proxy_addr).await?;
        client.write_all(b"ok").await?;
        let mut buffer = [0_u8; 2];
        client.read_exact(&mut buffer).await?;
        assert_eq!(&buffer, b"ok");
        drop(client);

        let report = receive_proxy_result(result_rx).await?;
        assert_eq!(report.downstream_to_upstream_bytes, 2);
        assert_eq!(report.upstream_to_downstream_bytes, 2);
    }

    Ok(())
}

async fn spawn_echo_server() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0_u8; 4096];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(bytes_read) => {
                        if stream.write_all(&buffer[..bytes_read]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });

    Ok(address)
}

async fn spawn_collect_then_reply_server() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = Vec::new();
            let _ = stream.read_to_end(&mut buffer).await;
            let _ = stream.write_all(&buffer).await;
            let _ = stream.shutdown().await;
        }
    });

    Ok(address)
}

async fn spawn_idle_server() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((_stream, _)) = listener.accept().await {
            time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(address)
}

async fn spawn_one_shot_proxy_listener(
    config: TcpProxyConfig,
) -> io::Result<(SocketAddr, oneshot::Receiver<Result<ProxySessionReport, TcpProxyError>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = match listener.accept().await {
            Ok((downstream, _)) => proxy_tcp_stream(downstream, &config).await,
            Err(error) => Err(TcpProxyError::RelayIo { direction: "proxy-accept", source: error }),
        };
        let _ = result_tx.send(result);
    });

    Ok((address, result_rx))
}

async fn receive_proxy_result(
    result_rx: oneshot::Receiver<Result<ProxySessionReport, TcpProxyError>>,
) -> Result<ProxySessionReport, TcpProxyError> {
    match time::timeout(Duration::from_secs(2), result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(TcpProxyError::IdleTimeout("proxy result channel closed")),
        Err(_) => Err(TcpProxyError::IdleTimeout("proxy result wait")),
    }
}

fn proxy_config(upstream_addr: SocketAddr) -> TcpProxyConfig {
    TcpProxyConfig::passthrough(UpstreamTarget::new("echo", upstream_addr))
}

fn unused_local_address() -> io::Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

fn build_client_hello(server_name: Option<&str>) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0_u8; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0x00, 0x02]);
    hello.extend_from_slice(&[0x13, 0x01]);
    hello.push(1);
    hello.push(0);

    let mut extensions = Vec::new();
    if let Some(name) = server_name {
        let mut server_name_extension = Vec::new();
        let name_bytes = name.as_bytes();
        let list_len = u16::try_from(1 + 2 + name_bytes.len()).unwrap_or(u16::MAX);
        server_name_extension.extend_from_slice(&list_len.to_be_bytes());
        server_name_extension.push(0);
        let name_len = u16::try_from(name_bytes.len()).unwrap_or(u16::MAX);
        server_name_extension.extend_from_slice(&name_len.to_be_bytes());
        server_name_extension.extend_from_slice(name_bytes);

        extensions.extend_from_slice(&0_u16.to_be_bytes());
        let extension_len = u16::try_from(server_name_extension.len()).unwrap_or(u16::MAX);
        extensions.extend_from_slice(&extension_len.to_be_bytes());
        extensions.extend_from_slice(&server_name_extension);
    }

    let extensions_len = u16::try_from(extensions.len()).unwrap_or(u16::MAX);
    hello.extend_from_slice(&extensions_len.to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    let hello_len = u32::try_from(hello.len()).unwrap_or(u32::MAX);
    handshake.push(((hello_len >> 16) & 0xff) as u8);
    handshake.push(((hello_len >> 8) & 0xff) as u8);
    handshake.push((hello_len & 0xff) as u8);
    handshake.extend_from_slice(&hello);

    let mut record = Vec::new();
    record.push(22);
    record.extend_from_slice(&[0x03, 0x01]);
    let handshake_len = u16::try_from(handshake.len()).unwrap_or(u16::MAX);
    record.extend_from_slice(&handshake_len.to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}
