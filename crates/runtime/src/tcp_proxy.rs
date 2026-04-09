use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

/// Runtime configuration for a single TCP proxy session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpProxyConfig {
    /// Static upstream target for the proxy session.
    pub upstream: lb_net_core::UpstreamTarget,
    /// Timeout model for connect, preface inspection and idle reads.
    pub timeouts: lb_net_core::ConnectionTimeouts,
    /// TLS operating mode for this session.
    pub tls_mode: lb_proto_tls::TlsMode,
    /// Whether to inspect the downstream preface for TLS passthrough classification.
    pub inspect_tls_client_hello: bool,
    /// Future-facing TLS termination foundation.
    pub termination_config: Option<lb_proto_tls::TlsTerminationConfig>,
}

impl TcpProxyConfig {
    /// Creates a passthrough TCP proxy configuration for a static upstream target.
    #[must_use]
    pub fn passthrough(upstream: lb_net_core::UpstreamTarget) -> Self {
        Self {
            upstream,
            timeouts: lb_net_core::ConnectionTimeouts::default(),
            tls_mode: lb_proto_tls::TlsMode::Passthrough,
            inspect_tls_client_hello: true,
            termination_config: None,
        }
    }
}

/// Stable connection event categories for L4 proxy observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEventKind {
    /// Downstream session metadata was established.
    SessionStarted,
    /// Upstream connection completed.
    UpstreamConnected,
    /// Bidirectional forwarding completed cleanly.
    Completed,
}

/// Connection metadata captured for a proxied session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMetadata {
    /// Downstream peer address.
    pub downstream_addr: SocketAddr,
    /// Upstream socket address.
    pub upstream_addr: SocketAddr,
    /// Human-readable upstream name.
    pub upstream_name: String,
    /// TLS classification outcome if inspection was enabled.
    pub tls_classification: Option<lb_proto_tls::TlsClientHelloClassification>,
    /// TLS mode configured for the session.
    pub tls_mode: lb_proto_tls::TlsMode,
}

/// Context for a completed proxy session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionContext {
    /// Session metadata.
    pub metadata: ConnectionMetadata,
    /// Ordered connection lifecycle events.
    pub events: Vec<ConnectionEventKind>,
}

/// Result of a completed TCP proxy session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySessionReport {
    /// Connection context and lifecycle summary.
    pub context: ConnectionContext,
    /// Time spent connecting to the upstream target.
    pub connect_duration: Duration,
    /// Bytes transferred from downstream to upstream.
    pub downstream_to_upstream_bytes: u64,
    /// Bytes transferred from upstream to downstream.
    pub upstream_to_downstream_bytes: u64,
}

/// Errors returned by the TCP proxy runtime.
#[derive(Debug)]
pub enum TcpProxyError {
    /// TLS termination is configured but not implemented in this feature.
    TlsTerminationNotImplemented,
    /// Upstream connect exceeded the configured timeout.
    ConnectTimeout { target: SocketAddr },
    /// Upstream connect failed with an I/O error.
    Connect { target: SocketAddr, source: std::io::Error },
    /// Downstream preface inspection exceeded the configured timeout.
    PrefaceTimeout,
    /// Downstream preface inspection failed.
    PrefaceRead(std::io::Error),
    /// TLS preface inspection found malformed bytes.
    TlsInspect(lb_proto_tls::TlsInspectError),
    /// A relay direction was idle for too long.
    IdleTimeout(&'static str),
    /// I/O failure while relaying traffic.
    RelayIo {
        /// Human-readable direction label.
        direction: &'static str,
        /// Underlying I/O source.
        source: std::io::Error,
    },
}

impl fmt::Display for TcpProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsTerminationNotImplemented => {
                formatter.write_str("TLS termination foundation is not implemented yet")
            }
            Self::ConnectTimeout { target } => {
                write!(formatter, "timed out connecting to upstream {target}")
            }
            Self::Connect { target, source } => {
                write!(formatter, "failed to connect to upstream {target}: {source}")
            }
            Self::PrefaceTimeout => formatter.write_str("timed out waiting for downstream preface"),
            Self::PrefaceRead(source) => {
                write!(formatter, "failed reading downstream preface: {source}")
            }
            Self::TlsInspect(source) => {
                write!(formatter, "failed inspecting TLS preface: {source}")
            }
            Self::IdleTimeout(direction) => {
                write!(formatter, "idle timeout exceeded for {direction}")
            }
            Self::RelayIo { direction, source } => {
                write!(formatter, "relay I/O failed for {direction}: {source}")
            }
        }
    }
}

impl std::error::Error for TcpProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect { source, .. } => Some(source),
            Self::PrefaceRead(source) => Some(source),
            Self::TlsInspect(source) => Some(source),
            Self::RelayIo { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Proxies a single downstream TCP stream to a configured upstream target.
pub async fn proxy_tcp_stream(
    mut downstream: TcpStream,
    config: &TcpProxyConfig,
) -> Result<ProxySessionReport, TcpProxyError> {
    if config.tls_mode == lb_proto_tls::TlsMode::Termination {
        return Err(TcpProxyError::TlsTerminationNotImplemented);
    }

    let downstream_addr = downstream.peer_addr().map_err(TcpProxyError::PrefaceRead)?;
    let mut events = vec![ConnectionEventKind::SessionStarted];
    let tls_classification = if config.inspect_tls_client_hello {
        Some(inspect_downstream_preface(&mut downstream, config.timeouts.preface_timeout).await?)
    } else {
        None
    };

    let connect_started = Instant::now();
    let upstream =
        time::timeout(config.timeouts.connect_timeout, TcpStream::connect(config.upstream.address))
            .await
            .map_err(|_| TcpProxyError::ConnectTimeout { target: config.upstream.address })?
            .map_err(|source| TcpProxyError::Connect { target: config.upstream.address, source })?;
    let connect_duration = connect_started.elapsed();
    let upstream_addr = upstream
        .peer_addr()
        .map_err(|source| TcpProxyError::Connect { target: config.upstream.address, source })?;
    events.push(ConnectionEventKind::UpstreamConnected);

    let (mut downstream_reader, mut downstream_writer) = downstream.into_split();
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    let idle_timeout = config.timeouts.idle_timeout;
    let (downstream_to_upstream_bytes, upstream_to_downstream_bytes) = tokio::try_join!(
        relay_direction(
            &mut downstream_reader,
            &mut upstream_writer,
            idle_timeout,
            "downstream->upstream",
        ),
        relay_direction(
            &mut upstream_reader,
            &mut downstream_writer,
            idle_timeout,
            "upstream->downstream",
        ),
    )?;
    events.push(ConnectionEventKind::Completed);

    Ok(ProxySessionReport {
        context: ConnectionContext {
            metadata: ConnectionMetadata {
                downstream_addr,
                upstream_addr,
                upstream_name: config.upstream.name.clone(),
                tls_classification,
                tls_mode: config.tls_mode,
            },
            events,
        },
        connect_duration,
        downstream_to_upstream_bytes,
        upstream_to_downstream_bytes,
    })
}

async fn inspect_downstream_preface(
    downstream: &mut TcpStream,
    preface_timeout: Duration,
) -> Result<lb_proto_tls::TlsClientHelloClassification, TcpProxyError> {
    let mut preface = [0_u8; 1024];
    let peeked = time::timeout(preface_timeout, downstream.peek(&mut preface))
        .await
        .map_err(|_| TcpProxyError::PrefaceTimeout)?
        .map_err(TcpProxyError::PrefaceRead)?;

    lb_proto_tls::inspect_client_hello(&preface[..peeked]).map_err(TcpProxyError::TlsInspect)
}

async fn relay_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
    direction: &'static str,
) -> Result<u64, TcpProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0_u64;
    let mut buffer = [0_u8; 8192];

    loop {
        let read_result = time::timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| TcpProxyError::IdleTimeout(direction))?;
        let bytes_read =
            read_result.map_err(|source| TcpProxyError::RelayIo { direction, source })?;

        if bytes_read == 0 {
            writer
                .shutdown()
                .await
                .map_err(|source| TcpProxyError::RelayIo { direction, source })?;
            return Ok(transferred);
        }

        writer
            .write_all(&buffer[..bytes_read])
            .await
            .map_err(|source| TcpProxyError::RelayIo { direction, source })?;
        transferred += u64::try_from(bytes_read).unwrap_or(u64::MAX);
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{relay_direction, TcpProxyConfig, TcpProxyError};

    #[test]
    fn passthrough_config_uses_safe_defaults() {
        let config = TcpProxyConfig::passthrough(lb_net_core::UpstreamTarget::new(
            "upstream",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        ));

        assert_eq!(config.tls_mode, lb_proto_tls::TlsMode::Passthrough);
        assert!(config.inspect_tls_client_hello);
        assert_eq!(config.termination_config, None);
    }

    #[test]
    fn tcp_proxy_errors_render_sources() {
        let connect = TcpProxyError::Connect {
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            source: io::Error::other("connect failed"),
        };
        let relay = TcpProxyError::RelayIo {
            direction: "upstream->downstream",
            source: io::Error::other("relay failed"),
        };

        assert!(connect.to_string().contains("failed to connect to upstream"));
        assert!(relay.to_string().contains("relay I/O failed"));
        assert!(std::error::Error::source(&connect).is_some());
        assert!(std::error::Error::source(&relay).is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_direction_transfers_bytes_and_shutdowns_cleanly(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut sink_reader, mut writer) = tokio::io::duplex(64);

        feeder.write_all(b"hello").await?;
        feeder.shutdown().await?;

        let transferred = relay_direction(
            &mut reader,
            &mut writer,
            Duration::from_millis(50),
            "downstream->upstream",
        )
        .await?;

        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;

        assert_eq!(transferred, 5);
        assert_eq!(output, b"hello");
        Ok(())
    }
}
