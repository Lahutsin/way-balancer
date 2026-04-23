async fn resolve_downstream_addr_from_proxy_protocol(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    mode: lb_config_model::ProxyProtocolModeConfig,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    let source_addr = match mode {
        lb_config_model::ProxyProtocolModeConfig::Disabled => None,
        lb_config_model::ProxyProtocolModeConfig::V1 => {
            time::timeout(timeout, read_proxy_protocol_v1(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy protocol v1 timeout"))??
        }
        lb_config_model::ProxyProtocolModeConfig::V2 => {
            time::timeout(timeout, read_proxy_protocol_v2(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy protocol v2 timeout"))??
        }
    };
    Ok(source_addr.unwrap_or(peer_addr))
}

async fn read_proxy_protocol_v1(stream: &mut TcpStream) -> io::Result<Option<SocketAddr>> {
    let mut line = Vec::with_capacity(PROXY_PROTOCOL_V1_MAX_LEN);
    loop {
        if line.len() >= PROXY_PROTOCOL_V1_MAX_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy protocol v1 header too long",
            ));
        }
        let byte = stream.read_u8().await?;
        line.push(byte);
        if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
            break;
        }
    }
    parse_proxy_protocol_v1_line(&line)
}

async fn read_proxy_protocol_v2(stream: &mut TcpStream) -> io::Result<Option<SocketAddr>> {
    let mut header = [0_u8; 16];
    stream.read_exact(&mut header).await?;
    let payload_len = parse_proxy_protocol_v2_header(&header)?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    parse_proxy_protocol_v2_payload(&header, &payload)
}

fn parse_proxy_protocol_v1_line(line: &[u8]) -> io::Result<Option<SocketAddr>> {
    let line = std::str::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 utf8"))?;
    let line = line
        .strip_suffix("\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 newline"))?;
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 || parts[0] != "PROXY" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v1 preface",
        ));
    }
    match parts[1] {
        "UNKNOWN" => Ok(None),
        "TCP4" | "TCP6" => {
            if parts.len() != 6 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy protocol v1 address fields",
                ));
            }
            let source_ip: IpAddr = parts[2]
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 source ip"))?;
            let _destination_ip: IpAddr = parts[3].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 destination ip")
            })?;
            let source_port: u16 = parts[4].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 source port")
            })?;
            let _destination_port: u16 = parts[5].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 destination port")
            })?;
            Ok(Some(SocketAddr::new(source_ip, source_port)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v1 transport",
        )),
    }
}

fn parse_proxy_protocol_v2_header(header: &[u8; 16]) -> io::Result<usize> {
    if header[..12] != PROXY_PROTOCOL_V2_SIGNATURE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v2 signature",
        ));
    }
    if header[12] >> 4 != 0x2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v2 version",
        ));
    }
    Ok(u16::from_be_bytes([header[14], header[15]]) as usize)
}

fn parse_proxy_protocol_v2_payload(
    header: &[u8; 16],
    payload: &[u8],
) -> io::Result<Option<SocketAddr>> {
    let command = header[12] & 0x0f;
    if command == 0x00 {
        return Ok(None);
    }
    if command != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v2 command",
        ));
    }
    match header[13] {
        0x11 => {
            if payload.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy protocol v2 ipv4 payload",
                ));
            }
            let source_ip = IpAddr::from([payload[0], payload[1], payload[2], payload[3]]);
            let source_port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(SocketAddr::new(source_ip, source_port)))
        }
        0x21 => {
            if payload.len() < 36 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy protocol v2 ipv6 payload",
                ));
            }
            let mut source = [0_u8; 16];
            source.copy_from_slice(&payload[..16]);
            let source_port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(SocketAddr::new(IpAddr::from(source), source_port)))
        }
        0x00 => Ok(None),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v2 transport",
        )),
    }
}

async fn await_managed_listener_ready(
    listener: ManagedServeListener,
    ready_rx: oneshot::Receiver<()>,
) -> Result<ManagedServeListener, DynError> {
    match ready_rx.await {
        Ok(()) => Ok(listener),
        Err(_) => {
            let _ = listener.shutdown_tx.send(true);
            match listener.join().await {
                Ok(_) => Err(to_dyn_error("listener exited before becoming ready")),
                Err(error) => Err(to_dyn_error(error)),
            }
        }
    }
}

