async fn resolve_downstream_addr_from_proxy_protocol(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    mode: lb_config_model::ProxyProtocolModeConfig,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    let source_addr = match mode {
        lb_config_model::ProxyProtocolModeConfig::Disabled => None,
        lb_config_model::ProxyProtocolModeConfig::V1 => {
            time::timeout(timeout, read_proxy_protocol_v1(stream)).await.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "proxy protocol v1 timeout")
            })??
        }
        lb_config_model::ProxyProtocolModeConfig::V2 => {
            time::timeout(timeout, read_proxy_protocol_v2(stream)).await.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "proxy protocol v2 timeout")
            })??
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
        return Err(io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 preface"));
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
            let source_ip: IpAddr = parts[2].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 source ip")
            })?;
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
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 transport")),
    }
}

fn parse_proxy_protocol_v2_header(header: &[u8; 16]) -> io::Result<usize> {
    if header[..12] != PROXY_PROTOCOL_V2_SIGNATURE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v2 signature"));
    }
    if header[12] >> 4 != 0x2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v2 version"));
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
        return Err(io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v2 command"));
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
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v2 transport")),
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

#[cfg(test)]
mod proxy_protocol_tests {
    use super::{
        parse_proxy_protocol_v1_line, parse_proxy_protocol_v2_header,
        parse_proxy_protocol_v2_payload, read_proxy_protocol_v1, read_proxy_protocol_v2,
        PROXY_PROTOCOL_V2_SIGNATURE,
    };
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn parses_v1_addresses_unknown_and_malformed_headers() {
        assert_eq!(
            parse_proxy_protocol_v1_line(b"PROXY TCP4 192.0.2.1 192.0.2.2 4312 80\r\n").unwrap(),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 4312))
        );
        assert_eq!(
            parse_proxy_protocol_v1_line(b"PROXY TCP6 2001:db8::1 2001:db8::2 443 8443\r\n")
                .unwrap(),
            Some(SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 443))
        );
        assert_eq!(parse_proxy_protocol_v1_line(b"PROXY UNKNOWN\r\n").unwrap(), None);
        for malformed in [
            &b"not proxy\r\n"[..],
            b"PROXY TCP4 192.0.2.1 192.0.2.2 80\r\n",
            b"PROXY TCP4 bad 192.0.2.2 80 80\r\n",
            b"PROXY TCP4 192.0.2.1 bad 80 80\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 bad 80\r\n",
            b"PROXY TCP4 192.0.2.1 192.0.2.2 80 bad\r\n",
            b"PROXY UDP4 192.0.2.1 192.0.2.2 80 80\r\n",
            b"PROXY UNKNOWN\n",
            b"\xff\r\n",
        ] {
            assert_eq!(
                parse_proxy_protocol_v1_line(malformed).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn parses_v2_ipv4_ipv6_local_command_and_rejects_invalid_frames() {
        let mut header = [0_u8; 16];
        assert!(parse_proxy_protocol_v2_header(&header).is_err());
        header[..12].copy_from_slice(&PROXY_PROTOCOL_V2_SIGNATURE);
        header[12] = 0x11;
        assert!(parse_proxy_protocol_v2_header(&header).is_err());
        header[12] = 0x21;
        header[13] = 0x11;
        header[14..].copy_from_slice(&12_u16.to_be_bytes());
        assert_eq!(parse_proxy_protocol_v2_header(&header).unwrap(), 12);
        let mut v4 = [0_u8; 12];
        v4[..4].copy_from_slice(&[198, 51, 100, 7]);
        v4[8..10].copy_from_slice(&5432_u16.to_be_bytes());
        assert_eq!(
            parse_proxy_protocol_v2_payload(&header, &v4).unwrap(),
            Some("198.51.100.7:5432".parse().unwrap())
        );
        assert!(parse_proxy_protocol_v2_payload(&header, &[0; 11]).is_err());

        header[13] = 0x21;
        let mut v6 = [0_u8; 36];
        v6[..16].copy_from_slice(&"2001:db8::8".parse::<Ipv6Addr>().unwrap().octets());
        v6[32..34].copy_from_slice(&8443_u16.to_be_bytes());
        assert_eq!(
            parse_proxy_protocol_v2_payload(&header, &v6).unwrap(),
            Some("[2001:db8::8]:8443".parse().unwrap())
        );
        assert!(parse_proxy_protocol_v2_payload(&header, &[0; 35]).is_err());

        header[12] = 0x20;
        assert_eq!(parse_proxy_protocol_v2_payload(&header, &[]).unwrap(), None);
        header[12] = 0x21;
        header[13] = 0x00;
        assert_eq!(parse_proxy_protocol_v2_payload(&header, &[]).unwrap(), None);
        header[12] = 0x23;
        assert!(parse_proxy_protocol_v2_payload(&header, &[]).is_err());
        header[12] = 0x21;
        header[13] = 0x31;
        assert!(parse_proxy_protocol_v2_payload(&header, &[0; 36]).is_err());
    }

    #[tokio::test]
    async fn stream_readers_consume_proxy_preambles_and_leave_following_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(b"PROXY UNKNOWN\r\npayload").await.unwrap();
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_proxy_protocol_v1(&mut stream).await.unwrap(), None);
        let mut payload = [0_u8; 7];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
        sender.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let mut header = [0_u8; 16];
            header[..12].copy_from_slice(&PROXY_PROTOCOL_V2_SIGNATURE);
            header[12] = 0x21;
            header[13] = 0x11;
            header[14..].copy_from_slice(&12_u16.to_be_bytes());
            let mut payload = [0_u8; 12];
            payload[..4].copy_from_slice(&[203, 0, 113, 10]);
            payload[8..10].copy_from_slice(&3210_u16.to_be_bytes());
            client.write_all(&header).await.unwrap();
            client.write_all(&payload).await.unwrap();
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(
            read_proxy_protocol_v2(&mut stream).await.unwrap(),
            Some("203.0.113.10:3210".parse().unwrap())
        );
        sender.await.unwrap();
    }
}
