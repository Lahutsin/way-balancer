async fn relay_upgraded_streams<S>(
    downstream: &mut S,
    downstream_buffer: &mut Vec<u8>,
    upstream: &mut TcpStream,
    upstream_buffer: &mut Vec<u8>,
    idle_timeout: Duration,
) -> Result<(), Http1ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !downstream_buffer.is_empty() {
        upstream.write_all(downstream_buffer).await.map_err(Http1ProxyError::RequestIo)?;
        downstream_buffer.clear();
    }
    if !upstream_buffer.is_empty() {
        downstream.write_all(upstream_buffer).await.map_err(Http1ProxyError::ResponseIo)?;
        upstream_buffer.clear();
    }

    let (mut downstream_reader, mut downstream_writer) = tokio::io::split(downstream);
    let (mut upstream_reader, mut upstream_writer) = upstream.split();

    tokio::try_join!(
        relay_upgrade_direction(
            &mut downstream_reader,
            &mut upstream_writer,
            idle_timeout,
            RelayDirection::Request,
        ),
        relay_upgrade_direction(
            &mut upstream_reader,
            &mut downstream_writer,
            idle_timeout,
            RelayDirection::Response,
        ),
    )?;
    Ok(())
}

async fn relay_upgrade_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 8192];
    loop {
        let read_result = time::timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| relay_idle_timeout_error(direction))?;
        let bytes_read = read_result.map_err(|source| relay_io_error(direction, source))?;
        if bytes_read == 0 {
            writer.shutdown().await.map_err(|source| relay_io_error(direction, source))?;
            return Ok(());
        }
        writer
            .write_all(&buffer[..bytes_read])
            .await
            .map_err(|source| relay_io_error(direction, source))?;
    }
}

fn relay_idle_timeout_error(direction: RelayDirection) -> Http1ProxyError {
    match direction {
        RelayDirection::Request | RelayDirection::Response => {
            Http1ProxyError::IdleTimeout("upgrade tunnel")
        }
    }
}

fn relay_io_error(direction: RelayDirection, source: std::io::Error) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::RequestIo(source),
        RelayDirection::Response => Http1ProxyError::ResponseIo(source),
    }
}

