#[derive(Clone, Copy)]
enum RelayDirection {
    Request,
    Response,
}

async fn relay_body<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    body_kind: &lb_proto_http::BodyKind,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body_kind {
        lb_proto_http::BodyKind::None => Ok(()),
        lb_proto_http::BodyKind::ContentLength(length) => {
            if *length > max_body_bytes {
                return Err(body_limit_error(direction));
            }
            relay_content_length(reader, read_buffer, writer, *length, idle_timeout, direction)
                .await
        }
        lb_proto_http::BodyKind::Chunked => {
            relay_chunked(reader, read_buffer, writer, max_body_bytes, idle_timeout, direction)
                .await
        }
    }
}

async fn relay_content_length<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    length: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = usize::try_from(length).unwrap_or(usize::MAX);

    if !read_buffer.is_empty() {
        let buffered = remaining.min(read_buffer.len());
        writer
            .write_all(&read_buffer[..buffered])
            .await
            .map_err(|source| io_error(direction, source))?;
        read_buffer.drain(..buffered);
        remaining = remaining.saturating_sub(buffered);
    }

    let mut chunk = [0_u8; 8192];
    while remaining != 0 {
        let to_read = remaining.min(chunk.len());
        let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk[..to_read]))
            .await
            .map_err(|_| idle_error(direction))?
            .map_err(|source| io_error(direction, source))?;
        if bytes_read == 0 {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::IncompleteHead,
            ));
        }

        writer
            .write_all(&chunk[..bytes_read])
            .await
            .map_err(|source| io_error(direction, source))?;
        remaining = remaining.saturating_sub(bytes_read);
    }

    Ok(())
}

async fn relay_content_length_collect<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    length: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<bytes::Bytes, Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = usize::try_from(length).unwrap_or(usize::MAX);
    let mut collected = Vec::with_capacity(remaining.min(8192));

    if !read_buffer.is_empty() {
        let buffered = remaining.min(read_buffer.len());
        writer
            .write_all(&read_buffer[..buffered])
            .await
            .map_err(|source| io_error(direction, source))?;
        collected.extend_from_slice(&read_buffer[..buffered]);
        read_buffer.drain(..buffered);
        remaining = remaining.saturating_sub(buffered);
    }

    let mut chunk = [0_u8; 8192];
    while remaining != 0 {
        let to_read = remaining.min(chunk.len());
        let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk[..to_read]))
            .await
            .map_err(|_| idle_error(direction))?
            .map_err(|source| io_error(direction, source))?;
        if bytes_read == 0 {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::IncompleteHead,
            ));
        }

        writer
            .write_all(&chunk[..bytes_read])
            .await
            .map_err(|source| io_error(direction, source))?;
        collected.extend_from_slice(&chunk[..bytes_read]);
        remaining = remaining.saturating_sub(bytes_read);
    }

    Ok(bytes::Bytes::from(collected))
}

async fn relay_chunked<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total_body_bytes = 0_u64;

    loop {
        let line = read_crlf_line(reader, read_buffer, idle_timeout, direction).await?;
        writer.write_all(&line).await.map_err(|source| io_error(direction, source))?;

        let line_text =
            std::str::from_utf8(&line[..line.len().saturating_sub(2)]).map_err(|_| {
                parse_side_error(
                    direction,
                    lb_proto_http::Http1ParseError::Invalid("invalid chunk size line"),
                )
            })?;
        let chunk_size_text = line_text.split(';').next().unwrap_or_default().trim();
        let chunk_size = u64::from_str_radix(chunk_size_text, 16).map_err(|_| {
            parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::Invalid("invalid chunk size"),
            )
        })?;

        total_body_bytes = total_body_bytes.saturating_add(chunk_size);
        if total_body_bytes > max_body_bytes {
            return Err(body_limit_error(direction));
        }

        let chunk_plus_crlf = usize::try_from(chunk_size).unwrap_or(usize::MAX).saturating_add(2);
        relay_exact_bytes(reader, read_buffer, writer, chunk_plus_crlf, idle_timeout, direction)
            .await?;

        if chunk_size == 0 {
            loop {
                let trailer_line =
                    read_crlf_line(reader, read_buffer, idle_timeout, direction).await?;
                writer
                    .write_all(&trailer_line)
                    .await
                    .map_err(|source| io_error(direction, source))?;
                if trailer_line == b"\r\n" {
                    return Ok(());
                }
            }
        }
    }
}

async fn relay_exact_bytes<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    length: usize,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = length;
    while remaining != 0 {
        if !read_buffer.is_empty() {
            let buffered = remaining.min(read_buffer.len());
            writer
                .write_all(&read_buffer[..buffered])
                .await
                .map_err(|source| io_error(direction, source))?;
            read_buffer.drain(..buffered);
            remaining = remaining.saturating_sub(buffered);
            continue;
        }

        let mut chunk = vec![0_u8; remaining.min(8192)];
        let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk))
            .await
            .map_err(|_| idle_error(direction))?
            .map_err(|source| io_error(direction, source))?;
        if bytes_read == 0 {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::IncompleteHead,
            ));
        }

        writer
            .write_all(&chunk[..bytes_read])
            .await
            .map_err(|source| io_error(direction, source))?;
        remaining = remaining.saturating_sub(bytes_read);
    }

    Ok(())
}

async fn read_crlf_line<R>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<Vec<u8>, Http1ProxyError>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(position) = read_buffer.windows(2).position(|window| window == b"\r\n") {
            let line = read_buffer.drain(..position + 2).collect();
            return Ok(line);
        }

        let mut chunk = [0_u8; 1024];
        let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk))
            .await
            .map_err(|_| idle_error(direction))?
            .map_err(|source| io_error(direction, source))?;
        if bytes_read == 0 {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::IncompleteHead,
            ));
        }
        read_buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn idle_error(direction: RelayDirection) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::IdleTimeout("request body"),
        RelayDirection::Response => Http1ProxyError::IdleTimeout("response body"),
    }
}

fn body_limit_error(direction: RelayDirection) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::BodyLimitExceeded("request body"),
        RelayDirection::Response => Http1ProxyError::BodyLimitExceeded("response body"),
    }
}

fn io_error(direction: RelayDirection, source: std::io::Error) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::RequestIo(source),
        RelayDirection::Response => Http1ProxyError::ResponseIo(source),
    }
}

fn parse_side_error(
    direction: RelayDirection,
    source: lb_proto_http::Http1ParseError,
) -> Http1ProxyError {
    match direction {
        RelayDirection::Request => Http1ProxyError::ParseRequest(source),
        RelayDirection::Response => Http1ProxyError::ParseResponse(source),
    }
}


fn classify_http1_request_parse_error(
    error: &lb_proto_http::Http1ParseError,
) -> Option<ProtocolAnomalyCategory> {
    match error {
        lb_proto_http::Http1ParseError::HeadTooLarge => {
            Some(ProtocolAnomalyCategory::HeadSizeLimitExceeded)
        }
        lb_proto_http::Http1ParseError::TooManyHeaders => {
            Some(ProtocolAnomalyCategory::HeaderCountLimitExceeded)
        }
        lb_proto_http::Http1ParseError::Invalid(message)
            if message.contains("ambiguous content-length")
                || message.contains("missing required host header")
                || message.contains("multiple host headers") =>
        {
            Some(ProtocolAnomalyCategory::AmbiguousFraming)
        }
        lb_proto_http::Http1ParseError::Invalid(_)
        | lb_proto_http::Http1ParseError::IncompleteHead => {
            Some(ProtocolAnomalyCategory::MalformedMessage)
        }
        lb_proto_http::Http1ParseError::Io(_) => None,
    }
}

