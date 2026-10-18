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
        lb_proto_http::BodyKind::CloseDelimited => {
            relay_close_delimited_as_chunked(
                reader,
                read_buffer,
                writer,
                max_body_bytes,
                idle_timeout,
                direction,
            )
            .await
        }
    }
}

/// Maximum size of a single chunk-size line (including extensions) or trailer field line.
const MAX_CHUNK_LINE_BYTES: usize = 4 * 1024;
/// Maximum cumulative size of the trailer section of a chunked body.
const MAX_CHUNK_TRAILER_BYTES: usize = 16 * 1024;

/// Relays a close-delimited upstream body, re-framing it as chunked so the downstream
/// connection can stay persistent.
async fn relay_close_delimited_as_chunked<R, W>(
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
    let mut chunk = vec![0_u8; 16 * 1024];
    loop {
        let bytes_read = if read_buffer.is_empty() {
            time::timeout(idle_timeout, reader.read(&mut chunk))
                .await
                .map_err(|_| idle_error(direction))?
                .map_err(|source| io_error(direction, source))?
        } else {
            let buffered = read_buffer.len().min(chunk.len());
            chunk[..buffered].copy_from_slice(&read_buffer[..buffered]);
            read_buffer.drain(..buffered);
            buffered
        };
        if bytes_read == 0 {
            writer.write_all(b"0\r\n\r\n").await.map_err(|source| io_error(direction, source))?;
            return Ok(());
        }

        total_body_bytes = total_body_bytes.saturating_add(bytes_read as u64);
        if total_body_bytes > max_body_bytes {
            return Err(body_limit_error(direction));
        }

        let mut framed = Vec::with_capacity(bytes_read + 20);
        framed.extend_from_slice(format!("{bytes_read:x}\r\n").as_bytes());
        framed.extend_from_slice(&chunk[..bytes_read]);
        framed.extend_from_slice(b"\r\n");
        writer.write_all(&framed).await.map_err(|source| io_error(direction, source))?;
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
    relay_chunked_with_framing(
        reader,
        read_buffer,
        writer,
        max_body_bytes,
        idle_timeout,
        direction,
        true,
    )
    .await
}

/// Relays a response body to an HTTP/1.0 downstream, which cannot decode chunked framing.
/// The caller must close the downstream connection afterwards to delimit the body.
async fn relay_response_body_for_http10<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    body_kind: &lb_proto_http::BodyKind,
    max_body_bytes: u64,
    idle_timeout: Duration,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let direction = RelayDirection::Response;
    match body_kind {
        lb_proto_http::BodyKind::Chunked => {
            relay_chunked_with_framing(
                reader,
                read_buffer,
                writer,
                max_body_bytes,
                idle_timeout,
                direction,
                false,
            )
            .await
        }
        lb_proto_http::BodyKind::CloseDelimited => {
            let mut total_body_bytes = read_buffer.len() as u64;
            if total_body_bytes > max_body_bytes {
                return Err(body_limit_error(direction));
            }
            writer.write_all(read_buffer).await.map_err(|source| io_error(direction, source))?;
            read_buffer.clear();
            let mut chunk = vec![0_u8; 16 * 1024];
            loop {
                let bytes_read = time::timeout(idle_timeout, reader.read(&mut chunk))
                    .await
                    .map_err(|_| idle_error(direction))?
                    .map_err(|source| io_error(direction, source))?;
                if bytes_read == 0 {
                    return Ok(());
                }
                total_body_bytes = total_body_bytes.saturating_add(bytes_read as u64);
                if total_body_bytes > max_body_bytes {
                    return Err(body_limit_error(direction));
                }
                writer
                    .write_all(&chunk[..bytes_read])
                    .await
                    .map_err(|source| io_error(direction, source))?;
            }
        }
        lb_proto_http::BodyKind::None | lb_proto_http::BodyKind::ContentLength(_) => {
            relay_body(reader, read_buffer, writer, body_kind, max_body_bytes, idle_timeout, direction)
                .await
        }
    }
}

/// Relays a chunked body; with `forward_framing == false` only the payload bytes are written.
async fn relay_chunked_with_framing<R, W>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    writer: &mut W,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
    forward_framing: bool,
) -> Result<(), Http1ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total_body_bytes = 0_u64;

    loop {
        let line = read_crlf_line(reader, read_buffer, idle_timeout, direction).await?;
        let chunk_size = parse_chunk_size_line(&line[..line.len().saturating_sub(2)])
            .ok_or_else(|| {
                parse_side_error(
                    direction,
                    lb_proto_http::Http1ParseError::Invalid("invalid chunk size"),
                )
            })?;

        total_body_bytes = total_body_bytes.saturating_add(chunk_size);
        if total_body_bytes > max_body_bytes {
            return Err(body_limit_error(direction));
        }
        if forward_framing {
            writer.write_all(&line).await.map_err(|source| io_error(direction, source))?;
        }

        if chunk_size == 0 {
            let mut trailer_bytes = 0_usize;
            loop {
                let trailer_line =
                    read_crlf_line(reader, read_buffer, idle_timeout, direction).await?;
                trailer_bytes = trailer_bytes.saturating_add(trailer_line.len());
                if trailer_bytes > MAX_CHUNK_TRAILER_BYTES {
                    return Err(parse_side_error(
                        direction,
                        lb_proto_http::Http1ParseError::HeadTooLarge,
                    ));
                }
                if forward_framing {
                    writer
                        .write_all(&trailer_line)
                        .await
                        .map_err(|source| io_error(direction, source))?;
                }
                if trailer_line == b"\r\n" {
                    return Ok(());
                }
            }
        }

        let chunk_len = usize::try_from(chunk_size).map_err(|_| body_limit_error(direction))?;
        relay_exact_bytes(reader, read_buffer, writer, chunk_len, idle_timeout, direction)
            .await?;
        // Each chunk's data must be terminated by exactly CRLF; forwarding anything else lets
        // downstream parsers disagree on message boundaries.
        let terminator = read_crlf_line(reader, read_buffer, idle_timeout, direction).await?;
        if terminator != b"\r\n" {
            return Err(parse_side_error(
                direction,
                lb_proto_http::Http1ParseError::Invalid("invalid chunk data terminator"),
            ));
        }
        if forward_framing {
            writer.write_all(&terminator).await.map_err(|source| io_error(direction, source))?;
        }
    }
}

/// Parses `chunk-size [ chunk-ext ]` (RFC 9112 §7.1), rejecting signs, prefixes, and overflow.
fn parse_chunk_size_line(line: &[u8]) -> Option<u64> {
    let size_end = line
        .iter()
        .position(|byte| !byte.is_ascii_hexdigit())
        .unwrap_or(line.len());
    let (size_digits, rest) = line.split_at(size_end);
    if size_digits.is_empty() || size_digits.len() > 16 {
        return None;
    }
    let rest_trimmed = rest.iter().skip_while(|byte| matches!(byte, b' ' | b'\t'));
    let remainder: Vec<u8> = rest_trimmed.copied().collect();
    if !remainder.is_empty() && remainder[0] != b';' {
        return None;
    }
    if remainder.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(size_digits).ok()?, 16).ok()
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
    let mut scanned = 0_usize;
    loop {
        if let Some(position) =
            read_buffer[scanned..].windows(2).position(|window| window == b"\r\n")
        {
            let line = read_buffer.drain(..scanned + position + 2).collect();
            return Ok(line);
        }
        if read_buffer.len() > MAX_CHUNK_LINE_BYTES {
            return Err(parse_side_error(direction, lb_proto_http::Http1ParseError::HeadTooLarge));
        }
        scanned = read_buffer.len().saturating_sub(1);

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

/// Decodes a chunked body that was already validated by [`relay_chunked`] (or produced by
/// [`relay_close_delimited_as_chunked`]) into its payload bytes, discarding trailers.
fn decode_chunked_body(raw: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut cursor = 0_usize;
    loop {
        let line_len = raw[cursor..].windows(2).position(|window| window == b"\r\n")?;
        let size = usize::try_from(parse_chunk_size_line(&raw[cursor..cursor + line_len])?).ok()?;
        cursor += line_len + 2;
        if size == 0 {
            return Some(decoded);
        }
        let end = cursor.checked_add(size)?;
        decoded.extend_from_slice(raw.get(cursor..end)?);
        if raw.get(end..end + 2)? != b"\r\n" {
            return None;
        }
        cursor = end + 2;
    }
}

/// Reads a full body and returns its payload with any HTTP/1.1 transfer framing removed.
async fn collect_decoded_body<R>(
    reader: &mut R,
    read_buffer: &mut Vec<u8>,
    body_kind: &lb_proto_http::BodyKind,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: RelayDirection,
) -> Result<Vec<u8>, Http1ProxyError>
where
    R: AsyncRead + Unpin,
{
    let mut writer = VecAsyncWriter::default();
    relay_body(reader, read_buffer, &mut writer, body_kind, max_body_bytes, idle_timeout, direction)
        .await?;
    let raw = writer.into_inner();
    match body_kind {
        lb_proto_http::BodyKind::Chunked | lb_proto_http::BodyKind::CloseDelimited => {
            decode_chunked_body(&raw).ok_or_else(|| {
                parse_side_error(
                    direction,
                    lb_proto_http::Http1ParseError::Invalid("invalid chunked body"),
                )
            })
        }
        lb_proto_http::BodyKind::None | lb_proto_http::BodyKind::ContentLength(_) => Ok(raw),
    }
}

/// Rewrites framing headers for a body that is delivered fully buffered and de-chunked.
fn reframe_buffered_headers(headers: &mut Vec<lb_proto_http::HttpHeader>, body_len: usize) {
    headers.retain(|header| {
        !header.name.eq_ignore_ascii_case("transfer-encoding")
            && !header.name.eq_ignore_ascii_case("content-length")
            && !header.name.eq_ignore_ascii_case("trailer")
    });
    headers.push(lb_proto_http::HttpHeader {
        name: String::from("content-length"),
        value: body_len.to_string(),
    });
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

