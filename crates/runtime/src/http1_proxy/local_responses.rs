#[derive(Default)]
struct VecAsyncWriter {
    bytes: Vec<u8>,
}

impl VecAsyncWriter {
    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl AsyncWrite for VecAsyncWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn local_http1_response(
    keep_alive: bool,
    status: StatusCode,
    body: &'static str,
) -> Http1SingleRequestResponse {
    let mut headers = vec![lb_proto_http::HttpHeader {
        name: String::from("content-type"),
        value: String::from("text/plain; charset=utf-8"),
    }];
    if !keep_alive {
        headers.push(lb_proto_http::HttpHeader {
            name: String::from("connection"),
            value: String::from("close"),
        });
    }
    headers.push(lb_proto_http::HttpHeader {
        name: String::from("content-length"),
        value: body.len().to_string(),
    });
    Http1SingleRequestResponse {
        head: lb_proto_http::Http1ResponseHead {
            version: lb_proto_http::SupportedHttpVersion::Http1,
            status: status.as_u16(),
            reason: String::new(),
            headers,
            body_kind: lb_proto_http::BodyKind::ContentLength(body.len() as u64),
            keep_alive,
        },
        body: body.as_bytes().to_vec(),
    }
}

fn request_is_safe_stale_reuse_retry_candidate(request: &lb_proto_http::Http1RequestHead) -> bool {
    matches!(request.body_kind, lb_proto_http::BodyKind::None)
        && (request_method_is_idempotent(&request.method)
            || request_has_idempotency_key_override(&request.headers))
}

fn request_method_is_idempotent(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET")
        || method.eq_ignore_ascii_case("HEAD")
        || method.eq_ignore_ascii_case("OPTIONS")
        || method.eq_ignore_ascii_case("TRACE")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("DELETE")
}

fn request_has_idempotency_key_override(headers: &[lb_proto_http::HttpHeader]) -> bool {
    headers.iter().any(|header| {
        (header.name.eq_ignore_ascii_case("idempotency-key")
            || header.name.eq_ignore_ascii_case("x-idempotency-key"))
            && !header.value.trim().is_empty()
    })
}


fn http1_stale_reuse_retryable_response_error(error: &Http1ProxyError) -> bool {
    match error {
        Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::IncompleteHead) => true,
        Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::Io(source)) => {
            matches!(
                source.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            )
        }
        _ => false,
    }
}

async fn write_local_response<W>(
    downstream: &mut W,
    keep_alive: bool,
    status: StatusCode,
    body: &'static str,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    let mut headers = vec![lb_proto_http::HttpHeader {
        name: String::from("content-type"),
        value: String::from("text/plain; charset=utf-8"),
    }];
    if !keep_alive {
        headers.push(lb_proto_http::HttpHeader {
            name: String::from("connection"),
            value: String::from("close"),
        });
    }
    headers.push(lb_proto_http::HttpHeader {
        name: String::from("content-length"),
        value: body.len().to_string(),
    });
    let response_head = lb_proto_http::encode_response_head(
        lb_proto_http::SupportedHttpVersion::Http1,
        status.as_u16(),
        "",
        &headers,
    );
    downstream.write_all(&response_head).await?;
    downstream.write_all(body.as_bytes()).await?;
    Ok(())
}

