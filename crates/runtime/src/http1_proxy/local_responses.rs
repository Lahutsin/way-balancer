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

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
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

#[cfg(test)]
mod local_responses_tests {
    use std::io;
    use tokio::io::AsyncReadExt;

    use super::Http1ProxyError;
    use super::{
        http1_stale_reuse_retryable_response_error, local_http1_response,
        request_has_idempotency_key_override, request_is_safe_stale_reuse_retry_candidate,
        request_method_is_idempotent, write_local_response,
    };
    use http::StatusCode;

    fn request(
        method: &str,
        body_kind: lb_proto_http::BodyKind,
        headers: Vec<lb_proto_http::HttpHeader>,
    ) -> lb_proto_http::Http1RequestHead {
        lb_proto_http::Http1RequestHead {
            method: method.to_owned(),
            target: String::from("/"),
            version: lb_proto_http::SupportedHttpVersion::Http1,
            headers,
            body_kind,
            keep_alive: true,
            route: None,
            http10: false,
        }
    }

    fn header(name: &str, value: &str) -> lb_proto_http::HttpHeader {
        lb_proto_http::HttpHeader { name: name.to_owned(), value: value.to_owned() }
    }

    #[test]
    fn stale_reuse_retry_requires_idempotent_bodyless_request_and_connection_error() {
        for method in ["get", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"] {
            assert!(request_method_is_idempotent(method));
        }
        assert!(!request_method_is_idempotent("POST"));
        assert!(request_is_safe_stale_reuse_retry_candidate(&request(
            "GET",
            lb_proto_http::BodyKind::None,
            Vec::new()
        )));
        assert!(!request_is_safe_stale_reuse_retry_candidate(&request(
            "POST",
            lb_proto_http::BodyKind::None,
            Vec::new()
        )));
        let keyed = request(
            "POST",
            lb_proto_http::BodyKind::None,
            vec![header("X-Idempotency-Key", " retry-1 ")],
        );
        assert!(request_has_idempotency_key_override(&keyed.headers));
        assert!(request_is_safe_stale_reuse_retry_candidate(&keyed));
        assert!(!request_has_idempotency_key_override(&[header("idempotency-key", "  ")]));
        assert!(!request_is_safe_stale_reuse_retry_candidate(&request(
            "POST",
            lb_proto_http::BodyKind::ContentLength(1),
            vec![header("idempotency-key", "retry-1")]
        )));

        assert!(http1_stale_reuse_retryable_response_error(&Http1ProxyError::ParseResponse(
            lb_proto_http::Http1ParseError::IncompleteHead
        )));
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NotConnected,
        ] {
            assert!(http1_stale_reuse_retryable_response_error(&Http1ProxyError::ParseResponse(
                lb_proto_http::Http1ParseError::Io(io::Error::new(kind, "closed"))
            )));
        }
        assert!(!http1_stale_reuse_retryable_response_error(&Http1ProxyError::ParseResponse(
            lb_proto_http::Http1ParseError::Io(io::Error::other("other"))
        )));
        assert!(!http1_stale_reuse_retryable_response_error(
            &Http1ProxyError::UpstreamGracefulDrain
        ));
    }

    #[test]
    fn local_response_builder_matches_status_body_and_connection_policy() {
        let keep_alive = local_http1_response(true, StatusCode::BAD_REQUEST, "bad request\n");
        assert_eq!(keep_alive.head.status, 400);
        assert!(keep_alive.head.keep_alive);
        assert_eq!(keep_alive.body, b"bad request\n");
        assert!(keep_alive.head.headers.iter().all(|header| header.name != "connection"));

        let close = local_http1_response(false, StatusCode::FORBIDDEN, "forbidden\n");
        assert!(!close.head.keep_alive);
        assert_eq!(
            close
                .head
                .headers
                .iter()
                .find(|header| header.name == "connection")
                .map(|header| header.value.as_str()),
            Some("close")
        );
        assert_eq!(close.head.body_kind, lb_proto_http::BodyKind::ContentLength(10));
    }

    #[tokio::test]
    async fn local_response_writer_emits_length_and_optional_close_header(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        write_local_response(&mut writer, true, StatusCode::NO_CONTENT, "").await?;
        drop(writer);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await?;
        let response = String::from_utf8(bytes)?;
        assert!(response.starts_with("HTTP/1.1 204"));
        assert!(response.contains("content-length: 0\r\n"));
        assert!(!response.contains("connection: close"));
        assert!(response.ends_with("\r\n\r\n"));

        let (mut writer, mut reader) = tokio::io::duplex(256);
        write_local_response(&mut writer, false, StatusCode::BAD_GATEWAY, "failed").await?;
        drop(writer);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await?;
        let response = String::from_utf8(bytes)?;
        assert!(response.contains("connection: close\r\n"));
        assert!(response.ends_with("\r\n\r\nfailed"));
        Ok(())
    }
}
