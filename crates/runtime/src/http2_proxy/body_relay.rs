async fn relay_recv_body_to_send_stream(
    mut recv_stream: RecvStream,
    send_stream: &mut SendStream<Bytes>,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: StreamBodyDirection,
) -> Result<Option<http::HeaderMap>, StreamForwardError> {
    let mut transferred = 0_u64;
    while let Some(chunk) =
        time::timeout(idle_timeout, recv_stream.data()).await.map_err(|_| match direction {
            StreamBodyDirection::Request => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
            }
            StreamBodyDirection::Response => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
            }
        })?
    {
        let chunk = chunk.map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        recv_stream.flow_control().release_capacity(chunk.len()).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        transferred = transferred.saturating_add(chunk.len() as u64);
        if transferred > max_body_bytes {
            return Err(match direction {
                StreamBodyDirection::Request => StreamForwardError::RequestBodyLimitExceeded,
                StreamBodyDirection::Response => StreamForwardError::ResponseBodyLimitExceeded,
            });
        }
        send_bytes_chunked(send_stream, chunk, false, idle_timeout, direction).await?;
    }

    if let Some(trailers) = time::timeout(idle_timeout, recv_stream.trailers())
        .await
        .map_err(|_| match direction {
            StreamBodyDirection::Request => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
            }
            StreamBodyDirection::Response => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
            }
        })?
        .map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?
    {
        let trailers = sanitize_http2_trailers(trailers);
        let trailers_for_metrics = trailers.clone();
        send_stream.send_trailers(trailers).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        return Ok(Some(trailers_for_metrics));
    } else {
        send_bytes_chunked(send_stream, Bytes::new(), true, idle_timeout, direction).await?;
    }

    Ok(None)
}

async fn relay_recv_body_to_send_stream_buffered(
    mut recv_stream: RecvStream,
    send_stream: &mut SendStream<Bytes>,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: StreamBodyDirection,
) -> Result<BufferedStreamPayload, StreamForwardError> {
    let mut transferred = 0_u64;
    let mut body = Vec::new();
    while let Some(chunk) =
        time::timeout(idle_timeout, recv_stream.data()).await.map_err(|_| match direction {
            StreamBodyDirection::Request => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
            }
            StreamBodyDirection::Response => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
            }
        })?
    {
        let chunk = chunk.map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        recv_stream.flow_control().release_capacity(chunk.len()).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        transferred = transferred.saturating_add(chunk.len() as u64);
        if transferred > max_body_bytes {
            return Err(match direction {
                StreamBodyDirection::Request => StreamForwardError::RequestBodyLimitExceeded,
                StreamBodyDirection::Response => StreamForwardError::ResponseBodyLimitExceeded,
            });
        }
        body.extend_from_slice(&chunk);
        send_bytes_chunked(send_stream, chunk, false, idle_timeout, direction).await?;
    }

    let trailers = time::timeout(idle_timeout, recv_stream.trailers())
        .await
        .map_err(|_| match direction {
            StreamBodyDirection::Request => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
            }
            StreamBodyDirection::Response => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
            }
        })?
        .map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;

    let trailers = trailers.map(sanitize_http2_trailers);
    if let Some(trailers_to_send) = trailers.clone() {
        send_stream.send_trailers(trailers_to_send).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
    } else {
        send_bytes_chunked(send_stream, Bytes::new(), true, idle_timeout, direction).await?;
    }

    Ok(BufferedStreamPayload {
        body: Bytes::from(body),
        trailers,
    })
}

async fn read_recv_body_to_buffer(
    mut recv_stream: RecvStream,
    max_body_bytes: u64,
    idle_timeout: Duration,
    direction: StreamBodyDirection,
) -> Result<BufferedStreamPayload, StreamForwardError> {
    let mut transferred = 0_u64;
    let mut body = Vec::new();
    while let Some(chunk) =
        time::timeout(idle_timeout, recv_stream.data()).await.map_err(|_| match direction {
            StreamBodyDirection::Request => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
            }
            StreamBodyDirection::Response => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
            }
        })?
    {
        let chunk = chunk.map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        recv_stream.flow_control().release_capacity(chunk.len()).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        transferred = transferred.saturating_add(chunk.len() as u64);
        if transferred > max_body_bytes {
            return Err(match direction {
                StreamBodyDirection::Request => StreamForwardError::RequestBodyLimitExceeded,
                StreamBodyDirection::Response => StreamForwardError::ResponseBodyLimitExceeded,
            });
        }
        body.extend_from_slice(&chunk);
    }

    let trailers = time::timeout(idle_timeout, recv_stream.trailers())
        .await
        .map_err(|_| match direction {
            StreamBodyDirection::Request => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
            }
            StreamBodyDirection::Response => {
                StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
            }
        })?
        .map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;

    Ok(BufferedStreamPayload {
        body: Bytes::from(body),
        trailers,
    })
}

async fn send_buffered_stream_payload(
    send_stream: &mut SendStream<Bytes>,
    payload: &BufferedStreamPayload,
    idle_timeout: Duration,
    direction: StreamBodyDirection,
) -> Result<(), StreamForwardError> {
    if !payload.body.is_empty() {
        send_bytes_chunked(
            send_stream,
            payload.body.clone(),
            payload.trailers.is_none(),
            idle_timeout,
            direction,
        )
        .await?;
    } else if payload.trailers.is_none() {
        send_bytes_chunked(send_stream, Bytes::new(), true, idle_timeout, direction).await?;
    }

    if let Some(trailers) = payload.trailers.clone().map(sanitize_http2_trailers) {
        send_stream.send_trailers(trailers).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
    }

    Ok(())
}

/// Drops connection-specific fields that are never valid in an HTTP/2 trailer block.
fn sanitize_http2_trailers(mut trailers: http::HeaderMap) -> http::HeaderMap {
    let forbidden: Vec<HeaderName> = trailers
        .iter()
        .filter(|(name, value)| should_skip_http2_header(name, value))
        .map(|(name, _)| name.clone())
        .collect();
    for name in forbidden {
        trailers.remove(&name);
    }
    for name in [http::header::CONTENT_LENGTH, http::header::TRAILER] {
        trailers.remove(&name);
    }
    trailers
}

async fn send_bytes_chunked(
    send_stream: &mut SendStream<Bytes>,
    mut bytes: Bytes,
    end_stream: bool,
    idle_timeout: Duration,
    direction: StreamBodyDirection,
) -> Result<(), StreamForwardError> {
    if bytes.is_empty() {
        return send_stream.send_data(bytes, end_stream).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        });
    }

    const MAX_FRAME_CHUNK: usize = 16 * 1024;
    while bytes.has_remaining() {
        let next_len = bytes.remaining().min(MAX_FRAME_CHUNK);
        let capacity = loop {
            send_stream.reserve_capacity(next_len);
            // A peer that stops granting flow-control window must not pin this stream forever.
            let capacity = time::timeout(
                idle_timeout,
                poll_fn(|cx| match send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity)),
                    Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                        Poll::Ready(Err(match direction {
                            StreamBodyDirection::Request => StreamForwardError::RequestBody,
                            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
                        }))
                    }
                    Poll::Pending => Poll::Pending,
                }),
            )
            .await
            .map_err(|_| {
                send_stream.send_reset(h2::Reason::CANCEL);
                match direction {
                    StreamBodyDirection::Request => {
                        StreamForwardError::IdleTimeout(StreamIdlePhase::RequestBody)
                    }
                    StreamBodyDirection::Response => {
                        StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody)
                    }
                }
            })??;
            if capacity != 0 {
                break capacity;
            }
            tokio::task::yield_now().await;
        };
        let to_send = bytes.remaining().min(next_len).min(capacity);
        let chunk = bytes.split_to(to_send);
        let is_last = end_stream && !bytes.has_remaining();
        send_stream.send_data(chunk, is_last).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
    }

    Ok(())
}


async fn discard_recv_stream_body(
    mut recv_stream: RecvStream,
    idle_timeout: Duration,
) -> Result<(), StreamForwardError> {
    while let Some(chunk) = time::timeout(idle_timeout, recv_stream.data())
        .await
        .map_err(|_| StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody))?
    {
        let chunk = chunk.map_err(|_| StreamForwardError::ResponseBody)?;
        recv_stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|_| StreamForwardError::ResponseBody)?;
    }
    let _ = time::timeout(idle_timeout, recv_stream.trailers())
        .await
        .map_err(|_| StreamForwardError::IdleTimeout(StreamIdlePhase::ResponseBody))?
        .map_err(|_| StreamForwardError::ResponseBody)?;
    Ok(())
}

#[cfg(test)]
mod body_relay_coverage_tests {
    use super::*;

    async fn incoming_stream(
        body: Bytes,
        trailers: Option<http::HeaderMap>,
    ) -> Result<RecvStream, Box<dyn std::error::Error>> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server, client) =
            tokio::join!(h2::server::handshake(server_io), h2::client::handshake(client_io));
        let mut server = server?;
        let (mut client, client_connection) = client?;
        tokio::spawn(async move {
            let _ = client_connection.await;
        });

        let request = Request::builder().method("POST").uri("https://example.test/body").body(())?;
        let (response, mut send) = client.send_request(request, false)?;
        tokio::spawn(async move {
            let _ = response.await;
        });
        if let Some(trailers) = trailers {
            send.send_data(body, false)?;
            send.send_trailers(trailers)?;
        } else {
            send.send_data(body, true)?;
        }

        let (request, respond) = time::timeout(Duration::from_secs(1), server.accept())
            .await?
            .ok_or("HTTP/2 request was not accepted")??;
        tokio::spawn(async move {
            let _respond = respond;
            while let Some(result) = server.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        Ok(request.into_body())
    }

    async fn outgoing_stream(
    ) -> Result<(SendStream<Bytes>, RecvStream), Box<dyn std::error::Error>> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server, client) =
            tokio::join!(h2::server::handshake(server_io), h2::client::handshake(client_io));
        let mut server = server?;
        let (mut client, client_connection) = client?;
        tokio::spawn(async move {
            let _ = client_connection.await;
        });

        let request = Request::builder().method("POST").uri("https://example.test/body").body(())?;
        let (response, send) = client.send_request(request, false)?;
        tokio::spawn(async move {
            let _ = response.await;
        });
        let (request, respond) = time::timeout(Duration::from_secs(1), server.accept())
            .await?
            .ok_or("HTTP/2 request was not accepted")??;
        tokio::spawn(async move {
            let _respond = respond;
            while let Some(result) = server.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        Ok((send, request.into_body()))
    }

    #[tokio::test]
    async fn relays_payload_and_sanitized_trailers() -> Result<(), Box<dyn std::error::Error>> {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("abc"));
        trailers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("4"));
        let incoming =
            incoming_stream(Bytes::from_static(b"body"), Some(trailers)).await?;
        let (mut send, mut received) = outgoing_stream().await?;

        let forwarded = relay_recv_body_to_send_stream(
            incoming,
            &mut send,
            8,
            Duration::from_secs(1),
            StreamBodyDirection::Request,
        )
        .await
        .expect("request body relays")
        .expect("trailers are relayed");
        assert_eq!(forwarded.get("x-checksum").and_then(|value| value.to_str().ok()), Some("abc"));
        assert!(!forwarded.contains_key(http::header::CONTENT_LENGTH));

        let mut body = Vec::new();
        while let Some(chunk) = received.data().await {
            let chunk = chunk?;
            received.flow_control().release_capacity(chunk.len())?;
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"body");
        let received_trailers = received.trailers().await?.expect("trailers arrive downstream");
        assert_eq!(
            received_trailers.get("x-checksum").and_then(|value| value.to_str().ok()),
            Some("abc")
        );
        Ok(())
    }

    #[tokio::test]
    async fn relay_enforces_body_limit_and_buffer_reader_handles_empty_body(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let incoming = incoming_stream(Bytes::from_static(b"too large"), None).await?;
        let (mut send, _) = outgoing_stream().await?;
        assert!(matches!(
            relay_recv_body_to_send_stream(
                incoming,
                &mut send,
                1,
                Duration::from_secs(1),
                StreamBodyDirection::Request,
            )
            .await,
            Err(StreamForwardError::RequestBodyLimitExceeded)
        ));

        let empty = incoming_stream(Bytes::new(), None).await?;
        let payload = read_recv_body_to_buffer(
            empty,
            1,
            Duration::from_secs(1),
            StreamBodyDirection::Response,
        )
        .await
        .expect("empty response body is buffered");
        assert!(payload.body.is_empty());
        assert!(payload.trailers.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn buffers_and_replays_response_body_and_discards_unused_body(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("buffered"));
        let incoming =
            incoming_stream(Bytes::from_static(b"buffered"), Some(trailers)).await?;
        let (mut send, mut received) = outgoing_stream().await?;
        let payload = relay_recv_body_to_send_stream_buffered(
            incoming,
            &mut send,
            32,
            Duration::from_secs(1),
            StreamBodyDirection::Response,
        )
        .await
        .expect("response is buffered");
        assert_eq!(payload.body, Bytes::from_static(b"buffered"));
        let mut body = Vec::new();
        while let Some(chunk) = received.data().await {
            let chunk = chunk?;
            received.flow_control().release_capacity(chunk.len())?;
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"buffered");
        let received_trailers = received.trailers().await?.expect("trailers are preserved");
        assert_eq!(
            received_trailers.get("x-checksum").and_then(|value| value.to_str().ok()),
            Some("buffered")
        );

        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("buffered"));
        let incoming =
            incoming_stream(Bytes::from_static(b"buffered"), Some(trailers)).await?;
        let (mut send, mut received) = outgoing_stream().await?;
        let payload = read_recv_body_to_buffer(
            incoming,
            32,
            Duration::from_secs(1),
            StreamBodyDirection::Response,
        )
        .await
        .expect("response payload is buffered without forwarding");
        send_buffered_stream_payload(
            &mut send,
            &payload,
            Duration::from_secs(1),
            StreamBodyDirection::Response,
        )
        .await
        .expect("buffered response is forwarded");
        let mut body = Vec::new();
        while let Some(chunk) = received.data().await {
            let chunk = chunk?;
            received.flow_control().release_capacity(chunk.len())?;
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"buffered");
        assert!(received.trailers().await?.is_some());

        let unused = incoming_stream(Bytes::from_static(b"discard"), None).await?;
        discard_recv_stream_body(unused, Duration::from_secs(1))
            .await
            .expect("unused body is drained");
        Ok(())
    }

    #[tokio::test]
    async fn relays_empty_and_multi_frame_bodies() -> Result<(), Box<dyn std::error::Error>> {
        let (mut send, mut received) = outgoing_stream().await?;
        send_buffered_stream_payload(
            &mut send,
            &BufferedStreamPayload::default(),
            Duration::from_secs(1),
            StreamBodyDirection::Request,
        )
        .await
        .expect("empty buffered body ends the stream");
        let mut buffered_body = Vec::new();
        while let Some(chunk) = received.data().await {
            let chunk = chunk?;
            received.flow_control().release_capacity(chunk.len())?;
            buffered_body.extend_from_slice(&chunk);
        }
        assert!(buffered_body.is_empty());
        assert!(received.trailers().await?.is_none());

        let empty = incoming_stream(Bytes::new(), None).await?;
        let (mut send, mut received) = outgoing_stream().await?;
        assert!(
            relay_recv_body_to_send_stream(
                empty,
                &mut send,
                32 * 1024,
                Duration::from_secs(1),
                StreamBodyDirection::Response,
            )
            .await
            .expect("empty response relays")
            .is_none()
        );
        let mut empty_body = Vec::new();
        while let Some(chunk) = received.data().await {
            let chunk = chunk?;
            received.flow_control().release_capacity(chunk.len())?;
            empty_body.extend_from_slice(&chunk);
        }
        assert!(empty_body.is_empty());
        assert!(received.trailers().await?.is_none());

        let body = Bytes::from(vec![b'x'; 20 * 1024]);
        let incoming = incoming_stream(body.clone(), None).await?;
        let (mut send, mut received) = outgoing_stream().await?;
        relay_recv_body_to_send_stream(
            incoming,
            &mut send,
            32 * 1024,
            Duration::from_secs(1),
            StreamBodyDirection::Response,
        )
        .await
        .expect("multi-frame body relays");
        let mut received_body = Vec::new();
        while let Some(chunk) = received.data().await {
            let chunk = chunk?;
            received.flow_control().release_capacity(chunk.len())?;
            received_body.extend_from_slice(&chunk);
        }
        assert_eq!(received_body, body);
        assert!(received.trailers().await?.is_none());
        Ok(())
    }
}
