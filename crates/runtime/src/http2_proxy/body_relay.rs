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
        send_bytes_chunked(send_stream, chunk, false, direction).await?;
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
        let trailers_for_metrics = trailers.clone();
        send_stream.send_trailers(trailers).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
        return Ok(Some(trailers_for_metrics));
    } else {
        send_bytes_chunked(send_stream, Bytes::new(), true, direction).await?;
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
        send_bytes_chunked(send_stream, chunk, false, direction).await?;
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

    if let Some(trailers_to_send) = trailers.clone() {
        send_stream.send_trailers(trailers_to_send).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
    } else {
        send_bytes_chunked(send_stream, Bytes::new(), true, direction).await?;
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
    direction: StreamBodyDirection,
) -> Result<(), StreamForwardError> {
    if !payload.body.is_empty() {
        send_bytes_chunked(
            send_stream,
            payload.body.clone(),
            payload.trailers.is_none(),
            direction,
        )
        .await?;
    } else if payload.trailers.is_none() {
        send_bytes_chunked(send_stream, Bytes::new(), true, direction).await?;
    }

    if let Some(trailers) = payload.trailers.clone() {
        send_stream.send_trailers(trailers).map_err(|_| match direction {
            StreamBodyDirection::Request => StreamForwardError::RequestBody,
            StreamBodyDirection::Response => StreamForwardError::ResponseBody,
        })?;
    }

    Ok(())
}

async fn send_bytes_chunked(
    send_stream: &mut SendStream<Bytes>,
    mut bytes: Bytes,
    end_stream: bool,
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
            let capacity = poll_fn(|cx| match send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity)),
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                    Poll::Ready(Err(match direction {
                        StreamBodyDirection::Request => StreamForwardError::RequestBody,
                        StreamBodyDirection::Response => StreamForwardError::ResponseBody,
                    }))
                }
                Poll::Pending => Poll::Pending,
            })
            .await?;
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

