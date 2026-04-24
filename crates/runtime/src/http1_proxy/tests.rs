#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::io;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::{
        body_limit_error, classify_http1_request_parse_error, ensure_upstream_connection,
        idle_error, io_error, parse_side_error, read_crlf_line, relay_body, relay_chunked,
        relay_content_length, relay_content_length_collect, relay_exact_bytes, Http1ProxyError,
        RelayDirection,
    };
    use crate::{ProtocolAnomalyCategory, SlowClientStage};

    #[test]
    fn request_parse_errors_map_to_stable_anomaly_categories() {
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::HeadTooLarge),
            Some(ProtocolAnomalyCategory::HeadSizeLimitExceeded)
        );
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::TooManyHeaders),
            Some(ProtocolAnomalyCategory::HeaderCountLimitExceeded)
        );
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::Invalid(
                "multiple host headers",
            )),
            Some(ProtocolAnomalyCategory::AmbiguousFraming)
        );
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::IncompleteHead),
            Some(ProtocolAnomalyCategory::MalformedMessage)
        );
        assert_eq!(
            classify_http1_request_parse_error(&lb_proto_http::Http1ParseError::Io(
                io::Error::other("io"),
            )),
            None
        );
    }

    #[test]
    fn error_helpers_preserve_direction_and_source() {
        let request_idle = idle_error(RelayDirection::Request);
        let response_limit = body_limit_error(RelayDirection::Response);
        let request_io = io_error(RelayDirection::Request, io::Error::other("write failed"));
        let response_parse = parse_side_error(
            RelayDirection::Response,
            lb_proto_http::Http1ParseError::IncompleteHead,
        );
        let connect_timeout = Http1ProxyError::ConnectTimeout {
            target: "127.0.0.1:8080".parse().expect("socket addr"),
        };
        let connect = Http1ProxyError::Connect {
            target: "127.0.0.1:8080".parse().expect("socket addr"),
            source: io::Error::other("connect failed"),
        };
        let parse_request =
            Http1ProxyError::ParseRequest(lb_proto_http::Http1ParseError::HeadTooLarge);
        let parse_response =
            Http1ProxyError::ParseResponse(lb_proto_http::Http1ParseError::IncompleteHead);
        let response_io = Http1ProxyError::ResponseIo(io::Error::other("response failed"));
        let graceful_drain = Http1ProxyError::UpstreamGracefulDrain;

        assert_eq!(request_idle.slow_client_stage(), Some(SlowClientStage::RequestBody));
        assert_eq!(response_limit.anomaly_category(), None);
        assert!(connect_timeout.to_string().contains("timed out connecting HTTP/1.1 upstream"));
        assert!(connect.to_string().contains("failed to connect HTTP/1.1 upstream"));
        assert_eq!(
            parse_request.anomaly_category(),
            Some(ProtocolAnomalyCategory::HeadSizeLimitExceeded)
        );
        assert_eq!(parse_response.anomaly_category(), None);
        assert!(request_io.to_string().contains("upstream write failed"));
        assert!(std::error::Error::source(&request_io).is_some());
        assert!(std::error::Error::source(&connect).is_some());
        assert!(std::error::Error::source(&parse_request).is_some());
        assert!(std::error::Error::source(&response_io).is_some());
        assert!(graceful_drain.to_string().contains("gracefully draining"));
        assert!(std::error::Error::source(&graceful_drain).is_none());
        assert!(matches!(response_parse, Http1ProxyError::ParseResponse(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_body_none_and_body_limit_paths_are_explicit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut reader_peer) = tokio::io::duplex(64);
        let (mut writer_peer, mut writer) = tokio::io::duplex(64);
        reader_peer.write_all(b"abc").await?;

        relay_body(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            &lb_proto_http::BodyKind::None,
            10,
            Duration::from_millis(10),
            RelayDirection::Request,
        )
        .await?;

        let body_limit = relay_body(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            &lb_proto_http::BodyKind::ContentLength(11),
            10,
            Duration::from_millis(10),
            RelayDirection::Request,
        )
        .await
        .expect_err("oversized body should fail");

        assert_eq!(
            body_limit.anomaly_category(),
            Some(ProtocolAnomalyCategory::BodySizeLimitExceeded)
        );

        drop(writer);
        let mut sink = Vec::new();
        writer_peer.read_to_end(&mut sink).await?;
        assert!(sink.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_content_length_flushes_buffered_bytes_and_detects_truncation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut sink_reader, mut writer) = tokio::io::duplex(64);
        let mut buffered = b"ab".to_vec();
        feeder.write_all(b"cd").await?;
        feeder.shutdown().await?;

        relay_content_length(
            &mut reader,
            &mut buffered,
            &mut writer,
            4,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await?;

        drop(writer);
        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;
        assert_eq!(output, b"abcd");

        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut _sink_reader, mut writer) = tokio::io::duplex(64);
        feeder.write_all(b"x").await?;
        feeder.shutdown().await?;
        let truncation = relay_content_length(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            2,
            Duration::from_millis(50),
            RelayDirection::Response,
        )
        .await
        .expect_err("truncated body should fail");

        assert!(matches!(truncation, Http1ProxyError::ParseResponse(_)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_content_length_collect_writes_and_returns_body(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut sink_reader, mut writer) = tokio::io::duplex(64);
        feeder.write_all(b"payload").await?;
        feeder.shutdown().await?;

        let collected = relay_content_length_collect(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            7,
            Duration::from_millis(50),
            RelayDirection::Response,
        )
        .await?;

        drop(writer);
        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;
        assert_eq!(output, b"payload");
        assert_eq!(collected, bytes::Bytes::from_static(b"payload"));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_exact_bytes_and_read_crlf_line_cover_buffer_and_eof_paths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut sink_reader, mut writer) = tokio::io::duplex(64);
        let mut buffered = b"ab".to_vec();
        feeder.write_all(b"cd").await?;
        feeder.shutdown().await?;

        relay_exact_bytes(
            &mut reader,
            &mut buffered,
            &mut writer,
            4,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await?;

        drop(writer);
        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;
        assert_eq!(output, b"abcd");

        let mut line_buffer = b"size\r\nrest".to_vec();
        let (mut reader, _feeder) = tokio::io::duplex(64);
        let line = read_crlf_line(
            &mut reader,
            &mut line_buffer,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await?;
        assert_eq!(line, b"size\r\n");

        let (mut reader, mut feeder) = tokio::io::duplex(64);
        feeder.write_all(b"unterminated").await?;
        feeder.shutdown().await?;
        let eof = read_crlf_line(
            &mut reader,
            &mut Vec::new(),
            Duration::from_millis(50),
            RelayDirection::Response,
        )
        .await
        .expect_err("missing CRLF should fail");
        assert!(matches!(eof, Http1ProxyError::ParseResponse(_)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_chunked_handles_success_and_invalid_chunk_sizes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut feeder) = tokio::io::duplex(256);
        let (mut sink_reader, mut writer) = tokio::io::duplex(256);
        feeder.write_all(b"4\r\ntest\r\n0\r\nheader: ok\r\n\r\n").await?;
        feeder.shutdown().await?;

        relay_chunked(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            10,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await?;

        drop(writer);
        let mut output = Vec::new();
        sink_reader.read_to_end(&mut output).await?;
        assert_eq!(output, b"4\r\ntest\r\n0\r\nheader: ok\r\n\r\n");

        let (mut reader, mut feeder) = tokio::io::duplex(64);
        let (mut _sink_reader, mut writer) = tokio::io::duplex(64);
        feeder.write_all(b"zz\r\n").await?;
        feeder.shutdown().await?;

        let invalid = relay_chunked(
            &mut reader,
            &mut Vec::new(),
            &mut writer,
            10,
            Duration::from_millis(50),
            RelayDirection::Request,
        )
        .await
        .expect_err("invalid chunk sizes should fail");
        assert!(matches!(invalid, Http1ProxyError::ParseRequest(_)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ensure_upstream_connection_reconnects_after_idle_timeout(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = oneshot::channel();

        tokio::spawn(async move {
            let mut accepted_peer_addrs = Vec::new();
            let mut held_streams = Vec::new();
            for _ in 0..2 {
                let Ok((stream, peer_addr)) = listener.accept().await else {
                    break;
                };
                accepted_peer_addrs.push(peer_addr);
                held_streams.push(stream);
            }
            let _ = accepted_tx.send(accepted_peer_addrs);
            let _held_streams = held_streams;
        });

        let target = lb_net_core::UpstreamTarget::new("unit-http1-upstream", target_addr);
        let timeouts = lb_net_core::ConnectionTimeouts {
            connect_timeout: Duration::from_millis(100),
            preface_timeout: Duration::from_millis(50),
            idle_timeout: Duration::from_millis(25),
        };
        let mut upstream = None;
        let mut active_upstream = None;
        let mut last_upstream_activity = None;
        let mut upstream_connected_at = None;
        let mut upstream_addr = target_addr;
        let mut connect_duration = Duration::ZERO;

        ensure_upstream_connection(
            &mut upstream,
            &mut active_upstream,
            &mut last_upstream_activity,
            &mut upstream_connected_at,
            &mut upstream_addr,
            &mut connect_duration,
            &target,
            &timeouts,
        )
        .await?;

        let first_local_addr =
            upstream.as_ref().expect("first upstream connection").local_addr()?;
        last_upstream_activity = Some(
            Instant::now()
                .checked_sub(Duration::from_millis(50))
                .expect("valid instant subtraction"),
        );

        ensure_upstream_connection(
            &mut upstream,
            &mut active_upstream,
            &mut last_upstream_activity,
            &mut upstream_connected_at,
            &mut upstream_addr,
            &mut connect_duration,
            &target,
            &timeouts,
        )
        .await?;

        let second_local_addr =
            upstream.as_ref().expect("second upstream connection").local_addr()?;
        assert_ne!(first_local_addr, second_local_addr);

        drop(upstream.take());
        let accepted_peer_addrs = accepted_rx.await?;
        assert_eq!(accepted_peer_addrs.len(), 2);
        assert_eq!(accepted_peer_addrs[0], first_local_addr);
        assert_eq!(accepted_peer_addrs[1], second_local_addr);

        Ok(())
    }
}
