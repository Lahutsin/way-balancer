fn build_downstream_response_from_parts(
    status: StatusCode,
    response_headers: &http::HeaderMap,
    response_transform: Option<&lb_config_model::ResponseTransformConfig>,
) -> Result<Response<()>, StreamForwardError> {
    let mut builder = Response::builder().status(status).version(http::Version::HTTP_2);
    let mut headers = response_headers.clone();
    if let Some(transform) = response_transform {
        apply_http2_header_mutations(&mut headers, &transform.header_mutations)?;
    }
    for (name, value) in &headers {
        if should_skip_http2_header(name, value) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder.body(()).map_err(|_| StreamForwardError::InvalidRequest)
}

fn build_downstream_response(
    response: &Response<RecvStream>,
    response_transform: Option<&lb_config_model::ResponseTransformConfig>,
) -> Result<Response<()>, StreamForwardError> {
    build_downstream_response_from_parts(response.status(), response.headers(), response_transform)
}

fn should_skip_http2_header(name: &HeaderName, value: &HeaderValue) -> bool {
    if name == http::header::CONNECTION
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::PROXY_AUTHENTICATE
        || name == http::header::PROXY_AUTHORIZATION
        || name == http::header::UPGRADE
        || name == http::header::HOST
        || name == http::header::TE && value != "trailers"
        || name == HeaderName::from_static("proxy-connection")
        || name == HeaderName::from_static("keep-alive")
        || name == HeaderName::from_static("x-forwarded-for")
    {
        return true;
    }

    false
}

fn send_local_response(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
) -> Result<(), h2::Error> {
    let response = Response::builder()
        .status(status)
        .version(http::Version::HTTP_2)
        .body(())
        .map_err(|_| h2::Error::from(h2::Reason::INTERNAL_ERROR))?;
    respond.send_response(response, true).map(|_| ())
}

fn header_map_to_http_headers(headers: &http::HeaderMap) -> Vec<lb_proto_http::HttpHeader> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| lb_proto_http::HttpHeader {
                name: name.as_str().to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

fn grpc_status_from_header_map(headers: &http::HeaderMap) -> Option<u16> {
    headers
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u16>().ok())
}

