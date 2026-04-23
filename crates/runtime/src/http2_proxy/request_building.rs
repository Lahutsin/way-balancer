fn build_upstream_request(
    request: &Request<RecvStream>,
    authority_override: Option<&str>,
    effective_client_ip: IpAddr,
    upstream_addr: SocketAddr,
) -> Result<Request<()>, StreamForwardError> {
    prepare_upstream_request_template(request, authority_override, effective_client_ip, upstream_addr)?
        .into_request()
}

#[derive(Clone)]
struct UpstreamRequestTemplate {
    method: http::Method,
    uri: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl UpstreamRequestTemplate {
    fn into_request(self) -> Result<Request<()>, StreamForwardError> {
        let mut builder =
            Request::builder().method(self.method).uri(self.uri).version(http::Version::HTTP_2);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        builder.body(()).map_err(|_| StreamForwardError::InvalidRequest)
    }
}

fn prepare_upstream_request_template(
    request: &Request<RecvStream>,
    authority_override: Option<&str>,
    effective_client_ip: IpAddr,
    upstream_addr: SocketAddr,
) -> Result<UpstreamRequestTemplate, StreamForwardError> {
    let mut headers = Vec::new();
    for (name, value) in request.headers() {
        if should_skip_http2_header(name, value) {
            continue;
        }
        headers.push((name.clone(), value.clone()));
    }
    headers.push((
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&effective_client_ip.to_string())
            .map_err(|_| StreamForwardError::InvalidRequest)?,
    ));
    Ok(UpstreamRequestTemplate {
        method: request.method().clone(),
        uri: normalize_request_uri(request.uri(), authority_override, upstream_addr)?,
        headers,
    })
}

fn request_is_safe_stale_reuse_retry_candidate(request: &Request<RecvStream>) -> bool {
    request.body().is_end_stream()
        && matches!(request.method().as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

fn http2_stale_reuse_retryable_error(error: &h2::Error) -> bool {
    error.is_io() || error.is_go_away()
}

fn classify_http2_upstream_error(
    error: &h2::Error,
    fallback: StreamForwardError,
) -> StreamForwardError {
    if error.is_go_away() && error.reason() == Some(Reason::NO_ERROR) {
        StreamForwardError::UpstreamGracefulDrain
    } else {
        fallback
    }
}


fn normalize_request_uri(
    uri: &Uri,
    authority_override: Option<&str>,
    upstream_addr: SocketAddr,
) -> Result<Uri, StreamForwardError> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.clone());
    }
    let target = uri.path_and_query().map(|value| value.as_str()).unwrap_or("/");
    let fallback_authority = upstream_addr.to_string();
    let rewritten_authority = authority_override.map(|authority| {
        if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{authority}:{}", upstream_addr.port())
        }
    });
    let authority = rewritten_authority.as_deref().unwrap_or(fallback_authority.as_str());
    format!("http://{authority}{target}")
        .parse::<Uri>()
        .map_err(|_| StreamForwardError::InvalidRequest)
}

