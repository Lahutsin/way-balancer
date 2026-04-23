fn selection_context_for_request(
    request: &lb_proto_http::Http1RequestHead,
    affinity_policy: Option<&crate::AffinityPolicy>,
) -> crate::SelectionContext {
    crate::SelectionContext {
        preferred_locality: request_header_value(request, "x-lb-locality").map(String::from),
        preferred_zone: request_header_value(request, "x-lb-zone").map(String::from),
        affinity_key: request_affinity_key(request, affinity_policy),
        request_hash: stable_request_hash(request.target.as_bytes()),
    }
}

fn request_affinity_key(
    request: &lb_proto_http::Http1RequestHead,
    affinity_policy: Option<&crate::AffinityPolicy>,
) -> Option<String> {
    match affinity_policy {
        Some(crate::AffinityPolicy::HeaderHash { header_name, .. }) => {
            request_header_value(request, header_name).map(String::from)
        }
        Some(crate::AffinityPolicy::CookieHash { cookie_name, .. }) => {
            request_cookie_value(&request.headers, cookie_name).map(String::from)
        }
        None => None,
    }
}

fn request_header_value<'a>(
    request: &'a lb_proto_http::Http1RequestHead,
    name: &str,
) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.trim())
        .filter(|value| !value.is_empty())
}

fn request_cookie_value<'a>(
    headers: &'a [lb_proto_http::HttpHeader],
    cookie_name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("cookie"))
        .find_map(|header| cookie_value_from_header(&header.value, cookie_name))
}

fn cookie_value_from_header<'a>(header_value: &'a str, cookie_name: &str) -> Option<&'a str> {
    header_value.split(';').filter_map(|cookie| cookie.split_once('=')).find_map(|(name, value)| {
        let name = name.trim();
        if name == cookie_name {
            let value = value.trim();
            (!value.is_empty()).then_some(value)
        } else {
            None
        }
    })
}

fn resolve_effective_client_ip(
    config: &Http1ProxyConfig,
    downstream_addr: SocketAddr,
    request: &lb_proto_http::Http1RequestHead,
) -> Result<IpAddr, crate::TrustedClientIpError> {
    config.trusted_client_ip.as_ref().map_or(Ok(downstream_addr.ip()), |policy| {
        policy
            .resolve_resolution_from_http1_headers(downstream_addr.ip(), &request.headers)
            .map(|resolution| resolution.client_ip)
    })
}

