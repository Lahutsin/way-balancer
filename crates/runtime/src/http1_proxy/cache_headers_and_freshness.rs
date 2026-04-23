fn request_method_is_cache_lookup_eligible(
    policy: &lb_config_model::HttpCachePolicyConfig,
    method: &str,
) -> bool {
    policy.methods.iter().any(|configured_method| match configured_method {
        lb_config_model::HttpCacheMethodConfig::Get => method.eq_ignore_ascii_case("GET"),
        lb_config_model::HttpCacheMethodConfig::Head => method.eq_ignore_ascii_case("HEAD"),
    })
}

fn response_is_cacheable(
    policy: &lb_config_model::HttpCachePolicyConfig,
    response: &lb_proto_http::Http1ResponseHead,
    headers: &[lb_proto_http::HttpHeader],
) -> bool {
    if !policy.cacheable_status_codes.contains(&response.status) {
        return false;
    }
    if !policy.allow_set_cookie_storage
        && headers.iter().any(|header| header.name.eq_ignore_ascii_case("set-cookie"))
    {
        return false;
    }
    if response_has_unsafe_vary(headers) {
        return false;
    }
    true
}

fn response_has_unsafe_vary(headers: &[lb_proto_http::HttpHeader]) -> bool {
    for header in headers.iter().filter(|header| header.name.eq_ignore_ascii_case("vary")) {
        for value in header.value.split(',').map(str::trim) {
            if value.is_empty() || value == "*" || is_disallowed_cache_vary_header(value) {
                return true;
            }
        }
    }
    false
}

fn is_disallowed_cache_vary_header(header: &str) -> bool {
    matches!(
        header.to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-proto"
    )
}

fn derive_cache_metadata(
    policy: &lb_config_model::HttpCachePolicyConfig,
    headers: &[lb_proto_http::HttpHeader],
    status: StatusCode,
    now: Duration,
) -> Option<HttpCacheMetadata> {
    let freshness = if policy.honor_cache_control {
        derive_freshness_windows_from_origin(policy, headers)?
    } else {
        CacheFreshnessWindows {
            fresh_for: Duration::from_secs(policy.default_ttl_secs),
            stale_while_revalidate_for: duration_if_non_zero(policy.stale_while_revalidate_secs),
            stale_if_error_for: duration_if_non_zero(policy.stale_if_error_secs),
        }
    };

    if freshness.fresh_for.is_zero()
        && freshness.stale_while_revalidate_for.is_none()
        && freshness.stale_if_error_for.is_none()
    {
        return None;
    }

    let fresh_until = now + freshness.fresh_for;
    Some(HttpCacheMetadata {
        status,
        stored_at: now,
        fresh_until,
        stale_while_revalidate_until: freshness
            .stale_while_revalidate_for
            .map(|window| fresh_until + window),
        stale_if_error_until: freshness.stale_if_error_for.map(|window| fresh_until + window),
        etag: response_header_value(headers, "etag"),
        last_modified: response_header_value(headers, "last-modified"),
    })
}

fn should_revalidate_entry(
    policy: &lb_config_model::HttpCachePolicyConfig,
    entry: &HttpCacheEntry,
) -> bool {
    policy.revalidation_enabled
        && (entry.metadata.etag.is_some() || entry.metadata.last_modified.is_some())
}

fn append_conditional_revalidation_headers(
    mut headers: Vec<lb_proto_http::HttpHeader>,
    revalidation_entry: Option<&HttpCacheEntry>,
) -> Vec<lb_proto_http::HttpHeader> {
    let Some(revalidation_entry) = revalidation_entry else {
        return headers;
    };
    if let Some(etag) = &revalidation_entry.metadata.etag {
        if let Ok(etag) = etag.to_str() {
            headers.push(lb_proto_http::HttpHeader {
                name: String::from("if-none-match"),
                value: String::from(etag),
            });
        }
    }
    if let Some(last_modified) = &revalidation_entry.metadata.last_modified {
        if let Ok(last_modified) = last_modified.to_str() {
            headers.push(lb_proto_http::HttpHeader {
                name: String::from("if-modified-since"),
                value: String::from(last_modified),
            });
        }
    }
    headers
}

fn refresh_revalidated_entry(
    policy: Option<&lb_config_model::HttpCachePolicyConfig>,
    stale_entry: &HttpCacheEntry,
    response_headers: &[lb_proto_http::HttpHeader],
    now: Duration,
) -> Option<HttpCacheEntry> {
    let policy = policy?;
    let mut refreshed = stale_entry.clone();
    let metadata =
        derive_cache_metadata(policy, response_headers, stale_entry.metadata.status, now)?;
    refreshed.metadata = HttpCacheMetadata {
        etag: metadata.etag.or_else(|| stale_entry.metadata.etag.clone()),
        last_modified: metadata
            .last_modified
            .or_else(|| stale_entry.metadata.last_modified.clone()),
        ..metadata
    };
    Some(refreshed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheFreshnessWindows {
    fresh_for: Duration,
    stale_while_revalidate_for: Option<Duration>,
    stale_if_error_for: Option<Duration>,
}

fn derive_freshness_windows_from_origin(
    policy: &lb_config_model::HttpCachePolicyConfig,
    headers: &[lb_proto_http::HttpHeader],
) -> Option<CacheFreshnessWindows> {
    let directives = parse_cache_control(headers)?;
    if directives.no_store
        || directives.private
        || directives.no_cache
        || has_pragma_no_cache(headers)
    {
        return None;
    }

    let age_secs = match header_value(headers, "age") {
        Some(value) => value.parse::<u64>().ok()?,
        None => 0,
    };

    let freshness_secs = if let Some(max_age) = directives.shared_max_age.or(directives.max_age) {
        max_age.saturating_sub(age_secs)
    } else if let Some(expires_header) = header_value(headers, "expires") {
        let expires_at = parse_http_date(expires_header).ok()?;
        if let Some(date_header) = header_value(headers, "date") {
            let origin_date = parse_http_date(date_header).ok()?;
            expires_at
                .duration_since(origin_date)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(age_secs)
        } else {
            policy.default_ttl_secs
        }
    } else {
        policy.default_ttl_secs
    };

    let fresh_for = Duration::from_secs(freshness_secs.min(policy.max_ttl_secs));
    let stale_while_revalidate_for = duration_if_non_zero(
        directives
            .stale_while_revalidate
            .unwrap_or(policy.stale_while_revalidate_secs)
            .min(policy.stale_while_revalidate_secs),
    );
    let stale_if_error_for = duration_if_non_zero(
        directives
            .stale_if_error
            .unwrap_or(policy.stale_if_error_secs)
            .min(policy.stale_if_error_secs),
    );

    Some(CacheFreshnessWindows { fresh_for, stale_while_revalidate_for, stale_if_error_for })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ParsedCacheControl {
    no_store: bool,
    private: bool,
    no_cache: bool,
    max_age: Option<u64>,
    shared_max_age: Option<u64>,
    stale_while_revalidate: Option<u64>,
    stale_if_error: Option<u64>,
}

fn parse_cache_control(headers: &[lb_proto_http::HttpHeader]) -> Option<ParsedCacheControl> {
    let mut parsed = ParsedCacheControl::default();
    for value in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("cache-control"))
        .map(|header| header.value.as_str())
    {
        for directive in value.split(',').map(str::trim).filter(|value| !value.is_empty()) {
            let (name, parameter) = directive
                .split_once('=')
                .map_or((directive, None), |(name, value)| (name.trim(), Some(value.trim())));
            if name.eq_ignore_ascii_case("no-store") {
                parsed.no_store = true;
            } else if name.eq_ignore_ascii_case("private") {
                parsed.private = true;
            } else if name.eq_ignore_ascii_case("no-cache") {
                parsed.no_cache = true;
            } else if name.eq_ignore_ascii_case("max-age") {
                parsed.max_age = Some(parse_cache_delta(parameter?)?);
            } else if name.eq_ignore_ascii_case("s-maxage") {
                parsed.shared_max_age = Some(parse_cache_delta(parameter?)?);
            } else if name.eq_ignore_ascii_case("stale-while-revalidate") {
                parsed.stale_while_revalidate = Some(parse_cache_delta(parameter?)?);
            } else if name.eq_ignore_ascii_case("stale-if-error") {
                parsed.stale_if_error = Some(parse_cache_delta(parameter?)?);
            }
        }
    }
    Some(parsed)
}

fn parse_cache_delta(value: &str) -> Option<u64> {
    let value = value.trim_matches('"');
    value.parse::<u64>().ok()
}

fn header_value<'a>(headers: &'a [lb_proto_http::HttpHeader], name: &str) -> Option<&'a str> {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.trim());
    let first = values.next()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn has_pragma_no_cache(headers: &[lb_proto_http::HttpHeader]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("pragma") && header.value.eq_ignore_ascii_case("no-cache")
    })
}

fn duration_if_non_zero(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn record_cache_request_telemetry(
    response_cache: Option<&Http1ResponseCacheConfig>,
    outcome: HttpCacheRequestOutcome,
    reason: &str,
    detail: &str,
) {
    if let Some(telemetry) =
        response_cache.and_then(|response_cache| response_cache.telemetry.as_ref())
    {
        let _ = telemetry.telemetry.record_http_cache_request(
            &telemetry.scope,
            outcome,
            reason,
            detail,
        );
    }
}

fn record_cache_revalidation_telemetry(
    response_cache: Option<&Http1ResponseCacheConfig>,
    result: HttpCacheRevalidationResult,
    detail: &str,
) {
    if let Some(telemetry) =
        response_cache.and_then(|response_cache| response_cache.telemetry.as_ref())
    {
        let _ =
            telemetry.telemetry.record_http_cache_revalidation(&telemetry.scope, result, detail);
    }
}

fn is_stale_if_error_response_status(status: u16) -> bool {
    (500..=599).contains(&status)
}

fn error_allows_stale_if_error(error: &Http1ProxyError) -> bool {
    matches!(
        error,
        Http1ProxyError::ConnectTimeout { .. }
            | Http1ProxyError::Connect { .. }
            | Http1ProxyError::ParseResponse(_)
            | Http1ProxyError::RequestIo(_)
            | Http1ProxyError::IdleTimeout("request body")
            | Http1ProxyError::IdleTimeout("response head")
    )
}

fn response_header_value(headers: &[lb_proto_http::HttpHeader], name: &str) -> Option<HeaderValue> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .and_then(|header| HeaderValue::from_str(&header.value).ok())
}

fn to_cache_headers(headers: &[lb_proto_http::HttpHeader]) -> Option<Vec<HttpCacheHeader>> {
    headers
        .iter()
        .map(|header| {
            Some(HttpCacheHeader::new(
                HeaderName::from_bytes(header.name.as_bytes()).ok()?,
                HeaderValue::from_str(&header.value).ok()?,
            ))
        })
        .collect()
}
