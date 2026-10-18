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
            | Http1ProxyError::UpstreamGracefulDrain
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

#[cfg(test)]
mod cache_headers_coverage_tests {
    use std::time::Duration;

    use super::*;

    fn header(name: &str, value: &str) -> lb_proto_http::HttpHeader {
        lb_proto_http::HttpHeader { name: name.to_owned(), value: value.to_owned() }
    }

    fn entry() -> HttpCacheEntry {
        HttpCacheEntry {
            metadata: HttpCacheMetadata {
                status: StatusCode::OK,
                stored_at: Duration::ZERO,
                fresh_until: Duration::from_secs(1),
                stale_while_revalidate_until: None,
                stale_if_error_until: None,
                etag: Some(HeaderValue::from_static("\"v1\"")),
                last_modified: Some(HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT")),
            },
            headers: Vec::new(),
            body: bytes::Bytes::from_static(b"cached"),
        }
    }

    #[test]
    fn cache_control_and_date_metadata_produce_bounded_freshness() {
        let policy = lb_config_model::HttpCachePolicyConfig::default();
        let windows =
            derive_freshness_windows_from_origin(&policy, &[]).expect("default freshness");
        assert_eq!(windows.fresh_for, Duration::from_secs(policy.default_ttl_secs));

        let windows = derive_freshness_windows_from_origin(
            &policy,
            &[header("Cache-Control", "max-age=120, s-maxage=90"), header("Age", "20")],
        )
        .expect("valid shared cache freshness");
        assert_eq!(windows.fresh_for, Duration::from_secs(70));

        let expires = derive_freshness_windows_from_origin(
            &policy,
            &[
                header("expires", "Wed, 21 Oct 2015 07:30:00 GMT"),
                header("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                header("age", "30"),
            ],
        )
        .expect("valid date freshness");
        assert_eq!(expires.fresh_for, Duration::from_secs(90));
        assert!(derive_freshness_windows_from_origin(&policy, &[header("expires", "not-a-date")])
            .is_none());
        assert!(derive_freshness_windows_from_origin(
            &policy,
            &[header("age", "invalid"), header("cache-control", "max-age=10")]
        )
        .is_none());
    }

    #[test]
    fn cache_control_pragma_vary_and_header_parsers_fail_closed() {
        let policy = lb_config_model::HttpCachePolicyConfig::default();
        for directive in ["no-store", "private", "no-cache"] {
            assert!(derive_freshness_windows_from_origin(
                &policy,
                &[header("cache-control", directive)]
            )
            .is_none());
        }
        assert!(derive_freshness_windows_from_origin(&policy, &[header("pragma", "no-cache")])
            .is_none());
        assert!(parse_cache_control(&[header("cache-control", "max-age")]).is_none());
        assert!(parse_cache_control(&[header("cache-control", "max-age=invalid")]).is_none());
        assert!(parse_cache_control(&[header("cache-control", "max-age=\"12\"")]).is_some());
        assert_eq!(parse_cache_delta("\"12\""), Some(12));
        assert_eq!(parse_cache_delta("-1"), None);
        assert_eq!(header_value(&[], "age"), None);
        assert_eq!(header_value(&[header("age", " 3 ")], "age"), Some("3"));
        assert_eq!(header_value(&[header("age", "1"), header("age", "2")], "age"), None);
        assert!(has_pragma_no_cache(&[header("Pragma", "no-cache")]));
        assert!(!has_pragma_no_cache(&[header("Pragma", "no-cache, no-store")]));
        assert!(response_has_unsafe_vary(&[header("vary", "*")]));
        assert!(response_has_unsafe_vary(&[header("vary", "Accept, Authorization")]));
        assert!(response_has_unsafe_vary(&[header("vary", "Accept,")]));
        assert!(!response_has_unsafe_vary(&[header("vary", "Accept-Encoding")]));
        assert!(is_disallowed_cache_vary_header("X-Forwarded-For"));
    }

    #[test]
    fn validators_methods_statuses_and_telemetry_inputs_are_handled() {
        let policy = lb_config_model::HttpCachePolicyConfig::default();
        assert!(request_method_is_cache_lookup_eligible(&policy, "get"));
        assert!(request_method_is_cache_lookup_eligible(&policy, "HEAD"));
        assert!(!request_method_is_cache_lookup_eligible(&policy, "POST"));

        let response = lb_proto_http::Http1ResponseHead {
            version: lb_proto_http::SupportedHttpVersion::Http1,
            status: 200,
            reason: String::new(),
            headers: Vec::new(),
            body_kind: lb_proto_http::BodyKind::None,
            keep_alive: true,
        };
        assert!(response_is_cacheable(&policy, &response, &[]));
        assert!(!response_is_cacheable(
            &policy,
            &lb_proto_http::Http1ResponseHead { status: 400, ..response.clone() },
            &[]
        ));
        assert!(!response_is_cacheable(
            &policy,
            &response,
            &[header("set-cookie", "session=secret")]
        ));
        assert!(response_header_value(&[header("ETag", "\"v1\"")], "etag").is_some());
        assert!(response_header_value(&[header("etag", "bad\nvalue")], "etag").is_none());
        assert!(to_cache_headers(&[header("content-type", "text/plain")]).is_some());
        assert!(to_cache_headers(&[header("bad header", "value")]).is_none());
        assert!(to_cache_headers(&[header("x-test", "bad\nvalue")]).is_none());

        let stale = entry();
        assert!(should_revalidate_entry(&policy, &stale));
        let conditional = append_conditional_revalidation_headers(Vec::new(), Some(&stale));
        assert_eq!(conditional.len(), 2);
        assert_eq!(conditional[0].name, "if-none-match");
        assert_eq!(conditional[1].name, "if-modified-since");
        assert!(append_conditional_revalidation_headers(Vec::new(), None).is_empty());
        let refreshed = refresh_revalidated_entry(
            Some(&policy),
            &stale,
            &[header("cache-control", "max-age=20")],
            Duration::from_secs(5),
        )
        .expect("revalidated metadata");
        assert_eq!(refreshed.metadata.etag, stale.metadata.etag);
        assert_eq!(refreshed.metadata.last_modified, stale.metadata.last_modified);
        assert!(refresh_revalidated_entry(None, &stale, &[], Duration::ZERO).is_none());
        assert!(derive_cache_metadata(
            &lb_config_model::HttpCachePolicyConfig {
                honor_cache_control: false,
                default_ttl_secs: 0,
                stale_while_revalidate_secs: 0,
                stale_if_error_secs: 0,
                ..policy
            },
            &[],
            StatusCode::OK,
            Duration::ZERO
        )
        .is_none());

        assert_eq!(duration_if_non_zero(0), None);
        assert_eq!(duration_if_non_zero(2), Some(Duration::from_secs(2)));
        assert!(is_stale_if_error_response_status(500));
        assert!(is_stale_if_error_response_status(599));
        assert!(!is_stale_if_error_response_status(600));
        assert!(error_allows_stale_if_error(&Http1ProxyError::UpstreamGracefulDrain));
        assert!(error_allows_stale_if_error(&Http1ProxyError::IdleTimeout("request body")));
        assert!(!error_allows_stale_if_error(&Http1ProxyError::IdleTimeout("request head")));

        record_cache_request_telemetry(None, HttpCacheRequestOutcome::Bypass, "test", "disabled");
        record_cache_revalidation_telemetry(None, HttpCacheRevalidationResult::Failed, "disabled");
    }
}
