enum CacheRequestOutcome {
    CacheHit {
        entry: Box<HttpCacheEntry>,
        outcome: HttpCacheRequestOutcome,
        reason: &'static str,
    },
    Fetch {
        key: Option<HttpCacheKey>,
        stale_fallback: Option<Box<HttpCacheEntry>>,
        revalidation_entry: Option<Box<HttpCacheEntry>>,
        reason: &'static str,
    },
    Bypass(&'static str),
}

fn resolve_cache_request(
    response_cache: Option<&Http1ResponseCacheConfig>,
    request: &lb_proto_http::Http1RequestHead,
    now: Duration,
) -> Option<CacheRequestOutcome> {
    let response_cache = response_cache?;
    if !request_method_is_cache_lookup_eligible(&response_cache.policy, &request.method) {
        return Some(CacheRequestOutcome::Bypass("method_ineligible"));
    }
    if !matches!(request.body_kind, lb_proto_http::BodyKind::None) {
        return Some(CacheRequestOutcome::Bypass("request_body"));
    }

    let key_material = match build_http_cache_key_material(
        &response_cache.policy,
        &HttpCacheRequest {
            method: &request.method,
            target: &request.target,
            headers: &request.headers,
        },
        &response_cache.policy.vary_headers,
    ) {
        Ok(Some(material)) => material,
        Ok(None) => {
            let reason = if request
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("cookie"))
            {
                "request_cookie"
            } else if request
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("authorization"))
            {
                "request_authorization"
            } else {
                "policy_bypass"
            };
            return Some(CacheRequestOutcome::Bypass(reason));
        }
        Err(_) => return Some(CacheRequestOutcome::Bypass("key_build_error")),
    };
    let storage_key = match key_material.storage_key() {
        Ok(key) => key,
        Err(_) => return Some(CacheRequestOutcome::Bypass("key_storage_error")),
    };

    match response_cache.store.lookup(now, &storage_key) {
        Some(lookup) if matches!(lookup.freshness, crate::HttpCacheFreshness::Fresh) => {
            Some(CacheRequestOutcome::CacheHit {
                entry: Box::new(lookup.entry),
                outcome: HttpCacheRequestOutcome::Hit,
                reason: "fresh",
            })
        }
        Some(lookup)
            if matches!(lookup.freshness, crate::HttpCacheFreshness::StaleWhileRevalidate)
                && !should_revalidate_entry(&response_cache.policy, &lookup.entry) =>
        {
            Some(CacheRequestOutcome::CacheHit {
                entry: Box::new(lookup.entry),
                outcome: HttpCacheRequestOutcome::StaleHit,
                reason: "stale_while_revalidate",
            })
        }
        Some(lookup) if should_revalidate_entry(&response_cache.policy, &lookup.entry) => {
            Some(CacheRequestOutcome::Fetch {
                key: Some(storage_key),
                stale_fallback: Some(Box::new(lookup.entry.clone())),
                revalidation_entry: Some(Box::new(lookup.entry)),
                reason: "revalidation",
            })
        }
        Some(lookup) if matches!(lookup.freshness, crate::HttpCacheFreshness::StaleIfError) => {
            Some(CacheRequestOutcome::Fetch {
                key: Some(storage_key),
                stale_fallback: Some(Box::new(lookup.entry)),
                revalidation_entry: None,
                reason: "stale_if_error_revalidation",
            })
        }
        _ => Some(CacheRequestOutcome::Fetch {
            key: Some(storage_key),
            stale_fallback: None,
            revalidation_entry: None,
            reason: "miss",
        }),
    }
}
