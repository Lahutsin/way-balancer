fn stable_request_hash(input: &[u8]) -> u64 {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    hash.write(input);
    hash.finish()
}

fn selection_context_for_request(
    path_and_query: &str,
    headers: &http::HeaderMap,
    affinity_policy: Option<&crate::AffinityPolicy>,
) -> crate::SelectionContext {
    crate::SelectionContext {
        preferred_locality: header_value(headers, "x-lb-locality").map(String::from),
        preferred_zone: header_value(headers, "x-lb-zone").map(String::from),
        affinity_key: request_affinity_key(headers, affinity_policy),
        request_hash: stable_request_hash(path_and_query.as_bytes()),
    }
}

fn request_affinity_key(
    headers: &http::HeaderMap,
    affinity_policy: Option<&crate::AffinityPolicy>,
) -> Option<String> {
    match affinity_policy {
        Some(crate::AffinityPolicy::HeaderHash { header_name, .. }) => {
            header_value(headers, header_name).map(String::from)
        }
        Some(crate::AffinityPolicy::CookieHash { cookie_name, .. }) => {
            request_cookie_value(headers, cookie_name).map(String::from)
        }
        None => None,
    }
}

fn header_value<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}


fn request_cookie_value<'a>(headers: &'a http::HeaderMap, cookie_name: &str) -> Option<&'a str> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| cookie_value_from_header(value, cookie_name))
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

