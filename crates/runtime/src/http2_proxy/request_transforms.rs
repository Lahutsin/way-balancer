fn effective_request_transform(
    config: &Http2ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
) -> Option<lb_config_model::RequestTransformConfig> {
    merge_request_transforms(
        config.listener_request_transform.as_ref(),
        route.and_then(|route| config.route_request_transforms.get(&route.label)),
    )
}

fn effective_response_transform(
    config: &Http2ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
) -> Option<lb_config_model::ResponseTransformConfig> {
    merge_response_transforms(
        config.listener_response_transform.as_ref(),
        route.and_then(|route| config.route_response_transforms.get(&route.label)),
    )
}

fn effective_destination_response_transform(
    config: &Http2ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
    destination_policy: Option<&crate::RouteDestinationPolicyRuntime>,
) -> Option<lb_config_model::ResponseTransformConfig> {
    destination_policy
        .and_then(|policy| policy.response_transform.clone())
        .or_else(|| effective_response_transform(config, route))
}


fn merge_request_transforms(
    listener: Option<&lb_config_model::RequestTransformConfig>,
    route: Option<&lb_config_model::RequestTransformConfig>,
) -> Option<lb_config_model::RequestTransformConfig> {
    if listener.is_none() && route.is_none() {
        return None;
    }

    let mut merged = listener.cloned().unwrap_or_default();
    if let Some(route) = route {
        if route.path_rewrite.is_some() {
            merged.path_rewrite = route.path_rewrite.clone();
        }
        if route.host_rewrite.is_some() {
            merged.host_rewrite = route.host_rewrite.clone();
        }
        merged.header_mutations.extend(route.header_mutations.clone());
    }
    Some(merged)
}

fn merge_response_transforms(
    listener: Option<&lb_config_model::ResponseTransformConfig>,
    route: Option<&lb_config_model::ResponseTransformConfig>,
) -> Option<lb_config_model::ResponseTransformConfig> {
    if listener.is_none() && route.is_none() {
        return None;
    }

    let mut merged = listener.cloned().unwrap_or_default();
    if let Some(route) = route {
        merged.header_mutations.extend(route.header_mutations.clone());
    }
    Some(merged)
}

fn apply_request_transform(
    request: &mut Request<RecvStream>,
    transform: &lb_config_model::RequestTransformConfig,
) -> Result<Option<String>, StreamForwardError> {
    if transform.path_rewrite.is_some() {
        *request.uri_mut() = rewrite_request_uri(request.uri(), transform.path_rewrite.as_ref())?;
    }
    apply_http2_header_mutations(request.headers_mut(), &transform.header_mutations)?;
    Ok(transform.host_rewrite.clone())
}

fn apply_http2_header_mutations(
    headers: &mut http::HeaderMap,
    mutations: &[lb_config_model::HeaderMutationConfig],
) -> Result<(), StreamForwardError> {
    for mutation in mutations {
        match mutation {
            lb_config_model::HeaderMutationConfig::Set { name, value } => {
                let normalized = lb_proto_http::normalize_http_header_name(name)
                    .unwrap_or_else(|| name.to_ascii_lowercase());
                let header_name = HeaderName::from_bytes(normalized.as_bytes())
                    .map_err(|_| StreamForwardError::InvalidRequest)?;
                let header_value =
                    HeaderValue::from_str(value).map_err(|_| StreamForwardError::InvalidRequest)?;
                headers.remove(&header_name);
                headers.insert(header_name, header_value);
            }
            lb_config_model::HeaderMutationConfig::Remove { name } => {
                let normalized = lb_proto_http::normalize_http_header_name(name)
                    .unwrap_or_else(|| name.to_ascii_lowercase());
                let header_name = HeaderName::from_bytes(normalized.as_bytes())
                    .map_err(|_| StreamForwardError::InvalidRequest)?;
                headers.remove(header_name);
            }
        }
    }
    Ok(())
}

fn rewrite_request_uri(
    uri: &Uri,
    path_rewrite: Option<&lb_config_model::PathRewriteTransformConfig>,
) -> Result<Uri, StreamForwardError> {
    let path_and_query = uri.path_and_query().map(|value| value.as_str()).unwrap_or("/");
    let rewritten_path_and_query = rewrite_path_and_query(path_and_query, path_rewrite);
    match uri.authority().map(|authority| authority.as_str()) {
        Some(authority) => format!(
            "{}://{authority}{rewritten_path_and_query}",
            uri.scheme_str().unwrap_or("http")
        )
        .parse::<Uri>()
        .map_err(|_| StreamForwardError::InvalidRequest),
        None => rewritten_path_and_query
            .parse::<Uri>()
            .map_err(|_| StreamForwardError::InvalidRequest),
    }
}

fn rewrite_path_and_query(
    path_and_query: &str,
    path_rewrite: Option<&lb_config_model::PathRewriteTransformConfig>,
) -> String {
    let Some(path_rewrite) = path_rewrite else {
        return path_and_query.to_string();
    };
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (if path.is_empty() { "/" } else { path }, Some(query)),
        None => (path_and_query, None),
    };
    let rewritten_path = match path_rewrite {
        lb_config_model::PathRewriteTransformConfig::ReplacePrefix {
            match_prefix,
            replacement,
        } if path.starts_with(match_prefix) => {
            format!("{replacement}{}", &path[match_prefix.len()..])
        }
        lb_config_model::PathRewriteTransformConfig::ReplacePrefix { .. } => path.to_string(),
    };
    query.map_or(rewritten_path.clone(), |query| format!("{rewritten_path}?{query}"))
}

