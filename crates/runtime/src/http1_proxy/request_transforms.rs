fn effective_request_transform(
    config: &Http1ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
) -> Option<lb_config_model::RequestTransformConfig> {
    merge_request_transforms(
        config.listener_request_transform.as_ref(),
        route.and_then(|route| config.route_request_transforms.get(&route.label)),
    )
}

fn effective_response_transform(
    config: &Http1ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
) -> Option<lb_config_model::ResponseTransformConfig> {
    merge_response_transforms(
        config.listener_response_transform.as_ref(),
        route.and_then(|route| config.route_response_transforms.get(&route.label)),
    )
}

fn effective_destination_response_transform(
    config: &Http1ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
    destination_policy: Option<&RouteDestinationPolicyRuntime>,
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
    request: &mut lb_proto_http::Http1RequestHead,
    transform: &lb_config_model::RequestTransformConfig,
) -> Result<(), lb_proto_http::RequestTargetError> {
    if transform.path_rewrite.is_some() || transform.host_rewrite.is_some() {
        request.target = rewrite_http1_request_target(
            &request.target,
            transform.path_rewrite.as_ref(),
            transform.host_rewrite.as_deref(),
        )?;
    }
    apply_http1_header_mutations(&mut request.headers, &transform.header_mutations);
    if let Some(host_rewrite) = transform.host_rewrite.as_deref() {
        upsert_http1_header(&mut request.headers, "host", host_rewrite);
    }
    Ok(())
}

fn apply_http1_header_mutations(
    headers: &mut Vec<lb_proto_http::HttpHeader>,
    mutations: &[lb_config_model::HeaderMutationConfig],
) {
    for mutation in mutations {
        match mutation {
            lb_config_model::HeaderMutationConfig::Set { name, value } => {
                let normalized = lb_proto_http::normalize_http_header_name(name)
                    .unwrap_or_else(|| name.to_ascii_lowercase());
                headers.retain(|header| !header.name.eq_ignore_ascii_case(&normalized));
                headers.push(lb_proto_http::HttpHeader {
                    name: normalized,
                    value: value.clone(),
                });
            }
            lb_config_model::HeaderMutationConfig::Remove { name } => {
                headers.retain(|header| !header.name.eq_ignore_ascii_case(name));
            }
        }
    }
}

fn upsert_http1_header(
    headers: &mut Vec<lb_proto_http::HttpHeader>,
    name: &str,
    value: &str,
) {
    headers.retain(|header| !header.name.eq_ignore_ascii_case(name));
    headers.push(lb_proto_http::HttpHeader {
        name: name.to_ascii_lowercase(),
        value: value.to_string(),
    });
}

fn rewrite_http1_request_target(
    target: &str,
    path_rewrite: Option<&lb_config_model::PathRewriteTransformConfig>,
    host_rewrite: Option<&str>,
) -> Result<String, lb_proto_http::RequestTargetError> {
    let target = target.trim();
    if target.is_empty() || target == "*" {
        return Err(lb_proto_http::RequestTargetError::UnsupportedForm);
    }
    if target.contains('#') {
        return Err(lb_proto_http::RequestTargetError::FragmentNotAllowed);
    }

    let (scheme, authority, path_and_query) = if let Some(scheme_end) = target.find("://") {
        let scheme = &target[..scheme_end];
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(lb_proto_http::RequestTargetError::UnsupportedForm);
        }
        let remainder = &target[scheme_end + 3..];
        let split_index = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let authority = &remainder[..split_index];
        if authority.trim().is_empty() {
            return Err(lb_proto_http::RequestTargetError::EmptyAuthority);
        }
        let tail = &remainder[split_index..];
        let path_and_query = if tail.is_empty() {
            String::from("/")
        } else if tail.starts_with('?') {
            format!("/{tail}")
        } else {
            tail.to_string()
        };
        (Some(scheme), Some(authority), path_and_query)
    } else if target.starts_with('/') {
        (None, None, target.to_string())
    } else {
        return Err(lb_proto_http::RequestTargetError::UnsupportedForm);
    };

    let rewritten_path_and_query = rewrite_path_and_query(&path_and_query, path_rewrite);
    if let Some(scheme) = scheme {
        let authority = host_rewrite.or(authority).unwrap_or_default();
        Ok(format!("{scheme}://{authority}{rewritten_path_and_query}"))
    } else {
        Ok(rewritten_path_and_query)
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

