enum HeaderMutationTarget {
    Request,
    Response,
}

fn validate_header_mutations(
    mutations: &[HeaderMutationConfig],
    path: &str,
    target: HeaderMutationTarget,
    report: &mut ValidationReport,
) {
    for (index, mutation) in mutations.iter().enumerate() {
        let (name, value) = match mutation {
            HeaderMutationConfig::Set { name, value } => (name.as_str(), Some(value.as_str())),
            HeaderMutationConfig::Remove { name } => (name.as_str(), None),
        };
        let name_path = format!("{path}[{index}].name");
        let Some(normalized_name) = lb_proto_http::normalize_http_header_name(name) else {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                name_path,
                "header mutation name must be a valid HTTP header name",
            ));
            continue;
        };

        let disallowed = match target {
            HeaderMutationTarget::Request => is_disallowed_request_transform_header(&normalized_name),
            HeaderMutationTarget::Response => {
                is_disallowed_response_transform_header(&normalized_name)
            }
        };
        if disallowed {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{path}[{index}]"),
                format!(
                    "header mutation for {normalized_name} is not allowed because it affects hop-by-hop or framing behavior"
                ),
            ));
        }

        if let Some(value) = value {
            if value.trim().is_empty() || value.contains(['\r', '\n']) {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{path}[{index}].value"),
                    "header mutation set values must be non-empty and must not contain CR or LF",
                ));
            }
        }
    }
}


fn is_disallowed_request_transform_header(header: &str) -> bool {
    matches!(
        header,
        "connection"
            | "content-length"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_disallowed_response_transform_header(header: &str) -> bool {
    matches!(
        header,
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn validate_named_header_list(headers: &[String], path: &str, report: &mut ValidationReport) {
    let mut seen = BTreeSet::new();
    for (index, header) in headers.iter().enumerate() {
        let normalized = header.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{path}[{index}]"),
                "header names must not be empty",
            ));
            continue;
        }
        if !seen.insert(normalized.clone()) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                format!("{path}[{index}]"),
                format!("header {normalized} is repeated"),
            ));
        }
        if is_disallowed_http_cache_key_header(&normalized) {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{path}[{index}]"),
                format!("header {normalized} is not allowed in cache key or vary configuration"),
            ));
        }
    }
}

fn is_disallowed_http_cache_key_header(header: &str) -> bool {
    matches!(
        header,
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

