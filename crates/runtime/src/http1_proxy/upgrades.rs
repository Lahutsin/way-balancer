#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpgradeRequestError {
    MissingUpgradeHeader,
    MissingConnectionToken,
    UnsupportedProtocol,
    InvalidMethod,
    BodyNotAllowed,
}

impl UpgradeRequestError {
    const fn message(self) -> &'static str {
        match self {
            Self::MissingUpgradeHeader => "malformed upgrade request: missing Upgrade header\n",
            Self::MissingConnectionToken => {
                "malformed upgrade request: missing Connection: upgrade token\n"
            }
            Self::UnsupportedProtocol => "unsupported upgrade protocol\n",
            Self::InvalidMethod => "websocket upgrade requires GET\n",
            Self::BodyNotAllowed => "websocket upgrade requests must not include a body\n",
        }
    }

    const fn telemetry_reason(self) -> &'static str {
        match self {
            Self::MissingUpgradeHeader => "missing_upgrade_header",
            Self::MissingConnectionToken => "missing_connection_upgrade",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::InvalidMethod => "invalid_method",
            Self::BodyNotAllowed => "body_not_allowed",
        }
    }
}

fn route_allows_requested_upgrade(
    config: &Http1ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
) -> bool {
    config
        .listener_upgrade_protocols
        .contains(&lb_config_model::UpgradeProtocolConfig::Websocket)
        || route.is_some_and(|route| {
            config
                .route_upgrade_protocols
                .get(&route.label)
                .is_some_and(|protocols| {
                    protocols.contains(&lb_config_model::UpgradeProtocolConfig::Websocket)
                })
        })
}

fn classify_requested_upgrade(
    request: &lb_proto_http::Http1RequestHead,
) -> Result<Option<lb_config_model::UpgradeProtocolConfig>, UpgradeRequestError> {
    let connection_has_upgrade = header_value_contains_token(&request.headers, "connection", "upgrade");
    let upgrade_header = single_header_value(&request.headers, "upgrade");

    let Some(upgrade_header) = upgrade_header else {
        return if connection_has_upgrade {
            Err(UpgradeRequestError::MissingUpgradeHeader)
        } else {
            Ok(None)
        };
    };

    if !connection_has_upgrade {
        return Err(UpgradeRequestError::MissingConnectionToken);
    }
    if !upgrade_header.eq_ignore_ascii_case("websocket") {
        return Err(UpgradeRequestError::UnsupportedProtocol);
    }
    if !request.method.eq_ignore_ascii_case("GET") {
        return Err(UpgradeRequestError::InvalidMethod);
    }
    if !matches!(request.body_kind, lb_proto_http::BodyKind::None) {
        return Err(UpgradeRequestError::BodyNotAllowed);
    }

    Ok(Some(lb_config_model::UpgradeProtocolConfig::Websocket))
}

fn single_header_value<'a>(headers: &'a [lb_proto_http::HttpHeader], name: &str) -> Option<&'a str> {
    let mut matches = headers.iter().filter(|header| header.name.eq_ignore_ascii_case(name));
    let first = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(first.value.as_str())
}

fn header_value_contains_token(
    headers: &[lb_proto_http::HttpHeader],
    header_name: &str,
    token: &str,
) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(header_name))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .any(|candidate| candidate.eq_ignore_ascii_case(token))
}

fn append_upgrade_headers(
    target: &mut Vec<lb_proto_http::HttpHeader>,
    source: &[lb_proto_http::HttpHeader],
) {
    target.extend(
        source
            .iter()
            .filter(|header| {
                header.name.eq_ignore_ascii_case("connection")
                    || header.name.eq_ignore_ascii_case("upgrade")
            })
            .cloned(),
    );
}

fn response_accepts_requested_upgrade(
    response: &lb_proto_http::Http1ResponseHead,
    requested_upgrade: lb_config_model::UpgradeProtocolConfig,
) -> bool {
    match requested_upgrade {
        lb_config_model::UpgradeProtocolConfig::Websocket => {
            header_value_contains_token(&response.headers, "connection", "upgrade")
                && single_header_value(&response.headers, "upgrade")
                    .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        }
    }
}

fn record_upgrade_telemetry(
    config: &Http1ProxyConfig,
    result: HttpUpgradeResult,
    reason: &str,
    detail: &str,
) {
    if let Some(telemetry) = config.upgrade_telemetry.as_ref() {
        let _ = telemetry
            .telemetry
            .record_http_upgrade(&telemetry.scope, result, reason, detail);
    }
}

