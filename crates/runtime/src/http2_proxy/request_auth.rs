fn verify_route_destination_jwt_auth(
    config: &Http2ProxyConfig,
    request: &Request<RecvStream>,
    route: Option<&lb_proto_http::RouteMatch>,
    selected_upstream: &SelectedUpstream,
) -> Result<(), crate::JwtAuthVerificationError> {
    let Some(policy) = route_destination_jwt_auth_policy_runtime(config, route, selected_upstream) else {
        return Ok(());
    };

    let authorization = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(crate::JwtAuthVerificationError::MissingAuthorizationHeader)?;

    let result = policy.verify_bearer(authorization);
    if let Some(request_telemetry) = config.request_telemetry.as_ref() {
        let _ = request_telemetry.telemetry.record_decision_trace(
            &request_telemetry.scope,
            lb_observability::DecisionTraceKind::PolicyEnforcement,
            if result.is_ok() { "allowed" } else { "rejected" },
            route.map(|entry| entry.label.as_str()),
            Some(selected_destination_label(selected_upstream)),
            Some("jwt_auth"),
            None,
            if result.is_ok() {
                "jwt auth policy accepted stream"
            } else {
                "jwt auth policy rejected stream"
            },
        );
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalAuthEnforcementOutcome {
    Denied,
    ServiceUnavailable,
    InvalidResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamIdentityEnforcementOutcome {
    ServiceUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationEnforcementOutcome {
    Denied,
}

async fn enforce_route_destination_external_auth(
    config: &Http2ProxyConfig,
    request: &mut Request<RecvStream>,
    route: Option<&lb_proto_http::RouteMatch>,
    selected_upstream: &SelectedUpstream,
) -> Result<(), ExternalAuthEnforcementOutcome> {
    let Some(policy) = route_destination_external_auth_policy_runtime(config, route, selected_upstream) else {
        return Ok(());
    };

    let hook = crate::RuntimeExternalAuthHook::new(policy);
    let path = request
        .uri()
        .path_and_query()
        .map(|entry| entry.as_str())
        .unwrap_or("/");
    let hook_request = hook.build_request(
        request.method().as_str(),
        path,
        request
            .headers()
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|raw| (name.as_str(), raw))),
    );
    let decision = match hook.execute(&hook_request).await {
        Ok(decision) => {
            let resolved_headers = hook
                .resolve_context_headers(&decision)
                .map_err(|_| ExternalAuthEnforcementOutcome::Denied)?;
            for (target_header, value) in resolved_headers {
                let Ok(name) = http::header::HeaderName::from_bytes(target_header.as_bytes()) else {
                    return Err(ExternalAuthEnforcementOutcome::InvalidResponse);
                };
                let Ok(header_value) = http::HeaderValue::from_str(&value) else {
                    return Err(ExternalAuthEnforcementOutcome::InvalidResponse);
                };
                request.headers_mut().insert(name, header_value);
            }
            Ok(())
        }
        Err(crate::ExternalAuthHookError::Denied) => Err(ExternalAuthEnforcementOutcome::Denied),
        Err(crate::ExternalAuthHookError::ServiceUnavailable) => {
            Err(ExternalAuthEnforcementOutcome::ServiceUnavailable)
        }
        Err(crate::ExternalAuthHookError::InvalidResponse) => {
            Err(ExternalAuthEnforcementOutcome::InvalidResponse)
        }
    };

    if let Some(request_telemetry) = config.request_telemetry.as_ref() {
        let _ = request_telemetry.telemetry.record_decision_trace(
            &request_telemetry.scope,
            lb_observability::DecisionTraceKind::PolicyEnforcement,
            if decision.is_ok() { "allowed" } else { "rejected" },
            route.map(|entry| entry.label.as_str()),
            Some(selected_destination_label(selected_upstream)),
            Some("external_auth"),
            None,
            if decision.is_ok() {
                "external auth policy accepted stream"
            } else {
                "external auth policy rejected stream"
            },
        );
    }

    decision
}

fn enforce_route_destination_upstream_identity(
    config: &Http2ProxyConfig,
    _request: &Request<RecvStream>,
    route: Option<&lb_proto_http::RouteMatch>,
    selected_upstream: &SelectedUpstream,
) -> Result<(), UpstreamIdentityEnforcementOutcome> {
    let Some(policy) = route_destination_upstream_identity_policy_runtime(config, route, selected_upstream)
    else {
        return Ok(());
    };

    let result = policy.verify_peer_identity(None);
    if let Some(request_telemetry) = config.request_telemetry.as_ref() {
        let _ = request_telemetry.telemetry.record_decision_trace(
            &request_telemetry.scope,
            lb_observability::DecisionTraceKind::PolicyEnforcement,
            if result.is_ok() { "allowed" } else { "rejected" },
            route.map(|entry| entry.label.as_str()),
            Some(selected_destination_label(selected_upstream)),
            Some("upstream_identity"),
            None,
            if result.is_ok() {
                "upstream identity policy accepted stream"
            } else {
                "upstream identity policy rejected stream"
            },
        );
    }

    result.map_err(|_| UpstreamIdentityEnforcementOutcome::ServiceUnavailable)
}

fn enforce_route_destination_authorization(
    config: &Http2ProxyConfig,
    request: &Request<RecvStream>,
    route: Option<&lb_proto_http::RouteMatch>,
    selected_upstream: &SelectedUpstream,
) -> Result<(), AuthorizationEnforcementOutcome> {
    let Some(policy) = route_destination_authorization_policy_runtime(config, route, selected_upstream)
    else {
        return Ok(());
    };

    let header_map = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|raw| (name.as_str().to_ascii_lowercase(), raw.to_string()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let result = policy.authorize_headers(&header_map);
    if let Some(request_telemetry) = config.request_telemetry.as_ref() {
        let _ = request_telemetry.telemetry.record_decision_trace(
            &request_telemetry.scope,
            lb_observability::DecisionTraceKind::PolicyEnforcement,
            if result.is_ok() { "allowed" } else { "rejected" },
            route.map(|entry| entry.label.as_str()),
            Some(selected_destination_label(selected_upstream)),
            Some("authorization"),
            None,
            if result.is_ok() {
                "authorization policy accepted stream"
            } else {
                "authorization policy rejected stream"
            },
        );
    }

    result.map_err(|_| AuthorizationEnforcementOutcome::Denied)
}
