fn verify_route_destination_jwt_auth(
    config: &Http1ProxyConfig,
    request: &lb_proto_http::Http1RequestHead,
    selected_upstream: &SelectedUpstream,
) -> Result<(), crate::JwtAuthVerificationError> {
    let Some(policy) =
        route_destination_jwt_auth_policy_runtime(config, request.route.as_ref(), selected_upstream)
    else {
        return Ok(());
    };

    let authorization = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))
        .map(|header| header.value.as_str())
        .ok_or(crate::JwtAuthVerificationError::MissingAuthorizationHeader)?;

    let result = policy.verify_bearer(authorization);
    if let Some(request_telemetry) = config.request_telemetry.as_ref() {
        let _ = request_telemetry.telemetry.record_decision_trace(
            &request_telemetry.scope,
            lb_observability::DecisionTraceKind::PolicyEnforcement,
            if result.is_ok() { "allowed" } else { "rejected" },
            request.route.as_ref().map(|route| route.label.as_str()),
            Some(selected_destination_label(selected_upstream)),
            Some("jwt_auth"),
            None,
            if result.is_ok() {
                "jwt auth policy accepted request"
            } else {
                "jwt auth policy rejected request"
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
    config: &Http1ProxyConfig,
    request: &mut lb_proto_http::Http1RequestHead,
    selected_upstream: &SelectedUpstream,
) -> Result<(), ExternalAuthEnforcementOutcome> {
    let Some(policy) = route_destination_external_auth_policy_runtime(
        config,
        request.route.as_ref(),
        selected_upstream,
    ) else {
        return Ok(());
    };

    let hook = crate::RuntimeExternalAuthHook::new(policy);
    let hook_request = hook.build_request(
        &request.method,
        &request.target,
        request
            .headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str())),
    );

    let decision = match hook.execute(&hook_request).await {
        Ok(decision) => {
            let resolved_headers = hook
                .resolve_context_headers(&decision)
                .map_err(|_| ExternalAuthEnforcementOutcome::Denied)?;
            for (target_header, value) in resolved_headers {
                if let Some(existing) = request
                    .headers
                    .iter_mut()
                    .find(|header| header.name.eq_ignore_ascii_case(&target_header))
                {
                    existing.value = value;
                } else {
                    request.headers.push(lb_proto_http::HttpHeader {
                        name: target_header,
                        value,
                    });
                }
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
            request.route.as_ref().map(|route| route.label.as_str()),
            Some(selected_destination_label(selected_upstream)),
            Some("external_auth"),
            None,
            if decision.is_ok() {
                "external auth policy accepted request"
            } else {
                "external auth policy rejected request"
            },
        );
    }

    decision
}

fn enforce_route_destination_upstream_identity(
    config: &Http1ProxyConfig,
    request: &lb_proto_http::Http1RequestHead,
    selected_upstream: &SelectedUpstream,
) -> Result<(), UpstreamIdentityEnforcementOutcome> {
    let Some(policy) = route_destination_upstream_identity_policy_runtime(
        config,
        request.route.as_ref(),
        selected_upstream,
    ) else {
        return Ok(());
    };

    let result = policy.verify_peer_identity(None);
    if let Some(request_telemetry) = config.request_telemetry.as_ref() {
        let _ = request_telemetry.telemetry.record_decision_trace(
            &request_telemetry.scope,
            lb_observability::DecisionTraceKind::PolicyEnforcement,
            if result.is_ok() { "allowed" } else { "rejected" },
            request.route.as_ref().map(|route| route.label.as_str()),
            Some(selected_destination_label(selected_upstream)),
            Some("upstream_identity"),
            None,
            if result.is_ok() {
                "upstream identity policy accepted request"
            } else {
                "upstream identity policy rejected request"
            },
        );
    }

    result.map_err(|_| UpstreamIdentityEnforcementOutcome::ServiceUnavailable)
}

fn enforce_route_destination_authorization(
    config: &Http1ProxyConfig,
    request: &lb_proto_http::Http1RequestHead,
    selected_upstream: &SelectedUpstream,
) -> Result<(), AuthorizationEnforcementOutcome> {
    let Some(policy) = route_destination_authorization_policy_runtime(
        config,
        request.route.as_ref(),
        selected_upstream,
    ) else {
        return Ok(());
    };

    let header_map = request
        .headers
        .iter()
        .map(|header| (header.name.to_ascii_lowercase(), header.value.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let result = policy.authorize_headers(&header_map);
    if let Some(request_telemetry) = config.request_telemetry.as_ref() {
        let _ = request_telemetry.telemetry.record_decision_trace(
            &request_telemetry.scope,
            lb_observability::DecisionTraceKind::PolicyEnforcement,
            if result.is_ok() { "allowed" } else { "rejected" },
            request.route.as_ref().map(|route| route.label.as_str()),
            Some(selected_destination_label(selected_upstream)),
            Some("authorization"),
            None,
            if result.is_ok() {
                "authorization policy accepted request"
            } else {
                "authorization policy rejected request"
            },
        );
    }

    result.map_err(|_| AuthorizationEnforcementOutcome::Denied)
}
