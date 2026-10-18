fn verify_route_destination_jwt_auth(
    config: &Http1ProxyConfig,
    request: &lb_proto_http::Http1RequestHead,
    selected_upstream: &SelectedUpstream,
) -> Result<(), crate::JwtAuthVerificationError> {
    let Some(policy) = route_destination_jwt_auth_policy_runtime(
        config,
        request.route.as_ref(),
        selected_upstream,
    ) else {
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
        request.headers.iter().map(|header| (header.name.as_str(), header.value.as_str())),
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
                    request.headers.push(lb_proto_http::HttpHeader { name: target_header, value });
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

#[cfg(test)]
mod request_auth_coverage_tests {
    use super::*;

    fn selected_route_upstream() -> Result<(SelectedUpstream, String), Box<dyn std::error::Error>> {
        let cluster_name = String::from("auth-cluster");
        let pool = crate::RouteBackendPool::from_cluster(
            lb_net_core::UpstreamCluster::new(
                lb_net_core::UpstreamClusterName::new(cluster_name.clone())?,
                vec![lb_net_core::UpstreamEndpoint::new(
                    lb_net_core::UpstreamEndpointId::new("auth-endpoint")?,
                    "127.0.0.1:8080".parse()?,
                    lb_net_core::EndpointState::Ready,
                    lb_net_core::EndpointMetadata { zone: None, locality: None, weight: 1 },
                )?],
            )?,
            crate::EndpointHealthPolicy::default(),
            crate::UpstreamSelectionPolicy::default(),
        )?;
        let route_backend = pool.select_backend(0)?;
        let target = route_backend.upstream().clone();
        Ok((SelectedUpstream { target, route_backend: Some(route_backend) }, cluster_name))
    }

    #[tokio::test]
    async fn destination_authentication_is_a_noop_without_a_selected_route_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let target = lb_net_core::UpstreamTarget::new("static-upstream", "127.0.0.1:8080".parse()?);
        let config = Http1ProxyConfig::new(target.clone());
        let selected = SelectedUpstream { target, route_backend: None };
        let mut request = lb_proto_http::Http1RequestHead {
            method: String::from("GET"),
            target: String::from("/"),
            version: lb_proto_http::SupportedHttpVersion::Http1,
            headers: Vec::new(),
            body_kind: lb_proto_http::BodyKind::None,
            keep_alive: true,
            route: None,
            http10: false,
        };

        assert!(verify_route_destination_jwt_auth(&config, &request, &selected).is_ok());
        assert!(enforce_route_destination_external_auth(&config, &mut request, &selected)
            .await
            .is_ok());
        assert!(enforce_route_destination_upstream_identity(&config, &request, &selected).is_ok());
        assert!(enforce_route_destination_authorization(&config, &request, &selected).is_ok());

        request.route = Some(lb_proto_http::RouteMatch {
            label: String::from("api"),
            prefix: String::from("/"),
        });
        assert!(verify_route_destination_jwt_auth(&config, &request, &selected).is_ok());
        assert!(enforce_route_destination_external_auth(&config, &mut request, &selected)
            .await
            .is_ok());
        assert!(enforce_route_destination_upstream_identity(&config, &request, &selected).is_ok());
        assert!(enforce_route_destination_authorization(&config, &request, &selected).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn destination_authentication_enforces_configured_route_policies(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (selected, cluster_name) = selected_route_upstream()?;
        let route = lb_proto_http::RouteMatch {
            label: String::from("api"),
            prefix: String::from("/"),
        };
        let jwt = crate::JwtAuthPolicyRuntime::from_config(
            &lb_config_model::JwtAuthPolicyConfig {
                issuers: vec![String::from("https://issuer.example")],
                audiences: vec![String::from("edge-api")],
                jwks: Some(lb_config_model::JwtJwksSourceConfig::Inline {
                    jwks_json: String::from(
                        r#"{"keys":[{"kty":"oct","k":"c2VjcmV0","alg":"HS256","kid":"key"}]}"#,
                    ),
                }),
                required_claims: Vec::new(),
                clock_skew_secs: 30,
            },
        )?;
        let external = crate::ExternalAuthPolicyRuntime::from_config(
            &lb_config_model::ExternalAuthPolicyConfig {
                endpoint: String::from("http://127.0.0.1:9/authz"),
                protocol: lb_config_model::ExternalAuthProtocolConfig::Http,
                timeout_ms: 1_000,
                fail_open: false,
                include_headers: Vec::new(),
                context_mappings: Vec::new(),
            },
        )?;
        let authorization = crate::AuthorizationPolicyRuntime::from_config(
            &lb_config_model::AuthorizationPolicyConfig {
                rules: Vec::new(),
                default_decision: lb_config_model::AuthorizationDecisionConfig::Deny,
            },
        );
        let certified = rcgen::generate_simple_self_signed(vec![String::from("localhost")])?;
        let identity = crate::UpstreamIdentityPolicyRuntime::from_config(
            &lb_config_model::UpstreamIdentityPolicyConfig {
                mode: lb_config_model::UpstreamIdentityModeConfig::Spiffe,
                trust_bundle: lb_config_model::IdentityTrustBundleSourceConfig::InlinePem {
                    pem: certified.cert.pem(),
                },
                allowed_spiffe_ids: Vec::new(),
                allowed_trust_domains: Vec::new(),
            },
        )?;
        let config = Http1ProxyConfig::new(selected.target.clone())
            .with_route_destination_jwt_auth_policies([(
                String::from("api"),
                std::collections::BTreeMap::from([(cluster_name.clone(), jwt)]),
            )])
            .with_route_destination_external_auth_policies([(
                String::from("api"),
                std::collections::BTreeMap::from([(cluster_name.clone(), external)]),
            )])
            .with_route_destination_authorization_policies([(
                String::from("api"),
                std::collections::BTreeMap::from([(cluster_name.clone(), authorization)]),
            )])
            .with_route_destination_upstream_identity_policies([(
                String::from("api"),
                std::collections::BTreeMap::from([(String::from("auth-cluster"), identity)]),
            )]);
        let mut request = lb_proto_http::Http1RequestHead {
            method: String::from("GET"),
            target: String::from("/"),
            version: lb_proto_http::SupportedHttpVersion::Http1,
            headers: Vec::new(),
            body_kind: lb_proto_http::BodyKind::None,
            keep_alive: true,
            route: Some(route),
            http10: false,
        };

        assert_eq!(
            verify_route_destination_jwt_auth(&config, &request, &selected),
            Err(crate::JwtAuthVerificationError::MissingAuthorizationHeader)
        );
        request.headers.push(lb_proto_http::HttpHeader {
            name: String::from("authorization"),
            value: String::from("Bearer malformed"),
        });
        assert!(verify_route_destination_jwt_auth(&config, &request, &selected).is_err());
        assert_eq!(
            enforce_route_destination_external_auth(&config, &mut request, &selected).await,
            Err(ExternalAuthEnforcementOutcome::ServiceUnavailable)
        );
        assert_eq!(
            enforce_route_destination_upstream_identity(&config, &request, &selected),
            Err(UpstreamIdentityEnforcementOutcome::ServiceUnavailable)
        );
        assert_eq!(
            enforce_route_destination_authorization(&config, &request, &selected),
            Err(AuthorizationEnforcementOutcome::Denied)
        );
        let allowed = crate::AuthorizationPolicyRuntime::from_config(
            &lb_config_model::AuthorizationPolicyConfig {
                rules: Vec::new(),
                default_decision: lb_config_model::AuthorizationDecisionConfig::Allow,
            },
        );
        let allowed_config = Http1ProxyConfig::new(selected.target.clone())
            .with_route_destination_authorization_policies([(
                String::from("api"),
                std::collections::BTreeMap::from([(cluster_name, allowed)]),
            )]);
        assert!(enforce_route_destination_authorization(&allowed_config, &request, &selected)
            .is_ok());
        Ok(())
    }
}
