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

#[cfg(test)]
mod request_auth_coverage_tests {
    use super::*;

    async fn request() -> Result<Request<RecvStream>, Box<dyn std::error::Error>> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server, client) =
            tokio::join!(h2::server::handshake(server_io), h2::client::handshake(client_io));
        let mut server = server?;
        let (mut client, client_connection) = client?;
        tokio::spawn(async move {
            let _ = client_connection.await;
        });

        let request = Request::builder().method("GET").uri("https://example.test/secure").body(())?;
        let (response, mut send) = client.send_request(request, false)?;
        tokio::spawn(async move {
            let _ = response.await;
        });
        send.send_data(Bytes::new(), true)?;
        let (request, respond) = time::timeout(Duration::from_secs(1), server.accept())
            .await?
            .ok_or("HTTP/2 request was not accepted")??;
        tokio::spawn(async move {
            let _respond = respond;
            while let Some(result) = server.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        Ok(request)
    }

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
        let config = Http2ProxyConfig::new(selected.target.clone())
            .with_route_destination_jwt_auth_policies([(
                String::from("api"),
                BTreeMap::from([(cluster_name.clone(), jwt)]),
            )])
            .with_route_destination_external_auth_policies([(
                String::from("api"),
                BTreeMap::from([(cluster_name.clone(), external)]),
            )])
            .with_route_destination_authorization_policies([(
                String::from("api"),
                BTreeMap::from([(cluster_name.clone(), authorization)]),
            )])
            .with_route_destination_upstream_identity_policies([(
                String::from("api"),
                BTreeMap::from([(cluster_name.clone(), identity)]),
            )]);
        let mut request = request().await?;

        assert_eq!(
            verify_route_destination_jwt_auth(&config, &request, Some(&route), &selected),
            Err(crate::JwtAuthVerificationError::MissingAuthorizationHeader)
        );
        assert_eq!(
            enforce_route_destination_external_auth(&config, &mut request, Some(&route), &selected)
                .await,
            Err(ExternalAuthEnforcementOutcome::ServiceUnavailable)
        );
        assert_eq!(
            enforce_route_destination_upstream_identity(
                &config,
                &request,
                Some(&route),
                &selected,
            ),
            Err(UpstreamIdentityEnforcementOutcome::ServiceUnavailable)
        );
        assert_eq!(
            enforce_route_destination_authorization(&config, &request, Some(&route), &selected),
            Err(AuthorizationEnforcementOutcome::Denied)
        );
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer malformed"),
        );
        assert!(verify_route_destination_jwt_auth(&config, &request, Some(&route), &selected)
            .is_err());

        let allowed = crate::AuthorizationPolicyRuntime::from_config(
            &lb_config_model::AuthorizationPolicyConfig {
                rules: Vec::new(),
                default_decision: lb_config_model::AuthorizationDecisionConfig::Allow,
            },
        );
        let allowed_config = Http2ProxyConfig::new(selected.target.clone())
            .with_route_destination_authorization_policies([(
                String::from("api"),
                BTreeMap::from([(cluster_name, allowed)]),
            )]);
        assert!(
            enforce_route_destination_authorization(
                &allowed_config,
                &request,
                Some(&route),
                &selected,
            )
            .is_ok()
        );

        let fail_open_external = crate::ExternalAuthPolicyRuntime::from_config(
            &lb_config_model::ExternalAuthPolicyConfig {
                endpoint: String::from("http://127.0.0.1:9/authz"),
                protocol: lb_config_model::ExternalAuthProtocolConfig::Http,
                timeout_ms: 1_000,
                fail_open: true,
                include_headers: Vec::new(),
                context_mappings: Vec::new(),
            },
        )?;
        let fail_open_config = Http2ProxyConfig::new(selected.target.clone())
            .with_route_destination_external_auth_policies([(
                String::from("api"),
                BTreeMap::from([(String::from("auth-cluster"), fail_open_external)]),
            )]);
        assert!(enforce_route_destination_external_auth(
            &fail_open_config,
            &mut request,
            Some(&route),
            &selected,
        )
        .await
        .is_ok());
        Ok(())
    }
}
