#[cfg_attr(not(test), allow(dead_code))]
fn compile_workspace_runtime(config_path: &str) -> Result<CompiledWorkspaceRuntime, DynError> {
    compile_workspace_runtime_with_telemetry(config_path, None)
}

fn compile_workspace_runtime_with_telemetry(
    config_path: &str,
    telemetry: Option<&Arc<lb_runtime::RuntimeTelemetry>>,
) -> Result<CompiledWorkspaceRuntime, DynError> {
    let config = crate::load_workspace_config(config_path).map_err(to_dyn_error)?;
    let snapshot = config.compile_snapshot().map_err(to_dyn_error)?;
    let compiled_listeners = config.compile_listeners()?;
    let compiled_routes = config.compile_http_route_rules()?;
    let mut listeners = BTreeMap::new();
    let mut http_cache_scopes = BTreeMap::new();

    for (listener, compiled_listener) in config.listeners.iter().zip(compiled_listeners.iter()) {
        let http_cache_scope =
            if matches!(listener.class, lb_config_model::ListenerClassConfig::Public)
                && matches!(
                    listener.protocol,
                    lb_config_model::ListenerProtocolConfig::Http1
                        | lb_config_model::ListenerProtocolConfig::Https
                )
            {
                resolve_listener_http_cache_policy(&config, listener)?
                    .map(|(_policy_name, policy)| -> Result<_, DynError> {
                        let store = build_http_cache_store(&policy)?;
                        Ok((
                            HttpCacheScopeRuntime {
                                service: Arc::new(Mutex::new(
                                    lb_admin_api::HttpCacheAdminService::new(
                                        listener.name.clone(),
                                        policy.purge_enabled,
                                        Arc::clone(&store),
                                    ),
                                )),
                                store,
                            },
                            policy,
                        ))
                    })
                    .transpose()?
            } else {
                None
            };
        let compiled = match (listener.class, listener.protocol) {
            (
                lb_config_model::ListenerClassConfig::Public,
                lb_config_model::ListenerProtocolConfig::Http1,
            ) => CompiledServeListener::Public {
                class: listener.class,
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                proxy: ManagedProxyConfig::Http1(compile_http1_proxy_config(
                    &config,
                    listener,
                    &compiled_routes,
                    http_cache_scope.as_ref().map(|(scope_runtime, policy)| {
                        (policy.clone(), Arc::clone(&scope_runtime.store))
                    }),
                    telemetry,
                )?),
            },
            (
                lb_config_model::ListenerClassConfig::Public,
                lb_config_model::ListenerProtocolConfig::Http2,
            ) => CompiledServeListener::Public {
                class: listener.class,
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                proxy: ManagedProxyConfig::Http2(compile_http2_proxy_config(
                    &config,
                    listener,
                    &compiled_routes,
                )?),
            },
            (
                lb_config_model::ListenerClassConfig::Public,
                lb_config_model::ListenerProtocolConfig::Https,
            ) => CompiledServeListener::Public {
                class: listener.class,
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                proxy: ManagedProxyConfig::Https(compile_https_proxy_config(
                    &config,
                    listener,
                    compiled_listener,
                    &compiled_routes,
                    http_cache_scope.as_ref().map(|(scope_runtime, policy)| {
                        (policy.clone(), Arc::clone(&scope_runtime.store))
                    }),
                    telemetry,
                )?),
            },
            (
                lb_config_model::ListenerClassConfig::Public,
                lb_config_model::ListenerProtocolConfig::Http3,
            ) => CompiledServeListener::Public {
                class: listener.class,
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                proxy: ManagedProxyConfig::Http3(compile_http3_proxy_config(
                    &config,
                    listener,
                    &compiled_routes,
                )?),
            },
            (lb_config_model::ListenerClassConfig::Public, protocol) => {
                return Err(format!(
                    "listener {} uses unsupported public protocol {:?} in serve mode",
                    listener.name, protocol
                )
                .into());
            }
            (
                lb_config_model::ListenerClassConfig::Admin,
                lb_config_model::ListenerProtocolConfig::Http1,
            ) => CompiledServeListener::Admin {
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                admin_policy: compile_admin_policy(listener)?,
                tls: None,
            },
            (
                lb_config_model::ListenerClassConfig::Admin,
                lb_config_model::ListenerProtocolConfig::Https,
            ) => CompiledServeListener::Admin {
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                admin_policy: compile_admin_policy(listener)?,
                tls: Some(ManagedAdminTlsConfig {
                    tls_server_config: Arc::new(build_tls_server_config(
                        listener.tls_termination.as_ref().ok_or_else(|| {
                            to_dyn_error(format!(
                                "listener {} is missing tls_termination",
                                listener.name
                            ))
                        })?,
                    )?),
                    tls_status: build_listener_tls_status(
                        listener.tls_termination.as_ref().ok_or_else(|| {
                            to_dyn_error(format!(
                                "listener {} is missing tls_termination",
                                listener.name
                            ))
                        })?,
                    )?,
                }),
            },
            (lb_config_model::ListenerClassConfig::Admin, protocol) => {
                return Err(format!(
                    "listener {} uses unsupported admin protocol {:?} in serve mode",
                    listener.name, protocol
                )
                .into());
            }
        };

        if let Some((scope_runtime, _policy)) = http_cache_scope {
            http_cache_scopes.insert(listener.name.clone(), scope_runtime);
        }

        listeners.insert(listener.name.clone(), compiled);
    }

    Ok(CompiledWorkspaceRuntime {
        source_label: format!("config_path={config_path}"),
        snapshot,
        listeners,
        http_cache_scopes,
    })
}

fn compile_http1_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
    response_cache: Option<(
        lb_config_model::HttpCachePolicyConfig,
        Arc<lb_runtime::HttpCacheStore>,
    )>,
    upgrade_telemetry: Option<&Arc<lb_runtime::RuntimeTelemetry>>,
) -> Result<lb_runtime::Http1ProxyConfig, DynError> {
    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http1_route_backends(config, listener, compiled_routes)?;
    let mirror_backend_pools = compile_mirror_backend_pools(config)?;
    let (listener_request_transform, route_request_transforms) =
        resolve_listener_request_transforms(config, listener)?;
    let (listener_response_transform, route_response_transforms) =
        resolve_listener_response_transforms(config, listener)?;
    let route_backend_policy_diagnostics =
        resolve_effective_route_backend_policy_diagnostics(config, listener)?;
    let route_destination_policies =
        compile_route_destination_policy_runtime(config, &route_backend_policy_diagnostics)?;
    let (listener_upgrade_protocols, route_upgrade_protocols) =
        resolve_listener_upgrade_policies(config, listener);
    let mut proxy = lb_runtime::Http1ProxyConfig::new(primary_upstream);
    proxy.routes = route_rules;
    proxy = proxy
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools)
        .with_mirror_backend_pools(mirror_backend_pools)
        .with_request_transforms(listener_request_transform, route_request_transforms)
        .with_response_transforms(listener_response_transform, route_response_transforms)
        .with_route_destination_policies(route_destination_policies)
        .with_route_backend_policy_diagnostics(route_backend_policy_diagnostics)
        .with_upgrade_policies(listener_upgrade_protocols, route_upgrade_protocols)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(telemetry) = upgrade_telemetry {
        proxy = proxy.with_upgrade_telemetry(listener.name.clone(), Arc::clone(telemetry));
    }
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        proxy = proxy.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        proxy = proxy.with_anonymous_source_filter(filter);
    }
    if let Some((policy, store)) = response_cache {
        proxy = proxy.with_response_cache(lb_runtime::Http1ResponseCacheConfig::new(policy, store));
    }
    Ok(proxy)
}

fn compile_http2_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<lb_runtime::Http2ProxyConfig, DynError> {
    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http2_route_backends(config, listener, compiled_routes)?;
    let mirror_backend_pools = compile_mirror_backend_pools(config)?;
    let (listener_request_transform, route_request_transforms) =
        resolve_listener_request_transforms(config, listener)?;
    let (listener_response_transform, route_response_transforms) =
        resolve_listener_response_transforms(config, listener)?;
    let route_backend_policy_diagnostics =
        resolve_effective_route_backend_policy_diagnostics(config, listener)?;
    let route_destination_policies =
        compile_route_destination_policy_runtime(config, &route_backend_policy_diagnostics)?;
    let mut proxy = lb_runtime::Http2ProxyConfig::new(primary_upstream);
    proxy.routes = route_rules;
    proxy.limits = config.defaults.http.http2_limits();
    proxy = proxy
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools)
        .with_mirror_backend_pools(mirror_backend_pools)
        .with_request_transforms(listener_request_transform, route_request_transforms)
        .with_response_transforms(listener_response_transform, route_response_transforms)
        .with_route_destination_policies(route_destination_policies)
        .with_route_backend_policy_diagnostics(route_backend_policy_diagnostics)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        proxy = proxy.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        proxy = proxy.with_anonymous_source_filter(filter);
    }
    Ok(proxy)
}

fn compile_https_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_listener: &lb_net_core::ListenerConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
    response_cache: Option<(
        lb_config_model::HttpCachePolicyConfig,
        Arc<lb_runtime::HttpCacheStore>,
    )>,
    upgrade_telemetry: Option<&Arc<lb_runtime::RuntimeTelemetry>>,
) -> Result<ManagedHttpsProxyConfig, DynError> {
    let _compiled_tls_termination =
        compiled_listener.tls_termination.as_ref().ok_or_else(|| {
            to_dyn_error(format!("listener {} is missing tls_termination", listener.name))
        })?;
    let tls_termination = listener.tls_termination.as_ref().ok_or_else(|| {
        to_dyn_error(format!("listener {} is missing tls_termination", listener.name))
    })?;

    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http1_route_backends(config, listener, compiled_routes)?;
    let mirror_backend_pools = compile_mirror_backend_pools(config)?;
    let (listener_request_transform, route_request_transforms) =
        resolve_listener_request_transforms(config, listener)?;
    let (listener_response_transform, route_response_transforms) =
        resolve_listener_response_transforms(config, listener)?;
    let route_backend_policy_diagnostics =
        resolve_effective_route_backend_policy_diagnostics(config, listener)?;
    let route_destination_policies =
        compile_route_destination_policy_runtime(config, &route_backend_policy_diagnostics)?;
    let (listener_upgrade_protocols, route_upgrade_protocols) =
        resolve_listener_upgrade_policies(config, listener);
    let route_upstreams_http2 = route_upstreams
        .iter()
        .map(|upstream| lb_runtime::Http2RouteUpstream {
            route_label: upstream.route_label.clone(),
            upstream: upstream.upstream.clone(),
        })
        .collect::<Vec<_>>();

    let mut http1 = lb_runtime::Http1ProxyConfig::new(primary_upstream.clone());
    http1.routes = route_rules.clone();
    http1 = http1
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools.clone())
        .with_mirror_backend_pools(mirror_backend_pools.clone())
        .with_request_transforms(
            listener_request_transform.clone(),
            route_request_transforms.clone(),
        )
        .with_response_transforms(
            listener_response_transform.clone(),
            route_response_transforms.clone(),
        )
        .with_route_destination_policies(route_destination_policies.clone())
        .with_route_backend_policy_diagnostics(route_backend_policy_diagnostics.clone())
        .with_upgrade_policies(listener_upgrade_protocols, route_upgrade_protocols)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(telemetry) = upgrade_telemetry {
        http1 = http1.with_upgrade_telemetry(listener.name.clone(), Arc::clone(telemetry));
    }
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        http1 = http1.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        http1 = http1.with_anonymous_source_filter(filter);
    }
    if let Some((policy, store)) = response_cache.clone() {
        http1 = http1.with_response_cache(lb_runtime::Http1ResponseCacheConfig::new(policy, store));
    }

    let mut http2 = lb_runtime::Http2ProxyConfig::new(primary_upstream);
    http2.routes = route_rules;
    http2.limits = config.defaults.http.http2_limits();
    http2 = http2
        .with_route_upstreams(route_upstreams_http2)
        .with_route_backend_pools(route_backend_pools)
        .with_mirror_backend_pools(mirror_backend_pools)
        .with_request_transforms(listener_request_transform, route_request_transforms)
        .with_response_transforms(listener_response_transform, route_response_transforms)
        .with_route_destination_policies(route_destination_policies)
        .with_route_backend_policy_diagnostics(route_backend_policy_diagnostics)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        http2 = http2.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        http2 = http2.with_anonymous_source_filter(filter);
    }

    Ok(ManagedHttpsProxyConfig {
        http1,
        http2,
        tls_server_config: Arc::new(build_tls_server_config(tls_termination)?),
        tls_status: build_listener_tls_status(tls_termination)?,
    })
}

fn compile_http3_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<ManagedHttp3ProxyConfig, DynError> {
    let tls_termination = listener.tls_termination.as_ref().ok_or_else(|| {
        to_dyn_error(format!("listener {} is missing tls_termination", listener.name))
    })?;
    let http1 = compile_http1_proxy_config(config, listener, compiled_routes, None, None)?;
    let tls_server_config = Arc::new(build_tls_server_config(tls_termination)?);
    let quic_server_config = Arc::new(build_quic_server_config(Arc::clone(&tls_server_config))?);
    let _ = config;

    Ok(ManagedHttp3ProxyConfig {
        http1,
        quic_server_config,
    })
}

fn build_quic_server_config(
    tls_server_config: Arc<rustls::ServerConfig>,
) -> Result<quinn::ServerConfig, DynError> {
    let crypto = QuicServerConfig::try_from((*tls_server_config).clone()).map_err(to_dyn_error)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(32_u8.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

