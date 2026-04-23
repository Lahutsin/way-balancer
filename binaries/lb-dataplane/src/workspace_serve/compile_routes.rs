fn compile_http1_route_backends(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<
    (
        Vec<lb_proto_http::RoutePrefixRule>,
        Vec<lb_runtime::Http1RouteUpstream>,
        Vec<(String, lb_runtime::RouteBackendPool)>,
        lb_net_core::UpstreamTarget,
    ),
    DynError,
> {
    let mut route_rules = Vec::with_capacity(listener.routes.len());
    let mut route_upstreams = Vec::new();
    let mut route_backend_pools = Vec::new();
    let mut pools_by_cluster = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();

    for route_name in &listener.routes {
        let route =
            config.routes.iter().find(|route| route.name == *route_name).ok_or_else(|| {
                format!("listener {} references unknown route {route_name}", listener.name)
            })?;
        let compiled_route = compiled_routes
            .iter()
            .find(|compiled| compiled.label == *route_name)
            .ok_or_else(|| format!("compiled route {route_name} is missing"))?;
        route_rules.push(compiled_route.clone());
        let mut route_destinations = Vec::new();
        for destination in route.normalized_destinations() {
            let cluster = config
                .upstream_clusters
                .iter()
                .find(|cluster| cluster.name == destination.upstream_cluster)
                .ok_or_else(|| {
                    format!(
                        "route {} references unknown upstream cluster {}",
                        route.name, destination.upstream_cluster
                    )
                })?;
            if cluster.endpoints.is_empty() {
                return Err(format!(
                    "upstream cluster {} must declare at least one endpoint",
                    cluster.name
                )
                .into());
            }

            route_upstreams.extend(cluster.endpoints.iter().map(|endpoint| {
                lb_runtime::Http1RouteUpstream {
                    route_label: route.name.clone(),
                    upstream: lb_net_core::UpstreamTarget::new(
                        format!("{}:{}", cluster.name, endpoint.id),
                        endpoint.address,
                    ),
                }
            }));
            let pool = match pools_by_cluster.get(&cluster.name) {
                Some(pool) => pool.clone(),
                None => {
                    let pool = compile_route_backend_pool(cluster)?;
                    pools_by_cluster.insert(cluster.name.clone(), pool.clone());
                    pool
                }
            };
            route_destinations.push(lb_runtime::WeightedRouteDestination {
                weight: destination.weight,
                pool,
            });
        }

        let route_backend_pool = if route_destinations.len() == 1 {
            route_destinations.remove(0).pool
        } else {
            lb_runtime::RouteBackendPool::from_weighted_destinations(route_destinations)
                .map_err(to_dyn_error)?
        };
        route_backend_pools.push((route.name.clone(), route_backend_pool));
    }

    let primary_upstream =
        route_upstreams.first().map(|route_upstream| route_upstream.upstream.clone()).ok_or_else(
            || format!("public listener {} must reference at least one route", listener.name),
        )?;
    Ok((route_rules, route_upstreams, route_backend_pools, primary_upstream))
}

fn compile_http2_route_backends(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<
    (
        Vec<lb_proto_http::RoutePrefixRule>,
        Vec<lb_runtime::Http2RouteUpstream>,
        Vec<(String, lb_runtime::RouteBackendPool)>,
        lb_net_core::UpstreamTarget,
    ),
    DynError,
> {
    let mut route_rules = Vec::with_capacity(listener.routes.len());
    let mut route_upstreams = Vec::new();
    let mut route_backend_pools = Vec::new();
    let mut pools_by_cluster = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();

    for route_name in &listener.routes {
        let route =
            config.routes.iter().find(|route| route.name == *route_name).ok_or_else(|| {
                format!("listener {} references unknown route {route_name}", listener.name)
            })?;
        let compiled_route = compiled_routes
            .iter()
            .find(|compiled| compiled.label == *route_name)
            .ok_or_else(|| format!("compiled route {route_name} is missing"))?;
        route_rules.push(compiled_route.clone());
        let mut route_destinations = Vec::new();
        for destination in route.normalized_destinations() {
            let cluster = config
                .upstream_clusters
                .iter()
                .find(|cluster| cluster.name == destination.upstream_cluster)
                .ok_or_else(|| {
                    format!(
                        "route {} references unknown upstream cluster {}",
                        route.name, destination.upstream_cluster
                    )
                })?;
            if cluster.endpoints.is_empty() {
                return Err(format!(
                    "upstream cluster {} must declare at least one endpoint",
                    cluster.name
                )
                .into());
            }

            route_upstreams.extend(cluster.endpoints.iter().map(|endpoint| {
                lb_runtime::Http2RouteUpstream {
                    route_label: route.name.clone(),
                    upstream: lb_net_core::UpstreamTarget::new(
                        format!("{}:{}", cluster.name, endpoint.id),
                        endpoint.address,
                    ),
                }
            }));
            let pool = match pools_by_cluster.get(&cluster.name) {
                Some(pool) => pool.clone(),
                None => {
                    let pool = compile_route_backend_pool(cluster)?;
                    pools_by_cluster.insert(cluster.name.clone(), pool.clone());
                    pool
                }
            };
            route_destinations.push(lb_runtime::WeightedRouteDestination {
                weight: destination.weight,
                pool,
            });
        }

        let route_backend_pool = if route_destinations.len() == 1 {
            route_destinations.remove(0).pool
        } else {
            lb_runtime::RouteBackendPool::from_weighted_destinations(route_destinations)
                .map_err(to_dyn_error)?
        };
        route_backend_pools.push((route.name.clone(), route_backend_pool));
    }

    let primary_upstream =
        route_upstreams.first().map(|route_upstream| route_upstream.upstream.clone()).ok_or_else(
            || format!("public listener {} must reference at least one route", listener.name),
        )?;
    Ok((route_rules, route_upstreams, route_backend_pools, primary_upstream))
}

fn compile_route_backend_pool(
    cluster: &lb_config_model::UpstreamClusterConfig,
) -> Result<lb_runtime::RouteBackendPool, DynError> {
    let cluster_name =
        lb_net_core::UpstreamClusterName::new(cluster.name.clone()).map_err(to_dyn_error)?;
    let endpoints = cluster
        .endpoints
        .iter()
        .map(|endpoint| {
            lb_net_core::UpstreamEndpoint::new(
                lb_net_core::UpstreamEndpointId::new(endpoint.id.clone()).map_err(to_dyn_error)?,
                endpoint.address,
                match endpoint.state {
                    lb_config_model::EndpointStateConfig::Ready => {
                        lb_net_core::EndpointState::Ready
                    }
                    lb_config_model::EndpointStateConfig::Draining => {
                        lb_net_core::EndpointState::Draining
                    }
                    lb_config_model::EndpointStateConfig::Unavailable => {
                        lb_net_core::EndpointState::Unavailable
                    }
                },
                lb_net_core::EndpointMetadata {
                    zone: endpoint.zone.clone(),
                    locality: endpoint.locality.clone(),
                    weight: endpoint.weight,
                },
            )
            .map_err(to_dyn_error)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_dyn_error)?;
    let cluster_model =
        lb_net_core::UpstreamCluster::new(cluster_name, endpoints).map_err(to_dyn_error)?;
    lb_runtime::RouteBackendPool::from_cluster(
        cluster_model,
        lb_runtime::EndpointHealthPolicy {
            warmup_duration: ROUTE_BACKEND_WARMUP_DURATION,
            ..lb_runtime::EndpointHealthPolicy::default()
        },
        lb_runtime::UpstreamSelectionPolicy {
            algorithm: match cluster.traffic_policy.algorithm {
                lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin => {
                    lb_runtime::LoadBalancingAlgorithm::RoundRobin
                }
                lb_config_model::LoadBalancingAlgorithmConfig::WeightedRoundRobin => {
                    lb_runtime::LoadBalancingAlgorithm::WeightedRoundRobin
                }
                lb_config_model::LoadBalancingAlgorithmConfig::PowerOfTwoChoices => {
                    lb_runtime::LoadBalancingAlgorithm::PowerOfTwoChoices
                }
            },
            locality: match cluster.traffic_policy.locality {
                lb_config_model::LocalityRoutingConfig::Disabled => {
                    lb_runtime::LocalityRoutingPolicy::Disabled
                }
                lb_config_model::LocalityRoutingConfig::PreferLocality => {
                    lb_runtime::LocalityRoutingPolicy::PreferLocality
                }
                lb_config_model::LocalityRoutingConfig::PreferZone => {
                    lb_runtime::LocalityRoutingPolicy::PreferZone
                }
                lb_config_model::LocalityRoutingConfig::PreferLocalityThenZone => {
                    lb_runtime::LocalityRoutingPolicy::PreferLocalityThenZone
                }
            },
            no_healthy_fallback: match cluster.traffic_policy.no_healthy_fallback {
                lb_config_model::NoHealthyFallbackConfig::Fail => {
                    lb_runtime::NoHealthyFallback::Fail
                }
                lb_config_model::NoHealthyFallbackConfig::IncludeUnhealthy => {
                    lb_runtime::NoHealthyFallback::IncludeUnhealthy
                }
            },
            affinity: cluster.traffic_policy.affinity.as_ref().map(|affinity| match affinity {
                lb_config_model::AffinityPolicyConfig::HeaderHash { header_name, fallback } => {
                    lb_runtime::AffinityPolicy::HeaderHash {
                        header_name: header_name.clone(),
                        fallback: match fallback {
                            lb_config_model::AffinityFallbackConfig::BalanceHealthy => {
                                lb_runtime::AffinityFallbackPolicy::BalanceHealthy
                            }
                        },
                    }
                }
                lb_config_model::AffinityPolicyConfig::CookieHash { cookie_name, fallback } => {
                    lb_runtime::AffinityPolicy::CookieHash {
                        cookie_name: cookie_name.clone(),
                        fallback: match fallback {
                            lb_config_model::AffinityFallbackConfig::BalanceHealthy => {
                                lb_runtime::AffinityFallbackPolicy::BalanceHealthy
                            }
                        },
                    }
                }
            }),
        },
    )
    .map_err(to_dyn_error)
}

fn compile_mirror_backend_pools(
    config: &lb_config_model::WorkspaceConfig,
) -> Result<Vec<(String, lb_runtime::RouteBackendPool)>, DynError> {
    config
        .upstream_clusters
        .iter()
        .map(|cluster| Ok((cluster.name.clone(), compile_route_backend_pool(cluster)?)))
        .collect()
}

fn default_route_enumeration_policy() -> lb_runtime::RouteEnumerationProtectionPolicy {
    lb_runtime::RouteEnumerationProtectionPolicy {
        source_aggregation: lb_runtime::SourceAggregation::ExactIp,
        evaluation_window: Duration::from_secs(30),
        max_unmatched_route_events: 3,
        max_distinct_query_signatures_per_route: 6,
        base_ban_duration: Duration::from_secs(60),
        max_ban_duration: Duration::from_secs(15 * 60),
        max_tracked_sources: 4096,
    }
}

