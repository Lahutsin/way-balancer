fn route_selection_metrics(
    route_backend_pools: &BTreeMap<String, crate::RouteBackendPool>,
) -> Option<crate::UpstreamSelectionMetrics> {
    if route_backend_pools.is_empty() {
        return None;
    }

    Some(route_backend_pools.values().fold(
        crate::UpstreamSelectionMetrics::default(),
        |mut aggregate, pool| {
            let metrics = pool.selection_metrics();
            aggregate.round_robin_selection_count += metrics.round_robin_selection_count;
            aggregate.weighted_round_robin_selection_count +=
                metrics.weighted_round_robin_selection_count;
            aggregate.weighted_route_selection_count += metrics.weighted_route_selection_count;
            aggregate.power_of_two_selection_count += metrics.power_of_two_selection_count;
            aggregate.locality_preference_hit_count += metrics.locality_preference_hit_count;
            aggregate.no_healthy_endpoint_count += metrics.no_healthy_endpoint_count;
            aggregate.unhealthy_fallback_selection_count +=
                metrics.unhealthy_fallback_selection_count;
            aggregate.affinity_hit_count += metrics.affinity_hit_count;
            aggregate.affinity_fallback_count += metrics.affinity_fallback_count;
            aggregate.route_destination_fallback_count += metrics.route_destination_fallback_count;
            for (destination_name, count) in metrics.route_destination_selection_counts {
                *aggregate
                    .route_destination_selection_counts
                    .entry(destination_name)
                    .or_default() += count;
            }
            aggregate
        },
    ))
}

enum RequestUpstreamResolution {
    Selected(SelectedUpstream),
    Reject(StatusCode, &'static str),
}

struct SelectedUpstream {
    target: lb_net_core::UpstreamTarget,
    route_backend: Option<crate::SelectedRouteBackend>,
}

fn resolve_request_upstream(
    config: &Http1ProxyConfig,
    request: &lb_proto_http::Http1RequestHead,
) -> RequestUpstreamResolution {
    if config.route_upstreams.is_empty() && config.route_backend_pools.is_empty() {
        return RequestUpstreamResolution::Selected(SelectedUpstream {
            target: config.upstream.clone(),
            route_backend: None,
        });
    }

    let Some(route) = &request.route else {
        return if config.reject_unmatched_routes {
            RequestUpstreamResolution::Reject(StatusCode::FORBIDDEN, "route not allowed\n")
        } else {
            RequestUpstreamResolution::Selected(SelectedUpstream {
                target: config.upstream.clone(),
                route_backend: None,
            })
        };
    };

    if let Some(pool) = config.route_backend_pools.get(&route.label) {
        return match pool.select_backend_with_context(&selection_context_for_request(
            request,
            pool.affinity_policy(),
        )) {
            Ok(route_backend) => RequestUpstreamResolution::Selected(SelectedUpstream {
                target: route_backend.upstream().clone(),
                route_backend: Some(route_backend),
            }),
            Err(_) => RequestUpstreamResolution::Reject(
                StatusCode::BAD_GATEWAY,
                "route backend unavailable\n",
            ),
        };
    }

    match config.route_upstreams.get(&route.label) {
        Some(upstreams) if !upstreams.is_empty() => {
            RequestUpstreamResolution::Selected(SelectedUpstream {
                target: select_route_upstream(config, &route.label, upstreams),
                route_backend: None,
            })
        }
        _ => RequestUpstreamResolution::Reject(
            StatusCode::BAD_GATEWAY,
            "route backend unavailable\n",
        ),
    }
}

fn selected_destination_label(selected_upstream: &SelectedUpstream) -> &str {
    selected_upstream
        .route_backend
        .as_ref()
        .map_or(selected_upstream.target.name.as_str(), |backend| {
            backend.cluster_name().as_str()
        })
}

fn record_route_selection_decision(
    config: &Http1ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
    resolution: &RequestUpstreamResolution,
) {
    let Some(request_telemetry) = config.request_telemetry.as_ref() else {
        return;
    };

    let route_label = route.map(|value| value.label.as_str());
    match resolution {
        RequestUpstreamResolution::Selected(selected) => {
            let _ = request_telemetry.telemetry.record_decision_trace(
                &request_telemetry.scope,
                lb_observability::DecisionTraceKind::RouteSelection,
                "selected",
                route_label,
                Some(selected_destination_label(selected)),
                None,
                None,
                "upstream selected for HTTP/1 request",
            );
        }
        RequestUpstreamResolution::Reject(status, _) => {
            let _ = request_telemetry.telemetry.record_decision_trace(
                &request_telemetry.scope,
                lb_observability::DecisionTraceKind::RouteSelection,
                "rejected",
                route_label,
                None,
                None,
                None,
                &format!("route resolution rejected request with status {status}"),
            );
        }
    }
}

fn stable_request_hash(input: &[u8]) -> u64 {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    hash.write(input);
    hash.finish()
}

fn select_route_upstream(
    config: &Http1ProxyConfig,
    route_label: &str,
    upstreams: &[lb_net_core::UpstreamTarget],
) -> lb_net_core::UpstreamTarget {
    if upstreams.len() == 1 {
        return upstreams[0].clone();
    }

    let mut cursors =
        config.route_upstream_cursors.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let cursor = cursors.entry(route_label.to_string()).or_insert(0);
    let index = *cursor % upstreams.len();
    *cursor = (*cursor + 1) % upstreams.len();
    upstreams[index].clone()
}

fn request_authority(request: &lb_proto_http::Http1RequestHead) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.as_str())
}

