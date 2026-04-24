enum RequestUpstreamResolution {
    Selected(Box<SelectedUpstream>),
    Reject(StatusCode),
}

struct SelectedUpstream {
    target: lb_net_core::UpstreamTarget,
    route_backend: Option<crate::SelectedRouteBackend>,
}

fn resolve_stream_upstream(
    config: &Http2ProxyConfig,
    route: Option<&lb_proto_http::RouteMatch>,
    path_and_query: &str,
    headers: &http::HeaderMap,
) -> RequestUpstreamResolution {
    if config.route_upstreams.is_empty() && config.route_backend_pools.is_empty() {
        return RequestUpstreamResolution::Selected(Box::new(SelectedUpstream {
            target: config.upstream.clone(),
            route_backend: None,
        }));
    }

    let Some(route) = route else {
        return if config.reject_unmatched_routes {
            RequestUpstreamResolution::Reject(StatusCode::FORBIDDEN)
        } else {
            RequestUpstreamResolution::Selected(Box::new(SelectedUpstream {
                target: config.upstream.clone(),
                route_backend: None,
            }))
        };
    };

    if let Some(pool) = config.route_backend_pools.get(&route.label) {
        let selection_context =
            selection_context_for_request(path_and_query, headers, pool.affinity_policy());
        return match pool.select_backend_with_context(&selection_context) {
            Ok(route_backend) => RequestUpstreamResolution::Selected(Box::new(SelectedUpstream {
                target: route_backend.upstream().clone(),
                route_backend: Some(route_backend),
            })),
            Err(_) => RequestUpstreamResolution::Reject(StatusCode::BAD_GATEWAY),
        };
    }

    match config.route_upstreams.get(&route.label) {
        Some(upstreams) if !upstreams.is_empty() => {
            RequestUpstreamResolution::Selected(Box::new(SelectedUpstream {
                target: select_http2_route_upstream(config, &route.label, upstreams),
                route_backend: None,
            }))
        }
        _ => RequestUpstreamResolution::Reject(StatusCode::BAD_GATEWAY),
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
    config: &Http2ProxyConfig,
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
                "upstream selected for HTTP/2 stream",
            );
        }
        RequestUpstreamResolution::Reject(status) => {
            let _ = request_telemetry.telemetry.record_decision_trace(
                &request_telemetry.scope,
                lb_observability::DecisionTraceKind::RouteSelection,
                "rejected",
                route_label,
                None,
                None,
                None,
                &format!("route resolution rejected stream with status {status}"),
            );
        }
    }
}


fn select_http2_route_upstream(
    config: &Http2ProxyConfig,
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

