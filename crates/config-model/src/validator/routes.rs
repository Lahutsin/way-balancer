fn validate_route(
    route: &RouteConfig,
    index: usize,
    upstream_names: &BTreeSet<String>,
    policy_registry: &PolicyRegistry,
    report: &mut ValidationReport,
) {
    let base_path = format!("routes[{index}]");
    if route.name.trim().is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::EmptyResourceName,
            format!("{base_path}.name"),
            "route name must not be empty",
        ));
    }

    validate_upgrade_policy(
        &route.upgrade,
        &format!("{base_path}.upgrade"),
        ValidationCode::InvalidRouteMatch,
        "route upgrade policy",
        report,
    );

    match &route.match_rule {
        RouteMatchConfig::PathPrefix {
            prefix,
            hostnames,
            methods,
            headers,
            query_params,
            content_types,
            grpc_services,
            grpc_methods,
            source_cidrs,
        } => {
            if prefix.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidRouteMatch,
                    format!("{base_path}.match.prefix"),
                    format!("route {} must declare a non-empty path prefix", route.name),
                ));
            }
            for (hostname_index, hostname) in hostnames.iter().enumerate() {
                if lb_proto_http::canonicalize_host(hostname).is_err() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidRouteMatch,
                        format!("{base_path}.match.hostnames[{hostname_index}]"),
                        format!(
                            "route {} declares invalid hostname filter {}",
                            route.name, hostname
                        ),
                    ));
                }
            }
            for (method_index, method) in methods.iter().enumerate() {
                if lb_proto_http::normalize_http_method(method).is_none() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidRouteMatch,
                        format!("{base_path}.match.methods[{method_index}]"),
                        format!("route {} declares invalid method filter {}", route.name, method),
                    ));
                }
            }
            for (header_index, header_match) in headers.iter().enumerate() {
                match header_match {
                    crate::RouteHeaderMatchConfig::Exact { name, value } => {
                        if lb_proto_http::normalize_http_header_name(name).is_none() || value.trim().is_empty() {
                            report.errors.push(ValidationError::schema(
                                ValidationCode::InvalidRouteMatch,
                                format!("{base_path}.match.headers[{header_index}]"),
                                format!("route {} declares invalid header matcher", route.name),
                            ));
                        }
                    }
                    crate::RouteHeaderMatchConfig::Present { name }
                    | crate::RouteHeaderMatchConfig::Absent { name } => {
                        if lb_proto_http::normalize_http_header_name(name).is_none() {
                            report.errors.push(ValidationError::schema(
                                ValidationCode::InvalidRouteMatch,
                                format!("{base_path}.match.headers[{header_index}]"),
                                format!("route {} declares invalid header matcher", route.name),
                            ));
                        }
                    }
                }
            }
            for (query_index, query_match) in query_params.iter().enumerate() {
                match query_match {
                    crate::RouteQueryMatchConfig::Exact { name, value } => {
                        if lb_proto_http::canonicalize_query_match_name(name).is_err()
                            || lb_proto_http::canonicalize_query_match_value(value).is_err()
                        {
                            report.errors.push(ValidationError::schema(
                                ValidationCode::InvalidRouteMatch,
                                format!("{base_path}.match.query_params[{query_index}]"),
                                format!("route {} declares invalid query matcher", route.name),
                            ));
                        }
                    }
                    crate::RouteQueryMatchConfig::Present { name }
                    | crate::RouteQueryMatchConfig::Absent { name } => {
                        if lb_proto_http::canonicalize_query_match_name(name).is_err() {
                            report.errors.push(ValidationError::schema(
                                ValidationCode::InvalidRouteMatch,
                                format!("{base_path}.match.query_params[{query_index}]"),
                                format!("route {} declares invalid query matcher", route.name),
                            ));
                        }
                    }
                }
            }
            for (content_type_index, content_type) in content_types.iter().enumerate() {
                if lb_proto_http::normalize_content_type_match(content_type).is_none() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidRouteMatch,
                        format!("{base_path}.match.content_types[{content_type_index}]"),
                        format!("route {} declares invalid content-type filter {}", route.name, content_type),
                    ));
                }
            }
            for (grpc_service_index, grpc_service) in grpc_services.iter().enumerate() {
                if lb_proto_http::normalize_grpc_service_match(grpc_service).is_none() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidRouteMatch,
                        format!("{base_path}.match.grpc_services[{grpc_service_index}]"),
                        format!("route {} declares invalid gRPC service matcher {}", route.name, grpc_service),
                    ));
                }
            }
            for (grpc_method_index, grpc_method) in grpc_methods.iter().enumerate() {
                if lb_proto_http::normalize_grpc_method_match(grpc_method).is_none() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidRouteMatch,
                        format!("{base_path}.match.grpc_methods[{grpc_method_index}]"),
                        format!("route {} declares invalid gRPC method matcher {}", route.name, grpc_method),
                    ));
                }
            }
            if !(grpc_services.is_empty() && grpc_methods.is_empty()) {
                let declares_grpc_content_type = content_types
                    .iter()
                    .any(|content_type| lb_proto_http::is_grpc_content_type(content_type));
                if !declares_grpc_content_type {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidRouteMatch,
                        format!("{base_path}.match.content_types"),
                        format!(
                            "route {} must declare application/grpc content_types when gRPC service or method filters are present",
                            route.name
                        ),
                    ));
                }
                if methods.iter().any(|method| !method.eq_ignore_ascii_case("POST")) {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidRouteMatch,
                        format!("{base_path}.match.methods"),
                        format!(
                            "route {} must use only POST when gRPC service or method filters are present",
                            route.name
                        ),
                    ));
                }
            }
            for (source_index, source_cidr) in source_cidrs.iter().enumerate() {
                if source_cidr.parse::<ipnet::IpNet>().is_err() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidRouteMatch,
                        format!("{base_path}.match.source_cidrs[{source_index}]"),
                        format!("route {} declares invalid source CIDR {}", route.name, source_cidr),
                    ));
                }
            }
        }
    }

    if route.upstream_cluster.is_some() && !route.destinations.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidUpstreamReference,
            format!("{base_path}.destinations"),
            format!(
                "route {} must declare either upstream_cluster or destinations, not both",
                route.name
            ),
        ));
    }

    let destinations = route.normalized_destinations();
    if destinations.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidUpstreamReference,
            format!("{base_path}.destinations"),
            format!("route {} must declare at least one upstream destination", route.name),
        ));
    }

    let mut seen_destinations = BTreeSet::new();
    for (destination_index, destination) in destinations.iter().enumerate() {
        let destination_base_path = if route.destinations.is_empty() {
            format!("{base_path}.upstream_cluster")
        } else {
            format!("{base_path}.destinations[{destination_index}]")
        };
        let upstream_name = destination.upstream_cluster.trim();

        if upstream_name.is_empty() {
            let field_path = if route.destinations.is_empty() {
                destination_base_path.clone()
            } else {
                format!("{destination_base_path}.upstream_cluster")
            };
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidUpstreamReference,
                field_path,
                format!("route {} must reference a non-empty upstream cluster name", route.name),
            ));
            continue;
        }
        if destination.weight == 0 {
            let field_path = if route.destinations.is_empty() {
                destination_base_path.clone()
            } else {
                format!("{destination_base_path}.weight")
            };
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidUpstreamReference,
                field_path,
                format!("route {} destination {upstream_name} must use a non-zero weight", route.name),
            ));
        }
        if !seen_destinations.insert(upstream_name.to_string()) {
            let field_path = if route.destinations.is_empty() {
                destination_base_path.clone()
            } else {
                format!("{destination_base_path}.upstream_cluster")
            };
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidUpstreamReference,
                field_path,
                format!("route {} declares duplicate upstream destination {upstream_name}", route.name),
            ));
        } else if !upstream_names.contains(upstream_name) {
            let field_path = if route.destinations.is_empty() {
                destination_base_path.clone()
            } else {
                format!("{destination_base_path}.upstream_cluster")
            };
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidUpstreamReference,
                field_path,
                format!("route {} references unknown upstream cluster {upstream_name}", route.name),
            ));
        }

        if !route.destinations.is_empty() {
            validate_policy_binding(
                &destination.policies,
                &format!("{destination_base_path}.policies"),
                PolicyBindingTarget::RouteDestination {
                    route_name: &route.name,
                    upstream_cluster: upstream_name,
                },
                policy_registry,
                report,
            );
        }
    }

    validate_policy_binding(
        &route.policies,
        &format!("{base_path}.policies"),
        PolicyBindingTarget::Route(&route.name),
        policy_registry,
        report,
    );
}

fn validate_upgrade_policy(
    policy: &crate::UpgradePolicyConfig,
    path: &str,
    code: ValidationCode,
    subject: &str,
    report: &mut ValidationReport,
) {
    let mut seen = BTreeSet::new();
    for (index, protocol) in policy.protocols.iter().enumerate() {
        if !seen.insert(*protocol) {
            report.errors.push(ValidationError::schema(
                code,
                format!("{path}.protocols[{index}]"),
                format!(
                    "{subject} must not repeat upgrade protocol {}",
                    upgrade_protocol_name(*protocol)
                ),
            ));
        }
    }
}

fn upgrade_protocol_name(protocol: crate::UpgradeProtocolConfig) -> &'static str {
    match protocol {
        crate::UpgradeProtocolConfig::Websocket => "websocket",
    }
}

