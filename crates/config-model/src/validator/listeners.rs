fn validate_listener(
    listener: &crate::ListenerResourceConfig,
    index: usize,
    route_names: &BTreeSet<String>,
    route_registry: &BTreeMap<String, &RouteConfig>,
    policy_registry: &PolicyRegistry,
    report: &mut ValidationReport,
) {
    let base_path = format!("listeners[{index}]");
    if listener.name.trim().is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::EmptyResourceName,
            format!("{base_path}.name"),
            "listener name must not be empty",
        ));
    }

    if listener.max_connections == Some(0)
        || listener.backlog == Some(0)
        || listener.idle_timeout_ms == Some(0)
        || listener.drain_timeout_ms == Some(0)
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerField,
            base_path.clone(),
            "listener overrides must use non-zero max_connections, backlog, idle_timeout_ms, and drain_timeout_ms",
        ));
    }

    match listener.bind_mode {
        ListenerBindModeConfig::SingleStack => {}
        ListenerBindModeConfig::DualStack => {
            if !listener.bind_address.is_ipv6() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.bind_mode"),
                    "dual_stack listeners must use an IPv6 bind_address",
                ));
            } else if !listener.bind_address.ip().is_unspecified() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.bind_address"),
                    "dual_stack listeners currently require the IPv6 wildcard bind address [::]:port",
                ));
            }
        }
        ListenerBindModeConfig::Ipv6Only => {
            if !listener.bind_address.is_ipv6() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.bind_mode"),
                    "ipv6_only listeners must use an IPv6 bind_address",
                ));
            }
        }
    }

    if matches!(listener.protocol, ListenerProtocolConfig::Tcp) && !listener.routes.is_empty() {
        report.errors.push(ValidationError::semantic(
            ValidationCode::UnsupportedListenerRouting,
            format!("{base_path}.routes"),
            "tcp listeners cannot attach HTTP route references",
        ));
    }

    if !matches!(listener.proxy_protocol, crate::ProxyProtocolModeConfig::Disabled) {
        if listener.class != ListenerClassConfig::Public {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidListenerField,
                format!("{base_path}.proxy_protocol"),
                "proxy protocol is supported only on public listeners",
            ));
        }
        if listener.protocol == ListenerProtocolConfig::Http3 {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidListenerField,
                format!("{base_path}.proxy_protocol"),
                "proxy protocol is not supported on http3 listeners",
            ));
        }
    }

    if listener.protocol == ListenerProtocolConfig::Http3
        && listener.class != ListenerClassConfig::Public
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.protocol"),
            "http3 listeners are currently supported only on public listeners",
        ));
    }

    validate_upgrade_policy(
        &listener.upgrade,
        &format!("{base_path}.upgrade"),
        ValidationCode::InvalidListenerField,
        "listener upgrade policy",
        report,
    );
    if !listener.upgrade.is_default()
        && (listener.class != ListenerClassConfig::Public
            || !matches!(listener.protocol, ListenerProtocolConfig::Http1 | ListenerProtocolConfig::Https))
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.upgrade"),
            "upgrade policy is supported only on public http1 or https listeners",
        ));
    }

    match (&listener.protocol, &listener.tls_termination) {
        (protocol @ (ListenerProtocolConfig::Https | ListenerProtocolConfig::Http3), None) => {
            let protocol_name = listener_protocol_name(*protocol);
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidListenerField,
                format!("{base_path}.tls_termination"),
                format!(
                    "{protocol_name} listeners must declare tls_termination certificate material"
                ),
            ));
        }
        (protocol @ (ListenerProtocolConfig::Https | ListenerProtocolConfig::Http3), Some(tls_termination)) => {
            let protocol_name = listener_protocol_name(*protocol);
            if tls_termination.certificate_source.cert_path().trim().is_empty()
                || tls_termination.certificate_source.key_path().trim().is_empty()
            {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.tls_termination.certificate_source"),
                    format!(
                        "{protocol_name} listeners must use non-empty cert_path and key_path values"
                    ),
                ));
            }
            if tls_termination
                .certificate_source
                .ocsp_path()
                .is_some_and(|path| path.trim().is_empty())
            {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.tls_termination.certificate_source.ocsp_path"),
                    format!(
                        "{protocol_name} listeners must use a non-empty ocsp_path when OCSP stapling is configured"
                    ),
                ));
            }

            let mut seen_sni_names = BTreeSet::new();
            for (sni_index, sni_certificate) in tls_termination.sni_certificates.iter().enumerate()
            {
                let certificate_path =
                    format!("{base_path}.tls_termination.sni_certificates[{sni_index}]");
                if sni_certificate.server_names.is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{certificate_path}.server_names"),
                        "https SNI certificate mappings must declare at least one server name",
                    ));
                }
                if sni_certificate.certificate_source.cert_path().trim().is_empty()
                    || sni_certificate.certificate_source.key_path().trim().is_empty()
                {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{certificate_path}.certificate_source"),
                        "https SNI certificate mappings must use non-empty cert_path and key_path values",
                    ));
                }
                if sni_certificate
                    .certificate_source
                    .ocsp_path()
                    .is_some_and(|path| path.trim().is_empty())
                {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{certificate_path}.certificate_source.ocsp_path"),
                        "https SNI certificate mappings must use a non-empty ocsp_path when OCSP stapling is configured",
                    ));
                }

                for (name_index, server_name) in sni_certificate.server_names.iter().enumerate() {
                    match lb_proto_http::canonicalize_host(server_name) {
                        Ok(normalized) => {
                            if !seen_sni_names.insert(normalized.clone()) {
                                report.errors.push(ValidationError::schema(
                                    ValidationCode::InvalidListenerField,
                                    format!("{certificate_path}.server_names[{name_index}]"),
                                    format!(
                                        "{protocol_name} listeners must not repeat SNI server name {normalized}"
                                    ),
                                ));
                            }
                        }
                        Err(_) => report.errors.push(ValidationError::schema(
                            ValidationCode::InvalidListenerField,
                            format!("{certificate_path}.server_names[{name_index}]"),
                            format!(
                                "https listener {} declares invalid SNI server name {}",
                                listener.name, server_name
                            ),
                        )),
                    }
                }
            }

            match tls_termination.session_resumption.mode {
                crate::ListenerTlsSessionResumptionModeConfig::Disabled => {}
                crate::ListenerTlsSessionResumptionModeConfig::Stateful
                | crate::ListenerTlsSessionResumptionModeConfig::Hybrid => {
                    if tls_termination.session_resumption.session_cache_size == 0 {
                        report.errors.push(ValidationError::schema(
                            ValidationCode::InvalidListenerField,
                            format!("{base_path}.tls_termination.session_resumption.session_cache_size"),
                            format!(
                                "{protocol_name} listeners using stateful session resumption must use a non-zero session_cache_size"
                            ),
                        ));
                    }
                }
                crate::ListenerTlsSessionResumptionModeConfig::Tickets => {}
            }

            match tls_termination.session_resumption.mode {
                crate::ListenerTlsSessionResumptionModeConfig::Tickets
                | crate::ListenerTlsSessionResumptionModeConfig::Hybrid => {
                    if tls_termination.session_resumption.tls13_ticket_count == 0 {
                        report.errors.push(ValidationError::schema(
                            ValidationCode::InvalidListenerField,
                            format!("{base_path}.tls_termination.session_resumption.tls13_ticket_count"),
                            format!(
                                "{protocol_name} listeners issuing TLS tickets must use a non-zero tls13_ticket_count"
                            ),
                        ));
                    }
                }
                crate::ListenerTlsSessionResumptionModeConfig::Disabled
                | crate::ListenerTlsSessionResumptionModeConfig::Stateful => {}
            }

            if tls_termination.alpn_protocols.is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.tls_termination.alpn_protocols"),
                    format!("{protocol_name} listeners must advertise at least one ALPN protocol"),
                ));
            }

            if *protocol == ListenerProtocolConfig::Http3
                && !tls_termination
                    .alpn_protocols
                    .iter()
                    .all(|alpn| *alpn == ListenerAlpnProtocolConfig::Http3)
            {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.tls_termination.alpn_protocols"),
                    "http3 listeners must advertise only the http3 ALPN protocol",
                ));
            }

            let mut seen_alpn = BTreeSet::new();
            for (alpn_index, alpn_protocol) in tls_termination.alpn_protocols.iter().enumerate() {
                if !seen_alpn.insert(*alpn_protocol) {
                    let protocol_name = match alpn_protocol {
                        ListenerAlpnProtocolConfig::Http2 => "http2",
                        ListenerAlpnProtocolConfig::Http11 => "http11",
                        ListenerAlpnProtocolConfig::Http3 => "http3",
                    };
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{base_path}.tls_termination.alpn_protocols[{alpn_index}]"),
                        format!(
                            "{} listeners must not repeat ALPN protocol {protocol_name}",
                            listener_protocol_name(*protocol)
                        ),
                    ));
                }
            }
        }
        (_, Some(_)) => {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidListenerField,
                format!("{base_path}.tls_termination"),
                "tls_termination is currently supported only for https and http3 listeners",
            ));
        }
        (_, None) => {}
    }

    validate_admin_listener_policy(listener, &base_path, report);

    let mut seen_routes = BTreeSet::new();
    for (route_index, route_name) in listener.routes.iter().enumerate() {
        let route_path = format!("{base_path}.routes[{route_index}]");
        let normalized = route_name.trim();
        if normalized.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidRouteReference,
                route_path,
                "route reference must not be empty",
            ));
            continue;
        }
        if !seen_routes.insert(normalized.to_string()) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::DuplicateResourceName,
                format!("{base_path}.routes[{route_index}]"),
                format!("listener {} references route {normalized} more than once", listener.name),
            ));
        }
        if !route_names.contains(normalized) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidRouteReference,
                route_path,
                format!("listener {} references unknown route {normalized}", listener.name),
            ));
        } else if let Some(route) = route_registry.get(normalized) {
            if !route.upgrade.is_default()
                && (listener.class != ListenerClassConfig::Public
                    || !matches!(listener.protocol, ListenerProtocolConfig::Http1 | ListenerProtocolConfig::Https))
            {
                report.errors.push(ValidationError::semantic(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.routes[{route_index}]"),
                    format!(
                        "listener {} cannot attach route {} with upgrade policy unless the listener is public http1 or https",
                        listener.name, route.name
                    ),
                ));
            }
        }
    }

    validate_policy_binding(
        &listener.policies,
        &format!("{base_path}.policies"),
        PolicyBindingTarget::Listener(&listener.name),
        policy_registry,
        report,
    );
}

