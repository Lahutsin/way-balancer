fn validate_upstream_cluster(
    cluster: &crate::UpstreamClusterConfig,
    index: usize,
    policy_registry: &PolicyRegistry,
    report: &mut ValidationReport,
) {
    let base_path = format!("upstream_clusters[{index}]");
    if cluster.name.trim().is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::EmptyResourceName,
            format!("{base_path}.name"),
            "upstream cluster name must not be empty",
        ));
    }

    let mut seen_endpoint_ids = BTreeSet::new();
    for (endpoint_index, endpoint) in cluster.endpoints.iter().enumerate() {
        let endpoint_path = format!("{base_path}.endpoints[{endpoint_index}]");
        let endpoint_id = endpoint.id.trim();
        if endpoint_id.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidUpstreamField,
                format!("{endpoint_path}.id"),
                format!("upstream cluster {} contains an endpoint with an empty id", cluster.name),
            ));
        } else if !seen_endpoint_ids.insert(endpoint_id.to_string()) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                format!("{endpoint_path}.id"),
                format!(
                    "upstream cluster {} contains duplicate endpoint id {endpoint_id}",
                    cluster.name
                ),
            ));
        }

        if endpoint.weight == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidUpstreamField,
                format!("{endpoint_path}.weight"),
                format!(
                    "endpoint {endpoint_id} in cluster {} must use a weight greater than zero",
                    cluster.name
                ),
            ));
        }
        if endpoint.zone.as_deref().is_some_and(|zone| zone.trim().is_empty()) {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidUpstreamField,
                format!("{endpoint_path}.zone"),
                format!(
                    "endpoint {endpoint_id} in cluster {} must not use an empty zone",
                    cluster.name
                ),
            ));
        }
        if endpoint.locality.as_deref().is_some_and(|locality| locality.trim().is_empty()) {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidUpstreamField,
                format!("{endpoint_path}.locality"),
                format!(
                    "endpoint {endpoint_id} in cluster {} must not use an empty locality",
                    cluster.name
                ),
            ));
        }
    }

    if cluster.endpoints.is_empty() && cluster.discovery.is_none() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidUpstreamField,
            format!("{base_path}.endpoints"),
            format!(
                "upstream cluster {} must declare static endpoints or a discovery source",
                cluster.name
            ),
        ));
    }

    if !cluster.endpoints.is_empty() && cluster.discovery.is_some() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidUpstreamField,
            format!("{base_path}.discovery"),
            format!(
                "upstream cluster {} must not mix static endpoints with discovery",
                cluster.name
            ),
        ));
    }

    if let Some(discovery) = &cluster.discovery {
        validate_discovery_source(discovery, &cluster.name, &base_path, report);
    }

    if let Some(affinity) = &cluster.traffic_policy.affinity {
        match affinity {
            AffinityPolicyConfig::HeaderHash { header_name, .. } => {
                if !is_valid_affinity_token(header_name) {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidUpstreamField,
                        format!("{base_path}.traffic_policy.affinity.header_name"),
                        format!(
                            "upstream cluster {} must use a non-empty HTTP token for affinity header_name",
                            cluster.name
                        ),
                    ));
                }
            }
            AffinityPolicyConfig::CookieHash { cookie_name, .. } => {
                if !is_valid_affinity_token(cookie_name) {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidUpstreamField,
                        format!("{base_path}.traffic_policy.affinity.cookie_name"),
                        format!(
                            "upstream cluster {} must use a non-empty cookie token for affinity cookie_name",
                            cluster.name
                        ),
                    ));
                }
            }
        }
    }

    validate_policy_binding(
        &cluster.policies,
        &format!("{base_path}.policies"),
        PolicyBindingTarget::UpstreamCluster(&cluster.name),
        policy_registry,
        report,
    );
}

fn validate_discovery_source(
    discovery: &crate::DiscoverySourceConfig,
    cluster_name: &str,
    base_path: &str,
    report: &mut ValidationReport,
) {
    match discovery {
        crate::DiscoverySourceConfig::DnsAaaa { hostname, port, .. } => {
            if hostname.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidUpstreamField,
                    format!("{base_path}.discovery.hostname"),
                    format!("upstream cluster {cluster_name} must use a non-empty DNS hostname"),
                ));
            }
            if *port == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidUpstreamField,
                    format!("{base_path}.discovery.port"),
                    format!("upstream cluster {cluster_name} must use a non-zero DNS port"),
                ));
            }
        }
        crate::DiscoverySourceConfig::DnsSrv { service, .. } => {
            if service.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidUpstreamField,
                    format!("{base_path}.discovery.service"),
                    format!("upstream cluster {cluster_name} must use a non-empty DNS SRV service"),
                ));
            }
        }
        crate::DiscoverySourceConfig::KubernetesEndpointSlice { namespace, service } => {
            if namespace.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidUpstreamField,
                    format!("{base_path}.discovery.namespace"),
                    format!(
                        "upstream cluster {cluster_name} must use a non-empty Kubernetes namespace"
                    ),
                ));
            }
            if service.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidUpstreamField,
                    format!("{base_path}.discovery.service"),
                    format!(
                        "upstream cluster {cluster_name} must use a non-empty Kubernetes service"
                    ),
                ));
            }
        }
        crate::DiscoverySourceConfig::ConsulLike { service, datacenter } => {
            if service.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidUpstreamField,
                    format!("{base_path}.discovery.service"),
                    format!("upstream cluster {cluster_name} must use a non-empty Consul service"),
                ));
            }
            if datacenter.as_deref().is_some_and(|value| value.trim().is_empty()) {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidUpstreamField,
                    format!("{base_path}.discovery.datacenter"),
                    format!(
                        "upstream cluster {cluster_name} must not use an empty Consul datacenter"
                    ),
                ));
            }
        }
    }
}

fn is_valid_affinity_token(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

#[cfg(test)]
mod upstreams_coverage_regressions {
    use super::{
        PolicyRegistry, ValidationCode, ValidationReport, is_valid_affinity_token,
        validate_upstream_cluster,
    };
    use crate::{
        AffinityPolicyConfig, DiscoverySourceConfig, PolicyResourcesConfig, UpstreamClusterConfig,
        UpstreamEndpointConfig, UpstreamTrafficPolicyConfig, UpstreamTransportConfig,
    };
    use std::collections::BTreeSet;

    fn cluster(name: &str) -> UpstreamClusterConfig {
        UpstreamClusterConfig {
            name: String::from(name),
            transport: UpstreamTransportConfig::Http1,
            endpoints: Vec::new(),
            discovery: None,
            traffic_policy: UpstreamTrafficPolicyConfig::default(),
            policies: crate::PolicyBindingConfig::default(),
        }
    }

    fn validate(config: &UpstreamClusterConfig) -> ValidationReport {
        let mut report = ValidationReport::default();
        let registry =
            PolicyRegistry::new(&PolicyResourcesConfig::default(), &BTreeSet::new(), &mut report);
        validate_upstream_cluster(config, 0, &registry, &mut report);
        report
    }

    #[test]
    fn validates_static_endpoints_and_affinity_tokens() -> Result<(), Box<dyn std::error::Error>> {
        let address = "127.0.0.1:9000".parse()?;
        let mut config = cluster(" ");
        let mut blank = UpstreamEndpointConfig::foundation("", address);
        blank.weight = 0;
        blank.zone = Some(String::from(" "));
        blank.locality = Some(String::new());
        config.endpoints = vec![
            blank,
            UpstreamEndpointConfig::foundation("id", address),
            UpstreamEndpointConfig::foundation(" id ", address),
        ];
        config.traffic_policy.affinity = Some(AffinityPolicyConfig::HeaderHash {
            header_name: String::from("bad header"),
            fallback: Default::default(),
        });
        let report = validate(&config);
        for (code, path) in [
            (ValidationCode::EmptyResourceName, "upstream_clusters[0].name"),
            (ValidationCode::InvalidUpstreamField, "upstream_clusters[0].endpoints[0].id"),
            (ValidationCode::InvalidUpstreamField, "upstream_clusters[0].endpoints[0].weight"),
            (ValidationCode::InvalidUpstreamField, "upstream_clusters[0].endpoints[0].zone"),
            (ValidationCode::InvalidUpstreamField, "upstream_clusters[0].endpoints[0].locality"),
            (ValidationCode::DuplicateResourceName, "upstream_clusters[0].endpoints[2].id"),
            (
                ValidationCode::InvalidUpstreamField,
                "upstream_clusters[0].traffic_policy.affinity.header_name",
            ),
        ] {
            assert!(
                report.errors.iter().any(|error| error.code == code && error.path == path),
                "missing {path}"
            );
        }
        for token in ["x-session", "X_COOKIE", "!#$%&'*+-.^_`|~012AZaz"] {
            assert!(is_valid_affinity_token(token));
        }
        for token in ["", " leading", "trailing ", "with space", "bad/name"] {
            assert!(!is_valid_affinity_token(token));
        }
        Ok(())
    }

    #[test]
    fn validates_missing_and_mixed_discovery_configurations()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(
            validate(&cluster("missing"))
                .errors
                .iter()
                .any(|error| error.path == "upstream_clusters[0].endpoints")
        );
        let mut mixed = cluster("mixed");
        mixed
            .endpoints
            .push(UpstreamEndpointConfig::foundation("static", "127.0.0.1:9000".parse()?));
        mixed.discovery = Some(DiscoverySourceConfig::DnsSrv {
            service: String::from("payments"),
            min_refresh_secs: 1,
        });
        assert!(
            validate(&mixed)
                .errors
                .iter()
                .any(|error| error.path == "upstream_clusters[0].discovery")
        );
        for source in [
            DiscoverySourceConfig::DnsAaaa {
                hostname: String::from(" "),
                port: 0,
                min_refresh_secs: 1,
            },
            DiscoverySourceConfig::DnsSrv { service: String::new(), min_refresh_secs: 1 },
            DiscoverySourceConfig::KubernetesEndpointSlice {
                namespace: String::from(" "),
                service: String::new(),
            },
            DiscoverySourceConfig::ConsulLike {
                service: String::from(" "),
                datacenter: Some(String::from(" ")),
            },
        ] {
            let mut config = cluster("discovery");
            config.discovery = Some(source);
            assert!(
                validate(&config)
                    .errors
                    .iter()
                    .any(|error| error.code == ValidationCode::InvalidUpstreamField
                        && error.path.starts_with("upstream_clusters[0].discovery."))
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_invalid_cookie_affinity_token() {
        let mut config = cluster("cookie");
        config.traffic_policy.affinity = Some(AffinityPolicyConfig::CookieHash {
            cookie_name: String::from("bad;cookie"),
            fallback: Default::default(),
        });
        assert!(
            validate(&config)
                .errors
                .iter()
                .any(|error| error.path
                    == "upstream_clusters[0].traffic_policy.affinity.cookie_name")
        );
    }
}
