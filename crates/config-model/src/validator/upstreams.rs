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

