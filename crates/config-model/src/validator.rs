use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AdminAuthPolicyConfig, AdminAuthorizationScopeConfig, AffinityPolicyConfig,
    AnonymousSourceFilterConfig, ArtifactVerificationMode, CacheKeyPolicyConfig,
    HeaderMutationConfig, HostileEdgeProtectionPolicyConfig, HttpCachePolicyConfig,
    HttpCacheStorageConfig, ListenerAlpnProtocolConfig, ListenerBindModeConfig, ListenerClassConfig,
    ListenerProtocolConfig, LocalConcurrencyLimitPolicyConfig, LocalLimitScopeConfig,
    LocalRateLimitPolicyConfig, NamedOverloadResponsePolicyConfig, OverloadResponsePolicyConfig,
    PathRewriteTransformConfig, PolicyBindingConfig, PolicyResourcesConfig, RouteConfig,
    RouteMatchConfig, TransformPolicyConfig, TrustedClientIpConfig, WorkspaceConfig,
};

/// Stable validation error category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCategory {
    /// Structural and resource-local validation failure.
    Schema,
    /// Cross-resource semantic validation failure.
    Semantic,
}

/// Stable machine-readable validation code catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCode {
    EmptyWorkspaceName,
    InvalidListenerDefaults,
    InvalidHttp1Defaults,
    InvalidHttp2Defaults,
    InvalidSecurityDefaults,
    InsecureModeGated,
    EmptyResourceName,
    DuplicateResourceName,
    InvalidListenerField,
    InvalidRouteMatch,
    InvalidUpstreamField,
    InvalidPolicyField,
    InvalidPolicyReference,
    DuplicatePolicyReference,
    InvalidPolicyScope,
    InvalidRouteReference,
    InvalidUpstreamReference,
    UnsupportedListenerRouting,
}

/// Actionable config validation error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationError {
    /// Validation category.
    pub category: ValidationCategory,
    /// Stable machine-readable validation code.
    pub code: ValidationCode,
    /// Resource path in the config document.
    pub path: String,
    /// Operator-facing actionable message.
    pub message: String,
}

impl ValidationError {
    fn schema(code: ValidationCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            category: ValidationCategory::Schema,
            code,
            path: path.into(),
            message: message.into(),
        }
    }

    fn semantic(code: ValidationCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            category: ValidationCategory::Semantic,
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Stable machine-readable validation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ValidationReport {
    /// Ordered validation errors.
    pub errors: Vec<ValidationError>,
}

impl ValidationReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    #[must_use]
    pub fn operator_summary(&self) -> String {
        self.errors
            .iter()
            .map(|error| {
                format!(
                    "{:?} {:?} at {}: {}",
                    error.category, error.code, error.path, error.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl std::fmt::Display for ValidationReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errors.is_empty() {
            formatter.write_str("configuration validation succeeded")
        } else {
            formatter.write_str(&self.operator_summary())
        }
    }
}

impl std::error::Error for ValidationReport {}

/// Minimal validation counters for config ingestion observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConfigValidationStats {
    /// Count of successful validation attempts.
    pub success_count: u64,
    /// Count of schema validation errors observed.
    pub schema_error_count: u64,
    /// Count of semantic validation errors observed.
    pub semantic_error_count: u64,
}

/// Validator wrapper that exposes category counters alongside validation results.
#[derive(Debug, Default)]
pub struct WorkspaceConfigValidator {
    stats: ConfigValidationStats,
}

impl WorkspaceConfigValidator {
    /// Validates the workspace config and records category counters.
    pub fn validate(&mut self, config: &WorkspaceConfig) -> Result<(), ValidationReport> {
        let report = validate_workspace_config(config);
        if report.is_empty() {
            self.stats.success_count = self.stats.success_count.saturating_add(1);
            Ok(())
        } else {
            for error in &report.errors {
                match error.category {
                    ValidationCategory::Schema => {
                        self.stats.schema_error_count =
                            self.stats.schema_error_count.saturating_add(1);
                    }
                    ValidationCategory::Semantic => {
                        self.stats.semantic_error_count =
                            self.stats.semantic_error_count.saturating_add(1);
                    }
                }
            }
            Err(report)
        }
    }

    /// Returns the current validation counters.
    #[must_use]
    pub const fn stats(&self) -> ConfigValidationStats {
        self.stats
    }
}

pub(crate) fn validate_workspace_config(config: &WorkspaceConfig) -> ValidationReport {
    let mut report = ValidationReport::default();

    validate_workspace_basics(config, &mut report);
    validate_defaults(config, &mut report);
    validate_security(config, &mut report);

    let _listener_names = collect_named_resources(
        config.listeners.iter().enumerate().map(|(index, listener)| {
            (listener.name.clone(), format!("listeners[{index}].name"), "listener")
        }),
        &mut report,
    );
    let route_names =
        collect_named_resources(
            config.routes.iter().enumerate().map(|(index, route)| {
                (route.name.clone(), format!("routes[{index}].name"), "route")
            }),
            &mut report,
        );
    let route_registry = config
        .routes
        .iter()
        .map(|route| (route.name.clone(), route))
        .collect::<BTreeMap<_, _>>();
    let upstream_names = collect_named_resources(
        config.upstream_clusters.iter().enumerate().map(|(index, cluster)| {
            (cluster.name.clone(), format!("upstream_clusters[{index}].name"), "upstream cluster")
        }),
        &mut report,
    );

    let policy_registry = PolicyRegistry::new(&config.policies, &upstream_names, &mut report);

    for (index, listener) in config.listeners.iter().enumerate() {
        validate_listener(
            listener,
            index,
            &route_names,
            &route_registry,
            &policy_registry,
            &mut report,
        );
    }
    for (index, route) in config.routes.iter().enumerate() {
        validate_route(route, index, &upstream_names, &policy_registry, &mut report);
    }
    for (index, cluster) in config.upstream_clusters.iter().enumerate() {
        validate_upstream_cluster(cluster, index, &policy_registry, &mut report);
    }

    report
}

fn validate_workspace_basics(config: &WorkspaceConfig, report: &mut ValidationReport) {
    if config.name.trim().is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::EmptyWorkspaceName,
            "name",
            "workspace name must not be empty",
        ));
    }
}

fn validate_defaults(config: &WorkspaceConfig, report: &mut ValidationReport) {
    let listener = &config.defaults.listener;
    if listener.max_connections == 0
        || listener.backlog == 0
        || listener.idle_timeout_ms == 0
        || listener.drain_timeout_ms == 0
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerDefaults,
            "defaults.listener",
            "listener defaults must use non-zero max_connections, backlog, idle_timeout_ms, and drain_timeout_ms",
        ));
    }

    let http1 = &config.defaults.http.http1;
    if http1.max_head_bytes == 0 || http1.max_header_count == 0 || http1.max_body_bytes == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidHttp1Defaults,
            "defaults.http.http1",
            "http1 defaults must use non-zero max_head_bytes, max_header_count, and max_body_bytes",
        ));
    }

    let http2 = &config.defaults.http.http2;
    if http2.max_concurrent_streams == 0 || http2.max_body_bytes == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidHttp2Defaults,
            "defaults.http.http2",
            "http2 defaults must use non-zero max_concurrent_streams and max_body_bytes",
        ));
    }
}

fn validate_security(config: &WorkspaceConfig, report: &mut ValidationReport) {
    let security = &config.security;
    if security.insecure_dev_mode.enabled {
        let acknowledgement = security
            .insecure_dev_mode
            .acknowledgement
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if acknowledgement.is_none() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                "security.insecure_dev_mode.acknowledgement",
                "insecure_dev_mode requires a non-empty acknowledgement",
            ));
        }
    }

    if matches!(security.artifact_verification.mode, ArtifactVerificationMode::Disabled)
        && !security.insecure_dev_mode.enabled
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InsecureModeGated,
            "security.artifact_verification.mode",
            "artifact verification may only be disabled when insecure_dev_mode.enabled=true",
        ));
    }

    if matches!(security.artifact_verification.mode, ArtifactVerificationMode::Enforced)
        && security.artifact_verification.trusted_signers.iter().any(|trusted_signer| {
            trusted_signer.identity.trim().is_empty()
                || trusted_signer.public_key_ed25519.trim().is_empty()
        })
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidSecurityDefaults,
            "security.artifact_verification.trusted_signers",
            "artifact verification trusted_signers must not contain empty identities or public keys",
        ));
    }

    let mut trusted_signer_ids = BTreeSet::new();
    for (index, trusted_signer) in security.artifact_verification.trusted_signers.iter().enumerate()
    {
        let normalized_identity = trusted_signer.identity.trim();
        if normalized_identity.len() > 128 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                format!("security.artifact_verification.trusted_signers[{index}].identity"),
                "artifact verification signer identity exceeds max length",
            ));
        }
        if !crate::security::is_lower_hex_ed25519_public_key(&trusted_signer.public_key_ed25519) {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                format!(
                    "security.artifact_verification.trusted_signers[{index}].public_key_ed25519"
                ),
                "artifact verification signer public key must be a lowercase ed25519 hex string",
            ));
        }
        if !trusted_signer_ids.insert(normalized_identity) {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                "security.artifact_verification.trusted_signers",
                "artifact verification trusted_signers must not repeat identities",
            ));
        }
    }

    validate_anonymous_source_filter(&security.anonymous_source_filter, report);
    validate_trusted_client_ip(&security.trusted_client_ip, report);
}

fn validate_trusted_client_ip(config: &TrustedClientIpConfig, report: &mut ValidationReport) {
    for (index, cidr) in config.trusted_proxy_cidrs.iter().enumerate() {
        if cidr.parse::<ipnet::IpNet>().is_err() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidSecurityDefaults,
                format!("security.trusted_client_ip.trusted_proxy_cidrs[{index}]"),
                format!("trusted proxy CIDR must be a valid IPv4 or IPv6 CIDR: {cidr}"),
            ));
        }
    }
}

fn validate_anonymous_source_filter(
    filter: &AnonymousSourceFilterConfig,
    report: &mut ValidationReport,
) {
    for (path, cidrs) in [
        ("security.anonymous_source_filter.deny_cidrs", &filter.deny_cidrs),
        ("security.anonymous_source_filter.vpn_cidrs", &filter.vpn_cidrs),
        ("security.anonymous_source_filter.proxy_cidrs", &filter.proxy_cidrs),
        ("security.anonymous_source_filter.socks_cidrs", &filter.socks_cidrs),
        ("security.anonymous_source_filter.tor_exit_cidrs", &filter.tor_exit_cidrs),
    ] {
        for (index, cidr) in cidrs.iter().enumerate() {
            if cidr.parse::<ipnet::IpNet>().is_err() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidSecurityDefaults,
                    format!("{path}[{index}]"),
                    format!("anonymous source CIDR must be a valid IPv4 or IPv6 CIDR: {cidr}"),
                ));
            }
        }
    }
}

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

fn validate_admin_listener_policy(
    listener: &crate::ListenerResourceConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    if listener.class != ListenerClassConfig::Admin && !listener.admin.is_default() {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.admin"),
            "admin policy is supported only on admin listeners",
        ));
        return;
    }

    if listener.class != ListenerClassConfig::Admin {
        return;
    }

    if listener.protocol == ListenerProtocolConfig::Http1
        && !listener.bind_address.ip().is_loopback()
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.protocol"),
            "admin listeners exposed beyond loopback must use https",
        ));
    }

    for (index, cidr) in listener.admin.allowed_source_cidrs.iter().enumerate() {
        if cidr.parse::<ipnet::IpNet>().is_err() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidListenerField,
                format!("{base_path}.admin.allowed_source_cidrs[{index}]"),
                format!("admin allowed source CIDR must be a valid IPv4 or IPv6 CIDR: {cidr}"),
            ));
        }
    }

    if listener.admin.rate_limit.requests_per_minute == 0 || listener.admin.rate_limit.burst == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.admin.rate_limit"),
            "admin rate limits must use non-zero requests_per_minute and burst values",
        ));
    }

    if listener.admin.audit.max_retained_events == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerField,
            format!("{base_path}.admin.audit.max_retained_events"),
            "admin audit retention must keep at least one event",
        ));
    }

    match &listener.admin.auth {
        AdminAuthPolicyConfig::Bearer { secret_env, permissions } => {
            if secret_env.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.admin.auth.secret_env"),
                    "admin bearer auth must declare a non-empty secret_env",
                ));
            }
            validate_admin_permissions(
                permissions,
                &format!("{base_path}.admin.auth.permissions"),
                report,
            );
        }
        AdminAuthPolicyConfig::SignedHeaders { operators, max_clock_skew_secs, nonce_ttl_secs } => {
            if operators.is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.admin.auth.operators"),
                    "signed admin auth must declare at least one operator",
                ));
            }
            if *max_clock_skew_secs == 0 || *nonce_ttl_secs == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.admin.auth"),
                    "signed admin auth must use non-zero max_clock_skew_secs and nonce_ttl_secs",
                ));
            }

            let mut seen_operator_ids = BTreeSet::new();
            for (index, operator) in operators.iter().enumerate() {
                let operator_path = format!("{base_path}.admin.auth.operators[{index}]");
                if operator.id.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{operator_path}.id"),
                        "admin operator id must not be empty",
                    ));
                } else if !seen_operator_ids.insert(operator.id.trim().to_string()) {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::DuplicateResourceName,
                        format!("{operator_path}.id"),
                        format!("admin operator {} is declared more than once", operator.id),
                    ));
                }
                if operator.secret_env.trim().is_empty() {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{operator_path}.secret_env"),
                        "admin operator secret_env must not be empty",
                    ));
                }
                validate_admin_permissions(
                    &operator.permissions,
                    &format!("{operator_path}.permissions"),
                    report,
                );
            }
        }
    }
}

fn listener_protocol_name(protocol: ListenerProtocolConfig) -> &'static str {
    match protocol {
        ListenerProtocolConfig::Tcp => "tcp",
        ListenerProtocolConfig::Http1 => "http1",
        ListenerProtocolConfig::Https => "https",
        ListenerProtocolConfig::Http2 => "http2",
        ListenerProtocolConfig::Http3 => "http3",
        ListenerProtocolConfig::Auto => "auto",
    }
}

fn validate_admin_permissions(
    permissions: &[AdminAuthorizationScopeConfig],
    path: &str,
    report: &mut ValidationReport,
) {
    if permissions.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidListenerField,
            path.to_string(),
            "admin permissions must declare at least one scope",
        ));
        return;
    }

    let mut seen = BTreeSet::new();
    for permission in permissions {
        if !seen.insert(*permission) {
            let scope = match permission {
                AdminAuthorizationScopeConfig::Read => "read",
                AdminAuthorizationScopeConfig::Audit => "audit",
                AdminAuthorizationScopeConfig::Write => "write",
            };
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidListenerField,
                path.to_string(),
                format!("admin permissions must not repeat scope {scope}"),
            ));
        }
    }
}

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

fn validate_policy_binding(
    binding: &PolicyBindingConfig,
    base_path: &str,
    target: PolicyBindingTarget<'_>,
    registry: &PolicyRegistry,
    report: &mut ValidationReport,
) {
    let rate_limit_refs = validate_multi_policy_refs(
        &binding.local_rate_limits,
        &format!("{base_path}.local_rate_limits"),
        "local rate-limit policy",
        &registry.local_rate_limits,
        report,
    );
    for policy_name in rate_limit_refs {
        validate_rate_limit_scope(&policy_name, registry, target, report);
    }

    let concurrency_limit_refs = validate_multi_policy_refs(
        &binding.local_concurrency_limits,
        &format!("{base_path}.local_concurrency_limits"),
        "local concurrency-limit policy",
        &registry.local_concurrency_limits,
        report,
    );
    for policy_name in concurrency_limit_refs {
        validate_concurrency_scope(&policy_name, registry, target, report);
    }

    validate_single_policy_ref(
        binding.retry_budget.as_deref(),
        &format!("{base_path}.retry_budget"),
        "retry budget policy",
        &registry.retry_budgets,
        report,
    );
    validate_single_policy_ref(
        binding.timeout_hierarchy.as_deref(),
        &format!("{base_path}.timeout_hierarchy"),
        "timeout hierarchy policy",
        &registry.timeout_hierarchies,
        report,
    );
    validate_single_policy_ref(
        binding.circuit_breaker.as_deref(),
        &format!("{base_path}.circuit_breaker"),
        "circuit breaker policy",
        &registry.circuit_breakers,
        report,
    );
    validate_single_policy_ref(
        binding.overload_response.as_deref(),
        &format!("{base_path}.overload_response"),
        "overload response policy",
        &registry.overload_responses,
        report,
    );
    validate_single_policy_ref(
        binding.hostile_edge_protection.as_deref(),
        &format!("{base_path}.hostile_edge_protection"),
        "hostile-edge protection policy",
        &registry.hostile_edge_protections,
        report,
    );
    if binding.hostile_edge_protection.is_some()
        && !matches!(target, PolicyBindingTarget::Listener(_))
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.hostile_edge_protection"),
            "hostile-edge protection policies may only be bound to listeners",
        ));
    }
    validate_single_policy_ref(
        binding.cache_policy.as_deref(),
        &format!("{base_path}.cache_policy"),
        "http cache policy",
        &registry.http_caches,
        report,
    );
    validate_single_policy_ref(
        binding.transform_policy.as_deref(),
        &format!("{base_path}.transform_policy"),
        "transform policy",
        &registry.transforms,
        report,
    );
    validate_single_policy_ref(
        binding.traffic_mirror.as_deref(),
        &format!("{base_path}.traffic_mirror"),
        "traffic mirroring policy",
        &registry.traffic_mirrors,
        report,
    );
    validate_single_policy_ref(
        binding.fault_injection.as_deref(),
        &format!("{base_path}.fault_injection"),
        "fault injection policy",
        &registry.fault_injections,
        report,
    );
    if binding.transform_policy.is_some()
        && matches!(target, PolicyBindingTarget::UpstreamCluster(_))
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.transform_policy"),
            "transform policies may only be bound to listeners or routes",
        ));
    }
    if binding.traffic_mirror.is_some()
        && !matches!(target, PolicyBindingTarget::RouteDestination { .. })
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.traffic_mirror"),
            "traffic mirroring policies may only be bound to route destinations",
        ));
    }
    if let (
        Some(policy_name),
        PolicyBindingTarget::RouteDestination { upstream_cluster, .. },
    ) = (binding.traffic_mirror.as_deref(), target)
    {
        if let Some(spec) = registry.traffic_mirror_specs.get(policy_name) {
            if spec.target_upstream_cluster == upstream_cluster {
                report.errors.push(ValidationError::semantic(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.traffic_mirror"),
                    "traffic mirroring target_upstream_cluster must differ from the primary route destination upstream cluster",
                ));
            }
        }
    }
    if binding.fault_injection.is_some()
        && !matches!(target, PolicyBindingTarget::RouteDestination { .. })
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.fault_injection"),
            "fault injection policies may only be bound to route destinations",
        ));
    }
    if binding.overload_response.is_some()
        && matches!(target, PolicyBindingTarget::RouteDestination { .. })
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.overload_response"),
            "overload response policies may not be bound to route destinations",
        ));
    }
    if binding.cache_policy.is_some()
        && matches!(target, PolicyBindingTarget::RouteDestination { .. })
    {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            format!("{base_path}.cache_policy"),
            "http cache policies may not be bound to route destinations",
        ));
    }
}

fn validate_multi_policy_refs(
    references: &[String],
    base_path: &str,
    resource_kind: &str,
    known: &BTreeSet<String>,
    report: &mut ValidationReport,
) -> Vec<String> {
    let mut resolved = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, reference) in references.iter().enumerate() {
        let path = format!("{base_path}[{index}]");
        let name = reference.trim();
        if name.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyReference,
                path,
                format!("{resource_kind} reference must not be empty"),
            ));
            continue;
        }
        if !seen.insert(name.to_string()) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::DuplicatePolicyReference,
                path.clone(),
                format!("{resource_kind} {name} is referenced more than once"),
            ));
        }
        if !known.contains(name) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidPolicyReference,
                path,
                format!("unknown {resource_kind} {name}"),
            ));
            continue;
        }
        resolved.push(name.to_string());
    }
    resolved
}

fn validate_single_policy_ref(
    reference: Option<&str>,
    path: &str,
    resource_kind: &str,
    known: &BTreeSet<String>,
    report: &mut ValidationReport,
) {
    if let Some(reference) = reference {
        let name = reference.trim();
        if name.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyReference,
                path,
                format!("{resource_kind} reference must not be empty"),
            ));
        } else if !known.contains(name) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidPolicyReference,
                path,
                format!("unknown {resource_kind} {name}"),
            ));
        }
    }
}

fn validate_rate_limit_scope(
    policy_name: &str,
    registry: &PolicyRegistry,
    target: PolicyBindingTarget<'_>,
    report: &mut ValidationReport,
) {
    if let Some(scope) = registry.rate_limit_scopes.get(policy_name) {
        validate_scope_match(scope, target, policy_name, "local rate-limit policy", report);
    }
}

fn validate_concurrency_scope(
    policy_name: &str,
    registry: &PolicyRegistry,
    target: PolicyBindingTarget<'_>,
    report: &mut ValidationReport,
) {
    if let Some(scope) = registry.concurrency_limit_scopes.get(policy_name) {
        validate_scope_match(scope, target, policy_name, "local concurrency-limit policy", report);
    }
}

fn validate_scope_match(
    scope: &LocalLimitScopeConfig,
    target: PolicyBindingTarget<'_>,
    policy_name: &str,
    resource_kind: &str,
    report: &mut ValidationReport,
) {
    let matches = match (scope, target) {
        (LocalLimitScopeConfig::Listener { name }, PolicyBindingTarget::Listener(target_name)) => {
            normalize_component(name) == normalize_component(target_name)
        }
        (LocalLimitScopeConfig::Route { name }, PolicyBindingTarget::Route(target_name)) => {
            normalize_component(name) == normalize_component(target_name)
        }
        (
            LocalLimitScopeConfig::RouteDestination {
                route,
                upstream_cluster,
            },
            PolicyBindingTarget::RouteDestination {
                route_name,
                upstream_cluster: target_upstream_cluster,
            },
        ) => {
            normalize_component(route) == normalize_component(route_name)
                && normalize_component(upstream_cluster)
                    == normalize_component(target_upstream_cluster)
        }
        (
            LocalLimitScopeConfig::UpstreamCluster { name },
            PolicyBindingTarget::UpstreamCluster(target_name),
        ) => normalize_component(name) == normalize_component(target_name),
        _ => false,
    };

    if !matches {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidPolicyScope,
            target.path_for_policy(policy_name),
            format!(
                "{resource_kind} {policy_name} scope {} does not match {} {}",
                describe_scope(scope),
                target.kind_name(),
                target.resource_name(),
            ),
        ));
    }
}

fn describe_scope(scope: &LocalLimitScopeConfig) -> String {
    match scope {
        LocalLimitScopeConfig::Listener { name } => format!("listener {name}"),
        LocalLimitScopeConfig::Route { name } => format!("route {name}"),
        LocalLimitScopeConfig::RouteDestination {
            route,
            upstream_cluster,
        } => format!("route destination {route}->{upstream_cluster}"),
        LocalLimitScopeConfig::UpstreamCluster { name } => format!("upstream cluster {name}"),
    }
}

fn collect_named_resources<I>(entries: I, report: &mut ValidationReport) -> BTreeSet<String>
where
    I: IntoIterator<Item = (String, String, &'static str)>,
{
    let mut names = BTreeSet::new();
    for (name, path, resource_kind) in entries {
        let normalized = name.trim();
        if normalized.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::EmptyResourceName,
                path,
                format!("{resource_kind} name must not be empty"),
            ));
            continue;
        }
        if !names.insert(normalized.to_string()) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                path,
                format!("duplicate {resource_kind} name {normalized}"),
            ));
        }
    }
    names
}

struct PolicyRegistry {
    local_rate_limits: BTreeSet<String>,
    local_concurrency_limits: BTreeSet<String>,
    hostile_edge_protections: BTreeSet<String>,
    retry_budgets: BTreeSet<String>,
    timeout_hierarchies: BTreeSet<String>,
    circuit_breakers: BTreeSet<String>,
    overload_responses: BTreeSet<String>,
    http_caches: BTreeSet<String>,
    transforms: BTreeSet<String>,
    traffic_mirrors: BTreeSet<String>,
    fault_injections: BTreeSet<String>,
    traffic_mirror_specs: BTreeMap<String, crate::TrafficMirrorPolicyConfig>,
    rate_limit_scopes: BTreeMap<String, LocalLimitScopeConfig>,
    concurrency_limit_scopes: BTreeMap<String, LocalLimitScopeConfig>,
}

impl PolicyRegistry {
    fn new(
        resources: &PolicyResourcesConfig,
        upstream_names: &BTreeSet<String>,
        report: &mut ValidationReport,
    ) -> Self {
        let mut registry = Self {
            local_rate_limits: BTreeSet::new(),
            local_concurrency_limits: BTreeSet::new(),
            hostile_edge_protections: BTreeSet::new(),
            retry_budgets: BTreeSet::new(),
            timeout_hierarchies: BTreeSet::new(),
            circuit_breakers: BTreeSet::new(),
            overload_responses: BTreeSet::new(),
            http_caches: BTreeSet::new(),
            transforms: BTreeSet::new(),
            traffic_mirrors: BTreeSet::new(),
            fault_injections: BTreeSet::new(),
            traffic_mirror_specs: BTreeMap::new(),
            rate_limit_scopes: BTreeMap::new(),
            concurrency_limit_scopes: BTreeMap::new(),
        };

        validate_named_local_rate_limits(resources, &mut registry, report);
        validate_named_local_concurrency_limits(resources, &mut registry, report);
        validate_named_hostile_edge_protections(resources, &mut registry, report);
        validate_named_retry_budgets(resources, &mut registry, report);
        validate_named_timeout_hierarchies(resources, &mut registry, report);
        validate_named_circuit_breakers(resources, &mut registry, report);
        validate_named_overload_responses(resources, &mut registry, report);
        validate_named_http_caches(resources, &mut registry, report);
        validate_named_transforms(resources, &mut registry, report);
        validate_named_traffic_mirrors(resources, upstream_names, &mut registry, report);
        validate_named_fault_injections(resources, &mut registry, report);

        registry
    }
}

fn validate_named_traffic_mirrors(
    resources: &PolicyResourcesConfig,
    upstream_names: &BTreeSet<String>,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.traffic_mirrors.iter().enumerate() {
        let base_path = format!("policies.traffic_mirrors[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "traffic mirroring policy",
            &mut registry.traffic_mirrors,
            report,
        );
        if policy.spec.percentage == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.percentage"),
                "traffic mirroring percentage must be between 1 and 100",
            ));
        }
        if policy.spec.target_upstream_cluster.trim().is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.target_upstream_cluster"),
                "traffic mirroring target_upstream_cluster must not be empty",
            ));
        } else if !upstream_names.contains(policy.spec.target_upstream_cluster.trim()) {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidUpstreamReference,
                format!("{base_path}.spec.target_upstream_cluster"),
                format!(
                    "traffic mirroring policy {} references unknown upstream cluster {}",
                    policy.name, policy.spec.target_upstream_cluster
                ),
            ));
        }
        registry.traffic_mirror_specs.insert(policy.name.clone(), policy.spec.clone());
    }
}

fn validate_named_transforms(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.transforms.iter().enumerate() {
        let base_path = format!("policies.transforms[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "transform policy",
            &mut registry.transforms,
            report,
        );
        validate_transform_policy(&policy.spec, &base_path, report);
    }
}

fn validate_transform_policy(
    policy: &TransformPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    let has_any_transform = policy.request.path_rewrite.is_some()
        || policy.request.host_rewrite.is_some()
        || !policy.request.header_mutations.is_empty()
        || !policy.response.header_mutations.is_empty();
    if !has_any_transform {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "transform policy must declare at least one request or response transform",
        ));
    }

    if let Some(path_rewrite) = &policy.request.path_rewrite {
        match path_rewrite {
            PathRewriteTransformConfig::ReplacePrefix { match_prefix, replacement } => {
                if match_prefix.trim().is_empty()
                    || !match_prefix.starts_with('/')
                    || replacement.trim().is_empty()
                    || !replacement.starts_with('/')
                {
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidPolicyField,
                        format!("{base_path}.spec.request.path_rewrite"),
                        "path rewrite replace_prefix must use non-empty match_prefix and replacement values that start with '/'",
                    ));
                }
            }
        }
    }

    if let Some(host_rewrite) = &policy.request.host_rewrite {
        if lb_proto_http::canonicalize_host(host_rewrite).is_err() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.request.host_rewrite"),
                "host rewrite must use a valid canonical host or authority value",
            ));
        }
    }

    validate_header_mutations(
        &policy.request.header_mutations,
        &format!("{base_path}.spec.request.header_mutations"),
        HeaderMutationTarget::Request,
        report,
    );
    validate_header_mutations(
        &policy.response.header_mutations,
        &format!("{base_path}.spec.response.header_mutations"),
        HeaderMutationTarget::Response,
        report,
    );
}

fn validate_named_http_caches(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.http_caches.iter().enumerate() {
        let base_path = format!("policies.http_caches[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "http cache policy",
            &mut registry.http_caches,
            report,
        );
        validate_http_cache_policy(&policy.spec, &base_path, report);
    }
}

#[derive(Clone, Copy)]
enum HeaderMutationTarget {
    Request,
    Response,
}

fn validate_header_mutations(
    mutations: &[HeaderMutationConfig],
    path: &str,
    target: HeaderMutationTarget,
    report: &mut ValidationReport,
) {
    for (index, mutation) in mutations.iter().enumerate() {
        let (name, value) = match mutation {
            HeaderMutationConfig::Set { name, value } => (name.as_str(), Some(value.as_str())),
            HeaderMutationConfig::Remove { name } => (name.as_str(), None),
        };
        let name_path = format!("{path}[{index}].name");
        let Some(normalized_name) = lb_proto_http::normalize_http_header_name(name) else {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                name_path,
                "header mutation name must be a valid HTTP header name",
            ));
            continue;
        };

        let disallowed = match target {
            HeaderMutationTarget::Request => is_disallowed_request_transform_header(&normalized_name),
            HeaderMutationTarget::Response => {
                is_disallowed_response_transform_header(&normalized_name)
            }
        };
        if disallowed {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{path}[{index}]"),
                format!(
                    "header mutation for {normalized_name} is not allowed because it affects hop-by-hop or framing behavior"
                ),
            ));
        }

        if let Some(value) = value {
            if value.trim().is_empty() || value.contains(['\r', '\n']) {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{path}[{index}].value"),
                    "header mutation set values must be non-empty and must not contain CR or LF",
                ));
            }
        }
    }
}

fn validate_named_fault_injections(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.fault_injections.iter().enumerate() {
        let base_path = format!("policies.fault_injections[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "fault injection policy",
            &mut registry.fault_injections,
            report,
        );
        if policy.spec.delay.is_none() && policy.spec.abort.is_none() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec"),
                "fault injection policy must declare at least one of delay or abort",
            ));
        }
        if let Some(delay) = &policy.spec.delay {
            if delay.percentage == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.delay.percentage"),
                    "fault injection delay percentage must be between 1 and 100",
                ));
            }
            if delay.fixed_delay_ms == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.delay.fixed_delay_ms"),
                    "fault injection fixed_delay_ms must be greater than zero",
                ));
            }
        }
        if let Some(abort) = &policy.spec.abort {
            if abort.percentage == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.abort.percentage"),
                    "fault injection abort percentage must be between 1 and 100",
                ));
            }
            if !(400..=599).contains(&abort.http_status) {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.abort.http_status"),
                    "fault injection abort http_status must be between 400 and 599",
                ));
            }
        }
    }
}

fn is_disallowed_request_transform_header(header: &str) -> bool {
    matches!(
        header,
        "connection"
            | "content-length"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_disallowed_response_transform_header(header: &str) -> bool {
    matches!(
        header,
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn validate_http_cache_policy(
    policy: &HttpCachePolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    if policy.methods.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec.methods"),
            "http cache policy must declare at least one cacheable method",
        ));
    }

    let mut seen_methods = BTreeSet::new();
    for (index, method) in policy.methods.iter().enumerate() {
        let method_key = format!("{method:?}");
        if !seen_methods.insert(method_key) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                format!("{base_path}.spec.methods[{index}]"),
                "http cache policy methods must not repeat entries",
            ));
        }
    }

    if policy.default_ttl_secs == 0
        || policy.max_ttl_secs == 0
        || policy.max_object_bytes == 0
        || policy.default_ttl_secs > policy.max_ttl_secs
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "http cache policy must use non-zero TTLs and max_object_bytes with default_ttl_secs <= max_ttl_secs",
        ));
    }

    if policy.cacheable_status_codes.is_empty()
        || policy.cacheable_status_codes.iter().any(|status| !(100..=599).contains(status))
    {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec.cacheable_status_codes"),
            "http cache policy must use non-empty cacheable_status_codes within the HTTP status code range",
        ));
    }

    validate_named_header_list(
        &policy.vary_headers,
        &format!("{base_path}.spec.vary_headers"),
        report,
    );
    validate_cache_key_policy(&policy.cache_key, &format!("{base_path}.spec.cache_key"), report);

    match policy.storage {
        HttpCacheStorageConfig::Memory { max_entries, max_bytes } => {
            if max_entries == 0 || max_bytes == 0 {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{base_path}.spec.storage"),
                    "memory cache storage must use non-zero max_entries and max_bytes",
                ));
            }
        }
    }
}

fn validate_cache_key_policy(
    policy: &CacheKeyPolicyConfig,
    path: &str,
    report: &mut ValidationReport,
) {
    validate_named_header_list(&policy.headers, &format!("{path}.headers"), report);
    if !policy.include_host && !policy.include_method && policy.headers.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            path,
            "cache key policy must include at least one differentiating component",
        ));
    }
}

fn validate_named_header_list(headers: &[String], path: &str, report: &mut ValidationReport) {
    let mut seen = BTreeSet::new();
    for (index, header) in headers.iter().enumerate() {
        let normalized = header.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{path}[{index}]"),
                "header names must not be empty",
            ));
            continue;
        }
        if !seen.insert(normalized.clone()) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                format!("{path}[{index}]"),
                format!("header {normalized} is repeated"),
            ));
        }
        if is_disallowed_http_cache_key_header(&normalized) {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{path}[{index}]"),
                format!("header {normalized} is not allowed in cache key or vary configuration"),
            ));
        }
    }
}

fn is_disallowed_http_cache_key_header(header: &str) -> bool {
    matches!(
        header,
        "authorization"
            | "cookie"
            | "set-cookie"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-proto"
    )
}

fn validate_named_local_rate_limits(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.local_rate_limits.iter().enumerate() {
        let base_path = format!("policies.local_rate_limits[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "local rate-limit policy",
            &mut registry.local_rate_limits,
            report,
        );
        validate_rate_limit_policy(&policy.spec, &base_path, report);
        registry.rate_limit_scopes.insert(policy.name.clone(), policy.spec.scope.clone());
    }
}

fn validate_named_local_concurrency_limits(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.local_concurrency_limits.iter().enumerate() {
        let base_path = format!("policies.local_concurrency_limits[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "local concurrency-limit policy",
            &mut registry.local_concurrency_limits,
            report,
        );
        validate_concurrency_limit_policy(&policy.spec, &base_path, report);
        registry.concurrency_limit_scopes.insert(policy.name.clone(), policy.spec.scope.clone());
    }
}

fn validate_named_hostile_edge_protections(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.hostile_edge_protections.iter().enumerate() {
        let base_path = format!("policies.hostile_edge_protections[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "hostile-edge protection policy",
            &mut registry.hostile_edge_protections,
            report,
        );
        validate_hostile_edge_policy(&policy.spec, &base_path, report);
    }
}

fn validate_named_retry_budgets(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.retry_budgets.iter().enumerate() {
        let base_path = format!("policies.retry_budgets[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "retry budget policy",
            &mut registry.retry_budgets,
            report,
        );
        if policy.spec.window_ms == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.window_ms"),
                format!("retry budget policy {} must use a window greater than zero", policy.name),
            ));
        }
    }
}

fn validate_named_timeout_hierarchies(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.timeout_hierarchies.iter().enumerate() {
        let base_path = format!("policies.timeout_hierarchies[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "timeout hierarchy policy",
            &mut registry.timeout_hierarchies,
            report,
        );
        let spec = &policy.spec;
        let has_zero = spec.request_timeout_ms == 0
            || spec.attempt_timeout_ms == 0
            || spec.connect_timeout_ms == 0
            || spec.idle_timeout_ms == 0;
        let invalid_order = spec.attempt_timeout_ms > spec.request_timeout_ms
            || spec.connect_timeout_ms > spec.attempt_timeout_ms
            || spec.idle_timeout_ms > spec.attempt_timeout_ms;
        if has_zero || invalid_order {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec"),
                format!(
                    "timeout hierarchy policy {} must use non-zero values with connect/idle <= attempt <= request",
                    policy.name
                ),
            ));
        }
    }
}

fn validate_named_circuit_breakers(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.circuit_breakers.iter().enumerate() {
        let base_path = format!("policies.circuit_breakers[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "circuit breaker policy",
            &mut registry.circuit_breakers,
            report,
        );
        if policy.spec.open_failure_threshold == 0
            || policy.spec.open_duration_ms == 0
            || policy.spec.half_open_success_threshold == 0
        {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec"),
                format!(
                    "circuit breaker policy {} must use non-zero thresholds and duration",
                    policy.name
                ),
            ));
        }
    }
}

fn validate_named_overload_responses(
    resources: &PolicyResourcesConfig,
    registry: &mut PolicyRegistry,
    report: &mut ValidationReport,
) {
    for (index, policy) in resources.overload_responses.iter().enumerate() {
        let base_path = format!("policies.overload_responses[{index}]");
        register_policy_name(
            &policy.name,
            &format!("{base_path}.name"),
            "overload response policy",
            &mut registry.overload_responses,
            report,
        );
        validate_overload_policy(&policy.spec, policy, &base_path, report);
    }
}

fn validate_rate_limit_policy(
    policy: &LocalRateLimitPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    validate_local_limit_scope(&policy.scope, &format!("{base_path}.spec.scope"), report);
    if policy.requests_per_window == 0 || policy.window_ms == 0 || policy.max_tracked_keys == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "local rate-limit policy must use non-zero requests_per_window, window_ms, and max_tracked_keys",
        ));
    }
}

fn validate_concurrency_limit_policy(
    policy: &LocalConcurrencyLimitPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    validate_local_limit_scope(&policy.scope, &format!("{base_path}.spec.scope"), report);
    if policy.max_concurrent == 0 || policy.max_tracked_keys == 0 {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "local concurrency-limit policy must use non-zero max_concurrent and max_tracked_keys",
        ));
    }
}

fn validate_local_limit_scope(
    scope: &LocalLimitScopeConfig,
    path: &str,
    report: &mut ValidationReport,
) {
    match scope {
        LocalLimitScopeConfig::Listener { name }
        | LocalLimitScopeConfig::Route { name }
        | LocalLimitScopeConfig::UpstreamCluster { name } => {
            if name.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    path,
                    "local limit scope name must not be empty",
                ));
            }
        }
        LocalLimitScopeConfig::RouteDestination {
            route,
            upstream_cluster,
        } => {
            if route.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{path}.route"),
                    "local limit route-destination scope route must not be empty",
                ));
            }
            if upstream_cluster.trim().is_empty() {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidPolicyField,
                    format!("{path}.upstream_cluster"),
                    "local limit route-destination scope upstream_cluster must not be empty",
                ));
            }
        }
    }
}

fn validate_overload_policy(
    policy: &OverloadResponsePolicyConfig,
    named: &NamedOverloadResponsePolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    let has_zero = policy.signal_window_ms == 0
        || policy.constrained_signal_threshold == 0
        || policy.shedding_signal_threshold == 0
        || policy.brownout_signal_threshold == 0;
    let invalid_order = policy.constrained_signal_threshold > policy.shedding_signal_threshold
        || policy.shedding_signal_threshold > policy.brownout_signal_threshold;
    if has_zero || invalid_order {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            format!(
                "overload response policy {} must use non-zero thresholds with constrained <= shedding <= brownout",
                named.name
            ),
        ));
    }

    let mut seen_features = BTreeSet::new();
    for (feature_index, feature) in policy.brownout_features.iter().enumerate() {
        let feature_path = format!("{base_path}.spec.brownout_features[{feature_index}]");
        let name = feature.name.trim();
        if name.is_empty() {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{feature_path}.name"),
                format!(
                    "overload response policy {} contains an empty brownout feature name",
                    named.name
                ),
            ));
            continue;
        }
        let normalized = normalize_component(name);
        if !seen_features.insert(normalized) {
            report.errors.push(ValidationError::schema(
                ValidationCode::DuplicateResourceName,
                format!("{feature_path}.name"),
                format!(
                    "overload response policy {} contains duplicate brownout feature {name}",
                    named.name
                ),
            ));
        }
    }
}

fn validate_hostile_edge_policy(
    policy: &HostileEdgeProtectionPolicyConfig,
    base_path: &str,
    report: &mut ValidationReport,
) {
    if policy.source_quota.is_none() && policy.handshake_guard.is_none() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            format!("{base_path}.spec"),
            "hostile-edge protection policy must enable at least one guard",
        ));
    }

    if let Some(source_quota) = &policy.source_quota {
        if source_quota.max_active_per_source == 0 || source_quota.max_tracked_sources == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.source_quota"),
                "hostile-edge source quota must use non-zero max_active_per_source and max_tracked_sources",
            ));
        }
    }

    if let Some(handshake_guard) = &policy.handshake_guard {
        if handshake_guard.max_inflight == 0 || handshake_guard.timeout_ms == 0 {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidPolicyField,
                format!("{base_path}.spec.handshake_guard"),
                "hostile-edge handshake guard must use non-zero max_inflight and timeout_ms",
            ));
        }
    }
}

fn register_policy_name(
    name: &str,
    path: &str,
    resource_kind: &str,
    known: &mut BTreeSet<String>,
    report: &mut ValidationReport,
) {
    let normalized = name.trim();
    if normalized.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::EmptyResourceName,
            path,
            format!("{resource_kind} name must not be empty"),
        ));
        return;
    }
    if !known.insert(normalized.to_string()) {
        report.errors.push(ValidationError::schema(
            ValidationCode::DuplicateResourceName,
            path,
            format!("duplicate {resource_kind} name {normalized}"),
        ));
    }
}

fn normalize_component(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[derive(Clone, Copy)]
enum PolicyBindingTarget<'a> {
    Listener(&'a str),
    Route(&'a str),
    RouteDestination {
        route_name: &'a str,
        upstream_cluster: &'a str,
    },
    UpstreamCluster(&'a str),
}

impl PolicyBindingTarget<'_> {
    fn kind_name(self) -> &'static str {
        match self {
            Self::Listener(_) => "listener",
            Self::Route(_) => "route",
            Self::RouteDestination { .. } => "route destination",
            Self::UpstreamCluster(_) => "upstream cluster",
        }
    }

    fn resource_name(&self) -> String {
        match self {
            Self::Listener(name) | Self::Route(name) | Self::UpstreamCluster(name) => {
                (*name).to_string()
            }
            Self::RouteDestination {
                route_name,
                upstream_cluster,
            } => format!("{route_name}->{upstream_cluster}"),
        }
    }

    fn path_for_policy(self, policy_name: &str) -> String {
        format!("{} {} policy binding {}", self.kind_name(), self.resource_name(), policy_name)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        validate_workspace_config, ValidationCategory, ValidationCode, WorkspaceConfigValidator,
    };
    use crate::{
        AdminListenerPolicyConfig, AffinityFallbackConfig, AffinityPolicyConfig,
        AuthorizationCacheBehaviorConfig, CacheKeyPolicyConfig, CacheQueryKeyBehaviorConfig,
        HostileEdgeHandshakeGuardConfig, HostileEdgeProtectionPolicyConfig,
        HeaderMutationConfig, HostileEdgeSourceQuotaConfig, HttpCacheMethodConfig,
        HttpCachePolicyConfig, HttpCacheStorageConfig, ListenerCertificateSourceConfig,
        ListenerBindModeConfig, ListenerClassConfig, ListenerResourceConfig, ListenerTlsTerminationConfig,
        LocalConcurrencyLimitPolicyConfig, LocalLimitKeyKindConfig, LocalLimitScopeConfig,
        LocalRateLimitPolicyConfig,
        NamedHostileEdgeProtectionPolicyConfig, NamedHttpCachePolicyConfig,
        NamedLocalConcurrencyLimitPolicyConfig, NamedLocalRateLimitPolicyConfig,
        NamedOverloadResponsePolicyConfig, NamedRetryBudgetPolicyConfig,
        NamedFaultInjectionPolicyConfig,
        NamedTrafficMirrorPolicyConfig,
        NamedTransformPolicyConfig, OverloadResponsePolicyConfig, PathRewriteTransformConfig,
        PolicyBindingConfig, PolicyResourcesConfig, RequestTransformConfig, ResponseTransformConfig,
        RouteConfig, TrafficMirrorPolicyConfig, TransformPolicyConfig, UpgradePolicyConfig, UpgradeProtocolConfig,
        FaultInjectionPolicyConfig, FaultInjectionDelayConfig, FaultInjectionAbortConfig,
        UpstreamClusterConfig, UpstreamEndpointConfig, UpstreamTrafficPolicyConfig,
        WorkspaceConfig,
    };

    fn valid_workspace() -> Result<WorkspaceConfig, Box<dyn std::error::Error>> {
        let public_listener_addr: SocketAddr = "127.0.0.1:8080".parse()?;
        let payments_endpoint_addr: SocketAddr = "127.0.0.1:9000".parse()?;

        Ok(WorkspaceConfig {
            name: String::from("edge"),
            listeners: vec![ListenerResourceConfig {
                name: String::from("public"),
                class: ListenerClassConfig::Public,
                bind_address: public_listener_addr,
                bind_mode: ListenerBindModeConfig::SingleStack,
                protocol: crate::ListenerProtocolConfig::Http1,
                proxy_protocol: crate::ProxyProtocolModeConfig::Disabled,
                tls_termination: None,
                allow_unspecified_bind: false,
                max_connections: Some(1024),
                backlog: Some(1024),
                idle_timeout_ms: Some(30_000),
                drain_timeout_ms: Some(5_000),
                routes: vec![String::from("api")],
                policies: PolicyBindingConfig {
                    local_rate_limits: vec![String::from("public-rate")],
                    retry_budget: Some(String::from("standard-retry")),
                    timeout_hierarchy: Some(String::from("standard-timeouts")),
                    circuit_breaker: Some(String::from("standard-breaker")),
                    overload_response: Some(String::from("public-overload")),
                    cache_policy: Some(String::from("public-cache")),
                    ..PolicyBindingConfig::default()
                },
                upgrade: crate::UpgradePolicyConfig::default(),
                admin: AdminListenerPolicyConfig::default(),
            }],
            routes: vec![RouteConfig {
                name: String::from("api"),
                match_rule: crate::RouteMatchConfig::PathPrefix {
                    prefix: String::from("/api"),
                    hostnames: Vec::new(),
                    methods: Vec::new(),
                    headers: Vec::new(),
                    query_params: Vec::new(),
                    content_types: Vec::new(),
                    grpc_services: Vec::new(),
                    grpc_methods: Vec::new(),
                    source_cidrs: Vec::new(),
                },
                upstream_cluster: Some(String::from("payments")),
                destinations: Vec::new(),
                policies: PolicyBindingConfig {
                    local_concurrency_limits: vec![String::from("api-concurrency")],
                    transform_policy: Some(String::from("api-transform")),
                    ..PolicyBindingConfig::default()
                },
                upgrade: crate::UpgradePolicyConfig::default(),
            }],
            upstream_clusters: vec![UpstreamClusterConfig {
                name: String::from("payments"),
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "payments-a",
                    payments_endpoint_addr,
                )],
                traffic_policy: UpstreamTrafficPolicyConfig::default(),
                policies: PolicyBindingConfig::default(),
            }, UpstreamClusterConfig {
                name: String::from("payments-shadow"),
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "payments-shadow-a",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9002),
                )],
                traffic_policy: UpstreamTrafficPolicyConfig::default(),
                policies: PolicyBindingConfig::default(),
            }],
            policies: PolicyResourcesConfig {
                local_rate_limits: vec![NamedLocalRateLimitPolicyConfig {
                    name: String::from("public-rate"),
                    spec: LocalRateLimitPolicyConfig {
                        scope: LocalLimitScopeConfig::Listener { name: String::from("public") },
                        key_kind: LocalLimitKeyKindConfig::SourceIp,
                        requests_per_window: 100,
                        window_ms: 1_000,
                        max_tracked_keys: 1_024,
                    },
                }],
                local_concurrency_limits: vec![NamedLocalConcurrencyLimitPolicyConfig {
                    name: String::from("api-concurrency"),
                    spec: LocalConcurrencyLimitPolicyConfig {
                        scope: LocalLimitScopeConfig::Route { name: String::from("api") },
                        key_kind: LocalLimitKeyKindConfig::RouteName,
                        max_concurrent: 64,
                        max_tracked_keys: 256,
                    },
                }],
                hostile_edge_protections: Vec::new(),
                retry_budgets: vec![NamedRetryBudgetPolicyConfig {
                    name: String::from("standard-retry"),
                    spec: crate::RetryBudgetPolicyConfig {
                        min_retry_tokens: 3,
                        retry_percent: 20,
                        window_ms: 10_000,
                    },
                }],
                timeout_hierarchies: vec![crate::NamedTimeoutHierarchyPolicyConfig {
                    name: String::from("standard-timeouts"),
                    spec: crate::TimeoutHierarchyConfig {
                        request_timeout_ms: 30_000,
                        attempt_timeout_ms: 10_000,
                        connect_timeout_ms: 1_000,
                        idle_timeout_ms: 5_000,
                    },
                }],
                circuit_breakers: vec![crate::NamedCircuitBreakerPolicyConfig {
                    name: String::from("standard-breaker"),
                    spec: crate::CircuitBreakerPolicyConfig {
                        open_failure_threshold: 5,
                        open_duration_ms: 30_000,
                        half_open_success_threshold: 2,
                    },
                }],
                overload_responses: vec![NamedOverloadResponsePolicyConfig {
                    name: String::from("public-overload"),
                    spec: OverloadResponsePolicyConfig {
                        signal_window_ms: 10_000,
                        constrained_signal_threshold: 3,
                        shedding_signal_threshold: 6,
                        brownout_signal_threshold: 9,
                        brownout_features: vec![crate::BrownoutFeatureConfig {
                            name: String::from("expensive-search"),
                            priority: crate::TrafficClassConfig::BestEffort,
                        }],
                    },
                }],
                http_caches: vec![NamedHttpCachePolicyConfig {
                    name: String::from("public-cache"),
                    spec: HttpCachePolicyConfig {
                        methods: vec![HttpCacheMethodConfig::Get, HttpCacheMethodConfig::Head],
                        default_ttl_secs: 30,
                        max_ttl_secs: 300,
                        stale_while_revalidate_secs: 15,
                        stale_if_error_secs: 60,
                        cacheable_status_codes: vec![200, 304, 404],
                        vary_headers: vec![String::from("accept-encoding")],
                        max_object_bytes: 65_536,
                        honor_cache_control: true,
                        allow_set_cookie_storage: false,
                        authorization: AuthorizationCacheBehaviorConfig::Bypass,
                        revalidation_enabled: true,
                        purge_enabled: true,
                        cache_key: CacheKeyPolicyConfig {
                            include_host: true,
                            include_method: false,
                            query: CacheQueryKeyBehaviorConfig::IncludeAll,
                            headers: vec![String::from("accept-language")],
                        },
                        storage: HttpCacheStorageConfig::Memory {
                            max_entries: 1024,
                            max_bytes: 1_048_576,
                        },
                    },
                }],
                transforms: vec![NamedTransformPolicyConfig {
                    name: String::from("api-transform"),
                    spec: TransformPolicyConfig {
                        request: RequestTransformConfig {
                            path_rewrite: Some(PathRewriteTransformConfig::ReplacePrefix {
                                match_prefix: String::from("/api"),
                                replacement: String::from("/v1/api"),
                            }),
                            host_rewrite: Some(String::from("backend.internal")),
                            header_mutations: vec![HeaderMutationConfig::Set {
                                name: String::from("x-route"),
                                value: String::from("api"),
                            }],
                        },
                        response: ResponseTransformConfig {
                            header_mutations: vec![HeaderMutationConfig::Remove {
                                name: String::from("server"),
                            }],
                        },
                    },
                }],
                traffic_mirrors: vec![NamedTrafficMirrorPolicyConfig {
                    name: String::from("shadow-payments"),
                    spec: TrafficMirrorPolicyConfig {
                        percentage: 20,
                        target_upstream_cluster: String::from("payments-shadow"),
                    },
                }],
                fault_injections: vec![NamedFaultInjectionPolicyConfig {
                    name: String::from("canary-chaos"),
                    spec: FaultInjectionPolicyConfig {
                        delay: Some(FaultInjectionDelayConfig {
                            percentage: 10,
                            fixed_delay_ms: 250,
                        }),
                        abort: Some(FaultInjectionAbortConfig {
                            percentage: 5,
                            http_status: 503,
                        }),
                    },
                }],
            },
            ..WorkspaceConfig::foundation()
        })
    }

    #[test]
    fn validator_accepts_consistent_workspace() -> Result<(), Box<dyn std::error::Error>> {
        let mut validator = WorkspaceConfigValidator::default();
        let config = valid_workspace()?;

        let result = validator.validate(&config);

        assert!(result.is_ok());
        assert_eq!(validator.stats().success_count, 1);
        assert_eq!(validator.stats().schema_error_count, 0);
        assert_eq!(validator.stats().semantic_error_count, 0);
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_affinity_key_names() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.upstream_clusters[0].traffic_policy.affinity =
            Some(AffinityPolicyConfig::HeaderHash {
                header_name: String::from("bad header"),
                fallback: AffinityFallbackConfig::BalanceHealthy,
            });

        let report = validate_workspace_config(&config);
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidUpstreamField
                && error.path == "upstream_clusters[0].traffic_policy.affinity.header_name"
        }));

        config.upstream_clusters[0].traffic_policy.affinity =
            Some(AffinityPolicyConfig::CookieHash {
                cookie_name: String::from(" session_id"),
                fallback: AffinityFallbackConfig::BalanceHealthy,
            });

        let report = validate_workspace_config(&config);
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidUpstreamField
                && error.path == "upstream_clusters[0].traffic_policy.affinity.cookie_name"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_references() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].routes.push(String::from("missing-route"));
        config.routes[0].upstream_cluster = Some(String::from("missing-cluster"));
        config.listeners[0].policies.retry_budget = Some(String::from("missing-policy"));

        let report = validate_workspace_config(&config);

        assert_eq!(report.errors.len(), 3);
        assert_eq!(report.errors[0].category, ValidationCategory::Semantic);
        assert_eq!(report.errors[0].code, ValidationCode::InvalidRouteReference);
        assert_eq!(report.errors[1].code, ValidationCode::InvalidPolicyReference);
        assert_eq!(report.errors[2].code, ValidationCode::InvalidUpstreamReference);
        Ok(())
    }

    #[test]
    fn validator_accepts_weighted_route_destinations() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].upstream_cluster = None;
        config.routes[0].destinations = vec![
            crate::RouteDestinationConfig {
                upstream_cluster: String::from("payments"),
                weight: 90,
                policies: PolicyBindingConfig::default(),
            },
            crate::RouteDestinationConfig {
                upstream_cluster: String::from("payments-canary"),
                weight: 10,
                policies: PolicyBindingConfig::default(),
            },
        ];
        config.upstream_clusters.push(UpstreamClusterConfig {
            name: String::from("payments-canary"),
            endpoints: vec![UpstreamEndpointConfig::foundation(
                "payments-canary-a",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001),
            )],
            traffic_policy: UpstreamTrafficPolicyConfig::default(),
            policies: PolicyBindingConfig::default(),
        });

        let report = validate_workspace_config(&config);

        assert!(report.is_empty(), "{}", report.operator_summary());
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_route_destinations() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].upstream_cluster = None;
        config.routes[0].destinations = vec![
            crate::RouteDestinationConfig {
                upstream_cluster: String::from("payments"),
                weight: 0,
                policies: PolicyBindingConfig::default(),
            },
            crate::RouteDestinationConfig {
                upstream_cluster: String::from("payments"),
                weight: 1,
                policies: PolicyBindingConfig::default(),
            },
        ];

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| error.path == "routes[0].destinations[0].weight"));
        assert!(report.errors.iter().any(|error| {
            error.path == "routes[0].destinations[1].upstream_cluster"
        }));
        Ok(())
    }

    #[test]
    fn validator_accepts_route_destination_policy_bindings(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].upstream_cluster = None;
        config.routes[0].destinations = vec![
            crate::RouteDestinationConfig {
                upstream_cluster: String::from("payments"),
                weight: 90,
                policies: PolicyBindingConfig::default(),
            },
            crate::RouteDestinationConfig {
                upstream_cluster: String::from("payments-canary"),
                weight: 10,
                policies: PolicyBindingConfig {
                    traffic_mirror: Some(String::from("shadow-payments")),
                    fault_injection: Some(String::from("canary-chaos")),
                    local_rate_limits: vec![String::from("payments-canary-rate")],
                    local_concurrency_limits: vec![String::from("payments-canary-concurrency")],
                    retry_budget: Some(String::from("standard-retry")),
                    timeout_hierarchy: Some(String::from("standard-timeouts")),
                    circuit_breaker: Some(String::from("standard-breaker")),
                    transform_policy: Some(String::from("api-transform")),
                    ..PolicyBindingConfig::default()
                },
            },
        ];
        config.upstream_clusters.push(UpstreamClusterConfig {
            name: String::from("payments-canary"),
            endpoints: vec![UpstreamEndpointConfig::foundation(
                "payments-canary-a",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001),
            )],
            traffic_policy: UpstreamTrafficPolicyConfig::default(),
            policies: PolicyBindingConfig::default(),
        });
        config
            .policies
            .local_rate_limits
            .push(NamedLocalRateLimitPolicyConfig {
                name: String::from("payments-canary-rate"),
                spec: LocalRateLimitPolicyConfig {
                    scope: LocalLimitScopeConfig::RouteDestination {
                        route: String::from("api"),
                        upstream_cluster: String::from("payments-canary"),
                    },
                    key_kind: LocalLimitKeyKindConfig::Global,
                    requests_per_window: 25,
                    window_ms: 1_000,
                    max_tracked_keys: 64,
                },
            });
        config.policies.local_concurrency_limits.push(
            NamedLocalConcurrencyLimitPolicyConfig {
                name: String::from("payments-canary-concurrency"),
                spec: LocalConcurrencyLimitPolicyConfig {
                    scope: LocalLimitScopeConfig::RouteDestination {
                        route: String::from("api"),
                        upstream_cluster: String::from("payments-canary"),
                    },
                    key_kind: LocalLimitKeyKindConfig::Global,
                    max_concurrent: 8,
                    max_tracked_keys: 32,
                },
            },
        );

        let report = validate_workspace_config(&config);

        assert!(report.is_empty(), "{}", report.operator_summary());
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_traffic_mirror_policy_shapes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.policies.traffic_mirrors[0].spec.percentage = 0;
        config.policies.traffic_mirrors[0].spec.target_upstream_cluster = String::from("missing");

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.path == "policies.traffic_mirrors[0].spec.percentage"
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.traffic_mirrors[0].spec.target_upstream_cluster"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_traffic_mirror_bound_on_route(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].policies.traffic_mirror = Some(String::from("shadow-payments"));

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "routes[0].policies.traffic_mirror"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_traffic_mirror_targeting_same_destination(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].upstream_cluster = None;
        config.routes[0].destinations = vec![crate::RouteDestinationConfig {
            upstream_cluster: String::from("payments"),
            weight: 1,
            policies: PolicyBindingConfig {
                traffic_mirror: Some(String::from("loop-payments")),
                ..PolicyBindingConfig::default()
            },
        }];
        config.policies.traffic_mirrors.push(NamedTrafficMirrorPolicyConfig {
            name: String::from("loop-payments"),
            spec: TrafficMirrorPolicyConfig {
                percentage: 10,
                target_upstream_cluster: String::from("payments"),
            },
        });

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path == "routes[0].destinations[0].policies.traffic_mirror"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_fault_injection_policy_shapes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.policies.fault_injections[0].spec.delay = Some(FaultInjectionDelayConfig {
            percentage: 0,
            fixed_delay_ms: 0,
        });
        config.policies.fault_injections[0].spec.abort = Some(FaultInjectionAbortConfig {
            percentage: 0,
            http_status: 200,
        });

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.path == "policies.fault_injections[0].spec.delay.percentage"
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.fault_injections[0].spec.delay.fixed_delay_ms"
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.fault_injections[0].spec.abort.percentage"
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.fault_injections[0].spec.abort.http_status"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_fault_injection_bound_on_route(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].policies.fault_injection = Some(String::from("canary-chaos"));

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "routes[0].policies.fault_injection"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_route_destination_policy_bindings(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].upstream_cluster = None;
        config.routes[0].destinations = vec![crate::RouteDestinationConfig {
            upstream_cluster: String::from("payments"),
            weight: 1,
            policies: PolicyBindingConfig {
                local_rate_limits: vec![String::from("public-rate")],
                local_concurrency_limits: vec![String::from("api-concurrency")],
                overload_response: Some(String::from("public-overload")),
                cache_policy: Some(String::from("public-cache")),
                hostile_edge_protection: Some(String::from("edge-default")),
                ..PolicyBindingConfig::default()
            },
        }];
        config.policies.hostile_edge_protections.push(NamedHostileEdgeProtectionPolicyConfig {
            name: String::from("edge-default"),
            spec: HostileEdgeProtectionPolicyConfig {
                source_quota: Some(HostileEdgeSourceQuotaConfig::default()),
                handshake_guard: Some(HostileEdgeHandshakeGuardConfig::default()),
            },
        });

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.message.contains("local rate-limit policy public-rate scope listener public")
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.message.contains(
                    "local concurrency-limit policy api-concurrency scope route api"
                )
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "routes[0].destinations[0].policies.overload_response"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "routes[0].destinations[0].policies.cache_policy"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "routes[0].destinations[0].policies.hostile_edge_protection"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_route_hostname() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].match_rule = crate::RouteMatchConfig::PathPrefix {
            prefix: String::from("/api"),
            hostnames: vec![String::from("bad/host")],
            methods: Vec::new(),
            headers: Vec::new(),
            query_params: Vec::new(),
            content_types: Vec::new(),
            grpc_services: Vec::new(),
            grpc_methods: Vec::new(),
            source_cidrs: Vec::new(),
        };

        let report = validate_workspace_config(&config);

        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].code, ValidationCode::InvalidRouteMatch);
        assert_eq!(report.errors[0].path, "routes[0].match.hostnames[0]");
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_route_method() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].match_rule = crate::RouteMatchConfig::PathPrefix {
            prefix: String::from("/api"),
            hostnames: Vec::new(),
            methods: vec![String::from("bad token")],
            headers: Vec::new(),
            query_params: Vec::new(),
            content_types: Vec::new(),
            grpc_services: Vec::new(),
            grpc_methods: Vec::new(),
            source_cidrs: Vec::new(),
        };

        let report = validate_workspace_config(&config);

        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].code, ValidationCode::InvalidRouteMatch);
        assert_eq!(report.errors[0].path, "routes[0].match.methods[0]");
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_route_header_query_content_type_and_source(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].match_rule = crate::RouteMatchConfig::PathPrefix {
            prefix: String::from("/api"),
            hostnames: Vec::new(),
            methods: Vec::new(),
            headers: vec![crate::RouteHeaderMatchConfig::Exact {
                name: String::from("bad header"),
                value: String::from("beta"),
            }],
            query_params: vec![crate::RouteQueryMatchConfig::Present {
                name: String::from("a=b"),
            }],
            content_types: vec![String::from("broken")],
            grpc_services: vec![String::from("bad/service")],
            grpc_methods: vec![String::from("bad method")],
            source_cidrs: vec![String::from("not-a-cidr")],
        };

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| error.path == "routes[0].match.headers[0]"));
        assert!(report.errors.iter().any(|error| error.path == "routes[0].match.query_params[0]"));
        assert!(report.errors.iter().any(|error| error.path == "routes[0].match.content_types[0]"));
        assert!(report.errors.iter().any(|error| error.path == "routes[0].match.grpc_services[0]"));
        assert!(report.errors.iter().any(|error| error.path == "routes[0].match.grpc_methods[0]"));
        assert!(report.errors.iter().any(|error| error.path == "routes[0].match.source_cidrs[0]"));
        Ok(())
    }

    #[test]
    fn validator_rejects_grpc_matchers_without_grpc_content_type() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].match_rule = crate::RouteMatchConfig::PathPrefix {
            prefix: String::from("/"),
            hostnames: Vec::new(),
            methods: vec![String::from("POST")],
            headers: Vec::new(),
            query_params: Vec::new(),
            content_types: Vec::new(),
            grpc_services: vec![String::from("grpc.payments.v1.Payments")],
            grpc_methods: Vec::new(),
            source_cidrs: Vec::new(),
        };

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| error.path == "routes[0].match.content_types"));
        Ok(())
    }

    #[test]
    fn validator_rejects_grpc_matchers_with_non_post_methods() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].match_rule = crate::RouteMatchConfig::PathPrefix {
            prefix: String::from("/"),
            hostnames: Vec::new(),
            methods: vec![String::from("GET")],
            headers: Vec::new(),
            query_params: Vec::new(),
            content_types: vec![String::from("application/grpc")],
            grpc_services: Vec::new(),
            grpc_methods: vec![String::from("Capture")],
            source_cidrs: Vec::new(),
        };

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| error.path == "routes[0].match.methods"));
        Ok(())
    }

    #[test]
    fn validator_accepts_grpc_service_and_method_matchers() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].match_rule = crate::RouteMatchConfig::PathPrefix {
            prefix: String::from("/"),
            hostnames: Vec::new(),
            methods: vec![String::from("POST")],
            headers: Vec::new(),
            query_params: Vec::new(),
            content_types: vec![String::from("application/grpc")],
            grpc_services: vec![String::from("grpc.payments.v1.Payments")],
            grpc_methods: vec![String::from("Capture")],
            source_cidrs: Vec::new(),
        };

        let report = validate_workspace_config(&config);

        assert!(report.errors.is_empty());
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_anonymous_source_cidr() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.security.anonymous_source_filter.enabled = true;
        config.security.anonymous_source_filter.deny_tor = true;
        config.security.anonymous_source_filter.tor_exit_cidrs = vec![String::from("not-a-cidr")];

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidSecurityDefaults
                && error.path == "security.anonymous_source_filter.tor_exit_cidrs[0]"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_trusted_proxy_cidr() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.security.trusted_client_ip.enabled = true;
        config.security.trusted_client_ip.trusted_proxy_cidrs = vec![String::from("bad-cidr")];

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidSecurityDefaults
                && error.path == "security.trusted_client_ip.trusted_proxy_cidrs[0]"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_conflicting_policy_scope_and_tcp_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Tcp;
        config.listeners[0].policies.local_rate_limits.push(String::from("public-rate"));
        config.policies.local_rate_limits[0].spec.scope =
            LocalLimitScopeConfig::Route { name: String::from("api") };

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::UnsupportedListenerRouting
                && error.category == ValidationCategory::Semantic
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::DuplicatePolicyReference
                && error.category == ValidationCategory::Semantic
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.category == ValidationCategory::Semantic
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_policy_shapes_and_renders_stable_summary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.policies.retry_budgets[0].spec.window_ms = 0;
        config.policies.overload_responses[0].spec.shedding_signal_threshold = 0;
        config.policies.overload_responses[0].spec.brownout_features.push(
            crate::BrownoutFeatureConfig {
                name: String::from("expensive-search"),
                priority: crate::TrafficClassConfig::Default,
            },
        );

        let report = validate_workspace_config(&config);
        let summary = report.operator_summary();

        assert!(summary
            .contains("Schema InvalidPolicyField at policies.retry_budgets[0].spec.window_ms"));
        assert!(
            summary.contains("Schema InvalidPolicyField at policies.overload_responses[0].spec")
        );
        assert!(summary.contains(
            "Schema DuplicateResourceName at policies.overload_responses[0].spec.brownout_features[1].name"
        ));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_http_cache_policy_shapes() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = valid_workspace()?;
        config.policies.http_caches[0].spec.methods.clear();
        config.policies.http_caches[0].spec.default_ttl_secs = 0;
        config.policies.http_caches[0].spec.cacheable_status_codes = vec![99];
        config.policies.http_caches[0].spec.vary_headers = vec![String::from("cookie")];
        config.policies.http_caches[0].spec.cache_key = CacheKeyPolicyConfig {
            include_host: false,
            include_method: false,
            query: CacheQueryKeyBehaviorConfig::IgnoreAll,
            headers: vec![String::from("set-cookie")],
        };

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.path == "policies.http_caches[0].spec.methods"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.http_caches[0].spec"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.http_caches[0].spec.cacheable_status_codes"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.http_caches[0].spec.vary_headers[0]"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.http_caches[0].spec.cache_key.headers[0]"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_transform_policy_shapes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.policies.transforms[0].spec = TransformPolicyConfig::default();
        config.policies.transforms.push(NamedTransformPolicyConfig {
            name: String::from("broken-transform"),
            spec: TransformPolicyConfig {
                request: RequestTransformConfig {
                    path_rewrite: Some(PathRewriteTransformConfig::ReplacePrefix {
                        match_prefix: String::from("api"),
                        replacement: String::from("v1"),
                    }),
                    host_rewrite: Some(String::from("bad host")),
                    header_mutations: vec![HeaderMutationConfig::Set {
                        name: String::from("connection"),
                        value: String::from("close"),
                    }],
                },
                response: ResponseTransformConfig {
                    header_mutations: vec![HeaderMutationConfig::Set {
                        name: String::from("content-length"),
                        value: String::from("1"),
                    }],
                },
            },
        });
        config.routes[0].policies.transform_policy = Some(String::from("broken-transform"));

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.path == "policies.transforms[0].spec"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.transforms[1].spec.request.path_rewrite"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.transforms[1].spec.request.host_rewrite"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.transforms[1].spec.request.header_mutations[0]"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        assert!(report.errors.iter().any(|error| {
            error.path == "policies.transforms[1].spec.response.header_mutations[0]"
                && error.code == ValidationCode::InvalidPolicyField
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_transform_policy_bound_on_upstream_cluster(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.upstream_clusters[0].policies.transform_policy = Some(String::from("api-transform"));

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.path == "upstream_clusters[0].policies.transform_policy"
                && error.code == ValidationCode::InvalidPolicyScope
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_upgrade_policy_on_unsupported_listener_surfaces(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Http2;
        config.listeners[0].upgrade = UpgradePolicyConfig {
            protocols: vec![UpgradeProtocolConfig::Websocket, UpgradeProtocolConfig::Websocket],
        };
        config.routes[0].upgrade = UpgradePolicyConfig {
            protocols: vec![UpgradeProtocolConfig::Websocket],
        };

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidListenerField
                && error.path == "listeners[0].upgrade"
                && error.message
                    == "upgrade policy is supported only on public http1 or https listeners"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidListenerField
                && error.path == "listeners[0].routes[0]"
                && error.message.contains("cannot attach route api with upgrade policy")
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidListenerField
                && error.path == "listeners[0].upgrade.protocols[1]"
                && error.message.contains("must not repeat upgrade protocol websocket")
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_proxy_protocol_on_admin_listener(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners.push(ListenerResourceConfig {
            name: String::from("admin-proxy"),
            class: ListenerClassConfig::Admin,
            bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090),
            bind_mode: ListenerBindModeConfig::SingleStack,
            protocol: crate::ListenerProtocolConfig::Http1,
            proxy_protocol: crate::ProxyProtocolModeConfig::V1,
            tls_termination: None,
            allow_unspecified_bind: false,
            max_connections: None,
            backlog: None,
            idle_timeout_ms: None,
            drain_timeout_ms: None,
            routes: Vec::new(),
            policies: PolicyBindingConfig::default(),
            upgrade: UpgradePolicyConfig::default(),
            admin: AdminListenerPolicyConfig::default(),
        });

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidListenerField
                && error.path == "listeners[1].proxy_protocol"
                && error.message == "proxy protocol is supported only on public listeners"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_empty_hostile_edge_policy() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].policies.hostile_edge_protection = Some(String::from("edge-default"));
        config.policies.hostile_edge_protections.push(NamedHostileEdgeProtectionPolicyConfig {
            name: String::from("edge-default"),
            spec: HostileEdgeProtectionPolicyConfig::default(),
        });

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path == "policies.hostile_edge_protections[0].spec"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_hostile_edge_policy_bound_outside_listener(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].policies.hostile_edge_protection = Some(String::from("edge-default"));
        config.policies.hostile_edge_protections.push(NamedHostileEdgeProtectionPolicyConfig {
            name: String::from("edge-default"),
            spec: HostileEdgeProtectionPolicyConfig {
                source_quota: Some(HostileEdgeSourceQuotaConfig::default()),
                handshake_guard: Some(HostileEdgeHandshakeGuardConfig::default()),
            },
        });

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "routes[0].policies.hostile_edge_protection"
        }));
        Ok(())
    }

    #[test]
    fn validator_tracks_error_categories() -> Result<(), Box<dyn std::error::Error>> {
        let mut validator = WorkspaceConfigValidator::default();
        let mut config = valid_workspace()?;
        config.name = String::from(" ");
        config.routes[0].upstream_cluster = Some(String::from("missing"));

        let result = validator.validate(&config);

        assert!(result.is_err());
        assert_eq!(validator.stats().success_count, 0);
        assert_eq!(validator.stats().schema_error_count, 1);
        assert_eq!(validator.stats().semantic_error_count, 1);
        Ok(())
    }

    #[test]
    fn validator_rejects_https_without_tls_material() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Https;

        let report = validate_workspace_config(&config);

        assert!(report
            .to_string()
            .contains("https listeners must declare tls_termination certificate material"));
        Ok(())
    }

    #[test]
    fn validator_accepts_http3_listener_with_tls_and_h3_alpn(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Http3;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls13,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http3],
        });

        let report = validate_workspace_config(&config);

        assert!(report.errors.is_empty(), "{report}");
        Ok(())
    }

    #[test]
    fn validator_rejects_http3_without_tls_material() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Http3;

        let report = validate_workspace_config(&config);

        assert!(report
            .to_string()
            .contains("http3 listeners must declare tls_termination certificate material"));
        Ok(())
    }

    #[test]
    fn validator_rejects_tls_termination_on_non_https_listener(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http2],
        });

        let report = validate_workspace_config(&config);

        assert!(report
            .to_string()
            .contains("tls_termination is currently supported only for https and http3 listeners"));
        Ok(())
    }

    #[test]
    fn validator_rejects_http3_listener_without_h3_alpn(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Http3;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls13,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http2],
        });

        let report = validate_workspace_config(&config);

        assert!(report
            .to_string()
            .contains("http3 listeners must advertise only the http3 ALPN protocol"));
        Ok(())
    }

    #[test]
    fn validator_rejects_admin_http3_listener() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        let mut admin_listener =
            ListenerResourceConfig::foundation("admin", ListenerClassConfig::Admin, 9900);
        admin_listener.protocol = crate::ListenerProtocolConfig::Http3;
        admin_listener.tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/admin.pem"),
                key_path: String::from("certs/admin.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls13,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http3],
        });
        config.listeners.push(admin_listener);

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidListenerField
                && error.path == "listeners[1].protocol"
                && error.message == "http3 listeners are currently supported only on public listeners"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_https_listener_without_alpn_protocols(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Https;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: Vec::new(),
        });

        let report = validate_workspace_config(&config);

        assert!(report
            .to_string()
            .contains("https listeners must advertise at least one ALPN protocol"));
        Ok(())
    }

    #[test]
    fn validator_rejects_duplicate_https_alpn_protocols() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Https;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![
                crate::ListenerAlpnProtocolConfig::Http2,
                crate::ListenerAlpnProtocolConfig::Http2,
            ],
        });

        let report = validate_workspace_config(&config);

        assert!(report.to_string().contains("https listeners must not repeat ALPN protocol http2"));
        Ok(())
    }

    #[test]
    fn validator_rejects_https_sni_mapping_without_server_names(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Https;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: vec![crate::ListenerTlsSniCertificateConfig {
                server_names: Vec::new(),
                certificate_source: ListenerCertificateSourceConfig::Files {
                    cert_path: String::from("certs/tenant.pem"),
                    key_path: String::from("certs/tenant.key"),
                    ocsp_path: None,
                },
            }],
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http11],
        });

        let report = validate_workspace_config(&config);
        assert!(report
            .to_string()
            .contains("https SNI certificate mappings must declare at least one server name"));
        Ok(())
    }

    #[test]
    fn validator_rejects_duplicate_https_sni_server_names() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Https;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: vec![
                crate::ListenerTlsSniCertificateConfig {
                    server_names: vec![String::from("Tenant.Example")],
                    certificate_source: ListenerCertificateSourceConfig::Files {
                        cert_path: String::from("certs/tenant-a.pem"),
                        key_path: String::from("certs/tenant-a.key"),
                        ocsp_path: None,
                    },
                },
                crate::ListenerTlsSniCertificateConfig {
                    server_names: vec![String::from("tenant.example.")],
                    certificate_source: ListenerCertificateSourceConfig::Files {
                        cert_path: String::from("certs/tenant-b.pem"),
                        key_path: String::from("certs/tenant-b.key"),
                        ocsp_path: None,
                    },
                },
            ],
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http11],
        });

        let report = validate_workspace_config(&config);
        assert!(report
            .to_string()
            .contains("https listeners must not repeat SNI server name tenant.example"));
        Ok(())
    }

    #[test]
    fn validator_rejects_zero_stateful_session_cache_size() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Https;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig {
                mode: crate::ListenerTlsSessionResumptionModeConfig::Stateful,
                session_cache_size: 0,
                tls13_ticket_count: 0,
            },
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http11],
        });

        let report = validate_workspace_config(&config);
        assert!(report
            .to_string()
            .contains("https listeners using stateful session resumption must use a non-zero session_cache_size"));
        Ok(())
    }

    #[test]
    fn validator_rejects_zero_tls13_ticket_count_for_ticket_mode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Https;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig {
                mode: crate::ListenerTlsSessionResumptionModeConfig::Tickets,
                session_cache_size: 256,
                tls13_ticket_count: 0,
            },
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http11],
        });

        let report = validate_workspace_config(&config);
        assert!(report.to_string().contains(
            "https listeners issuing TLS tickets must use a non-zero tls13_ticket_count"
        ));
        Ok(())
    }

    #[test]
    fn validator_rejects_blank_ocsp_path() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].protocol = crate::ListenerProtocolConfig::Https;
        config.listeners[0].tls_termination = Some(ListenerTlsTerminationConfig {
            certificate_source: ListenerCertificateSourceConfig::Files {
                cert_path: String::from("certs/server.pem"),
                key_path: String::from("certs/server.key"),
                ocsp_path: Some(String::from("   ")),
            },
            sni_certificates: Vec::new(),
            session_resumption: crate::ListenerTlsSessionResumptionConfig::default(),
            minimum_version: crate::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![crate::ListenerAlpnProtocolConfig::Http11],
        });

        let report = validate_workspace_config(&config);
        assert!(report.to_string().contains(
            "https listeners must use a non-empty ocsp_path when OCSP stapling is configured"
        ));
        Ok(())
    }

    #[test]
    fn validator_rejects_remote_plaintext_admin_listener() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = valid_workspace()?;
        let mut admin_listener =
            ListenerResourceConfig::foundation("admin", ListenerClassConfig::Admin, 9900);
        admin_listener.bind_address = "192.0.2.10:9900".parse()?;
        admin_listener.protocol = crate::ListenerProtocolConfig::Http1;
        config.listeners.push(admin_listener);

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidListenerField
                && error.category == ValidationCategory::Semantic
                && error.path == "listeners[1].protocol"
                && error.message == "admin listeners exposed beyond loopback must use https"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_dual_stack_listener_on_ipv4_bind(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].bind_mode = ListenerBindModeConfig::DualStack;

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidListenerField
                && error.path == "listeners[0].bind_mode"
                && error.message == "dual_stack listeners must use an IPv6 bind_address"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_dual_stack_listener_without_ipv6_wildcard(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].bind_address = "[::1]:8080".parse()?;
        config.listeners[0].bind_mode = ListenerBindModeConfig::DualStack;

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidListenerField
                && error.path == "listeners[0].bind_address"
                && error.message
                    == "dual_stack listeners currently require the IPv6 wildcard bind address [::]:port"
        }));
        Ok(())
    }

    #[test]
    fn validator_accepts_ipv6_only_listener_bind_mode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.listeners[0].bind_address = "[::1]:8080".parse()?;
        config.listeners[0].bind_mode = ListenerBindModeConfig::Ipv6Only;

        let report = validate_workspace_config(&config);

        assert!(report.is_empty(), "{}", report.operator_summary());
        Ok(())
    }

    #[test]
    fn validator_rejects_unsigned_mode_without_explicit_insecure_gate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.security.artifact_verification.mode = crate::ArtifactVerificationMode::Disabled;

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InsecureModeGated
                && error.category == ValidationCategory::Semantic
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_duplicate_trusted_signers_after_identity_trim(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.security.artifact_verification.trusted_signers = vec![
            crate::TrustedArtifactSignerConfig::new(
                "control-plane",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            crate::TrustedArtifactSignerConfig::new(
                "  control-plane  ",
                "2222222222222222222222222222222222222222222222222222222222222222",
            ),
        ];

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidSecurityDefaults
                && error.path == "security.artifact_verification.trusted_signers"
                && error.message.contains("must not repeat identities")
        }));
        Ok(())
    }
}
