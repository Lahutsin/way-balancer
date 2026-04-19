use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AdminAuthPolicyConfig, AdminAuthorizationScopeConfig, AffinityPolicyConfig,
    AnonymousSourceFilterConfig, ArtifactVerificationMode, CacheKeyPolicyConfig,
    HostileEdgeProtectionPolicyConfig, HttpCachePolicyConfig, HttpCacheStorageConfig,
    ListenerAlpnProtocolConfig, ListenerClassConfig, ListenerProtocolConfig,
    LocalConcurrencyLimitPolicyConfig, LocalLimitScopeConfig, LocalRateLimitPolicyConfig,
    NamedOverloadResponsePolicyConfig, OverloadResponsePolicyConfig, PolicyBindingConfig,
    PolicyResourcesConfig, RouteConfig, RouteMatchConfig, TrustedClientIpConfig, WorkspaceConfig,
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
    let upstream_names = collect_named_resources(
        config.upstream_clusters.iter().enumerate().map(|(index, cluster)| {
            (cluster.name.clone(), format!("upstream_clusters[{index}].name"), "upstream cluster")
        }),
        &mut report,
    );

    let policy_registry = PolicyRegistry::new(&config.policies, &mut report);

    for (index, listener) in config.listeners.iter().enumerate() {
        validate_listener(listener, index, &route_names, &policy_registry, &mut report);
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

    if matches!(listener.protocol, ListenerProtocolConfig::Tcp) && !listener.routes.is_empty() {
        report.errors.push(ValidationError::semantic(
            ValidationCode::UnsupportedListenerRouting,
            format!("{base_path}.routes"),
            "tcp listeners cannot attach HTTP route references",
        ));
    }

    match (&listener.protocol, &listener.tls_termination) {
        (ListenerProtocolConfig::Https, None) => {
            report.errors.push(ValidationError::schema(
                ValidationCode::InvalidListenerField,
                format!("{base_path}.tls_termination"),
                "https listeners must declare tls_termination certificate material",
            ));
        }
        (ListenerProtocolConfig::Https, Some(tls_termination)) => {
            if tls_termination.certificate_source.cert_path().trim().is_empty()
                || tls_termination.certificate_source.key_path().trim().is_empty()
            {
                report.errors.push(ValidationError::schema(
                    ValidationCode::InvalidListenerField,
                    format!("{base_path}.tls_termination.certificate_source"),
                    "https listeners must use non-empty cert_path and key_path values",
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
                    "https listeners must use a non-empty ocsp_path when OCSP stapling is configured",
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
                                        "https listeners must not repeat SNI server name {normalized}"
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
                            "https listeners using stateful session resumption must use a non-zero session_cache_size",
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
                            "https listeners issuing TLS tickets must use a non-zero tls13_ticket_count",
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
                    "https listeners must advertise at least one ALPN protocol",
                ));
            }

            let mut seen_alpn = BTreeSet::new();
            for (alpn_index, alpn_protocol) in tls_termination.alpn_protocols.iter().enumerate() {
                if !seen_alpn.insert(*alpn_protocol) {
                    let protocol_name = match alpn_protocol {
                        ListenerAlpnProtocolConfig::Http2 => "http2",
                        ListenerAlpnProtocolConfig::Http11 => "http11",
                    };
                    report.errors.push(ValidationError::schema(
                        ValidationCode::InvalidListenerField,
                        format!("{base_path}.tls_termination.alpn_protocols[{alpn_index}]"),
                        format!("https listeners must not repeat ALPN protocol {protocol_name}"),
                    ));
                }
            }
        }
        (_, Some(_)) => {
            report.errors.push(ValidationError::semantic(
                ValidationCode::InvalidListenerField,
                format!("{base_path}.tls_termination"),
                "tls_termination is currently supported only for https listeners",
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

    match &route.match_rule {
        RouteMatchConfig::PathPrefix { prefix, hostnames } => {
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
        }
    }

    let upstream_name = route.upstream_cluster.trim();
    if upstream_name.is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidUpstreamReference,
            format!("{base_path}.upstream_cluster"),
            format!("route {} must reference a non-empty upstream cluster name", route.name),
        ));
    } else if !upstream_names.contains(upstream_name) {
        report.errors.push(ValidationError::semantic(
            ValidationCode::InvalidUpstreamReference,
            format!("{base_path}.upstream_cluster"),
            format!("route {} references unknown upstream cluster {upstream_name}", route.name),
        ));
    }

    validate_policy_binding(
        &route.policies,
        &format!("{base_path}.policies"),
        PolicyBindingTarget::Route(&route.name),
        policy_registry,
        report,
    );
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
    if binding.hostile_edge_protection.is_some() && !matches!(target, PolicyBindingTarget::Listener(_)) {
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
    rate_limit_scopes: BTreeMap<String, LocalLimitScopeConfig>,
    concurrency_limit_scopes: BTreeMap<String, LocalLimitScopeConfig>,
}

impl PolicyRegistry {
    fn new(resources: &PolicyResourcesConfig, report: &mut ValidationReport) -> Self {
        let mut registry = Self {
            local_rate_limits: BTreeSet::new(),
            local_concurrency_limits: BTreeSet::new(),
            hostile_edge_protections: BTreeSet::new(),
            retry_budgets: BTreeSet::new(),
            timeout_hierarchies: BTreeSet::new(),
            circuit_breakers: BTreeSet::new(),
            overload_responses: BTreeSet::new(),
            http_caches: BTreeSet::new(),
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

        registry
    }
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
    let name = match scope {
        LocalLimitScopeConfig::Listener { name }
        | LocalLimitScopeConfig::Route { name }
        | LocalLimitScopeConfig::UpstreamCluster { name } => name,
    };
    if name.trim().is_empty() {
        report.errors.push(ValidationError::schema(
            ValidationCode::InvalidPolicyField,
            path,
            "local limit scope name must not be empty",
        ));
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
    UpstreamCluster(&'a str),
}

impl PolicyBindingTarget<'_> {
    fn kind_name(self) -> &'static str {
        match self {
            Self::Listener(_) => "listener",
            Self::Route(_) => "route",
            Self::UpstreamCluster(_) => "upstream cluster",
        }
    }

    fn resource_name(&self) -> &str {
        match self {
            Self::Listener(name) | Self::Route(name) | Self::UpstreamCluster(name) => name,
        }
    }

    fn path_for_policy(self, policy_name: &str) -> String {
        format!("{} {} policy binding {}", self.kind_name(), self.resource_name(), policy_name)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{
        validate_workspace_config, ValidationCategory, ValidationCode, WorkspaceConfigValidator,
    };
    use crate::{
        AdminListenerPolicyConfig, AffinityFallbackConfig, AffinityPolicyConfig,
        AuthorizationCacheBehaviorConfig, CacheKeyPolicyConfig, CacheQueryKeyBehaviorConfig,
        HostileEdgeHandshakeGuardConfig, HostileEdgeProtectionPolicyConfig,
        HostileEdgeSourceQuotaConfig, HttpCacheMethodConfig, HttpCachePolicyConfig,
        HttpCacheStorageConfig, ListenerCertificateSourceConfig, ListenerClassConfig,
        ListenerResourceConfig, ListenerTlsTerminationConfig,
        LocalConcurrencyLimitPolicyConfig, LocalLimitKeyKindConfig, LocalLimitScopeConfig,
        LocalRateLimitPolicyConfig, NamedHostileEdgeProtectionPolicyConfig,
        NamedHttpCachePolicyConfig, NamedLocalConcurrencyLimitPolicyConfig,
        NamedLocalRateLimitPolicyConfig, NamedOverloadResponsePolicyConfig,
        NamedRetryBudgetPolicyConfig, OverloadResponsePolicyConfig, PolicyBindingConfig,
        PolicyResourcesConfig, RouteConfig, UpstreamClusterConfig, UpstreamEndpointConfig,
        UpstreamTrafficPolicyConfig, WorkspaceConfig,
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
                protocol: crate::ListenerProtocolConfig::Http1,
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
                admin: AdminListenerPolicyConfig::default(),
            }],
            routes: vec![RouteConfig {
                name: String::from("api"),
                match_rule: crate::RouteMatchConfig::PathPrefix {
                    prefix: String::from("/api"),
                    hostnames: Vec::new(),
                },
                upstream_cluster: String::from("payments"),
                policies: PolicyBindingConfig {
                    local_concurrency_limits: vec![String::from("api-concurrency")],
                    ..PolicyBindingConfig::default()
                },
            }],
            upstream_clusters: vec![UpstreamClusterConfig {
                name: String::from("payments"),
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "payments-a",
                    payments_endpoint_addr,
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
        config.routes[0].upstream_cluster = String::from("missing-cluster");
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
    fn validator_rejects_invalid_route_hostname() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.routes[0].match_rule = crate::RouteMatchConfig::PathPrefix {
            prefix: String::from("/api"),
            hostnames: vec![String::from("bad/host")],
        };

        let report = validate_workspace_config(&config);

        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].code, ValidationCode::InvalidRouteMatch);
        assert_eq!(report.errors[0].path, "routes[0].match.hostnames[0]");
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
        config.routes[0].upstream_cluster = String::from("missing");

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
            .contains("tls_termination is currently supported only for https listeners"));
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
