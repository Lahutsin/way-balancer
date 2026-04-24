
/// Runtime configuration for a bounded HTTP/1.1 proxy session.
#[derive(Debug, Clone)]
pub struct Http1ProxyConfig {
    /// Static upstream target used for request forwarding.
    pub upstream: lb_net_core::UpstreamTarget,
    /// Connection timeout model reused from the shared network primitives.
    pub timeouts: lb_net_core::ConnectionTimeouts,
    /// HTTP/1.1 parser and relay limits.
    pub limits: lb_proto_http::Http1Limits,
    /// Placeholder route rules for future routing extensions.
    pub routes: Vec<lb_proto_http::RoutePrefixRule>,
    /// Optional route-to-upstream pools keyed by route label.
    pub route_upstreams: BTreeMap<String, Vec<lb_net_core::UpstreamTarget>>,
    /// Optional health-aware route backend pools keyed by route label.
    pub route_backend_pools: BTreeMap<String, crate::RouteBackendPool>,
    /// Optional health-aware backend pools keyed by upstream cluster for shadow dispatch.
    pub mirror_backend_pools: BTreeMap<String, crate::RouteBackendPool>,
    /// Deterministic round-robin cursors for route upstream pools.
    route_upstream_cursors: Arc<Mutex<BTreeMap<String, usize>>>,
    /// Whether requests with no matching route should be rejected locally.
    pub reject_unmatched_routes: bool,
    pub anonymous_source_filter: Option<Arc<AnonymousSourceFilterState>>,
    /// Optional progressive ban guard for route and query enumeration by source.
    pub route_enumeration_protection: Option<Arc<RouteEnumerationProtectionState>>,
    /// Optional trusted-proxy model used to determine the effective client IP.
    pub trusted_client_ip: Option<TrustedClientIpPolicy>,
    /// Optional response-cache runtime for GET/HEAD traffic.
    pub response_cache: Option<Http1ResponseCacheConfig>,
    /// Optional listener-wide request transform applied before upstream dispatch.
    pub listener_request_transform: Option<lb_config_model::RequestTransformConfig>,
    /// Optional route-specific request transforms keyed by route label.
    pub route_request_transforms: BTreeMap<String, lb_config_model::RequestTransformConfig>,
    /// Optional listener-wide response transform applied before downstream write.
    pub listener_response_transform: Option<lb_config_model::ResponseTransformConfig>,
    /// Optional route-specific response transforms keyed by route label.
    pub route_response_transforms: BTreeMap<String, lb_config_model::ResponseTransformConfig>,
    /// Optional destination-specific policy runtime keyed by route label then upstream cluster.
    pub route_destination_policies:
        BTreeMap<String, BTreeMap<String, RouteDestinationPolicyRuntime>>,
    /// Optional destination-specific JWT auth policy keyed by route label then upstream cluster.
    pub route_destination_jwt_auth_policies:
        BTreeMap<String, BTreeMap<String, crate::JwtAuthPolicyRuntime>>,
    /// Optional destination-specific external auth policy keyed by route label then upstream cluster.
    pub route_destination_external_auth_policies:
        BTreeMap<String, BTreeMap<String, crate::ExternalAuthPolicyRuntime>>,
    /// Optional destination-specific authorization policy keyed by route label then upstream cluster.
    pub route_destination_authorization_policies:
        BTreeMap<String, BTreeMap<String, crate::AuthorizationPolicyRuntime>>,
    /// Optional destination-specific upstream identity policy keyed by route label then upstream cluster.
    pub route_destination_upstream_identity_policies:
        BTreeMap<String, BTreeMap<String, crate::UpstreamIdentityPolicyRuntime>>,
    /// Effective backend-policy diagnostics keyed by route label.
    pub route_backend_policy_diagnostics:
        BTreeMap<String, Vec<crate::EffectiveRouteDestinationPolicy>>,
    /// Listener-wide upgrade allow-list.
    pub listener_upgrade_protocols: Vec<lb_config_model::UpgradeProtocolConfig>,
    /// Route-specific upgrade allow-lists keyed by route label.
    pub route_upgrade_protocols:
        BTreeMap<String, Vec<lb_config_model::UpgradeProtocolConfig>>,
    /// Optional upgrade telemetry handle and scope.
    pub upgrade_telemetry: Option<HttpUpgradeTelemetryConfig>,
    /// Optional request-flow telemetry handle and scope.
    pub request_telemetry: Option<HttpRequestTelemetryConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1RouteUpstream {
    pub route_label: String,
    pub upstream: lb_net_core::UpstreamTarget,
}

/// Response cache runtime configuration for HTTP/1 proxying.
#[derive(Debug, Clone)]
pub struct Http1ResponseCacheConfig {
    /// Typed cache policy controlling lookup and fill behavior.
    pub policy: lb_config_model::HttpCachePolicyConfig,
    /// Shared bounded store used by the proxy.
    pub store: Arc<HttpCacheStore>,
    /// Optional cache telemetry handle and scope.
    pub telemetry: Option<HttpCacheTelemetryConfig>,
}

#[derive(Debug, Clone)]
pub struct HttpCacheTelemetryConfig {
    pub scope: String,
    pub telemetry: Arc<RuntimeTelemetry>,
}

#[derive(Debug, Clone)]
pub struct HttpUpgradeTelemetryConfig {
    pub scope: String,
    pub telemetry: Arc<RuntimeTelemetry>,
}

#[derive(Debug, Clone)]
pub struct HttpRequestTelemetryConfig {
    pub scope: String,
    pub telemetry: Arc<RuntimeTelemetry>,
}

#[derive(Debug, Clone, Default)]
pub struct RouteDestinationPolicyRuntime {
    pub request_transform: Option<lb_config_model::RequestTransformConfig>,
    pub response_transform: Option<lb_config_model::ResponseTransformConfig>,
    pub traffic_mirror: Option<lb_config_model::TrafficMirrorPolicyConfig>,
    pub fault_injection: Option<lb_config_model::FaultInjectionPolicyConfig>,
    pub rate_limiters: Vec<Arc<crate::LocalRateLimiter>>,
    pub concurrency_limiters: Vec<Arc<crate::LocalConcurrencyLimiter>>,
    pub failure_manager: Option<Arc<crate::FailureManager>>,
    pub enforce_retry_budget: bool,
    pub enforce_timeout_hierarchy: bool,
    pub enforce_circuit_breaker: bool,
}

impl Http1ResponseCacheConfig {
    /// Creates a reusable HTTP/1 response-cache runtime.
    #[must_use]
    pub fn new(policy: lb_config_model::HttpCachePolicyConfig, store: Arc<HttpCacheStore>) -> Self {
        Self { policy, store, telemetry: None }
    }

    #[must_use]
    pub fn with_telemetry(
        mut self,
        scope: impl Into<String>,
        telemetry: Arc<RuntimeTelemetry>,
    ) -> Self {
        self.telemetry = Some(HttpCacheTelemetryConfig { scope: scope.into(), telemetry });
        self
    }
}

impl Http1ProxyConfig {
    /// Creates a baseline HTTP/1.1 config for a static upstream.
    #[must_use]
    pub fn new(upstream: lb_net_core::UpstreamTarget) -> Self {
        Self {
            upstream,
            timeouts: lb_net_core::ConnectionTimeouts::default(),
            limits: lb_proto_http::Http1Limits::default(),
            routes: Vec::new(),
            route_upstreams: BTreeMap::new(),
            route_backend_pools: BTreeMap::new(),
            mirror_backend_pools: BTreeMap::new(),
            route_upstream_cursors: Arc::new(Mutex::new(BTreeMap::new())),
            reject_unmatched_routes: false,
            anonymous_source_filter: None,
            route_enumeration_protection: None,
            trusted_client_ip: None,
            response_cache: None,
            listener_request_transform: None,
            route_request_transforms: BTreeMap::new(),
            listener_response_transform: None,
            route_response_transforms: BTreeMap::new(),
            route_destination_policies: BTreeMap::new(),
            route_destination_jwt_auth_policies: BTreeMap::new(),
            route_destination_external_auth_policies: BTreeMap::new(),
            route_destination_authorization_policies: BTreeMap::new(),
            route_destination_upstream_identity_policies: BTreeMap::new(),
            route_backend_policy_diagnostics: BTreeMap::new(),
            listener_upgrade_protocols: Vec::new(),
            route_upgrade_protocols: BTreeMap::new(),
            upgrade_telemetry: None,
            request_telemetry: None,
        }
    }

    #[must_use]
    pub fn with_route_upstreams(
        mut self,
        route_upstreams: impl IntoIterator<Item = Http1RouteUpstream>,
    ) -> Self {
        self.route_upstreams.clear();
        for route_upstream in route_upstreams {
            self.route_upstreams
                .entry(route_upstream.route_label)
                .or_default()
                .push(route_upstream.upstream);
        }
        self
    }

    #[must_use]
    pub fn with_route_backend_pools(
        mut self,
        route_backend_pools: impl IntoIterator<Item = (String, crate::RouteBackendPool)>,
    ) -> Self {
        self.route_backend_pools = route_backend_pools.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_mirror_backend_pools(
        mut self,
        mirror_backend_pools: impl IntoIterator<Item = (String, crate::RouteBackendPool)>,
    ) -> Self {
        self.mirror_backend_pools = mirror_backend_pools.into_iter().collect();
        self
    }

    #[must_use]
    pub fn rejecting_unmatched_routes(mut self) -> Self {
        self.reject_unmatched_routes = true;
        self
    }

    #[must_use]
    pub fn with_anonymous_source_filter(mut self, policy: AnonymousSourceFilterPolicy) -> Self {
        self.anonymous_source_filter = Some(Arc::new(AnonymousSourceFilterState::new(policy)));
        self
    }

    #[must_use]
    pub fn with_route_enumeration_protection(
        mut self,
        policy: RouteEnumerationProtectionPolicy,
    ) -> Self {
        self.route_enumeration_protection =
            Some(Arc::new(RouteEnumerationProtectionState::new(policy)));
        self
    }

    #[must_use]
    pub fn with_trusted_client_ip(mut self, policy: TrustedClientIpPolicy) -> Self {
        self.trusted_client_ip = Some(policy);
        self
    }

    /// Attaches an HTTP response-cache runtime to the proxy.
    #[must_use]
    pub fn with_response_cache(mut self, response_cache: Http1ResponseCacheConfig) -> Self {
        self.response_cache = Some(response_cache);
        self
    }

    #[must_use]
    pub fn with_request_transforms(
        mut self,
        listener_request_transform: Option<lb_config_model::RequestTransformConfig>,
        route_request_transforms: impl IntoIterator<
            Item = (String, lb_config_model::RequestTransformConfig),
        >,
    ) -> Self {
        self.listener_request_transform = listener_request_transform;
        self.route_request_transforms = route_request_transforms.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_response_transforms(
        mut self,
        listener_response_transform: Option<lb_config_model::ResponseTransformConfig>,
        route_response_transforms: impl IntoIterator<
            Item = (String, lb_config_model::ResponseTransformConfig),
        >,
    ) -> Self {
        self.listener_response_transform = listener_response_transform;
        self.route_response_transforms = route_response_transforms.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_route_backend_policy_diagnostics(
        mut self,
        diagnostics: impl IntoIterator<Item = (String, Vec<crate::EffectiveRouteDestinationPolicy>)>,
    ) -> Self {
        self.route_backend_policy_diagnostics = diagnostics.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_route_destination_policies(
        mut self,
        policies: impl IntoIterator<Item = (String, BTreeMap<String, RouteDestinationPolicyRuntime>)>,
    ) -> Self {
        self.route_destination_policies = policies.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_route_destination_jwt_auth_policies(
        mut self,
        policies: impl IntoIterator<
            Item = (String, BTreeMap<String, crate::JwtAuthPolicyRuntime>),
        >,
    ) -> Self {
        self.route_destination_jwt_auth_policies = policies.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_route_destination_external_auth_policies(
        mut self,
        policies: impl IntoIterator<
            Item = (String, BTreeMap<String, crate::ExternalAuthPolicyRuntime>),
        >,
    ) -> Self {
        self.route_destination_external_auth_policies = policies.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_route_destination_authorization_policies(
        mut self,
        policies: impl IntoIterator<
            Item = (String, BTreeMap<String, crate::AuthorizationPolicyRuntime>),
        >,
    ) -> Self {
        self.route_destination_authorization_policies = policies.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_route_destination_upstream_identity_policies(
        mut self,
        policies: impl IntoIterator<
            Item = (String, BTreeMap<String, crate::UpstreamIdentityPolicyRuntime>),
        >,
    ) -> Self {
        self.route_destination_upstream_identity_policies = policies.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_upgrade_policies(
        mut self,
        listener_upgrade_protocols: impl IntoIterator<Item = lb_config_model::UpgradeProtocolConfig>,
        route_upgrade_protocols: impl IntoIterator<
            Item = (String, Vec<lb_config_model::UpgradeProtocolConfig>),
        >,
    ) -> Self {
        self.listener_upgrade_protocols = listener_upgrade_protocols.into_iter().collect();
        self.route_upgrade_protocols = route_upgrade_protocols.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_upgrade_telemetry(
        mut self,
        scope: impl Into<String>,
        telemetry: Arc<RuntimeTelemetry>,
    ) -> Self {
        self.upgrade_telemetry = Some(HttpUpgradeTelemetryConfig {
            scope: scope.into(),
            telemetry,
        });
        self
    }

    #[must_use]
    pub fn with_request_telemetry(
        mut self,
        scope: impl Into<String>,
        telemetry: Arc<RuntimeTelemetry>,
    ) -> Self {
        self.request_telemetry = Some(HttpRequestTelemetryConfig {
            scope: scope.into(),
            telemetry,
        });
        self
    }
}
