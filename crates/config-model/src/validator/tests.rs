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
        NamedAuthorizationPolicyConfig, NamedExternalAuthPolicyConfig,
        NamedJwtAuthPolicyConfig, NamedUpstreamIdentityPolicyConfig,
        NamedRequestClassificationPolicyConfig,
        NamedTrafficMirrorPolicyConfig,
        NamedTransformPolicyConfig, OverloadResponsePolicyConfig, PathRewriteTransformConfig,
        PolicyBindingConfig, PolicyResourcesConfig, RequestTransformConfig, ResponseTransformConfig,
        AuthorizationPolicyConfig, ExternalAuthPolicyConfig, JwtAuthPolicyConfig,
        RequestClassificationContextConfig, RequestClassificationPolicyConfig,
        BodyInspectionScoringConfig, HeaderAnomalyScoringConfig,
        RequestClassificationSignalWeightsConfig, RequestClassifierSensitivityConfig,
        UpstreamIdentityPolicyConfig, JwtJwksSourceConfig, IdentityTrustBundleSourceConfig,
        RouteConfig, TrafficMirrorPolicyConfig, TransformPolicyConfig, UpgradePolicyConfig, UpgradeProtocolConfig,
        DiscoverySourceConfig,
        FaultInjectionPolicyConfig, FaultInjectionDelayConfig, FaultInjectionAbortConfig,
        UpstreamClusterConfig, UpstreamEndpointConfig, UpstreamTrafficPolicyConfig,
        UpstreamTransportConfig,
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
                transport: UpstreamTransportConfig::Http1,
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "payments-a",
                    payments_endpoint_addr,
                )],
                discovery: None,
                traffic_policy: UpstreamTrafficPolicyConfig::default(),
                policies: PolicyBindingConfig::default(),
            }, UpstreamClusterConfig {
                name: String::from("payments-shadow"),
                transport: UpstreamTransportConfig::Http1,
                endpoints: vec![UpstreamEndpointConfig::foundation(
                    "payments-shadow-a",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9002),
                )],
                discovery: None,
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
                        per_try_timeout_ms: None,
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
                        methods: Vec::new(),
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
                jwt_auth_policies: vec![NamedJwtAuthPolicyConfig {
                    name: String::from("jwt-default"),
                    spec: JwtAuthPolicyConfig {
                        issuers: vec![String::from("https://issuer.example")],
                        audiences: vec![String::from("edge-api")],
                        jwks: Some(JwtJwksSourceConfig::File {
                            path: String::from("/etc/way-balancer/jwks.json"),
                            refresh_secs: 60,
                        }),
                        required_claims: vec![String::from("sub")],
                        clock_skew_secs: 30,
                    },
                }],
                external_auth_policies: vec![NamedExternalAuthPolicyConfig {
                    name: String::from("ext-authz"),
                    spec: ExternalAuthPolicyConfig {
                        endpoint: String::from("http://authz.local/check"),
                        timeout_ms: 500,
                        ..ExternalAuthPolicyConfig::default()
                    },
                }],
                authorization_policies: vec![NamedAuthorizationPolicyConfig {
                    name: String::from("rbac-default"),
                    spec: AuthorizationPolicyConfig::default(),
                }],
                upstream_identity_policies: vec![NamedUpstreamIdentityPolicyConfig {
                    name: String::from("spiffe-default"),
                    spec: UpstreamIdentityPolicyConfig {
                        trust_bundle: IdentityTrustBundleSourceConfig::File {
                            path: String::from("/etc/way-balancer/trust-bundle.pem"),
                            refresh_secs: 60,
                        },
                        allowed_trust_domains: vec![String::from("example.org")],
                        ..UpstreamIdentityPolicyConfig::default()
                    },
                }],
                request_classification_policies: vec![NamedRequestClassificationPolicyConfig {
                    name: String::from("waf-baseline"),
                    spec: RequestClassificationPolicyConfig {
                        sensitivity: RequestClassifierSensitivityConfig::Medium,
                        challenge_threshold: 55,
                        block_threshold: 80,
                        signal_weights: RequestClassificationSignalWeightsConfig::default(),
                        context: RequestClassificationContextConfig::default(),
                        header_scoring: HeaderAnomalyScoringConfig::default(),
                        body_scoring: BodyInspectionScoringConfig::default(),
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
    fn validator_accepts_discovery_backed_upstream_without_static_endpoints(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.upstream_clusters[0].endpoints.clear();
        config.upstream_clusters[0].discovery = Some(DiscoverySourceConfig::DnsAaaa {
            hostname: String::from("payments.internal"),
            port: 8443,
            min_refresh_secs: 5,
        });

        let report = validate_workspace_config(&config);

        assert!(report.is_empty(), "{}", report.operator_summary());
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_discovery_shapes_and_mixed_endpoint_mode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.upstream_clusters[0].discovery = Some(DiscoverySourceConfig::KubernetesEndpointSlice {
            namespace: String::from(" "),
            service: String::new(),
        });

        let report = validate_workspace_config(&config);
        assert!(report.errors.iter().any(|error| error.path == "upstream_clusters[0].discovery"));
        assert!(report
            .errors
            .iter()
            .any(|error| error.path == "upstream_clusters[0].discovery.namespace"));
        assert!(report
            .errors
            .iter()
            .any(|error| error.path == "upstream_clusters[0].discovery.service"));

        config.upstream_clusters[0].endpoints.clear();
        config.upstream_clusters[0].discovery = None;
        let report = validate_workspace_config(&config);
        assert!(report.errors.iter().any(|error| error.path == "upstream_clusters[0].endpoints"));
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
            transport: UpstreamTransportConfig::Http1,
            endpoints: vec![UpstreamEndpointConfig::foundation(
                "payments-canary-a",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001),
            )],
            discovery: None,
            traffic_policy: UpstreamTrafficPolicyConfig::default(),
            policies: PolicyBindingConfig::default(),
        });

        let report = validate_workspace_config(&config);

        assert!(report.is_empty(), "{}", report.operator_summary());
        Ok(())
    }

    #[test]
    fn validator_accepts_http3_upstream_transport() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.upstream_clusters[0].transport = UpstreamTransportConfig::Http3;

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
            transport: UpstreamTransportConfig::Http1,
            endpoints: vec![UpstreamEndpointConfig::foundation(
                "payments-canary-a",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001),
            )],
            discovery: None,
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
                methods: Vec::new(),
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
    fn validator_rejects_invalid_l7_policy_scopes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.upstream_clusters[0].policies.jwt_auth_policy = Some(String::from("jwt-default"));
        config.listeners[0].policies.upstream_identity_policy =
            Some(String::from("spiffe-default"));

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "upstream_clusters[0].policies.jwt_auth_policy"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "listeners[0].policies.upstream_identity_policy"
        }));
        Ok(())
    }

    #[test]
    fn validator_rejects_invalid_l7_policy_shapes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.policies.jwt_auth_policies[0].spec.jwks = None;
        config.policies.external_auth_policies[0].spec.endpoint = String::new();
        config.policies.upstream_identity_policies[0]
            .spec
            .allowed_trust_domains
            .clear();
        config.policies.upstream_identity_policies[0]
            .spec
            .allowed_spiffe_ids
            .clear();

        let report = validate_workspace_config(&config);

        assert!(report
            .errors
            .iter()
            .any(|error| error.path == "policies.jwt_auth_policies[0].spec.jwks"));
        assert!(report
            .errors
            .iter()
            .any(|error| error.path == "policies.external_auth_policies[0].spec.endpoint"));
        assert!(report
            .errors
            .iter()
            .any(|error| error.path == "policies.upstream_identity_policies[0].spec"));
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
        config.policies.timeout_hierarchies[0].spec.per_try_timeout_ms = Some(40_000);
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
        assert!(summary.contains("Schema InvalidPolicyField at policies.timeout_hierarchies[0].spec"));
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
    fn validator_rejects_invalid_request_classification_policy_and_scope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = valid_workspace()?;
        config.policies.request_classification_policies.push(
            NamedRequestClassificationPolicyConfig {
                name: String::from("waf-invalid"),
                spec: RequestClassificationPolicyConfig {
                    challenge_threshold: 90,
                    block_threshold: 60,
                    signal_weights: RequestClassificationSignalWeightsConfig {
                        header_anomaly: 0,
                        body_anomaly: 0,
                        query_anomaly: 0,
                        user_agent_anomaly: 0,
                        reputation: 0,
                        bot_signal: 0,
                    },
                    context: RequestClassificationContextConfig {
                        include_headers: vec![String::from("bad header")],
                        include_query_params: vec![String::from(" ")],
                        ..RequestClassificationContextConfig::default()
                    },
                    header_scoring: crate::HeaderAnomalyScoringConfig {
                        max_header_count: 0,
                        max_header_value_length: 0,
                        max_duplicate_headers_per_name: 0,
                        suspicious_headers: vec![String::from("bad header")],
                        suspicious_user_agent_patterns: vec![String::from(" ")],
                    },
                    body_scoring: crate::BodyInspectionScoringConfig {
                        max_inspect_bytes: 0,
                        max_body_bytes: 0,
                        min_suspicious_token_length: 0,
                        suspicious_patterns: vec![String::from(" ")],
                        allowlisted_content_types: vec![String::from(" ")],
                    },
                    ..RequestClassificationPolicyConfig::default()
                },
            },
        );
        config.upstream_clusters[0].policies.request_classification_policy =
            Some(String::from("waf-invalid"));

        let report = validate_workspace_config(&config);

        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path == "policies.request_classification_policies[1].spec"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path == "policies.request_classification_policies[1].spec.signal_weights"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.context.include_headers[0]"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.context.include_query_params[0]"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.header_scoring.max_header_count"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.header_scoring.max_header_value_length"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.header_scoring.max_duplicate_headers_per_name"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.header_scoring.suspicious_headers[0]"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.header_scoring.suspicious_user_agent_patterns[0]"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.body_scoring.max_inspect_bytes"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.body_scoring.max_body_bytes"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.body_scoring.min_suspicious_token_length"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.body_scoring.suspicious_patterns[0]"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyField
                && error.path
                    == "policies.request_classification_policies[1].spec.body_scoring.allowlisted_content_types[0]"
        }));
        assert!(report.errors.iter().any(|error| {
            error.code == ValidationCode::InvalidPolicyScope
                && error.path == "upstream_clusters[0].policies.request_classification_policy"
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
