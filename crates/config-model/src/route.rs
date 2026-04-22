use std::collections::BTreeSet;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{PolicyBindingConfig, UpgradePolicyConfig, WorkspaceConfigError};

/// Declarative route-header matcher.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteHeaderMatchConfig {
    Exact { name: String, value: String },
    Present { name: String },
    Absent { name: String },
}

/// Declarative route-query matcher.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteQueryMatchConfig {
    Exact { name: String, value: String },
    Present { name: String },
    Absent { name: String },
}

fn default_route_destination_weight() -> u16 {
    1
}

fn is_default_route_destination_weight(weight: &u16) -> bool {
    *weight == default_route_destination_weight()
}

/// Declarative route destination.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDestinationConfig {
    /// Referenced upstream cluster name.
    pub upstream_cluster: String,
    /// Relative traffic weight for this destination.
    #[serde(
        default = "default_route_destination_weight",
        skip_serializing_if = "is_default_route_destination_weight"
    )]
    pub weight: u16,
    /// Attached destination-local policy references.
    #[serde(default, skip_serializing_if = "PolicyBindingConfig::is_default")]
    pub policies: PolicyBindingConfig,
}

/// Declarative route resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Stable route name.
    pub name: String,
    /// Match rule for this route.
    #[serde(rename = "match")]
    pub match_rule: RouteMatchConfig,
    /// Legacy single upstream-cluster shorthand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_cluster: Option<String>,
    /// Canonical destination list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<RouteDestinationConfig>,
    /// Attached named policy references.
    #[serde(default)]
    pub policies: PolicyBindingConfig,
    /// Explicit route-scoped HTTP upgrade allow-list.
    #[serde(default, skip_serializing_if = "UpgradePolicyConfig::is_default")]
    pub upgrade: UpgradePolicyConfig,
}

impl RouteConfig {
    /// Creates a minimal path-prefix route.
    #[must_use]
    pub fn foundation_path_prefix(
        name: impl Into<String>,
        prefix: impl Into<String>,
        upstream_cluster: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            match_rule: RouteMatchConfig::PathPrefix {
                prefix: prefix.into(),
                hostnames: Vec::new(),
                methods: Vec::new(),
                headers: Vec::new(),
                query_params: Vec::new(),
                content_types: Vec::new(),
                grpc_services: Vec::new(),
                grpc_methods: Vec::new(),
                source_cidrs: Vec::new(),
            },
            upstream_cluster: Some(upstream_cluster.into()),
            destinations: Vec::new(),
            policies: PolicyBindingConfig::default(),
            upgrade: UpgradePolicyConfig::default(),
        }
    }

    #[must_use]
    pub fn normalized_destinations(&self) -> Vec<RouteDestinationConfig> {
        let mut destinations = if self.destinations.is_empty() {
            self.upstream_cluster
                .as_ref()
                .map(|upstream_cluster| {
                    vec![RouteDestinationConfig {
                        upstream_cluster: upstream_cluster.clone(),
                        weight: default_route_destination_weight(),
                        policies: PolicyBindingConfig::default(),
                    }]
                })
                .unwrap_or_default()
        } else {
            self.destinations.clone()
        };
        destinations.sort();
        destinations
    }

    fn compile_rule(&self) -> Result<lb_proto_http::RoutePrefixRule, WorkspaceConfigError> {
        match &self.match_rule {
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
                if self.name.trim().is_empty() {
                    return Err(WorkspaceConfigError::EmptyRouteName);
                }
                if prefix.trim().is_empty() {
                    return Err(WorkspaceConfigError::EmptyRoutePrefix(self.name.clone()));
                }

                let mut normalized_hostnames = BTreeSet::new();
                for hostname in hostnames {
                    let normalized = lb_proto_http::canonicalize_host(hostname).map_err(|_| {
                        WorkspaceConfigError::InvalidRouteHostname(self.name.clone())
                    })?;
                    normalized_hostnames.insert(normalized);
                }

                let mut normalized_methods = BTreeSet::new();
                for method in methods {
                    let normalized = lb_proto_http::normalize_http_method(method).ok_or_else(|| {
                        WorkspaceConfigError::InvalidRouteMethod(self.name.clone())
                    })?;
                    normalized_methods.insert(normalized);
                }

                let mut normalized_header_matches = BTreeSet::new();
                for header_match in headers {
                    let normalized = match header_match {
                        RouteHeaderMatchConfig::Exact { name, value } => {
                            lb_proto_http::RouteHeaderMatch::Exact {
                                name: lb_proto_http::normalize_http_header_name(name).ok_or_else(|| {
                                    WorkspaceConfigError::InvalidRouteHeader(self.name.clone())
                                })?,
                                value: value.trim().to_string(),
                            }
                        }
                        RouteHeaderMatchConfig::Present { name } => {
                            lb_proto_http::RouteHeaderMatch::Present {
                                name: lb_proto_http::normalize_http_header_name(name).ok_or_else(|| {
                                    WorkspaceConfigError::InvalidRouteHeader(self.name.clone())
                                })?,
                            }
                        }
                        RouteHeaderMatchConfig::Absent { name } => {
                            lb_proto_http::RouteHeaderMatch::Absent {
                                name: lb_proto_http::normalize_http_header_name(name).ok_or_else(|| {
                                    WorkspaceConfigError::InvalidRouteHeader(self.name.clone())
                                })?,
                            }
                        }
                    };
                    normalized_header_matches.insert(normalized);
                }

                let mut normalized_query_matches = BTreeSet::new();
                for query_match in query_params {
                    let normalized = match query_match {
                        RouteQueryMatchConfig::Exact { name, value } => {
                            lb_proto_http::RouteQueryMatch::Exact {
                                name: lb_proto_http::canonicalize_query_match_name(name).map_err(|_| {
                                    WorkspaceConfigError::InvalidRouteQuery(self.name.clone())
                                })?,
                                value: lb_proto_http::canonicalize_query_match_value(value).map_err(|_| {
                                    WorkspaceConfigError::InvalidRouteQuery(self.name.clone())
                                })?,
                            }
                        }
                        RouteQueryMatchConfig::Present { name } => {
                            lb_proto_http::RouteQueryMatch::Present {
                                name: lb_proto_http::canonicalize_query_match_name(name).map_err(|_| {
                                    WorkspaceConfigError::InvalidRouteQuery(self.name.clone())
                                })?,
                            }
                        }
                        RouteQueryMatchConfig::Absent { name } => {
                            lb_proto_http::RouteQueryMatch::Absent {
                                name: lb_proto_http::canonicalize_query_match_name(name).map_err(|_| {
                                    WorkspaceConfigError::InvalidRouteQuery(self.name.clone())
                                })?,
                            }
                        }
                    };
                    normalized_query_matches.insert(normalized);
                }

                let mut normalized_content_types = BTreeSet::new();
                for content_type in content_types {
                    let normalized = lb_proto_http::normalize_content_type_match(content_type)
                        .ok_or_else(|| WorkspaceConfigError::InvalidRouteContentType(self.name.clone()))?;
                    normalized_content_types.insert(normalized);
                }

                let mut normalized_grpc_services = BTreeSet::new();
                for grpc_service in grpc_services {
                    let normalized = lb_proto_http::normalize_grpc_service_match(grpc_service)
                        .ok_or_else(|| WorkspaceConfigError::InvalidRouteGrpcService(self.name.clone()))?;
                    normalized_grpc_services.insert(normalized);
                }

                let mut normalized_grpc_methods = BTreeSet::new();
                for grpc_method in grpc_methods {
                    let normalized = lb_proto_http::normalize_grpc_method_match(grpc_method)
                        .ok_or_else(|| WorkspaceConfigError::InvalidRouteGrpcMethod(self.name.clone()))?;
                    normalized_grpc_methods.insert(normalized);
                }

                let mut normalized_source_cidrs = BTreeSet::new();
                for source_cidr in source_cidrs {
                    let parsed: IpNet = source_cidr
                        .parse()
                        .map_err(|_| WorkspaceConfigError::InvalidRouteSourceCidr(self.name.clone()))?;
                    normalized_source_cidrs.insert(parsed);
                }

                Ok(lb_proto_http::RoutePrefixRule::new(self.name.clone(), prefix.clone())
                    .with_hostnames(normalized_hostnames.into_iter().collect())
                    .with_methods(normalized_methods.into_iter().collect())
                    .with_header_matches(normalized_header_matches.into_iter().collect())
                    .with_query_matches(normalized_query_matches.into_iter().collect())
                    .with_content_types(normalized_content_types.into_iter().collect())
                    .with_grpc_services(normalized_grpc_services.into_iter().collect())
                    .with_grpc_methods(normalized_grpc_methods.into_iter().collect())
                    .with_source_cidrs(normalized_source_cidrs.into_iter().collect()))
            }
        }
    }
}

/// Declarative route matching model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteMatchConfig {
    /// Match requests by path prefix.
    PathPrefix {
        /// Matched path prefix.
        prefix: String,
        /// Optional hostnames matched against the normalized Host/:authority value.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        hostnames: Vec<String>,
        /// Optional HTTP methods matched against the normalized request method.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        methods: Vec<String>,
        /// Optional request-header matchers.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        headers: Vec<RouteHeaderMatchConfig>,
        /// Optional query-parameter matchers.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        query_params: Vec<RouteQueryMatchConfig>,
        /// Optional content types matched against the request content type.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        content_types: Vec<String>,
        /// Optional gRPC service matchers derived from `/<package>.<Service>/<Method>` paths.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        grpc_services: Vec<String>,
        /// Optional gRPC method matchers derived from `/<package>.<Service>/<Method>` paths.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        grpc_methods: Vec<String>,
        /// Optional effective client source CIDRs.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        source_cidrs: Vec<String>,
    },
}

pub(crate) fn compile_route_rules(
    routes: &[RouteConfig],
) -> Result<Vec<lb_proto_http::RoutePrefixRule>, WorkspaceConfigError> {
    let mut seen = BTreeSet::new();
    let mut compiled = Vec::with_capacity(routes.len());

    for route in routes {
        if !seen.insert(route.name.clone()) {
            return Err(WorkspaceConfigError::DuplicateRouteName(route.name.clone()));
        }
        compiled.push(route.compile_rule()?);
    }

    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::{
        compile_route_rules, RouteConfig, RouteDestinationConfig, RouteHeaderMatchConfig,
        RouteQueryMatchConfig,
    };
    use crate::{UpgradePolicyConfig, WorkspaceConfigError};

    #[test]
    fn compile_routes_rejects_duplicate_names() {
        let routes = vec![
            RouteConfig::foundation_path_prefix("api", "/api", "payments"),
            RouteConfig::foundation_path_prefix("api", "/grpc", "payments"),
        ];

        let result = compile_route_rules(&routes);

        assert_eq!(result, Err(WorkspaceConfigError::DuplicateRouteName(String::from("api"))));
    }

    #[test]
    fn compile_routes_rejects_empty_prefix() {
        let routes = vec![RouteConfig::foundation_path_prefix("api", "   ", "payments")];

        let result = compile_route_rules(&routes);

        assert_eq!(result, Err(WorkspaceConfigError::EmptyRoutePrefix(String::from("api"))));
    }

    #[test]
    fn compile_routes_normalizes_hostnames() -> Result<(), Box<dyn std::error::Error>> {
        let routes = vec![RouteConfig {
            name: String::from("api"),
            match_rule: crate::RouteMatchConfig::PathPrefix {
                prefix: String::from("/api"),
                hostnames: vec![String::from("Example.COM."), String::from("example.com")],
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
            policies: crate::PolicyBindingConfig::default(),
            upgrade: UpgradePolicyConfig::default(),
        }];

        let compiled = compile_route_rules(&routes)?;

        assert_eq!(compiled[0].hostnames, vec![String::from("example.com")]);
        Ok(())
    }

    #[test]
    fn compile_routes_normalizes_methods() -> Result<(), Box<dyn std::error::Error>> {
        let routes = vec![RouteConfig {
            name: String::from("writes"),
            match_rule: crate::RouteMatchConfig::PathPrefix {
                prefix: String::from("/api"),
                hostnames: Vec::new(),
                methods: vec![String::from("post"), String::from("POST")],
                headers: Vec::new(),
                query_params: Vec::new(),
                content_types: Vec::new(),
                grpc_services: Vec::new(),
                grpc_methods: Vec::new(),
                source_cidrs: Vec::new(),
            },
            upstream_cluster: Some(String::from("payments")),
            destinations: Vec::new(),
            policies: crate::PolicyBindingConfig::default(),
            upgrade: UpgradePolicyConfig::default(),
        }];

        let compiled = compile_route_rules(&routes)?;

        assert_eq!(compiled[0].methods, vec![String::from("POST")]);
        Ok(())
    }

    #[test]
    fn compile_routes_normalizes_header_query_content_type_and_source_matchers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let routes = vec![RouteConfig {
            name: String::from("api"),
            match_rule: crate::RouteMatchConfig::PathPrefix {
                prefix: String::from("/api"),
                hostnames: Vec::new(),
                methods: Vec::new(),
                headers: vec![RouteHeaderMatchConfig::Exact {
                    name: String::from("X-Tenant"),
                    value: String::from("beta"),
                }],
                query_params: vec![RouteQueryMatchConfig::Exact {
                    name: String::from("auth"),
                    value: String::from("user%2Falpha"),
                }],
                content_types: vec![String::from("Application/JSON; charset=utf-8")],
                grpc_services: Vec::new(),
                grpc_methods: Vec::new(),
                source_cidrs: vec![String::from("198.51.100.0/24")],
            },
            upstream_cluster: Some(String::from("payments")),
            destinations: Vec::new(),
            policies: crate::PolicyBindingConfig::default(),
            upgrade: UpgradePolicyConfig::default(),
        }];

        let compiled = compile_route_rules(&routes)?;

        assert_eq!(compiled[0].header_matches.len(), 1);
        assert_eq!(compiled[0].query_matches.len(), 1);
        assert_eq!(compiled[0].content_types, vec![String::from("application/json")]);
        assert_eq!(compiled[0].source_cidrs.len(), 1);
        Ok(())
    }

    #[test]
    fn compile_routes_normalizes_grpc_matchers() -> Result<(), Box<dyn std::error::Error>> {
        let routes = vec![RouteConfig {
            name: String::from("grpc"),
            match_rule: crate::RouteMatchConfig::PathPrefix {
                prefix: String::from("/"),
                hostnames: Vec::new(),
                methods: vec![String::from("post")],
                headers: Vec::new(),
                query_params: Vec::new(),
                content_types: vec![String::from("application/grpc")],
                grpc_services: vec![String::from("grpc.payments.v1.Payments")],
                grpc_methods: vec![String::from("Capture")],
                source_cidrs: Vec::new(),
            },
            upstream_cluster: Some(String::from("payments")),
            destinations: Vec::new(),
            policies: crate::PolicyBindingConfig::default(),
            upgrade: UpgradePolicyConfig::default(),
        }];

        let compiled = compile_route_rules(&routes)?;

        assert_eq!(compiled[0].grpc_services, vec![String::from("grpc.payments.v1.Payments")]);
        assert_eq!(compiled[0].grpc_methods, vec![String::from("Capture")]);
        Ok(())
    }

    #[test]
    fn normalized_destinations_use_legacy_shorthand_when_needed() {
        let route = RouteConfig::foundation_path_prefix("api", "/api", "payments");

        assert_eq!(
            route.normalized_destinations(),
            vec![RouteDestinationConfig {
                upstream_cluster: String::from("payments"),
                weight: 1,
                policies: crate::PolicyBindingConfig::default(),
            }]
        );
    }

    #[test]
    fn normalized_destinations_prefer_explicit_destinations() {
        let route = RouteConfig {
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
            upstream_cluster: Some(String::from("legacy")),
            destinations: vec![
                RouteDestinationConfig {
                    upstream_cluster: String::from("payments-canary"),
                    weight: 10,
                    policies: crate::PolicyBindingConfig::default(),
                },
                RouteDestinationConfig {
                    upstream_cluster: String::from("payments-stable"),
                    weight: 90,
                    policies: crate::PolicyBindingConfig::default(),
                },
            ],
            policies: crate::PolicyBindingConfig::default(),
            upgrade: UpgradePolicyConfig::default(),
        };

        assert_eq!(
            route.normalized_destinations(),
            vec![
                RouteDestinationConfig {
                    upstream_cluster: String::from("payments-canary"),
                    weight: 10,
                    policies: crate::PolicyBindingConfig::default(),
                },
                RouteDestinationConfig {
                    upstream_cluster: String::from("payments-stable"),
                    weight: 90,
                    policies: crate::PolicyBindingConfig::default(),
                },
            ]
        );
    }
}
