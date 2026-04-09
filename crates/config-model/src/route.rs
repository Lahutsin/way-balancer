use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{PolicyBindingConfig, WorkspaceConfigError};

/// Declarative route resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Stable route name.
    pub name: String,
    /// Match rule for this route.
    #[serde(rename = "match")]
    pub match_rule: RouteMatchConfig,
    /// Referenced upstream cluster name.
    pub upstream_cluster: String,
    /// Attached named policy references.
    #[serde(default)]
    pub policies: PolicyBindingConfig,
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
            match_rule: RouteMatchConfig::PathPrefix { prefix: prefix.into() },
            upstream_cluster: upstream_cluster.into(),
            policies: PolicyBindingConfig::default(),
        }
    }

    fn compile_rule(&self) -> Result<lb_proto_http::RoutePrefixRule, WorkspaceConfigError> {
        match &self.match_rule {
            RouteMatchConfig::PathPrefix { prefix } => {
                if self.name.trim().is_empty() {
                    return Err(WorkspaceConfigError::EmptyRouteName);
                }
                if prefix.trim().is_empty() {
                    return Err(WorkspaceConfigError::EmptyRoutePrefix(self.name.clone()));
                }
                Ok(lb_proto_http::RoutePrefixRule::new(self.name.clone(), prefix.clone()))
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
    use super::{compile_route_rules, RouteConfig};
    use crate::WorkspaceConfigError;

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
}
