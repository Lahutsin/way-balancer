use serde::{Deserialize, Serialize};

/// Declarative JWT/OIDC verification policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct JwtAuthPolicyConfig {
    /// Allowed token issuers.
    pub issuers: Vec<String>,
    /// Allowed token audiences.
    pub audiences: Vec<String>,
    /// Source of the JSON Web Key Set used for signature verification.
    pub jwks: Option<JwtJwksSourceConfig>,
    /// Optional required claim keys that must be present.
    pub required_claims: Vec<String>,
    /// Accepted clock skew in seconds for exp/nbf/iat checks.
    pub clock_skew_secs: u64,
}

/// JWKS source for JWT verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum JwtJwksSourceConfig {
    /// Load JWKS from a local file path.
    File { path: String, refresh_secs: u64 },
    /// Load JWKS from a remote HTTPS endpoint.
    Remote { url: String, refresh_secs: u64 },
    /// Use an inline JWKS JSON document.
    Inline { jwks_json: String },
}

/// Declarative external authorization policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExternalAuthPolicyConfig {
    /// External auth service endpoint.
    pub endpoint: String,
    /// External auth protocol.
    pub protocol: ExternalAuthProtocolConfig,
    /// Timeout budget for auth service calls.
    pub timeout_ms: u64,
    /// If true, allow request when auth service is unavailable.
    pub fail_open: bool,
    /// Request headers forwarded to the auth service.
    pub include_headers: Vec<String>,
    /// Context mapping from auth response fields to request headers.
    pub context_mappings: Vec<AuthContextMappingConfig>,
}

impl Default for ExternalAuthPolicyConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            protocol: ExternalAuthProtocolConfig::Http,
            timeout_ms: 1_000,
            fail_open: false,
            include_headers: Vec::new(),
            context_mappings: Vec::new(),
        }
    }
}

/// External auth transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAuthProtocolConfig {
    #[default]
    Http,
    Grpc,
}

/// Response-context to header propagation mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AuthContextMappingConfig {
    /// External auth response field name.
    pub source: String,
    /// Downstream request header name to populate.
    pub target_header: String,
    /// If true, deny when source is absent.
    pub required: bool,
}

/// Declarative request authorization policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthorizationPolicyConfig {
    /// Ordered authorization rules.
    pub rules: Vec<AuthorizationRuleConfig>,
    /// Fallback decision when no rule matches.
    pub default_decision: AuthorizationDecisionConfig,
}

impl Default for AuthorizationPolicyConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_decision: AuthorizationDecisionConfig::Deny,
        }
    }
}

/// Authorization decision enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecisionConfig {
    Allow,
    #[default]
    Deny,
}

/// Declarative authorization rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AuthorizationRuleConfig {
    /// Stable rule name.
    pub name: String,
    /// Rule decision when matched.
    pub action: AuthorizationDecisionConfig,
    /// Any claim keys that make this rule eligible.
    pub any_claims: Vec<String>,
    /// Required OAuth scopes.
    pub required_scopes: Vec<String>,
    /// Required RBAC role claims.
    pub required_roles: Vec<String>,
}

/// Declarative upstream identity verification policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamIdentityPolicyConfig {
    /// Upstream identity mode.
    pub mode: UpstreamIdentityModeConfig,
    /// Trust bundle source used for peer identity verification.
    pub trust_bundle: IdentityTrustBundleSourceConfig,
    /// Allowed SPIFFE IDs.
    pub allowed_spiffe_ids: Vec<String>,
    /// Allowed trust domains.
    pub allowed_trust_domains: Vec<String>,
}

impl Default for UpstreamIdentityPolicyConfig {
    fn default() -> Self {
        Self {
            mode: UpstreamIdentityModeConfig::Spiffe,
            trust_bundle: IdentityTrustBundleSourceConfig::File {
                path: String::new(),
                refresh_secs: 60,
            },
            allowed_spiffe_ids: Vec::new(),
            allowed_trust_domains: Vec::new(),
        }
    }
}

/// Identity model used for upstream mTLS verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpstreamIdentityModeConfig {
    /// Verify SPIFFE URI SAN identity.
    Spiffe,
    /// Verify SPIRE-issued identities with workload API hints.
    SpireWorkloadApi { socket_path: String, trust_domain: String },
}

/// Trust bundle source used by identity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityTrustBundleSourceConfig {
    /// Load trust bundle PEM from file.
    File { path: String, refresh_secs: u64 },
    /// Load trust bundle PEM from inline config.
    InlinePem { pem: String },
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationDecisionConfig, AuthorizationPolicyConfig, AuthorizationRuleConfig,
        ExternalAuthPolicyConfig, ExternalAuthProtocolConfig, IdentityTrustBundleSourceConfig,
        JwtAuthPolicyConfig, JwtJwksSourceConfig, UpstreamIdentityModeConfig,
        UpstreamIdentityPolicyConfig,
    };

    #[test]
    fn l7_security_policy_models_are_constructible() {
        let jwt = JwtAuthPolicyConfig {
            issuers: vec![String::from("https://issuer.example")],
            audiences: vec![String::from("payments-api")],
            jwks: Some(JwtJwksSourceConfig::Remote {
                url: String::from("https://issuer.example/.well-known/jwks.json"),
                refresh_secs: 60,
            }),
            required_claims: vec![String::from("sub")],
            clock_skew_secs: 30,
        };

        let ext_auth = ExternalAuthPolicyConfig {
            endpoint: String::from("http://authz.local/check"),
            protocol: ExternalAuthProtocolConfig::Http,
            timeout_ms: 500,
            fail_open: false,
            include_headers: vec![String::from("authorization")],
            context_mappings: Vec::new(),
        };

        let authz = AuthorizationPolicyConfig {
            rules: vec![AuthorizationRuleConfig {
                name: String::from("payments-read"),
                action: AuthorizationDecisionConfig::Allow,
                any_claims: vec![String::from("sub")],
                required_scopes: vec![String::from("payments.read")],
                required_roles: vec![String::from("reader")],
            }],
            default_decision: AuthorizationDecisionConfig::Deny,
        };

        let identity = UpstreamIdentityPolicyConfig {
            mode: UpstreamIdentityModeConfig::SpireWorkloadApi {
                socket_path: String::from("/var/run/spire/sockets/agent.sock"),
                trust_domain: String::from("example.org"),
            },
            trust_bundle: IdentityTrustBundleSourceConfig::File {
                path: String::from("/etc/way-balancer/trust-bundle.pem"),
                refresh_secs: 60,
            },
            allowed_spiffe_ids: vec![String::from("spiffe://example.org/ns/payments/sa/default")],
            allowed_trust_domains: vec![String::from("example.org")],
        };

        assert_eq!(jwt.clock_skew_secs, 30);
        assert_eq!(ext_auth.timeout_ms, 500);
        assert_eq!(authz.rules.len(), 1);
        assert_eq!(identity.allowed_trust_domains.len(), 1);
    }
}
