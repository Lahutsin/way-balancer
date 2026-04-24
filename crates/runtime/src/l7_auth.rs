use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use http::Uri;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

#[derive(Clone)]
pub struct JwtAuthPolicyRuntime {
    issuers: Vec<String>,
    audiences: Vec<String>,
    required_claims: Vec<String>,
    clock_skew_secs: u64,
    key_source: JwtKeySource,
}

#[derive(Clone)]
struct JwtDecodingKey {
    kid: Option<String>,
    key: DecodingKey,
}

#[derive(Clone)]
enum JwtKeySource {
    Inline(Vec<JwtDecodingKey>),
    File {
        path: String,
        refresh_secs: u64,
        cache: Arc<RwLock<JwtFileKeyCache>>,
    },
}

#[derive(Clone)]
struct JwtFileKeyCache {
    keys: Vec<JwtDecodingKey>,
    loaded_at: SystemTime,
}

impl std::fmt::Debug for JwtAuthPolicyRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JwtAuthPolicyRuntime")
            .field("issuers", &self.issuers)
            .field("audiences", &self.audiences)
            .field("required_claims", &self.required_claims)
            .field("clock_skew_secs", &self.clock_skew_secs)
            .field("key_count", &self.active_keys().map_or(0, |keys| keys.len()))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtAuthVerificationError {
    MissingAuthorizationHeader,
    InvalidAuthorizationHeader,
    UnsupportedJwksSource,
    InvalidJwks,
    InvalidToken,
    MissingRequiredClaim(String),
}

#[derive(Debug, Clone)]
pub struct ExternalAuthPolicyRuntime {
    endpoint: ExternalAuthEndpoint,
    timeout_ms: u64,
    fail_open: bool,
    include_headers: Vec<String>,
    context_mappings: Vec<lb_config_model::AuthContextMappingConfig>,
}

#[derive(Debug, Clone)]
struct ExternalAuthEndpoint {
    authority: String,
    path_and_query: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuthVerificationError {
    UnsupportedProtocol,
    InvalidEndpoint,
    ServiceUnavailable,
    InvalidResponse,
    Denied,
    MissingMappedContext(String),
}

#[derive(Debug, Clone)]
pub struct AuthorizationPolicyRuntime {
    rules: Vec<AuthorizationRuleRuntime>,
    default_decision: lb_config_model::AuthorizationDecisionConfig,
}

#[derive(Debug, Clone)]
struct AuthorizationRuleRuntime {
    action: lb_config_model::AuthorizationDecisionConfig,
    any_claims: Vec<String>,
    required_scopes: Vec<String>,
    required_roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationVerificationError {
    Denied,
}

#[derive(Debug, Clone)]
pub struct UpstreamIdentityPolicyRuntime {
    mode: lb_config_model::UpstreamIdentityModeConfig,
    allowed_spiffe_ids: Vec<String>,
    allowed_trust_domains: Vec<String>,
    trust_bundle_source: UpstreamTrustBundleSource,
}

#[derive(Debug, Clone)]
enum UpstreamTrustBundleSource {
    Inline,
    File {
        path: String,
        refresh_secs: u64,
        last_validated_at: Arc<RwLock<SystemTime>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamIdentityVerificationError {
    InvalidTrustBundle,
    MissingPeerIdentity,
    InvalidPeerIdentity,
    IdentityNotAllowed,
    TrustDomainNotAllowed,
}

#[derive(Debug, Clone)]
pub struct ExternalAuthCheckResult {
    pub allowed: bool,
    pub context: BTreeMap<String, String>,
    pub fail_open_applied: bool,
}

impl std::fmt::Display for JwtAuthVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAuthorizationHeader => {
                write!(formatter, "missing bearer authorization header")
            }
            Self::InvalidAuthorizationHeader => {
                write!(formatter, "authorization header must use Bearer <token>")
            }
            Self::UnsupportedJwksSource => {
                write!(formatter, "remote JWKS source is not supported in local verifier")
            }
            Self::InvalidJwks => write!(formatter, "invalid JWKS content"),
            Self::InvalidToken => write!(formatter, "token verification failed"),
            Self::MissingRequiredClaim(claim) => {
                write!(formatter, "missing required claim {claim}")
            }
        }
    }
}

impl std::error::Error for JwtAuthVerificationError {}

impl std::fmt::Display for ExternalAuthVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProtocol => write!(formatter, "external auth protocol is not supported"),
            Self::InvalidEndpoint => write!(formatter, "external auth endpoint is invalid"),
            Self::ServiceUnavailable => write!(formatter, "external auth service unavailable"),
            Self::InvalidResponse => write!(formatter, "external auth service returned invalid response"),
            Self::Denied => write!(formatter, "external auth service denied request"),
            Self::MissingMappedContext(key) => {
                write!(formatter, "external auth context is missing required key {key}")
            }
        }
    }
}

impl std::error::Error for ExternalAuthVerificationError {}

impl std::fmt::Display for AuthorizationVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied => write!(formatter, "request authorization denied"),
        }
    }
}

impl std::error::Error for AuthorizationVerificationError {}

impl std::fmt::Display for UpstreamIdentityVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTrustBundle => write!(formatter, "upstream identity trust bundle is invalid"),
            Self::MissingPeerIdentity => write!(formatter, "upstream peer identity is missing"),
            Self::InvalidPeerIdentity => write!(formatter, "upstream peer identity is invalid"),
            Self::IdentityNotAllowed => write!(formatter, "upstream peer identity is not allowed"),
            Self::TrustDomainNotAllowed => {
                write!(formatter, "upstream peer trust domain is not allowed")
            }
        }
    }
}

impl std::error::Error for UpstreamIdentityVerificationError {}

impl JwtAuthPolicyRuntime {
    pub fn from_config(
        config: &lb_config_model::JwtAuthPolicyConfig,
    ) -> Result<Self, JwtAuthVerificationError> {
        let key_source = match config.jwks.as_ref() {
            Some(lb_config_model::JwtJwksSourceConfig::Inline { jwks_json }) => {
                JwtKeySource::Inline(load_jwt_decoding_keys(jwks_json)?)
            }
            Some(lb_config_model::JwtJwksSourceConfig::File { path, refresh_secs }) => {
                let jwks_json =
                    std::fs::read_to_string(path).map_err(|_| JwtAuthVerificationError::InvalidJwks)?;
                let keys = load_jwt_decoding_keys(&jwks_json)?;
                JwtKeySource::File {
                    path: path.clone(),
                    refresh_secs: *refresh_secs,
                    cache: Arc::new(RwLock::new(JwtFileKeyCache {
                        keys,
                        loaded_at: SystemTime::now(),
                    })),
                }
            }
            Some(lb_config_model::JwtJwksSourceConfig::Remote { .. }) => {
                return Err(JwtAuthVerificationError::UnsupportedJwksSource);
            }
            None => return Err(JwtAuthVerificationError::InvalidJwks),
        };

        Ok(Self {
            issuers: config.issuers.clone(),
            audiences: config.audiences.clone(),
            required_claims: config.required_claims.clone(),
            clock_skew_secs: config.clock_skew_secs,
            key_source,
        })
    }

    pub fn verify_bearer(&self, authorization_header: &str) -> Result<(), JwtAuthVerificationError> {
        let token = parse_bearer_token(authorization_header)?;
        self.verify_token(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<(), JwtAuthVerificationError> {
        let header = decode_header(token).map_err(|_| JwtAuthVerificationError::InvalidToken)?;
        let algorithm = header.alg;
        let keys = self.active_keys()?;
        let mut candidate_keys = keys
            .iter()
            .filter(|entry| entry.kid.as_deref() == header.kid.as_deref())
            .collect::<Vec<_>>();
        if candidate_keys.is_empty() {
            candidate_keys = keys.iter().collect();
        }

        for entry in candidate_keys {
            let mut validation = Validation::new(algorithm);
            validation.leeway = self.clock_skew_secs;
            validation.validate_exp = true;
            validation.set_issuer(&self.issuers);
            validation.set_audience(&self.audiences);
            if let Ok(payload) = decode::<Value>(token, &entry.key, &validation) {
                return validate_required_claims(payload.claims, &self.required_claims);
            }
        }

        Err(JwtAuthVerificationError::InvalidToken)
    }

    fn active_keys(&self) -> Result<Vec<JwtDecodingKey>, JwtAuthVerificationError> {
        match &self.key_source {
            JwtKeySource::Inline(keys) => Ok(keys.clone()),
            JwtKeySource::File {
                path,
                refresh_secs,
                cache,
            } => {
                {
                    let guard = cache
                        .read()
                        .map_err(|_| JwtAuthVerificationError::InvalidJwks)?;
                    let refresh_due = jwks_refresh_due(guard.loaded_at, *refresh_secs)?;
                    if !refresh_due {
                        return Ok(guard.keys.clone());
                    }
                }

                let jwks_json =
                    std::fs::read_to_string(path).map_err(|_| JwtAuthVerificationError::InvalidJwks)?;
                let keys = load_jwt_decoding_keys(&jwks_json)?;
                {
                    let mut guard = cache
                        .write()
                        .map_err(|_| JwtAuthVerificationError::InvalidJwks)?;
                    guard.keys = keys.clone();
                    guard.loaded_at = SystemTime::now();
                }
                Ok(keys)
            }
        }
    }
}

impl ExternalAuthPolicyRuntime {
    pub fn from_config(
        config: &lb_config_model::ExternalAuthPolicyConfig,
    ) -> Result<Self, ExternalAuthVerificationError> {
        if !matches!(config.protocol, lb_config_model::ExternalAuthProtocolConfig::Http) {
            return Err(ExternalAuthVerificationError::UnsupportedProtocol);
        }

        let endpoint = parse_external_auth_endpoint(&config.endpoint)?;
        Ok(Self {
            endpoint,
            timeout_ms: config.timeout_ms,
            fail_open: config.fail_open,
            include_headers: config.include_headers.clone(),
            context_mappings: config.context_mappings.clone(),
        })
    }

    pub async fn authorize_http_request(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &BTreeMap<String, String>,
    ) -> Result<ExternalAuthCheckResult, ExternalAuthVerificationError> {
        let payload = serde_json::json!({
            "method": method,
            "path": path_and_query,
            "headers": headers,
        });
        let payload = serde_json::to_vec(&payload)
            .map_err(|_| ExternalAuthVerificationError::InvalidResponse)?;

        let timeout = std::time::Duration::from_millis(self.timeout_ms.max(1));
        let raw = time::timeout(timeout, async {
            send_http_json(
                &self.endpoint.authority,
                &self.endpoint.path_and_query,
                &payload,
            )
            .await
        })
        .await
        .map_err(|_| ExternalAuthVerificationError::ServiceUnavailable)
        .and_then(|result| result)?;

        let service_result = parse_external_auth_response(&raw)?;
        if !service_result.allowed {
            return Ok(ExternalAuthCheckResult {
                allowed: false,
                context: BTreeMap::new(),
                fail_open_applied: false,
            });
        }

        Ok(ExternalAuthCheckResult {
            allowed: true,
            context: service_result.context,
            fail_open_applied: false,
        })
    }

    pub async fn authorize_http_request_with_fail_open(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &BTreeMap<String, String>,
    ) -> Result<ExternalAuthCheckResult, ExternalAuthVerificationError> {
        match self.authorize_http_request(method, path_and_query, headers).await {
            Ok(result) => Ok(result),
            Err(error) if self.fail_open && matches!(
                error,
                ExternalAuthVerificationError::ServiceUnavailable
                    | ExternalAuthVerificationError::InvalidResponse
            ) => Ok(ExternalAuthCheckResult {
                allowed: true,
                context: BTreeMap::new(),
                fail_open_applied: true,
            }),
            Err(error) => Err(error),
        }
    }

    pub fn include_headers(&self) -> &[String] {
        &self.include_headers
    }

    pub fn context_mappings(&self) -> &[lb_config_model::AuthContextMappingConfig] {
        &self.context_mappings
    }
}

impl AuthorizationPolicyRuntime {
    pub fn from_config(config: &lb_config_model::AuthorizationPolicyConfig) -> Self {
        Self {
            rules: config
                .rules
                .iter()
                .map(|rule| AuthorizationRuleRuntime {
                    action: rule.action,
                    any_claims: rule
                        .any_claims
                        .iter()
                        .map(|claim| claim.trim().to_ascii_lowercase())
                        .collect(),
                    required_scopes: rule
                        .required_scopes
                        .iter()
                        .map(|scope| scope.trim().to_ascii_lowercase())
                        .collect(),
                    required_roles: rule
                        .required_roles
                        .iter()
                        .map(|role| role.trim().to_ascii_lowercase())
                        .collect(),
                })
                .collect(),
            default_decision: config.default_decision,
        }
    }

    pub fn authorize_headers(
        &self,
        headers: &BTreeMap<String, String>,
    ) -> Result<(), AuthorizationVerificationError> {
        let normalized = headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
            .collect::<BTreeMap<_, _>>();

        for rule in &self.rules {
            if !rule_matches(&normalized, rule) {
                continue;
            }
            return match rule.action {
                lb_config_model::AuthorizationDecisionConfig::Allow => Ok(()),
                lb_config_model::AuthorizationDecisionConfig::Deny => {
                    Err(AuthorizationVerificationError::Denied)
                }
            };
        }

        match self.default_decision {
            lb_config_model::AuthorizationDecisionConfig::Allow => Ok(()),
            lb_config_model::AuthorizationDecisionConfig::Deny => {
                Err(AuthorizationVerificationError::Denied)
            }
        }
    }
}

impl UpstreamIdentityPolicyRuntime {
    pub fn from_config(
        config: &lb_config_model::UpstreamIdentityPolicyConfig,
    ) -> Result<Self, UpstreamIdentityVerificationError> {
        let trust_bundle_source = match &config.trust_bundle {
            lb_config_model::IdentityTrustBundleSourceConfig::File { path, refresh_secs } => {
                let trust_bundle_pem = std::fs::read_to_string(path)
                    .map_err(|_| UpstreamIdentityVerificationError::InvalidTrustBundle)?;
                validate_trust_bundle_pem(&trust_bundle_pem)?;
                UpstreamTrustBundleSource::File {
                    path: path.clone(),
                    refresh_secs: *refresh_secs,
                    last_validated_at: Arc::new(RwLock::new(SystemTime::now())),
                }
            }
            lb_config_model::IdentityTrustBundleSourceConfig::InlinePem { pem } => {
                validate_trust_bundle_pem(pem)?;
                UpstreamTrustBundleSource::Inline
            }
        };

        Ok(Self {
            mode: config.mode.clone(),
            allowed_spiffe_ids: config.allowed_spiffe_ids.clone(),
            allowed_trust_domains: config.allowed_trust_domains.clone(),
            trust_bundle_source,
        })
    }

    pub fn verify_peer_identity(
        &self,
        presented_peer_identity: Option<&str>,
    ) -> Result<(), UpstreamIdentityVerificationError> {
        self.refresh_trust_bundle_if_needed()?;

        let Some(identity) = presented_peer_identity else {
            return Err(UpstreamIdentityVerificationError::MissingPeerIdentity);
        };
        if !identity.starts_with("spiffe://") {
            return Err(UpstreamIdentityVerificationError::InvalidPeerIdentity);
        }
        let Some(without_prefix) = identity.strip_prefix("spiffe://") else {
            return Err(UpstreamIdentityVerificationError::InvalidPeerIdentity);
        };
        let peer_trust_domain = without_prefix
            .split('/')
            .next()
            .filter(|value| !value.trim().is_empty())
            .ok_or(UpstreamIdentityVerificationError::InvalidPeerIdentity)?;

        match &self.mode {
            lb_config_model::UpstreamIdentityModeConfig::Spiffe => {}
            lb_config_model::UpstreamIdentityModeConfig::SpireWorkloadApi { trust_domain, .. } => {
                if !peer_trust_domain.eq_ignore_ascii_case(trust_domain) {
                    return Err(UpstreamIdentityVerificationError::TrustDomainNotAllowed);
                }
            }
        }
        if !self.allowed_spiffe_ids.is_empty()
            && !self
                .allowed_spiffe_ids
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(identity))
        {
            return Err(UpstreamIdentityVerificationError::IdentityNotAllowed);
        }
        if !self.allowed_trust_domains.is_empty()
            && !self
                .allowed_trust_domains
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(peer_trust_domain))
        {
            return Err(UpstreamIdentityVerificationError::TrustDomainNotAllowed);
        }

        Ok(())
    }

    fn refresh_trust_bundle_if_needed(&self) -> Result<(), UpstreamIdentityVerificationError> {
        let UpstreamTrustBundleSource::File {
            path,
            refresh_secs,
            last_validated_at,
        } = &self.trust_bundle_source
        else {
            return Ok(());
        };

        {
            let guard = last_validated_at
                .read()
                .map_err(|_| UpstreamIdentityVerificationError::InvalidTrustBundle)?;
            let refresh_due = trust_bundle_refresh_due(*guard, *refresh_secs)?;
            if !refresh_due {
                return Ok(());
            }
        }

        let trust_bundle_pem = std::fs::read_to_string(path)
            .map_err(|_| UpstreamIdentityVerificationError::InvalidTrustBundle)?;
        validate_trust_bundle_pem(&trust_bundle_pem)?;
        {
            let mut guard = last_validated_at
                .write()
                .map_err(|_| UpstreamIdentityVerificationError::InvalidTrustBundle)?;
            *guard = SystemTime::now();
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ExternalAuthServiceResult {
    allowed: bool,
    context: BTreeMap<String, String>,
}

fn load_jwt_decoding_keys(jwks_json: &str) -> Result<Vec<JwtDecodingKey>, JwtAuthVerificationError> {
    let jwks = serde_json::from_str::<jsonwebtoken::jwk::JwkSet>(jwks_json)
        .map_err(|_| JwtAuthVerificationError::InvalidJwks)?;
    let mut keys = Vec::new();
    for jwk in jwks.keys {
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| JwtAuthVerificationError::InvalidJwks)?;
        keys.push(JwtDecodingKey {
            kid: jwk.common.key_id,
            key,
        });
    }
    if keys.is_empty() {
        return Err(JwtAuthVerificationError::InvalidJwks);
    }
    Ok(keys)
}

fn jwks_refresh_due(loaded_at: SystemTime, refresh_secs: u64) -> Result<bool, JwtAuthVerificationError> {
    if refresh_secs == 0 {
        return Ok(true);
    }
    let elapsed = SystemTime::now()
        .duration_since(loaded_at)
        .map_err(|_| JwtAuthVerificationError::InvalidJwks)?;
    Ok(elapsed >= Duration::from_secs(refresh_secs))
}

fn trust_bundle_refresh_due(
    loaded_at: SystemTime,
    refresh_secs: u64,
) -> Result<bool, UpstreamIdentityVerificationError> {
    if refresh_secs == 0 {
        return Ok(true);
    }
    let elapsed = SystemTime::now()
        .duration_since(loaded_at)
        .map_err(|_| UpstreamIdentityVerificationError::InvalidTrustBundle)?;
    Ok(elapsed >= Duration::from_secs(refresh_secs))
}

fn validate_trust_bundle_pem(pem: &str) -> Result<(), UpstreamIdentityVerificationError> {
    let _ = lb_proto_tls::CertificateValidator::from_trust_anchors_pem(pem)
        .map_err(|_| UpstreamIdentityVerificationError::InvalidTrustBundle)?;
    Ok(())
}

fn rule_matches(headers: &BTreeMap<String, String>, rule: &AuthorizationRuleRuntime) -> bool {
    let claim_matches = rule.any_claims.is_empty()
        || rule
            .any_claims
            .iter()
            .any(|claim| header_claim_present(headers, claim));
    if !claim_matches {
        return false;
    }

    let scopes = collect_token_set(headers, &["x-auth-scopes", "x-auth-scope"]);
    let roles = collect_token_set(headers, &["x-auth-roles", "x-auth-role"]);
    let scopes_match = rule
        .required_scopes
        .iter()
        .all(|scope| scopes.contains(scope));
    let roles_match = rule
        .required_roles
        .iter()
        .all(|role| roles.contains(role));

    scopes_match && roles_match
}

fn header_claim_present(headers: &BTreeMap<String, String>, claim: &str) -> bool {
    [
        claim.to_string(),
        format!("x-auth-{claim}"),
        format!("x-auth-claim-{claim}"),
    ]
    .into_iter()
    .any(|key| headers.get(&key).is_some_and(|value| !value.trim().is_empty()))
}

fn collect_token_set(
    headers: &BTreeMap<String, String>,
    names: &[&str],
) -> std::collections::BTreeSet<String> {
    let mut tokens = std::collections::BTreeSet::new();
    for name in names {
        let Some(value) = headers.get(*name) else {
            continue;
        };
        for token in value
            .split([' ', ','])
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            tokens.insert(token.to_ascii_lowercase());
        }
    }
    tokens
}

fn parse_external_auth_endpoint(
    endpoint: &str,
) -> Result<ExternalAuthEndpoint, ExternalAuthVerificationError> {
    let uri = endpoint
        .parse::<Uri>()
        .map_err(|_| ExternalAuthVerificationError::InvalidEndpoint)?;
    if uri.scheme_str() != Some("http") {
        return Err(ExternalAuthVerificationError::InvalidEndpoint);
    }
    let authority = uri
        .authority()
        .map(|value| value.as_str().to_string())
        .ok_or(ExternalAuthVerificationError::InvalidEndpoint)?;
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| String::from("/"));
    Ok(ExternalAuthEndpoint {
        authority,
        path_and_query,
    })
}

async fn send_http_json(
    authority: &str,
    path_and_query: &str,
    body: &[u8],
) -> Result<Vec<u8>, ExternalAuthVerificationError> {
    let mut stream = TcpStream::connect(authority)
        .await
        .map_err(|_| ExternalAuthVerificationError::ServiceUnavailable)?;
    let request = format!(
        "POST {path_and_query} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ExternalAuthVerificationError::ServiceUnavailable)?;
    stream
        .write_all(body)
        .await
        .map_err(|_| ExternalAuthVerificationError::ServiceUnavailable)?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|_| ExternalAuthVerificationError::ServiceUnavailable)?;
    Ok(response)
}

fn parse_external_auth_response(
    raw_response: &[u8],
) -> Result<ExternalAuthServiceResult, ExternalAuthVerificationError> {
    let marker = b"\r\n\r\n";
    let Some(head_end) = raw_response
        .windows(marker.len())
        .position(|window| window == marker)
    else {
        return Err(ExternalAuthVerificationError::InvalidResponse);
    };
    let head = std::str::from_utf8(&raw_response[..head_end])
        .map_err(|_| ExternalAuthVerificationError::InvalidResponse)?;
    let body = &raw_response[(head_end + marker.len())..];

    let mut head_lines = head.lines();
    let status_line = head_lines
        .next()
        .ok_or(ExternalAuthVerificationError::InvalidResponse)?;
    let status_ok = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        == Some(200);
    if !status_ok {
        return Err(ExternalAuthVerificationError::ServiceUnavailable);
    }

    let value = serde_json::from_slice::<Value>(body)
        .map_err(|_| ExternalAuthVerificationError::InvalidResponse)?;
    let allowed = value
        .get("allow")
        .and_then(Value::as_bool)
        .ok_or(ExternalAuthVerificationError::InvalidResponse)?;
    let mut context = BTreeMap::new();
    if let Some(map) = value.get("context").and_then(Value::as_object) {
        for (key, entry) in map {
            if let Some(raw) = entry.as_str() {
                context.insert(key.clone(), raw.to_string());
            }
        }
    }

    Ok(ExternalAuthServiceResult { allowed, context })
}

fn parse_bearer_token(authorization_header: &str) -> Result<&str, JwtAuthVerificationError> {
    let mut parts = authorization_header.splitn(2, ' ');
    let Some(scheme) = parts.next() else {
        return Err(JwtAuthVerificationError::InvalidAuthorizationHeader);
    };
    let Some(token) = parts.next() else {
        return Err(JwtAuthVerificationError::InvalidAuthorizationHeader);
    };
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return Err(JwtAuthVerificationError::InvalidAuthorizationHeader);
    }
    Ok(token.trim())
}

fn validate_required_claims(
    claims: Value,
    required_claims: &[String],
) -> Result<(), JwtAuthVerificationError> {
    let Value::Object(map) = claims else {
        return Err(JwtAuthVerificationError::InvalidToken);
    };
    let claim_index = map
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    for claim in required_claims {
        if claim_index.get(claim).is_none_or(Value::is_null) {
            return Err(JwtAuthVerificationError::MissingRequiredClaim(claim.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        AuthorizationPolicyRuntime, AuthorizationVerificationError, ExternalAuthPolicyRuntime,
        JwtAuthPolicyRuntime, UpstreamIdentityPolicyRuntime,
        UpstreamIdentityVerificationError,
    };

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Claims {
        iss: String,
        aud: String,
        exp: usize,
        sub: String,
    }

    fn policy() -> Result<JwtAuthPolicyRuntime, Box<dyn std::error::Error>> {
        let config = lb_config_model::JwtAuthPolicyConfig {
            issuers: vec![String::from("https://issuer.example")],
            audiences: vec![String::from("edge-api")],
            jwks: Some(lb_config_model::JwtJwksSourceConfig::Inline {
                jwks_json: String::from(
                    r#"{"keys":[{"kty":"oct","k":"c3VwZXItc2VjcmV0","alg":"HS256","kid":"jwt-key-1"}]}"#,
                ),
            }),
            required_claims: vec![String::from("sub")],
            clock_skew_secs: 30,
        };
        Ok(JwtAuthPolicyRuntime::from_config(&config)?)
    }

    fn unique_temp_file(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_nanos(0))
            .as_nanos();
        std::env::temp_dir().join(format!("way-balancer-{name}-{unique}.tmp"))
    }

    fn write_file(path: &PathBuf, content: &str) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::write(path, content)?;
        Ok(())
    }

    fn issue_token_with_secret(
        iss: &str,
        aud: &str,
        kid: &str,
        secret: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let claims = Claims {
            iss: iss.to_string(),
            aud: aud.to_string(),
            exp: 4_102_444_800,
            sub: String::from("alice"),
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        Ok(encode(&header, &claims, &EncodingKey::from_secret(secret))?)
    }

    fn issue_token(iss: &str, aud: &str) -> Result<String, Box<dyn std::error::Error>> {
        let claims = Claims {
            iss: iss.to_string(),
            aud: aud.to_string(),
            exp: 4_102_444_800,
            sub: String::from("alice"),
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(String::from("jwt-key-1"));
        Ok(encode(&header, &claims, &EncodingKey::from_secret(b"super-secret"))?)
    }

    fn file_based_upstream_identity_policy(path: &str) -> lb_config_model::UpstreamIdentityPolicyConfig {
        lb_config_model::UpstreamIdentityPolicyConfig {
            mode: lb_config_model::UpstreamIdentityModeConfig::Spiffe,
            trust_bundle: lb_config_model::IdentityTrustBundleSourceConfig::File {
                path: path.to_string(),
                refresh_secs: 0,
            },
            allowed_spiffe_ids: vec![String::from("spiffe://example.org/ns/payments/sa/default")],
            allowed_trust_domains: vec![String::from("example.org")],
        }
    }

    fn external_policy(endpoint: String, fail_open: bool) -> lb_config_model::ExternalAuthPolicyConfig {
        lb_config_model::ExternalAuthPolicyConfig {
            endpoint,
            protocol: lb_config_model::ExternalAuthProtocolConfig::Http,
            timeout_ms: 10_000,
            fail_open,
            include_headers: vec![String::from("authorization")],
            context_mappings: vec![lb_config_model::AuthContextMappingConfig {
                source: String::from("principal"),
                target_header: String::from("x-auth-principal"),
                required: true,
            }],
        }
    }

    fn authorization_policy_config() -> lb_config_model::AuthorizationPolicyConfig {
        lb_config_model::AuthorizationPolicyConfig {
            rules: vec![lb_config_model::AuthorizationRuleConfig {
                name: String::from("payments-reader"),
                action: lb_config_model::AuthorizationDecisionConfig::Allow,
                any_claims: vec![String::from("principal")],
                required_scopes: vec![String::from("payments.read")],
                required_roles: vec![String::from("reader")],
            }],
            default_decision: lb_config_model::AuthorizationDecisionConfig::Deny,
        }
    }

    fn upstream_identity_policy() -> lb_config_model::UpstreamIdentityPolicyConfig {
        lb_config_model::UpstreamIdentityPolicyConfig {
            mode: lb_config_model::UpstreamIdentityModeConfig::Spiffe,
            trust_bundle: lb_config_model::IdentityTrustBundleSourceConfig::InlinePem {
                pem: String::from(
                    "-----BEGIN CERTIFICATE-----\nMIIBiTCCAS+gAwIBAgIUPnmYo7+2Uc6G5X7qhj6sCDjxi9MwCgYIKoZIzj0EAwIw\nHjEcMBoGA1UEAwwTd2F5LWJhbGFuY2VyLXRydXN0LWNhMB4XDTI2MDEwMTAwMDAw\nMFoXDTM2MDEwMTAwMDAwMFowHjEcMBoGA1UEAwwTd2F5LWJhbGFuY2VyLXRydXN0\nLWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDE3sQk6AK9CXAAb0SXNfPOMs\nU1Br5blW9sk2ll6YV5Sxg2IxGXE4aR2dvgfS5WC11zLU+3l8ym7QW1Fj/4m6yaNT\nMFEwHQYDVR0OBBYEFNCZ72JmLzjs5nUWY9S+Y9Qf6x0SMB8GA1UdIwQYMBaAFNCZ\n72JmLzjs5nUWY9S+Y9Qf6x0SMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID\nSAAwRQIhAMZjFsQu3z9ZmT9rc1NqFyG7d75m84lOtEsf4mW51zwYAiB6nR0cnGSE\nNw0qf3k3x3QYPW8IlyslvFkHa9YIlm3UsA==\n-----END CERTIFICATE-----\n",
                ),
            },
            allowed_spiffe_ids: vec![String::from("spiffe://example.org/ns/payments/sa/default")],
            allowed_trust_domains: vec![String::from("example.org")],
        }
    }

    async fn spawn_external_auth_server(
        status: u16,
        body: &'static str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0_u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let head = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        Ok(format!("http://{address}/authz"))
    }

    #[test]
    fn verifies_valid_token() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = policy()?;
        let token = issue_token("https://issuer.example", "edge-api")?;
        runtime.verify_bearer(&format!("Bearer {token}"))?;
        Ok(())
    }

    #[test]
    fn rejects_wrong_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = policy()?;
        let token = issue_token("https://other-issuer.example", "edge-api")?;
        let result = runtime.verify_bearer(&format!("Bearer {token}"));
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn refreshes_jwks_file_without_runtime_rebuild() -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_temp_file("jwks");
        write_file(
            &path,
            r#"{"keys":[{"kty":"oct","k":"YWxwaGEtc2VjcmV0","alg":"HS256","kid":"jwt-key-2"}]}"#,
        )?;

        let config = lb_config_model::JwtAuthPolicyConfig {
            issuers: vec![String::from("https://issuer.example")],
            audiences: vec![String::from("edge-api")],
            jwks: Some(lb_config_model::JwtJwksSourceConfig::File {
                path: path.to_string_lossy().to_string(),
                refresh_secs: 0,
            }),
            required_claims: vec![String::from("sub")],
            clock_skew_secs: 30,
        };
        let runtime = JwtAuthPolicyRuntime::from_config(&config)?;

        let old_token = issue_token_with_secret(
            "https://issuer.example",
            "edge-api",
            "jwt-key-2",
            b"alpha-secret",
        )?;
        runtime.verify_bearer(&format!("Bearer {old_token}"))?;

        write_file(
            &path,
            r#"{"keys":[{"kty":"oct","k":"YmV0YS1zZWNyZXQ","alg":"HS256","kid":"jwt-key-2"}]}"#,
        )?;

        let old_result = runtime.verify_bearer(&format!("Bearer {old_token}"));
        assert!(old_result.is_err());

        let new_token = issue_token_with_secret(
            "https://issuer.example",
            "edge-api",
            "jwt-key-2",
            b"beta-secret",
        )?;
        runtime.verify_bearer(&format!("Bearer {new_token}"))?;

        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn authorization_policy_allows_matching_headers() {
        let runtime = AuthorizationPolicyRuntime::from_config(&authorization_policy_config());
        let headers = [
            (String::from("x-auth-principal"), String::from("alice")),
            (
                String::from("x-auth-scopes"),
                String::from("payments.read payments.write"),
            ),
            (String::from("x-auth-roles"), String::from("reader,admin")),
        ]
        .into_iter()
        .collect();

        let result = runtime.authorize_headers(&headers);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn authorization_policy_denies_missing_required_scope() {
        let runtime = AuthorizationPolicyRuntime::from_config(&authorization_policy_config());
        let headers = [
            (String::from("x-auth-principal"), String::from("alice")),
            (String::from("x-auth-scopes"), String::from("profile.read")),
            (String::from("x-auth-roles"), String::from("reader")),
        ]
        .into_iter()
        .collect();

        let result = runtime.authorize_headers(&headers);
        assert_eq!(result, Err(AuthorizationVerificationError::Denied));
    }

    #[tokio::test]
    async fn external_auth_allows_and_returns_context() -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = spawn_external_auth_server(
            200,
            r#"{"allow":true,"context":{"principal":"alice"}}"#,
        )
        .await?;
        let runtime = ExternalAuthPolicyRuntime::from_config(&external_policy(endpoint, false))?;
        let headers = [(String::from("authorization"), String::from("Bearer token"))]
            .into_iter()
            .collect();

        let result = runtime
            .authorize_http_request_with_fail_open("GET", "/v1", &headers)
            .await?;
        assert!(result.allowed);
        assert_eq!(result.context.get("principal"), Some(&String::from("alice")));
        assert!(!result.fail_open_applied);
        Ok(())
    }

    #[tokio::test]
    async fn external_auth_denies_when_service_denies() -> Result<(), Box<dyn std::error::Error>> {
        let endpoint =
            spawn_external_auth_server(200, r#"{"allow":false}"#).await?;
        let runtime = ExternalAuthPolicyRuntime::from_config(&external_policy(endpoint, false))?;
        let headers = [(String::from("authorization"), String::from("Bearer token"))]
            .into_iter()
            .collect();

        // Local one-shot test servers can race on loopback accept under heavy parallel load.
        // Retry transient service-unavailable once or twice so this test validates deny semantics,
        // not socket scheduling timing.
        for _attempt in 0..3 {
            match runtime
                .authorize_http_request_with_fail_open("GET", "/v1", &headers)
                .await
            {
                Ok(result) => {
                    assert!(!result.allowed);
                    assert!(!result.fail_open_applied);
                    return Ok(());
                }
                Err(super::ExternalAuthVerificationError::ServiceUnavailable) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }

        Err(super::ExternalAuthVerificationError::ServiceUnavailable.into())
    }

    #[tokio::test]
    async fn external_auth_fail_open_allows_when_service_unavailable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runtime = ExternalAuthPolicyRuntime::from_config(&external_policy(
            String::from("http://127.0.0.1:9/authz"),
            true,
        ))?;
        let headers = [(String::from("authorization"), String::from("Bearer token"))]
            .into_iter()
            .collect();

        let result = runtime
            .authorize_http_request_with_fail_open("GET", "/v1", &headers)
            .await?;
        assert!(result.allowed);
        assert!(result.fail_open_applied);
        Ok(())
    }

    #[test]
    fn upstream_identity_rejects_missing_peer_identity() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = UpstreamIdentityPolicyRuntime::from_config(&upstream_identity_policy())?;
        let result = runtime.verify_peer_identity(None);
        assert_eq!(
            result,
            Err(UpstreamIdentityVerificationError::MissingPeerIdentity)
        );
        Ok(())
    }

    #[test]
    fn upstream_identity_accepts_allowed_spiffe_id() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = UpstreamIdentityPolicyRuntime::from_config(&upstream_identity_policy())?;
        runtime.verify_peer_identity(Some("spiffe://example.org/ns/payments/sa/default"))?;
        Ok(())
    }

    #[test]
    fn upstream_identity_file_refresh_fails_on_invalid_bundle(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_temp_file("trust-bundle");
        let valid_pem = "-----BEGIN CERTIFICATE-----\nMIIBiTCCAS+gAwIBAgIUPnmYo7+2Uc6G5X7qhj6sCDjxi9MwCgYIKoZIzj0EAwIw\nHjEcMBoGA1UEAwwTd2F5LWJhbGFuY2VyLXRydXN0LWNhMB4XDTI2MDEwMTAwMDAw\nMFoXDTM2MDEwMTAwMDAwMFowHjEcMBoGA1UEAwwTd2F5LWJhbGFuY2VyLXRydXN0\nLWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDE3sQk6AK9CXAAb0SXNfPOMs\nU1Br5blW9sk2ll6YV5Sxg2IxGXE4aR2dvgfS5WC11zLU+3l8ym7QW1Fj/4m6yaNT\nMFEwHQYDVR0OBBYEFNCZ72JmLzjs5nUWY9S+Y9Qf6x0SMB8GA1UdIwQYMBaAFNCZ\n72JmLzjs5nUWY9S+Y9Qf6x0SMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID\nSAAwRQIhAMZjFsQu3z9ZmT9rc1NqFyG7d75m84lOtEsf4mW51zwYAiB6nR0cnGSE\nNw0qf3k3x3QYPW8IlyslvFkHa9YIlm3UsA==\n-----END CERTIFICATE-----\n";
        write_file(&path, valid_pem)?;

        let config = file_based_upstream_identity_policy(&path.to_string_lossy());
        let runtime = UpstreamIdentityPolicyRuntime::from_config(&config)?;

        runtime.verify_peer_identity(Some("spiffe://example.org/ns/payments/sa/default"))?;

        write_file(&path, "not-a-certificate")?;
        let result = runtime.verify_peer_identity(Some("spiffe://example.org/ns/payments/sa/default"));
        assert_eq!(result, Err(UpstreamIdentityVerificationError::InvalidTrustBundle));

        let _ = std::fs::remove_file(path);
        Ok(())
    }
}
