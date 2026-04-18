use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AbuseControlError, AbuseForensicsExportRequest, AbuseProtectionAdminService, AdminStatus,
    AdminSupportBundle, EmergencyModeAdminRequest, HttpCacheAdminService, HttpCachePurgeError,
    HttpCachePurgeRequest, HttpCachePurgeResponse, PublishResponse, PublishedSnapshotRecord,
    PublishedSnapshotSummary, RollbackRequest, RolloutCoordinator, RolloutError, RolloutRequest,
    RolloutResponse, SnapshotControlService, SnapshotLookupError, SnapshotPublicationError,
    SnapshotPublishRequest,
};

const MAX_TOKEN_ID_LEN: usize = 128;
const MAX_PRINCIPAL_LEN: usize = 128;
const MAX_SECRET_LEN: usize = 256;
const MAX_AUDIT_HISTORY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdminPermission {
    ReadControlState,
    PublishSnapshots,
    RolloutSnapshots,
    ManageEmergencyMode,
    ExportForensics,
    PurgeHttpCache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    Viewer,
    Operator,
    Admin,
}

impl AdminRole {
    #[must_use]
    pub const fn allows(self, permission: AdminPermission) -> bool {
        match self {
            Self::Viewer => matches!(permission, AdminPermission::ReadControlState),
            Self::Operator => matches!(
                permission,
                AdminPermission::ReadControlState
                    | AdminPermission::RolloutSnapshots
                    | AdminPermission::ManageEmergencyMode
                    | AdminPermission::ExportForensics
            ),
            Self::Admin => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCredential {
    pub token_id: String,
    pub principal: String,
    pub secret: String,
    pub role: AdminRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedAdminIdentity {
    pub token_id: String,
    pub principal: String,
    pub role: AdminRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAuditEventKind {
    Authenticated,
    AuthenticationFailed,
    Authorized,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthAuditEvent {
    pub kind: AuthAuditEventKind,
    pub principal: Option<String>,
    pub permission: Option<AdminPermission>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdminAuthMetrics {
    pub auth_success_count: u64,
    pub auth_failure_count: u64,
    pub denied_action_count: u64,
    pub audit_event_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidAdminCredential {
    EmptyTokenId,
    TokenIdTooLong,
    DuplicateTokenId(String),
    EmptyPrincipal,
    PrincipalTooLong,
    EmptySecret,
    SecretTooLong,
    DuplicateSecret,
}

impl std::fmt::Display for InvalidAdminCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTokenId => formatter.write_str("credential token_id must not be empty"),
            Self::TokenIdTooLong => formatter.write_str("credential token_id exceeds max length"),
            Self::DuplicateTokenId(token_id) => {
                write!(formatter, "credential token_id '{token_id}' is duplicated")
            }
            Self::EmptyPrincipal => formatter.write_str("credential principal must not be empty"),
            Self::PrincipalTooLong => {
                formatter.write_str("credential principal exceeds max length")
            }
            Self::EmptySecret => formatter.write_str("credential secret must not be empty"),
            Self::SecretTooLong => formatter.write_str("credential secret exceeds max length"),
            Self::DuplicateSecret => formatter.write_str("credential secret is duplicated"),
        }
    }
}

impl std::error::Error for InvalidAdminCredential {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAuthError {
    MissingCredentials,
    InvalidCredentials,
    PermissionDenied(AdminPermission),
}

impl std::fmt::Display for AdminAuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCredentials => formatter.write_str("admin credentials are required"),
            Self::InvalidCredentials => formatter.write_str("admin credentials are invalid"),
            Self::PermissionDenied(_) => formatter.write_str("admin action is not permitted"),
        }
    }
}

impl std::error::Error for AdminAuthError {}

#[derive(Debug)]
pub enum AdminOperationError {
    Auth(AdminAuthError),
    Publish(SnapshotPublicationError),
    Lookup(SnapshotLookupError),
    Rollout(RolloutError),
    Abuse(AbuseControlError),
    CachePurge(HttpCachePurgeError),
}

impl std::fmt::Display for AdminOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(error) => write!(formatter, "admin authentication failed: {error}"),
            Self::Publish(error) => write!(formatter, "publish operation failed: {error}"),
            Self::Lookup(error) => write!(formatter, "lookup operation failed: {error}"),
            Self::Rollout(error) => write!(formatter, "rollout operation failed: {error}"),
            Self::Abuse(error) => write!(formatter, "abuse-control operation failed: {error}"),
            Self::CachePurge(error) => write!(formatter, "cache purge operation failed: {error}"),
        }
    }
}

impl std::error::Error for AdminOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            Self::Publish(error) => Some(error),
            Self::Lookup(error) => Some(error),
            Self::Rollout(error) => Some(error),
            Self::Abuse(error) => Some(error),
            Self::CachePurge(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub struct AdminAuthService {
    credentials_by_secret: BTreeMap<String, AuthenticatedAdminIdentity>,
    audit_history: Vec<AuthAuditEvent>,
    metrics: AdminAuthMetrics,
}

impl AdminAuthService {
    pub fn from_credentials(
        credentials: Vec<AdminCredential>,
    ) -> Result<Self, InvalidAdminCredential> {
        validate_credentials(&credentials)?;

        let credentials_by_secret = credentials
            .into_iter()
            .map(|credential| {
                (
                    credential.secret,
                    AuthenticatedAdminIdentity {
                        token_id: credential.token_id,
                        principal: credential.principal,
                        role: credential.role,
                    },
                )
            })
            .collect();

        Ok(Self {
            credentials_by_secret,
            audit_history: Vec::new(),
            metrics: AdminAuthMetrics::default(),
        })
    }

    pub fn authenticate(
        &mut self,
        bearer_token: Option<&str>,
    ) -> Result<AuthenticatedAdminIdentity, AdminAuthError> {
        let Some(secret) = bearer_token else {
            self.metrics.auth_failure_count = self.metrics.auth_failure_count.saturating_add(1);
            self.push_audit(AuthAuditEvent {
                kind: AuthAuditEventKind::AuthenticationFailed,
                principal: None,
                permission: None,
                detail: String::from("missing admin credentials"),
            });
            return Err(AdminAuthError::MissingCredentials);
        };

        let mut authenticated_identity = None;
        for (known_secret, identity) in &self.credentials_by_secret {
            if constant_time_eq(secret.as_bytes(), known_secret.as_bytes()) {
                authenticated_identity = Some(identity.clone());
            }
        }

        let Some(identity) = authenticated_identity else {
            self.metrics.auth_failure_count = self.metrics.auth_failure_count.saturating_add(1);
            self.push_audit(AuthAuditEvent {
                kind: AuthAuditEventKind::AuthenticationFailed,
                principal: None,
                permission: None,
                detail: String::from("invalid admin credentials"),
            });
            return Err(AdminAuthError::InvalidCredentials);
        };

        self.metrics.auth_success_count = self.metrics.auth_success_count.saturating_add(1);
        self.push_audit(AuthAuditEvent {
            kind: AuthAuditEventKind::Authenticated,
            principal: Some(identity.principal.clone()),
            permission: None,
            detail: format!("authenticated admin principal {}", identity.principal),
        });
        Ok(identity)
    }

    pub fn authorize(
        &mut self,
        bearer_token: Option<&str>,
        permission: AdminPermission,
    ) -> Result<AuthenticatedAdminIdentity, AdminAuthError> {
        let identity = self.authenticate(bearer_token)?;
        if !identity.role.allows(permission) {
            self.metrics.denied_action_count = self.metrics.denied_action_count.saturating_add(1);
            self.push_audit(AuthAuditEvent {
                kind: AuthAuditEventKind::Denied,
                principal: Some(identity.principal.clone()),
                permission: Some(permission),
                detail: format!("denied admin action for principal {}", identity.principal),
            });
            return Err(AdminAuthError::PermissionDenied(permission));
        }

        self.push_audit(AuthAuditEvent {
            kind: AuthAuditEventKind::Authorized,
            principal: Some(identity.principal.clone()),
            permission: Some(permission),
            detail: format!("authorized admin action for principal {}", identity.principal),
        });
        Ok(identity)
    }

    pub fn list_versions(
        &mut self,
        control: &SnapshotControlService,
        bearer_token: Option<&str>,
    ) -> Result<Vec<PublishedSnapshotSummary>, AdminOperationError> {
        let _identity = self
            .authorize(bearer_token, AdminPermission::ReadControlState)
            .map_err(AdminOperationError::Auth)?;
        Ok(control.list_versions())
    }

    pub fn get_version(
        &mut self,
        control: &SnapshotControlService,
        bearer_token: Option<&str>,
        version: &str,
    ) -> Result<PublishedSnapshotRecord, AdminOperationError> {
        let _identity = self
            .authorize(bearer_token, AdminPermission::ReadControlState)
            .map_err(AdminOperationError::Auth)?;
        control.get_version(version).cloned().map_err(AdminOperationError::Lookup)
    }

    pub fn publish_snapshot(
        &mut self,
        control: &mut SnapshotControlService,
        bearer_token: Option<&str>,
        request: SnapshotPublishRequest,
    ) -> Result<PublishResponse, AdminOperationError> {
        let _identity = self
            .authorize(bearer_token, AdminPermission::PublishSnapshots)
            .map_err(AdminOperationError::Auth)?;
        control.publish(request).map_err(AdminOperationError::Publish)
    }

    pub fn rollout_snapshot(
        &mut self,
        control: &SnapshotControlService,
        rollout: &mut RolloutCoordinator,
        dataplane: &mut lb_runtime::DataplaneSnapshotManager,
        bearer_token: Option<&str>,
        request: RolloutRequest,
    ) -> Result<RolloutResponse, AdminOperationError> {
        let _identity = self
            .authorize(bearer_token, AdminPermission::RolloutSnapshots)
            .map_err(AdminOperationError::Auth)?;
        rollout.rollout(control, dataplane, request).map_err(AdminOperationError::Rollout)
    }

    pub fn rollback_snapshot(
        &mut self,
        control: &SnapshotControlService,
        rollout: &mut RolloutCoordinator,
        dataplane: &mut lb_runtime::DataplaneSnapshotManager,
        bearer_token: Option<&str>,
        request: RollbackRequest,
    ) -> Result<RolloutResponse, AdminOperationError> {
        let _identity = self
            .authorize(bearer_token, AdminPermission::RolloutSnapshots)
            .map_err(AdminOperationError::Auth)?;
        rollout.rollback(control, dataplane, request).map_err(AdminOperationError::Rollout)
    }

    pub fn switch_emergency_mode(
        &mut self,
        service: &mut AbuseProtectionAdminService,
        controller: &mut lb_runtime::EmergencyProtectionController,
        bearer_token: Option<&str>,
        request: EmergencyModeAdminRequest,
    ) -> Result<crate::EmergencyModeAdminResponse, AdminOperationError> {
        let _identity = self
            .authorize(bearer_token, AdminPermission::ManageEmergencyMode)
            .map_err(AdminOperationError::Auth)?;
        service.switch_mode(controller, request).map_err(AdminOperationError::Abuse)
    }

    pub fn export_abuse_forensics(
        &mut self,
        service: &mut AbuseProtectionAdminService,
        controller: &mut lb_runtime::EmergencyProtectionController,
        bearer_token: Option<&str>,
        request: AbuseForensicsExportRequest,
        diagnostics: &lb_observability::RuntimeDiagnostics,
        status: &AdminStatus,
    ) -> Result<AdminSupportBundle, AdminOperationError> {
        let _identity = self
            .authorize(bearer_token, AdminPermission::ExportForensics)
            .map_err(AdminOperationError::Auth)?;
        service
            .export_forensics(controller, request, diagnostics, status)
            .map_err(AdminOperationError::Abuse)
    }

    pub fn purge_http_cache(
        &mut self,
        service: &mut HttpCacheAdminService,
        bearer_token: Option<&str>,
        request: HttpCachePurgeRequest,
        telemetry: Option<&lb_runtime::RuntimeTelemetry>,
    ) -> Result<HttpCachePurgeResponse, AdminOperationError> {
        let _identity = self
            .authorize(bearer_token, AdminPermission::PurgeHttpCache)
            .map_err(AdminOperationError::Auth)?;
        service.purge(request, telemetry).map_err(AdminOperationError::CachePurge)
    }

    #[must_use]
    pub fn metrics(&self) -> AdminAuthMetrics {
        self.metrics
    }

    #[must_use]
    pub fn audit_history(&self) -> &[AuthAuditEvent] {
        &self.audit_history
    }

    fn push_audit(&mut self, event: AuthAuditEvent) {
        if self.audit_history.len() == MAX_AUDIT_HISTORY {
            let _ = self.audit_history.remove(0);
        }
        self.audit_history.push(event);
        self.metrics.audit_event_count = self.metrics.audit_event_count.saturating_add(1);
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        diff |= usize::from(left_byte ^ right_byte);
    }

    diff == 0
}

fn validate_credentials(credentials: &[AdminCredential]) -> Result<(), InvalidAdminCredential> {
    let mut token_ids = BTreeSet::new();
    let mut secrets = BTreeSet::new();

    for credential in credentials {
        if credential.token_id.trim().is_empty() {
            return Err(InvalidAdminCredential::EmptyTokenId);
        }
        if credential.token_id.len() > MAX_TOKEN_ID_LEN {
            return Err(InvalidAdminCredential::TokenIdTooLong);
        }
        if !token_ids.insert(credential.token_id.clone()) {
            return Err(InvalidAdminCredential::DuplicateTokenId(credential.token_id.clone()));
        }
        if credential.principal.trim().is_empty() {
            return Err(InvalidAdminCredential::EmptyPrincipal);
        }
        if credential.principal.len() > MAX_PRINCIPAL_LEN {
            return Err(InvalidAdminCredential::PrincipalTooLong);
        }
        if credential.secret.trim().is_empty() {
            return Err(InvalidAdminCredential::EmptySecret);
        }
        if credential.secret.len() > MAX_SECRET_LEN {
            return Err(InvalidAdminCredential::SecretTooLong);
        }
        if !secrets.insert(credential.secret.clone()) {
            return Err(InvalidAdminCredential::DuplicateSecret);
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use lb_test_support::{configure_test_trusted_signers, test_artifact_attestation};

    use super::{
        constant_time_eq, AdminAuthError, AdminAuthService, AdminCredential, AdminOperationError,
        AdminPermission, AdminRole,
    };
    use crate::{
        AbuseForensicsExportRequest, AbuseProtectionAdminService, AdminStatus,
        EmergencyModeAdminRequest, HttpCacheAdminService, HttpCachePurgeRequest,
        HttpCachePurgeTarget, SnapshotControlService, SnapshotPublishRequest,
    };

    fn auth_service() -> Result<AdminAuthService, Box<dyn std::error::Error>> {
        Ok(AdminAuthService::from_credentials(vec![
            AdminCredential {
                token_id: String::from("viewer-1"),
                principal: String::from("viewer-a"),
                secret: String::from("viewer-secret"),
                role: AdminRole::Viewer,
            },
            AdminCredential {
                token_id: String::from("operator-1"),
                principal: String::from("operator-a"),
                secret: String::from("operator-secret"),
                role: AdminRole::Operator,
            },
            AdminCredential {
                token_id: String::from("admin-1"),
                principal: String::from("admin-a"),
                secret: String::from("admin-secret"),
                role: AdminRole::Admin,
            },
        ])?)
    }

    #[test]
    fn auth_success_and_failure_are_explicit() -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = auth_service()?;

        let success = auth.authenticate(Some("viewer-secret"));
        let missing = auth.authenticate(None);
        let invalid = auth.authenticate(Some("wrong-secret"));

        assert!(success.is_ok());
        assert_eq!(missing, Err(AdminAuthError::MissingCredentials));
        assert_eq!(invalid, Err(AdminAuthError::InvalidCredentials));
        assert_eq!(auth.metrics().auth_success_count, 1);
        assert_eq!(auth.metrics().auth_failure_count, 2);
        Ok(())
    }

    #[test]
    fn unauthorized_mutation_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = auth_service()?;
        let mut workspace = lb_config_model::WorkspaceConfig::foundation();
        configure_test_trusted_signers(&mut workspace)?;
        let snapshot = workspace.compile_snapshot()?;
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let mut control = SnapshotControlService::new();

        let result = auth.publish_snapshot(
            &mut control,
            Some("viewer-secret"),
            SnapshotPublishRequest {
                version: String::from("v1"),
                expected_digest_sha256: Some(snapshot.metadata().digest_sha256().to_owned()),
                artifact_attestation: Some(artifact_attestation),
                snapshot,
                published_by: Some(String::from("viewer-a")),
                reason: Some(String::from("should be denied")),
            },
        );

        assert!(matches!(
            result,
            Err(AdminOperationError::Auth(AdminAuthError::PermissionDenied(_)))
        ));
        assert_eq!(auth.metrics().denied_action_count, 1);
        Ok(())
    }

    #[test]
    fn sensitive_actions_are_audited() -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = auth_service()?;
        let mut workspace = lb_config_model::WorkspaceConfig::foundation();
        configure_test_trusted_signers(&mut workspace)?;
        let snapshot = workspace.compile_snapshot()?;
        let artifact_attestation = test_artifact_attestation(&snapshot)?;
        let diagnostics =
            lb_observability::SupportBundleBuilder::new(lb_observability::RedactionEngine)
                .collect_runtime_diagnostics(
                    lb_observability::DiagnosticsLimits::default(),
                    lb_observability::RuntimeDiagnosticsInput {
                        metrics_text: Some(String::from("runtime_metric 1")),
                        logs: None,
                        events: Some(Vec::new()),
                        cache_diagnostics_text: None,
                    },
                );
        let mut control = SnapshotControlService::new();
        let publish = auth.publish_snapshot(
            &mut control,
            Some("admin-secret"),
            SnapshotPublishRequest {
                version: String::from("v1"),
                expected_digest_sha256: Some(snapshot.metadata().digest_sha256().to_owned()),
                artifact_attestation: Some(artifact_attestation),
                snapshot,
                published_by: Some(String::from("admin-a")),
                reason: Some(String::from("seed admin version")),
            },
        );
        let versions = auth.list_versions(&control, Some("viewer-secret"));
        let mut abuse_service = AbuseProtectionAdminService::new();
        let mut controller = lb_runtime::EmergencyProtectionController::new();
        let store = std::sync::Arc::new(lb_runtime::HttpCacheStore::new(
            lb_runtime::HttpCacheStoreConfig {
                max_entries: 4,
                max_bytes: 1024,
                max_object_bytes: 512,
            },
        )?);
        let mut cache_service =
            HttpCacheAdminService::new("public-http", true, std::sync::Arc::clone(&store));
        let export = auth.export_abuse_forensics(
            &mut abuse_service,
            &mut controller,
            Some("operator-secret"),
            AbuseForensicsExportRequest {
                bundle_name: String::from("audit-bundle"),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("capture evidence")),
                limits: lb_observability::DiagnosticsLimits::default(),
            },
            &diagnostics,
            &AdminStatus { config_name: String::from("way-balancer") },
        );
        let purge = auth.purge_http_cache(
            &mut cache_service,
            Some("admin-secret"),
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::PathPrefix(String::from("/api")),
                requested_by: Some(String::from("admin-a")),
                reason: Some(String::from("invalidate stale route")),
            },
            None,
        );
        let denied_mode_switch = auth.switch_emergency_mode(
            &mut abuse_service,
            &mut controller,
            Some("viewer-secret"),
            EmergencyModeAdminRequest {
                mode: lb_runtime::EmergencyProtectionMode::Elevated,
                requested_by: Some(String::from("viewer-a")),
                reason: Some(String::from("should be denied")),
                allow_relaxation: false,
            },
        );

        assert!(publish.is_ok());
        assert!(versions.is_ok());
        assert!(export.is_ok());
        assert!(purge.is_ok());
        assert!(matches!(
            denied_mode_switch,
            Err(AdminOperationError::Auth(AdminAuthError::PermissionDenied(_)))
        ));
        assert!(auth.audit_history().len() >= 9);
        assert!(auth.metrics().audit_event_count >= 9);
        assert_eq!(auth.metrics().denied_action_count, 1);
        Ok(())
    }

    #[test]
    fn unauthorized_cache_purge_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = auth_service()?;
        let store = std::sync::Arc::new(lb_runtime::HttpCacheStore::new(
            lb_runtime::HttpCacheStoreConfig {
                max_entries: 4,
                max_bytes: 1024,
                max_object_bytes: 512,
            },
        )?);
        let mut cache_service = HttpCacheAdminService::new("public-http", true, store);

        let result = auth.purge_http_cache(
            &mut cache_service,
            Some("operator-secret"),
            HttpCachePurgeRequest {
                target: HttpCachePurgeTarget::PathPrefix(String::from("/api")),
                requested_by: Some(String::from("operator-a")),
                reason: Some(String::from("should be denied")),
            },
            None,
        );

        assert!(matches!(
            result,
            Err(AdminOperationError::Auth(AdminAuthError::PermissionDenied(
                AdminPermission::PurgeHttpCache,
            )))
        ));
        assert_eq!(auth.metrics().denied_action_count, 1);
        Ok(())
    }

    #[test]
    fn credential_validation_rejects_duplicate_and_empty_fields() {
        let duplicate_token = AdminAuthService::from_credentials(vec![
            AdminCredential {
                token_id: String::from("dup"),
                principal: String::from("a"),
                secret: String::from("secret-a"),
                role: AdminRole::Viewer,
            },
            AdminCredential {
                token_id: String::from("dup"),
                principal: String::from("b"),
                secret: String::from("secret-b"),
                role: AdminRole::Admin,
            },
        ]);
        let empty_principal = AdminAuthService::from_credentials(vec![AdminCredential {
            token_id: String::from("id"),
            principal: String::new(),
            secret: String::from("secret"),
            role: AdminRole::Viewer,
        }]);

        assert!(matches!(
            duplicate_token,
            Err(super::InvalidAdminCredential::DuplicateTokenId(token)) if token == "dup"
        ));
        assert!(matches!(empty_principal, Err(super::InvalidAdminCredential::EmptyPrincipal)));
    }

    #[test]
    fn operation_errors_expose_sources() -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = auth_service()?;
        let error = auth
            .list_versions(&SnapshotControlService::new(), None)
            .expect_err("missing credentials should fail");

        assert!(error.to_string().contains("admin authentication failed"));
        assert!(std::error::Error::source(&error).is_some());
        Ok(())
    }

    #[test]
    fn constant_time_eq_requires_exact_match() {
        assert!(constant_time_eq(b"admin-secret", b"admin-secret"));
        assert!(!constant_time_eq(b"admin-secret", b"admin-secreu"));
        assert!(!constant_time_eq(b"admin-secret", b"admin-secret-long"));
    }
}
