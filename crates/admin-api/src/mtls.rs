#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedChannelMtlsConfig {
    pub expected_peer_identity: Option<String>,
    pub validation_policy: lb_proto_tls::CertificateValidationPolicy,
}

impl PrivilegedChannelMtlsConfig {
    #[must_use]
    pub fn admin_client(expected_peer_identity: Option<String>) -> Self {
        let validation_policy =
            lb_proto_tls::CertificateValidationPolicy::privileged_channel_client(
                expected_peer_identity.clone(),
            );
        Self { expected_peer_identity, validation_policy }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedChannelIdentity {
    pub principal: String,
    pub fingerprint_sha256: String,
    pub expires_within_warning_window: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrivilegedMtlsMetrics {
    pub validation_success_count: u64,
    pub validation_failure_count: u64,
    pub expiring_certificate_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegedChannelMtlsError {
    MissingPeerCertificate,
    Validation(lb_proto_tls::CertificateValidationError),
}

impl std::fmt::Display for PrivilegedChannelMtlsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPeerCertificate => {
                formatter.write_str("privileged channel requires a peer certificate")
            }
            Self::Validation(error) => {
                write!(formatter, "peer certificate validation failed: {error}")
            }
        }
    }
}

impl std::error::Error for PrivilegedChannelMtlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingPeerCertificate => None,
            Self::Validation(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub struct PrivilegedChannelAuthenticator {
    validator: lb_proto_tls::CertificateValidator,
    metrics: PrivilegedMtlsMetrics,
}

impl PrivilegedChannelAuthenticator {
    pub fn new(trusted_ca_pem: &str) -> Result<Self, lb_proto_tls::CertificateLoadError> {
        Ok(Self {
            validator: lb_proto_tls::CertificateValidator::from_trust_anchors_pem(trusted_ca_pem)?,
            metrics: PrivilegedMtlsMetrics::default(),
        })
    }

    pub fn authenticate_peer(
        &mut self,
        presented_certificate_chain_pem: Option<&str>,
        config: &PrivilegedChannelMtlsConfig,
        now_unix_secs: i64,
    ) -> Result<PrivilegedChannelIdentity, PrivilegedChannelMtlsError> {
        let Some(presented_certificate_chain_pem) = presented_certificate_chain_pem else {
            self.metrics.validation_failure_count =
                self.metrics.validation_failure_count.saturating_add(1);
            return Err(PrivilegedChannelMtlsError::MissingPeerCertificate);
        };

        let identity = self
            .validator
            .validate_peer_certificates_pem(
                presented_certificate_chain_pem,
                &config.validation_policy,
                now_unix_secs,
            )
            .map_err(|error| {
                self.metrics.validation_failure_count =
                    self.metrics.validation_failure_count.saturating_add(1);
                PrivilegedChannelMtlsError::Validation(error)
            })?;

        self.metrics.validation_success_count =
            self.metrics.validation_success_count.saturating_add(1);
        if identity.expires_within_warning_window {
            self.metrics.expiring_certificate_count =
                self.metrics.expiring_certificate_count.saturating_add(1);
        }

        Ok(PrivilegedChannelIdentity {
            principal: identity
                .common_name
                .or_else(|| identity.san_dns_names.first().cloned())
                .unwrap_or_else(|| String::from("unknown-peer")),
            fingerprint_sha256: identity.fingerprint_sha256,
            expires_within_warning_window: identity.expires_within_warning_window,
        })
    }

    #[must_use]
    pub fn metrics(&self) -> PrivilegedMtlsMetrics {
        self.metrics
    }

    #[must_use]
    pub fn certificate_metrics(&self) -> lb_proto_tls::CertificateValidationMetrics {
        self.validator.metrics()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    use super::{
        PrivilegedChannelAuthenticator, PrivilegedChannelMtlsConfig, PrivilegedChannelMtlsError,
    };

    #[test]
    fn mtls_authenticator_accepts_trusted_peer() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = fixtures(false)?;
        let mut authenticator = PrivilegedChannelAuthenticator::new(&fixtures.ca_pem)?;

        let identity = authenticator.authenticate_peer(
            Some(&fixtures.leaf_pem),
            &PrivilegedChannelMtlsConfig::admin_client(Some(String::from("operator.internal"))),
            fixtures.now_unix_secs,
        )?;

        assert_eq!(identity.principal, "operator.internal");
        assert_eq!(authenticator.metrics().validation_success_count, 1);
        Ok(())
    }

    #[test]
    fn mtls_authenticator_rejects_missing_peer_certificate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = fixtures(false)?;
        let mut authenticator = PrivilegedChannelAuthenticator::new(&fixtures.ca_pem)?;

        let result = authenticator.authenticate_peer(
            None,
            &PrivilegedChannelMtlsConfig::admin_client(Some(String::from("operator.internal"))),
            fixtures.now_unix_secs,
        );

        assert_eq!(result, Err(PrivilegedChannelMtlsError::MissingPeerCertificate));
        assert_eq!(authenticator.metrics().validation_failure_count, 1);
        Ok(())
    }

    #[test]
    fn mtls_authenticator_rejects_identity_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = fixtures(false)?;
        let mut authenticator = PrivilegedChannelAuthenticator::new(&fixtures.ca_pem)?;

        let result = authenticator.authenticate_peer(
            Some(&fixtures.leaf_pem),
            &PrivilegedChannelMtlsConfig::admin_client(Some(String::from("other.internal"))),
            fixtures.now_unix_secs,
        );

        assert!(matches!(
            result,
            Err(PrivilegedChannelMtlsError::Validation(
                lb_proto_tls::CertificateValidationError::IdentityMismatch
            ))
        ));
        Ok(())
    }

    struct Fixtures {
        ca_pem: String,
        leaf_pem: String,
        now_unix_secs: i64,
    }

    fn fixtures(expired: bool) -> Result<Fixtures, Box<dyn std::error::Error>> {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let mut ca_params = CertificateParams::new(Vec::new())?;
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params.distinguished_name.push(DnType::CommonName, "way-balancer Test Root");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.not_before = (now - Duration::from_secs(30 * 24 * 60 * 60)).into();
        ca_params.not_after = (now + Duration::from_secs(365 * 24 * 60 * 60)).into();
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;

        let mut leaf_params = CertificateParams::new(vec![String::from("operator.internal")])?;
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params.distinguished_name.push(DnType::CommonName, "operator.internal");
        leaf_params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
        leaf_params.not_after = if expired {
            (now - Duration::from_secs(60)).into()
        } else {
            (now + Duration::from_secs(14 * 24 * 60 * 60)).into()
        };
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = KeyPair::generate()?;
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;

        Ok(Fixtures {
            ca_pem: ca_cert.pem(),
            leaf_pem: leaf_cert.pem(),
            now_unix_secs: i64::try_from(now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs())?,
        })
    }
}
