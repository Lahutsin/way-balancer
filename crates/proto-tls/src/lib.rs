#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;
use std::time::Duration;

use pem::Pem;
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::time::ASN1Time;

/// Returns the crate identifier for TLS protocol abstractions.
pub const CRATE_ID: &str = "lb-proto-tls";

/// Minimal placeholder for future TLS mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Passes TLS through unchanged.
    Passthrough,
    /// Terminates TLS locally.
    Termination,
}

/// Minimal foundation for future TLS termination configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsTerminationConfig {
    /// Source of certificate material for future TLS termination.
    pub certificate_source: CertificateSource,
}

/// Loaded TLS termination material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedTlsIdentity {
    /// Parsed certificate chain in DER form.
    pub certificate_chain_der: Vec<Vec<u8>>,
    /// Parsed private key in DER form.
    pub private_key_der: Vec<u8>,
}

/// Operator-visible metadata about loaded TLS identity material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedTlsIdentityMetadata {
    /// Number of certificates present in the chain PEM.
    pub certificate_chain_len: usize,
    /// Parsed leaf common name, if present.
    pub common_name: Option<String>,
    /// Parsed leaf SAN DNS names.
    pub san_dns_names: Vec<String>,
    /// SHA-256 fingerprint of the leaf certificate DER.
    pub fingerprint_sha256: String,
    /// Leaf validity lower bound.
    pub not_before_unix_secs: i64,
    /// Leaf validity upper bound.
    pub not_after_unix_secs: i64,
    /// Whether the leaf certificate is not yet valid for the provided inspection time.
    pub not_yet_valid: bool,
    /// Whether the leaf certificate is already expired for the provided inspection time.
    pub expired: bool,
    /// Whether the leaf certificate will expire within the provided warning window.
    pub expires_within_warning_window: bool,
}

/// Certificate material source abstraction for future TLS termination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSource {
    /// Certificate and key are loaded from static file paths.
    Files { cert_path: String, key_path: String },
    /// Certificate material is expected from an external provider.
    DynamicProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateUsage {
    ServerAuth,
    ClientAuth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateValidationPolicy {
    pub usage: CertificateUsage,
    pub expected_identity: Option<String>,
    pub expiry_warning_window: Duration,
}

impl CertificateValidationPolicy {
    #[must_use]
    pub fn privileged_channel_client(expected_identity: Option<String>) -> Self {
        Self {
            usage: CertificateUsage::ClientAuth,
            expected_identity,
            expiry_warning_window: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }

    #[must_use]
    pub fn privileged_channel_server(expected_identity: Option<String>) -> Self {
        Self {
            usage: CertificateUsage::ServerAuth,
            expected_identity,
            expiry_warning_window: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCertificateIdentity {
    pub common_name: Option<String>,
    pub san_dns_names: Vec<String>,
    pub fingerprint_sha256: String,
    pub not_before_unix_secs: i64,
    pub not_after_unix_secs: i64,
    pub expires_within_warning_window: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CertificateValidationMetrics {
    pub loaded_certificate_count: u64,
    pub loaded_private_key_count: u64,
    pub validation_success_count: u64,
    pub validation_failure_count: u64,
    pub expiring_soon_count: u64,
    pub mtls_validation_failure_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateLoadError {
    NoCertificatesFound,
    InvalidPem,
    InvalidPrivateKey,
    ReadFile(String),
}

impl fmt::Display for CertificateLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCertificatesFound => formatter.write_str("no certificates found in PEM input"),
            Self::InvalidPem => formatter.write_str("certificate material is not valid PEM"),
            Self::InvalidPrivateKey => {
                formatter.write_str("private key material is invalid or unsupported")
            }
            Self::ReadFile(path) => {
                write!(formatter, "failed reading certificate material from {path}")
            }
        }
    }
}

impl std::error::Error for CertificateLoadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsIdentityInspectError {
    Load(CertificateLoadError),
    InvalidCertificate,
}

impl fmt::Display for TlsIdentityInspectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(error) => write!(formatter, "failed loading TLS identity: {error}"),
            Self::InvalidCertificate => {
                formatter.write_str("certificate material is malformed or unsupported")
            }
        }
    }
}

impl std::error::Error for TlsIdentityInspectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Load(error) => Some(error),
            Self::InvalidCertificate => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateValidationError {
    EmptyCertificateChain,
    TrustStoreEmpty,
    InvalidCertificate,
    CertificateNotYetValid,
    CertificateExpired,
    IdentityMismatch,
    UsageMismatch,
    InvalidChainSignature,
    UntrustedIssuer,
}

impl fmt::Display for CertificateValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCertificateChain => {
                formatter.write_str("certificate chain must not be empty")
            }
            Self::TrustStoreEmpty => {
                formatter.write_str("trusted certificate store must not be empty")
            }
            Self::InvalidCertificate => {
                formatter.write_str("certificate is malformed or unsupported")
            }
            Self::CertificateNotYetValid => formatter.write_str("certificate is not yet valid"),
            Self::CertificateExpired => formatter.write_str("certificate has expired"),
            Self::IdentityMismatch => {
                formatter.write_str("certificate identity does not match expected peer identity")
            }
            Self::UsageMismatch => {
                formatter.write_str("certificate usage does not satisfy required purpose")
            }
            Self::InvalidChainSignature => {
                formatter.write_str("certificate chain signature validation failed")
            }
            Self::UntrustedIssuer => {
                formatter.write_str("certificate chain does not terminate in a trusted issuer")
            }
        }
    }
}

impl std::error::Error for CertificateValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateValidator {
    trusted_roots_der: Vec<Vec<u8>>,
    metrics: CertificateValidationMetrics,
}

impl CertificateValidator {
    pub fn from_trust_anchors_pem(trust_anchors_pem: &str) -> Result<Self, CertificateLoadError> {
        let trusted_roots_der = load_certificates_from_pem(trust_anchors_pem)?;
        Ok(Self { trusted_roots_der, metrics: CertificateValidationMetrics::default() })
    }

    pub fn validate_peer_certificates_pem(
        &mut self,
        certificate_chain_pem: &str,
        policy: &CertificateValidationPolicy,
        now_unix_secs: i64,
    ) -> Result<ValidatedCertificateIdentity, CertificateValidationError> {
        if self.trusted_roots_der.is_empty() {
            self.metrics.validation_failure_count =
                self.metrics.validation_failure_count.saturating_add(1);
            self.metrics.mtls_validation_failure_count =
                self.metrics.mtls_validation_failure_count.saturating_add(1);
            return Err(CertificateValidationError::TrustStoreEmpty);
        }

        let chain_der = load_certificates_from_pem(certificate_chain_pem).map_err(|_| {
            self.record_validation_failure(CertificateValidationError::InvalidCertificate)
        })?;
        self.metrics.loaded_certificate_count = self
            .metrics
            .loaded_certificate_count
            .saturating_add(u64::try_from(chain_der.len()).unwrap_or(u64::MAX));
        if chain_der.is_empty() {
            self.metrics.validation_failure_count =
                self.metrics.validation_failure_count.saturating_add(1);
            self.metrics.mtls_validation_failure_count =
                self.metrics.mtls_validation_failure_count.saturating_add(1);
            return Err(CertificateValidationError::EmptyCertificateChain);
        }

        let chain = parse_certificates(&chain_der)
            .map_err(|error| self.record_validation_failure(error))?;
        let leaf = &chain[0];
        validate_validity(leaf, now_unix_secs)
            .map_err(|error| self.record_validation_failure(error))?;
        validate_usage(leaf, policy.usage)
            .map_err(|error| self.record_validation_failure(error))?;
        validate_identity(leaf, policy.expected_identity.as_deref())
            .map_err(|error| self.record_validation_failure(error))?;
        validate_chain_signatures(&chain, &self.trusted_roots_der)
            .map_err(|error| self.record_validation_failure(error))?;

        let fingerprint_sha256 = hex_sha256(&chain_der[0]);
        let san_dns_names = collect_san_dns_names(leaf);
        let common_name = collect_common_name(leaf);
        let not_before_unix_secs = leaf.validity().not_before.timestamp();
        let not_after_unix_secs = leaf.validity().not_after.timestamp();
        let expires_within_warning_window = not_after_unix_secs.saturating_sub(now_unix_secs)
            <= i64::try_from(policy.expiry_warning_window.as_secs()).unwrap_or(i64::MAX);

        self.metrics.validation_success_count =
            self.metrics.validation_success_count.saturating_add(1);
        if expires_within_warning_window {
            self.metrics.expiring_soon_count = self.metrics.expiring_soon_count.saturating_add(1);
        }

        Ok(ValidatedCertificateIdentity {
            common_name,
            san_dns_names,
            fingerprint_sha256,
            not_before_unix_secs,
            not_after_unix_secs,
            expires_within_warning_window,
        })
    }

    #[must_use]
    pub fn metrics(&self) -> CertificateValidationMetrics {
        self.metrics
    }

    fn record_validation_failure(
        &mut self,
        error: CertificateValidationError,
    ) -> CertificateValidationError {
        self.metrics.validation_failure_count =
            self.metrics.validation_failure_count.saturating_add(1);
        self.metrics.mtls_validation_failure_count =
            self.metrics.mtls_validation_failure_count.saturating_add(1);
        error
    }
}

pub fn load_certificates_from_pem(pem: &str) -> Result<Vec<Vec<u8>>, CertificateLoadError> {
    let certificates = parse_pem_blocks(pem)?
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(Pem::into_contents)
        .collect::<Vec<_>>();
    if certificates.is_empty() {
        return Err(CertificateLoadError::NoCertificatesFound);
    }
    Ok(certificates)
}

pub fn load_private_key_from_pem(pem: &str) -> Result<Vec<u8>, CertificateLoadError> {
    let key = parse_pem_blocks(pem)?
        .into_iter()
        .find(|block| matches!(block.tag(), "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"));
    let Some(key) = key else {
        return Err(CertificateLoadError::InvalidPrivateKey);
    };
    Ok(key.into_contents())
}

fn parse_pem_blocks(pem_text: &str) -> Result<Vec<Pem>, CertificateLoadError> {
    pem::parse_many(pem_text).map_err(|_| CertificateLoadError::InvalidPem)
}

pub fn load_tls_identity_from_files(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<LoadedTlsIdentity, CertificateLoadError> {
    let cert_path = cert_path.as_ref();
    let key_path = key_path.as_ref();
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|_| CertificateLoadError::ReadFile(cert_path.display().to_string()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|_| CertificateLoadError::ReadFile(key_path.display().to_string()))?;

    Ok(LoadedTlsIdentity {
        certificate_chain_der: load_certificates_from_pem(&cert_pem)?,
        private_key_der: load_private_key_from_pem(&key_pem)?,
    })
}

pub fn inspect_tls_identity_from_files(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    now_unix_secs: i64,
    warning_window: Duration,
) -> Result<LoadedTlsIdentityMetadata, TlsIdentityInspectError> {
    let cert_path = cert_path.as_ref();
    let key_path = key_path.as_ref();
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|_| TlsIdentityInspectError::Load(CertificateLoadError::ReadFile(
            cert_path.display().to_string(),
        )))?;
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|_| TlsIdentityInspectError::Load(CertificateLoadError::ReadFile(
            key_path.display().to_string(),
        )))?;
    let certificate_chain_der =
        load_certificates_from_pem(&cert_pem).map_err(TlsIdentityInspectError::Load)?;
    let _private_key = load_private_key_from_pem(&key_pem).map_err(TlsIdentityInspectError::Load)?;
    let chain = parse_certificates(&certificate_chain_der)
        .map_err(|_| TlsIdentityInspectError::InvalidCertificate)?;
    let leaf = chain.first().ok_or(TlsIdentityInspectError::InvalidCertificate)?;
    let not_before_unix_secs = leaf.validity().not_before.timestamp();
    let not_after_unix_secs = leaf.validity().not_after.timestamp();
    let not_yet_valid = not_before_unix_secs > now_unix_secs;
    let expired = not_after_unix_secs < now_unix_secs;
    let expires_within_warning_window = !expired
        && not_after_unix_secs.saturating_sub(now_unix_secs)
            <= i64::try_from(warning_window.as_secs()).unwrap_or(i64::MAX);

    Ok(LoadedTlsIdentityMetadata {
        certificate_chain_len: certificate_chain_der.len(),
        common_name: collect_common_name(leaf),
        san_dns_names: collect_san_dns_names(leaf),
        fingerprint_sha256: hex_sha256(&certificate_chain_der[0]),
        not_before_unix_secs,
        not_after_unix_secs,
        not_yet_valid,
        expired,
        expires_within_warning_window,
    })
}

/// Classification outcome for initial downstream TLS preface bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsClientHelloClassification {
    /// Bytes do not look like TLS client hello traffic.
    NotTls,
    /// Additional bytes are needed before a classification can be completed.
    Incomplete,
    /// Bytes represent a TLS client hello.
    ClientHello(TlsClientHelloMetadata),
}

/// Minimal metadata extracted from a TLS client hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloMetadata {
    /// TLS record version as seen in the outer record header.
    pub record_version: u16,
    /// Server Name Indication if present.
    pub server_name: Option<String>,
}

/// TLS inspection failures for malformed client hello payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsInspectError {
    /// The record structure is malformed.
    Malformed(&'static str),
}

impl fmt::Display for TlsInspectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => write!(formatter, "malformed TLS client hello: {message}"),
        }
    }
}

impl std::error::Error for TlsInspectError {}

fn parse_certificates<'a>(
    chain_der: &'a [Vec<u8>],
) -> Result<Vec<X509Certificate<'a>>, CertificateValidationError> {
    chain_der
        .iter()
        .map(|der| {
            X509Certificate::from_der(der)
                .map(|(_, certificate)| certificate)
                .map_err(|_| CertificateValidationError::InvalidCertificate)
        })
        .collect()
}

fn validate_validity(
    certificate: &X509Certificate<'_>,
    now_unix_secs: i64,
) -> Result<(), CertificateValidationError> {
    let now = ASN1Time::from_timestamp(now_unix_secs)
        .map_err(|_| CertificateValidationError::InvalidCertificate)?;
    if certificate.validity().not_before > now {
        return Err(CertificateValidationError::CertificateNotYetValid);
    }
    if certificate.validity().not_after < now {
        return Err(CertificateValidationError::CertificateExpired);
    }
    Ok(())
}

fn validate_usage(
    certificate: &X509Certificate<'_>,
    usage: CertificateUsage,
) -> Result<(), CertificateValidationError> {
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|_| CertificateValidationError::InvalidCertificate)?
        .ok_or(CertificateValidationError::UsageMismatch)?;
    let allowed = match usage {
        CertificateUsage::ServerAuth => extended_key_usage.value.server_auth,
        CertificateUsage::ClientAuth => extended_key_usage.value.client_auth,
    };
    if !allowed {
        return Err(CertificateValidationError::UsageMismatch);
    }

    Ok(())
}

fn validate_identity(
    certificate: &X509Certificate<'_>,
    expected_identity: Option<&str>,
) -> Result<(), CertificateValidationError> {
    let Some(expected_identity) = expected_identity else {
        return Ok(());
    };

    let expected = expected_identity.to_ascii_lowercase();
    if collect_san_dns_names(certificate).iter().any(|name| name.eq_ignore_ascii_case(&expected)) {
        return Ok(());
    }

    if let Some(common_name) = collect_common_name(certificate) {
        if common_name.eq_ignore_ascii_case(&expected) {
            return Ok(());
        }
    }

    Err(CertificateValidationError::IdentityMismatch)
}

fn validate_chain_signatures(
    chain: &[X509Certificate<'_>],
    trusted_roots_der: &[Vec<u8>],
) -> Result<(), CertificateValidationError> {
    for pair in chain.windows(2) {
        let subject = &pair[0];
        let issuer = &pair[1];
        if subject.issuer() != issuer.subject() {
            return Err(CertificateValidationError::InvalidChainSignature);
        }
        subject
            .verify_signature(Some(issuer.public_key()))
            .map_err(|_| CertificateValidationError::InvalidChainSignature)?;
    }

    let last = chain.last().ok_or(CertificateValidationError::EmptyCertificateChain)?;
    for root_der in trusted_roots_der {
        let (_, root) = X509Certificate::from_der(root_der)
            .map_err(|_| CertificateValidationError::InvalidCertificate)?;
        if last.issuer() == root.subject() {
            last.verify_signature(Some(root.public_key()))
                .map_err(|_| CertificateValidationError::UntrustedIssuer)?;
            return Ok(());
        }
    }

    Err(CertificateValidationError::UntrustedIssuer)
}

fn collect_san_dns_names(certificate: &X509Certificate<'_>) -> Vec<String> {
    certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|subject_alternative_name| {
            subject_alternative_name
                .value
                .general_names
                .iter()
                .filter_map(|general_name| match general_name {
                    GeneralName::DNSName(name) => Some(name.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn collect_common_name(certificate: &X509Certificate<'_>) -> Option<String> {
    certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attribute| attribute.as_str().ok().map(ToOwned::to_owned))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Inspects initial downstream bytes and classifies them as TLS or non-TLS.
pub fn inspect_client_hello(bytes: &[u8]) -> Result<TlsClientHelloClassification, TlsInspectError> {
    if bytes.is_empty() {
        return Ok(TlsClientHelloClassification::Incomplete);
    }

    if bytes.len() < 5 {
        return Ok(TlsClientHelloClassification::Incomplete);
    }

    if bytes[0] != 22 {
        return Ok(TlsClientHelloClassification::NotTls);
    }

    let record_version = u16::from_be_bytes([bytes[1], bytes[2]]);
    let record_length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    let total_length = 5 + record_length;

    if bytes.len() < total_length {
        return Ok(TlsClientHelloClassification::Incomplete);
    }

    let payload = &bytes[5..total_length];
    if payload.len() < 4 {
        return Err(TlsInspectError::Malformed("missing handshake header"));
    }

    if payload[0] != 1 {
        return Ok(TlsClientHelloClassification::NotTls);
    }

    let handshake_length = u24_to_usize(&payload[1..4]);
    if payload.len() < 4 + handshake_length {
        return Err(TlsInspectError::Malformed("truncated client hello"));
    }

    let hello = &payload[4..4 + handshake_length];
    let server_name = parse_sni(hello)?;

    Ok(TlsClientHelloClassification::ClientHello(TlsClientHelloMetadata {
        record_version,
        server_name,
    }))
}

fn parse_sni(hello: &[u8]) -> Result<Option<String>, TlsInspectError> {
    let mut offset = 0;

    require_remaining(hello, offset, 2, "missing legacy version")?;
    offset += 2;

    require_remaining(hello, offset, 32, "missing random bytes")?;
    offset += 32;

    let session_id_len = usize::from(
        *hello.get(offset).ok_or(TlsInspectError::Malformed("missing session id length"))?,
    );
    offset += 1;
    require_remaining(hello, offset, session_id_len, "truncated session id")?;
    offset += session_id_len;

    let cipher_suites_len = read_u16(hello, &mut offset, "missing cipher suites length")?;
    let cipher_suites_len = usize::from(cipher_suites_len);
    require_remaining(hello, offset, cipher_suites_len, "truncated cipher suites")?;
    offset += cipher_suites_len;

    let compression_methods_len = usize::from(
        *hello
            .get(offset)
            .ok_or(TlsInspectError::Malformed("missing compression methods length"))?,
    );
    offset += 1;
    require_remaining(hello, offset, compression_methods_len, "truncated compression methods")?;
    offset += compression_methods_len;

    if offset == hello.len() {
        return Ok(None);
    }

    let extensions_len = usize::from(read_u16(hello, &mut offset, "missing extensions length")?);
    require_remaining(hello, offset, extensions_len, "truncated extensions")?;
    let extensions_end = offset + extensions_len;

    while offset < extensions_end {
        let extension_type = read_u16(hello, &mut offset, "missing extension type")?;
        let extension_len = usize::from(read_u16(hello, &mut offset, "missing extension length")?);
        require_remaining(hello, offset, extension_len, "truncated extension body")?;

        if extension_type == 0 {
            return parse_server_name_extension(&hello[offset..offset + extension_len]);
        }

        offset += extension_len;
    }

    Ok(None)
}

fn parse_server_name_extension(extension: &[u8]) -> Result<Option<String>, TlsInspectError> {
    let mut offset = 0;
    let list_len =
        usize::from(read_u16(extension, &mut offset, "missing server name list length")?);
    require_remaining(extension, offset, list_len, "truncated server name list")?;
    let list_end = offset + list_len;

    while offset < list_end {
        let name_type =
            *extension.get(offset).ok_or(TlsInspectError::Malformed("missing server name type"))?;
        offset += 1;
        let name_len = usize::from(read_u16(extension, &mut offset, "missing server name length")?);
        require_remaining(extension, offset, name_len, "truncated server name")?;

        if name_type == 0 {
            let name = std::str::from_utf8(&extension[offset..offset + name_len])
                .map_err(|_| TlsInspectError::Malformed("server name is not valid UTF-8"))?;
            return Ok(Some(name.to_string()));
        }

        offset += name_len;
    }

    Ok(None)
}

fn require_remaining(
    buffer: &[u8],
    offset: usize,
    expected: usize,
    message: &'static str,
) -> Result<(), TlsInspectError> {
    if buffer.len().saturating_sub(offset) < expected {
        return Err(TlsInspectError::Malformed(message));
    }

    Ok(())
}

fn read_u16(
    buffer: &[u8],
    offset: &mut usize,
    message: &'static str,
) -> Result<u16, TlsInspectError> {
    require_remaining(buffer, *offset, 2, message)?;
    let value = u16::from_be_bytes([buffer[*offset], buffer[*offset + 1]]);
    *offset += 2;
    Ok(value)
}

fn u24_to_usize(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};
    use std::{env, fs};

    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    use super::{
        inspect_client_hello, inspect_tls_identity_from_files, load_certificates_from_pem,
        load_private_key_from_pem, load_tls_identity_from_files, CertificateSource,
        CertificateValidationError, CertificateValidationPolicy, CertificateValidator,
        TlsClientHelloClassification, TlsInspectError, TlsTerminationConfig,
    };

    #[test]
    fn classify_non_tls_preface() -> Result<(), Box<dyn std::error::Error>> {
        let result = inspect_client_hello(b"GET / HTTP/1.1\r\n")?;

        assert_eq!(result, TlsClientHelloClassification::NotTls);
        Ok(())
    }

    #[test]
    fn classify_incomplete_tls_preface() -> Result<(), Box<dyn std::error::Error>> {
        let result = inspect_client_hello(&[22, 3, 1])?;

        assert_eq!(result, TlsClientHelloClassification::Incomplete);
        Ok(())
    }

    #[test]
    fn extract_sni_from_client_hello() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = build_client_hello(Some("example.com"));
        let result = inspect_client_hello(&bytes)?;

        match result {
            TlsClientHelloClassification::ClientHello(metadata) => {
                assert_eq!(metadata.server_name.as_deref(), Some("example.com"));
            }
            other => {
                return Err(format!("unexpected classification: {other:?}").into());
            }
        }

        Ok(())
    }

    #[test]
    fn malformed_client_hello_is_rejected() {
        let mut bytes = build_client_hello(Some("example.com"));
        bytes.truncate(20);

        let result = inspect_client_hello(&bytes);

        assert!(matches!(result, Ok(TlsClientHelloClassification::Incomplete)));
    }

    #[test]
    fn tls_termination_config_is_extensible() {
        let config = TlsTerminationConfig {
            certificate_source: CertificateSource::Files {
                cert_path: String::from("cert.pem"),
                key_path: String::from("key.pem"),
            },
        };

        assert!(matches!(config.certificate_source, CertificateSource::Files { .. }));
    }

    #[test]
    fn malformed_sni_extension_reports_error() {
        let mut bytes = build_client_hello(Some("example.com"));
        let last = bytes.len().saturating_sub(1);
        bytes[last] = 0xff;

        let result = inspect_client_hello(&bytes);

        assert!(matches!(
            result,
            Err(TlsInspectError::Malformed("server name is not valid UTF-8"))
        ));
    }

    #[test]
    fn certificate_validation_accepts_trusted_client_certificate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = certificate_fixtures(false)?;
        let mut validator = CertificateValidator::from_trust_anchors_pem(&fixtures.ca_pem)?;

        let identity = validator.validate_peer_certificates_pem(
            &fixtures.leaf_pem,
            &CertificateValidationPolicy::privileged_channel_client(Some(String::from(
                "operator.internal",
            ))),
            fixtures.now_unix_secs,
        )?;

        assert_eq!(identity.common_name.as_deref(), Some("operator.internal"));
        assert!(identity.fingerprint_sha256.len() == 64);
        assert_eq!(validator.metrics().validation_success_count, 1);
        Ok(())
    }

    #[test]
    fn certificate_validation_rejects_expired_certificate() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixtures = certificate_fixtures(true)?;
        let mut validator = CertificateValidator::from_trust_anchors_pem(&fixtures.ca_pem)?;

        let result = validator.validate_peer_certificates_pem(
            &fixtures.leaf_pem,
            &CertificateValidationPolicy::privileged_channel_client(Some(String::from(
                "operator.internal",
            ))),
            fixtures.now_unix_secs,
        );

        assert_eq!(result, Err(CertificateValidationError::CertificateExpired));
        assert_eq!(validator.metrics().mtls_validation_failure_count, 1);
        Ok(())
    }

    #[test]
    fn certificate_validation_rejects_identity_mismatch() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixtures = certificate_fixtures(false)?;
        let mut validator = CertificateValidator::from_trust_anchors_pem(&fixtures.ca_pem)?;

        let result = validator.validate_peer_certificates_pem(
            &fixtures.leaf_pem,
            &CertificateValidationPolicy::privileged_channel_server(Some(String::from(
                "other.internal",
            ))),
            fixtures.now_unix_secs,
        );

        assert_eq!(result, Err(CertificateValidationError::IdentityMismatch));
        Ok(())
    }

    #[test]
    fn certificate_validation_rejects_missing_eku_extension(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = certificate_fixtures_with_eku(false, false)?;
        let mut validator = CertificateValidator::from_trust_anchors_pem(&fixtures.ca_pem)?;

        let result = validator.validate_peer_certificates_pem(
            &fixtures.leaf_pem,
            &CertificateValidationPolicy::privileged_channel_client(Some(String::from(
                "operator.internal",
            ))),
            fixtures.now_unix_secs,
        );

        assert_eq!(result, Err(CertificateValidationError::UsageMismatch));
        Ok(())
    }

    #[test]
    fn certificate_validation_rejects_self_signed_leaf_with_root_subject(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let trusted_root = certificate_fixtures(false)?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let mut leaf_params = CertificateParams::new(vec![String::from("operator.internal")])?;
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params.distinguished_name.push(DnType::CommonName, "way-balancer Test Root");
        leaf_params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
        leaf_params.not_after = (now + Duration::from_secs(14 * 24 * 60 * 60)).into();
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let rogue_key = KeyPair::generate()?;
        let rogue_leaf = leaf_params.self_signed(&rogue_key)?;

        let mut validator = CertificateValidator::from_trust_anchors_pem(&trusted_root.ca_pem)?;
        let result = validator.validate_peer_certificates_pem(
            &rogue_leaf.pem(),
            &CertificateValidationPolicy::privileged_channel_client(Some(String::from(
                "operator.internal",
            ))),
            trusted_root.now_unix_secs,
        );

        assert_eq!(result, Err(CertificateValidationError::UntrustedIssuer));
        Ok(())
    }

    #[test]
    fn certificate_loading_rejects_invalid_material() {
        assert!(load_certificates_from_pem("not pem").is_err());
        assert!(load_private_key_from_pem("not key").is_err());
    }

    #[test]
    fn tls_identity_loading_reads_certificate_and_key_files(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = certificate_fixtures(false)?;
        let temp_dir = env::temp_dir().join(format!(
            "way-balancer-proto-tls-{}",
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&temp_dir)?;
        let cert_path = temp_dir.join("server.pem");
        let key_path = temp_dir.join("server.key");
        fs::write(&cert_path, &fixtures.leaf_pem)?;
        fs::write(&key_path, &fixtures.leaf_key_pem)?;

        let loaded = load_tls_identity_from_files(&cert_path, &key_path)?;

        assert_eq!(loaded.certificate_chain_der.len(), 1);
        assert!(!loaded.private_key_der.is_empty());

        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn tls_identity_inspection_surfaces_leaf_expiry_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = certificate_fixtures(false)?;
        let temp_dir = env::temp_dir().join(format!(
            "way-balancer-proto-tls-inspect-{}",
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&temp_dir)?;
        let cert_path = temp_dir.join("server.pem");
        let key_path = temp_dir.join("server.key");
        fs::write(&cert_path, &fixtures.leaf_pem)?;
        fs::write(&key_path, &fixtures.leaf_key_pem)?;

        let metadata = inspect_tls_identity_from_files(
            &cert_path,
            &key_path,
            fixtures.now_unix_secs,
            Duration::from_secs(30 * 24 * 60 * 60),
        )?;

        assert_eq!(metadata.certificate_chain_len, 1);
        assert_eq!(metadata.common_name.as_deref(), Some("operator.internal"));
        assert!(metadata.san_dns_names.iter().any(|name| name == "operator.internal"));
        assert!(!metadata.fingerprint_sha256.is_empty());
        assert!(!metadata.not_yet_valid);
        assert!(!metadata.expired);
        assert!(metadata.expires_within_warning_window);

        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_dir(&temp_dir);
        Ok(())
    }

    struct CertificateFixtures {
        ca_pem: String,
        leaf_pem: String,
        leaf_key_pem: String,
        now_unix_secs: i64,
    }

    fn certificate_fixtures(
        expired: bool,
    ) -> Result<CertificateFixtures, Box<dyn std::error::Error>> {
        certificate_fixtures_with_eku(expired, true)
    }

    fn certificate_fixtures_with_eku(
        expired: bool,
        include_eku: bool,
    ) -> Result<CertificateFixtures, Box<dyn std::error::Error>> {
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
        if include_eku {
            leaf_params.extended_key_usages = vec![
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            ];
        }
        let leaf_key = KeyPair::generate()?;
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;

        Ok(CertificateFixtures {
            ca_pem: ca_cert.pem(),
            leaf_pem: leaf_cert.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
            now_unix_secs: i64::try_from(now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs())?,
        })
    }

    fn build_client_hello(server_name: Option<&str>) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0_u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x00, 0x02]);
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);

        let mut extensions = Vec::new();
        if let Some(name) = server_name {
            let mut server_name_extension = Vec::new();
            let name_bytes = name.as_bytes();
            let list_len = u16::try_from(1 + 2 + name_bytes.len()).unwrap_or(u16::MAX);
            server_name_extension.extend_from_slice(&list_len.to_be_bytes());
            server_name_extension.push(0);
            let name_len = u16::try_from(name_bytes.len()).unwrap_or(u16::MAX);
            server_name_extension.extend_from_slice(&name_len.to_be_bytes());
            server_name_extension.extend_from_slice(name_bytes);

            extensions.extend_from_slice(&0_u16.to_be_bytes());
            let extension_len = u16::try_from(server_name_extension.len()).unwrap_or(u16::MAX);
            extensions.extend_from_slice(&extension_len.to_be_bytes());
            extensions.extend_from_slice(&server_name_extension);
        }

        let extensions_len = u16::try_from(extensions.len()).unwrap_or(u16::MAX);
        hello.extend_from_slice(&extensions_len.to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        let hello_len = u32::try_from(hello.len()).unwrap_or(u32::MAX);
        handshake.push(((hello_len >> 16) & 0xff) as u8);
        handshake.push(((hello_len >> 8) & 0xff) as u8);
        handshake.push((hello_len & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x01]);
        let handshake_len = u16::try_from(handshake.len()).unwrap_or(u16::MAX);
        record.extend_from_slice(&handshake_len.to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
