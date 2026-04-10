use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::WorkspaceSnapshot;

const SHA256_HEX_LEN: usize = 64;
const MAX_SIGNER_IDENTITY_LEN: usize = 128;
const ED25519_PUBLIC_KEY_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspaceSecurityConfig {
    pub insecure_dev_mode: InsecureDevModeConfig,
    pub artifact_verification: ArtifactVerificationConfig,
    #[serde(skip_serializing_if = "TrustedClientIpConfig::is_default")]
    pub trusted_client_ip: TrustedClientIpConfig,
    #[serde(skip_serializing_if = "AnonymousSourceFilterConfig::is_default")]
    pub anonymous_source_filter: AnonymousSourceFilterConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TrustedClientIpConfig {
    pub enabled: bool,
    pub trusted_proxy_cidrs: Vec<String>,
}

impl TrustedClientIpConfig {
    #[must_use]
    pub fn is_default(&self) -> bool {
        !self.enabled && self.trusted_proxy_cidrs.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AnonymousSourceFilterConfig {
    pub enabled: bool,
    pub deny_cidrs: Vec<String>,
    pub deny_vpn: bool,
    pub deny_proxy: bool,
    pub deny_socks: bool,
    pub deny_tor: bool,
    pub vpn_cidrs: Vec<String>,
    pub proxy_cidrs: Vec<String>,
    pub socks_cidrs: Vec<String>,
    pub tor_exit_cidrs: Vec<String>,
}

impl AnonymousSourceFilterConfig {
    #[must_use]
    pub fn is_default(&self) -> bool {
        !self.enabled
            && self.deny_cidrs.is_empty()
            && !self.deny_vpn
            && !self.deny_proxy
            && !self.deny_socks
            && !self.deny_tor
            && self.vpn_cidrs.is_empty()
            && self.proxy_cidrs.is_empty()
            && self.socks_cidrs.is_empty()
            && self.tor_exit_cidrs.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct InsecureDevModeConfig {
    pub enabled: bool,
    pub acknowledgement: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVerificationMode {
    #[default]
    Enforced,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactVerificationConfig {
    pub mode: ArtifactVerificationMode,
    pub trusted_signers: Vec<TrustedArtifactSignerConfig>,
}

impl Default for ArtifactVerificationConfig {
    fn default() -> Self {
        Self { mode: ArtifactVerificationMode::Enforced, trusted_signers: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedArtifactSignerConfig {
    pub identity: String,
    pub public_key_ed25519: String,
}

impl TrustedArtifactSignerConfig {
    #[must_use]
    pub fn new(identity: impl Into<String>, public_key_ed25519: impl Into<String>) -> Self {
        let identity = identity.into();
        Self { identity: identity.trim().to_owned(), public_key_ed25519: public_key_ed25519.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAttestation {
    pub signer_identity: String,
    pub artifact_digest_sha256: String,
    pub signature_ed25519: String,
}

#[derive(Debug, Clone)]
pub struct ArtifactSigner {
    signer_identity: String,
    signing_key: SigningKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactSigningError {
    EmptySignerIdentity,
    SignerIdentityTooLong,
    InvalidPrivateKeyFormat,
}

impl std::fmt::Display for ArtifactSigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySignerIdentity => {
                formatter.write_str("artifact signer identity must not be empty")
            }
            Self::SignerIdentityTooLong => {
                formatter.write_str("artifact signer identity exceeds max length")
            }
            Self::InvalidPrivateKeyFormat => formatter.write_str(
                "artifact signer private key must be a lowercase ed25519 hex seed",
            ),
        }
    }
}

impl std::error::Error for ArtifactSigningError {}

impl ArtifactSigner {
    pub fn from_signing_key_hex(
        signer_identity: impl Into<String>,
        signing_key_ed25519: &str,
    ) -> Result<Self, ArtifactSigningError> {
        let signer_identity = signer_identity.into();
        let signer_identity = signer_identity.trim().to_owned();
        validate_signer_identity(&signer_identity).map_err(|error| match error {
            ArtifactIntegrityError::EmptySignerIdentity => ArtifactSigningError::EmptySignerIdentity,
            ArtifactIntegrityError::SignerIdentityTooLong => {
                ArtifactSigningError::SignerIdentityTooLong
            }
            _ => ArtifactSigningError::InvalidPrivateKeyFormat,
        })?;
        let seed = decode_hex_array::<32>(signing_key_ed25519)
            .ok_or(ArtifactSigningError::InvalidPrivateKeyFormat)?;

        Ok(Self { signer_identity, signing_key: SigningKey::from_bytes(&seed) })
    }

    #[must_use]
    pub fn signer_identity(&self) -> &str {
        &self.signer_identity
    }

    #[must_use]
    pub fn trusted_signer(&self) -> TrustedArtifactSignerConfig {
        TrustedArtifactSignerConfig {
            identity: self.signer_identity.clone(),
            public_key_ed25519: encode_hex(self.signing_key.verifying_key().as_bytes()),
        }
    }

    #[must_use]
    pub fn attest_snapshot(&self, snapshot: &WorkspaceSnapshot) -> ArtifactAttestation {
        let artifact_digest_sha256 = snapshot.metadata().digest_sha256().to_owned();
        let message = attestation_message(&self.signer_identity, &artifact_digest_sha256);
        let signature = self.signing_key.sign(&message);

        ArtifactAttestation {
            signer_identity: self.signer_identity.clone(),
            artifact_digest_sha256,
            signature_ed25519: encode_hex(&signature.to_bytes()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactIntegrityError {
    MissingAttestation,
    EmptySignerIdentity,
    SignerIdentityTooLong,
    InvalidArtifactDigestFormat,
    ArtifactDigestMismatch,
    InvalidTrustedSignerPublicKey,
    InvalidSignatureFormat,
    UntrustedSigner,
    SignatureVerificationFailed,
    InsecureModeNotEnabled,
    MissingInsecureDevAcknowledgement,
}

impl std::fmt::Display for ArtifactIntegrityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAttestation => formatter
                .write_str("artifact attestation is required by the snapshot security posture"),
            Self::EmptySignerIdentity => {
                formatter.write_str("artifact attestation signer identity must not be empty")
            }
            Self::SignerIdentityTooLong => {
                formatter.write_str("artifact attestation signer identity exceeds max length")
            }
            Self::InvalidArtifactDigestFormat => formatter
                .write_str("artifact attestation digest must be a lowercase sha256 hex string"),
            Self::ArtifactDigestMismatch => {
                formatter.write_str("artifact attestation digest does not match snapshot digest")
            }
            Self::InvalidTrustedSignerPublicKey => formatter.write_str(
                "trusted signer public key must be a lowercase ed25519 hex string",
            ),
            Self::InvalidSignatureFormat => formatter.write_str(
                "artifact attestation signature must be a lowercase ed25519 hex string",
            ),
            Self::UntrustedSigner => {
                formatter.write_str("artifact attestation signer is not trusted by snapshot policy")
            }
            Self::SignatureVerificationFailed => formatter
                .write_str("artifact attestation signature verification failed"),
            Self::InsecureModeNotEnabled => formatter.write_str(
                "artifact verification may only be disabled when insecure_dev_mode is enabled",
            ),
            Self::MissingInsecureDevAcknowledgement => {
                formatter.write_str("insecure_dev_mode requires a non-empty acknowledgement")
            }
        }
    }
}

impl std::error::Error for ArtifactIntegrityError {}

pub fn verify_snapshot_artifact_integrity(
    snapshot: &WorkspaceSnapshot,
    attestation: Option<&ArtifactAttestation>,
) -> Result<(), ArtifactIntegrityError> {
    let security = snapshot.security();
    match security.artifact_verification.mode {
        ArtifactVerificationMode::Enforced => {
            let Some(attestation) = attestation else {
                return Err(ArtifactIntegrityError::MissingAttestation);
            };

            let signer_identity = attestation.signer_identity.trim();
            validate_signer_identity(signer_identity)?;
            if !is_lower_hex_digest(&attestation.artifact_digest_sha256) {
                return Err(ArtifactIntegrityError::InvalidArtifactDigestFormat);
            }
            if attestation.artifact_digest_sha256 != snapshot.metadata().digest_sha256() {
                return Err(ArtifactIntegrityError::ArtifactDigestMismatch);
            }

            let trusted_signer = security
                .artifact_verification
                .trusted_signers
                .iter()
                .find(|trusted_signer| trusted_signer.identity.trim() == signer_identity)
                .ok_or(ArtifactIntegrityError::UntrustedSigner)?;
            let verifying_key = parse_verifying_key(&trusted_signer.public_key_ed25519)?;
            let signature = parse_signature(&attestation.signature_ed25519)?;
            let message = attestation_message(signer_identity, &attestation.artifact_digest_sha256);
            verifying_key
                .verify(&message, &signature)
                .map_err(|_| ArtifactIntegrityError::SignatureVerificationFailed)?;

            Ok(())
        }
        ArtifactVerificationMode::Disabled => {
            if !security.insecure_dev_mode.enabled {
                return Err(ArtifactIntegrityError::InsecureModeNotEnabled);
            }

            let acknowledgement = security
                .insecure_dev_mode
                .acknowledgement
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if acknowledgement.is_none() {
                return Err(ArtifactIntegrityError::MissingInsecureDevAcknowledgement);
            }

            Ok(())
        }
    }
}

fn validate_signer_identity(signer_identity: &str) -> Result<(), ArtifactIntegrityError> {
    let signer_identity = signer_identity.trim();
    if signer_identity.is_empty() {
        return Err(ArtifactIntegrityError::EmptySignerIdentity);
    }
    if signer_identity.len() > MAX_SIGNER_IDENTITY_LEN {
        return Err(ArtifactIntegrityError::SignerIdentityTooLong);
    }
    Ok(())
}

fn parse_verifying_key(public_key_ed25519: &str) -> Result<VerifyingKey, ArtifactIntegrityError> {
    let bytes = decode_hex_array::<32>(public_key_ed25519)
        .ok_or(ArtifactIntegrityError::InvalidTrustedSignerPublicKey)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| ArtifactIntegrityError::InvalidTrustedSignerPublicKey)
}

fn parse_signature(signature_ed25519: &str) -> Result<Signature, ArtifactIntegrityError> {
    let bytes = decode_hex_array::<64>(signature_ed25519)
        .ok_or(ArtifactIntegrityError::InvalidSignatureFormat)?;
    Ok(Signature::from_bytes(&bytes))
}

fn attestation_message(signer_identity: &str, artifact_digest_sha256: &str) -> Vec<u8> {
    format!(
        "way-balancer-artifact-attestation-v1\n{signer_identity}\n{artifact_digest_sha256}"
    )
    .into_bytes()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(nibble_to_hex(byte >> 4));
        encoded.push(nibble_to_hex(byte & 0x0f));
    }
    encoded
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => unreachable!(),
    }
}

fn decode_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }

    let mut bytes = [0_u8; N];
    let value = value.as_bytes();
    for (index, chunk) in value.chunks_exact(2).enumerate() {
        bytes[index] = (hex_value(chunk[0])? << 4) | hex_value(chunk[1])?;
    }
    Some(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn is_lower_hex_len(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_lower_hex_digest(value: &str) -> bool {
    is_lower_hex_len(value, SHA256_HEX_LEN)
}

pub(crate) fn is_lower_hex_ed25519_public_key(value: &str) -> bool {
    is_lower_hex_len(value, ED25519_PUBLIC_KEY_HEX_LEN)
}

#[cfg(test)]
mod tests {
    use super::{
        verify_snapshot_artifact_integrity, ArtifactIntegrityError, ArtifactSigner,
        ArtifactSigningError, ArtifactVerificationMode, TrustedArtifactSignerConfig,
    };
    use crate::WorkspaceConfig;

    const TEST_SIGNER_IDENTITY: &str = "control-plane";
    const TEST_SIGNING_KEY_ED25519: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn signer() -> Result<ArtifactSigner, Box<dyn std::error::Error>> {
        Ok(ArtifactSigner::from_signing_key_hex(
            TEST_SIGNER_IDENTITY,
            TEST_SIGNING_KEY_ED25519,
        )?)
    }

    fn signed_snapshot() -> Result<crate::WorkspaceSnapshot, Box<dyn std::error::Error>> {
        let signer = signer()?;
        let mut config = WorkspaceConfig::foundation();
        config.security.artifact_verification.trusted_signers = vec![signer.trusted_signer()];
        Ok(config.compile_snapshot()?)
    }

    #[test]
    fn enforced_integrity_rejects_missing_attestation() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = signed_snapshot()?;

        assert_eq!(
            verify_snapshot_artifact_integrity(&snapshot, None),
            Err(ArtifactIntegrityError::MissingAttestation)
        );
        Ok(())
    }

    #[test]
    fn disabled_integrity_requires_explicit_insecure_dev_acknowledgement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = WorkspaceConfig::foundation();
        config.security.artifact_verification.mode = ArtifactVerificationMode::Disabled;
        config.security.insecure_dev_mode.enabled = true;
        config.security.insecure_dev_mode.acknowledgement =
            Some(String::from("development-only override"));
        let snapshot = config.compile_snapshot()?;

        assert!(verify_snapshot_artifact_integrity(&snapshot, None).is_ok());
        Ok(())
    }

    #[test]
    fn enforced_integrity_accepts_trusted_attestation() -> Result<(), Box<dyn std::error::Error>> {
        let signer = signer()?;
        let snapshot = signed_snapshot()?;

        assert!(verify_snapshot_artifact_integrity(&snapshot, Some(&signer.attest_snapshot(&snapshot)))
            .is_ok());
        Ok(())
    }

    #[test]
    fn enforced_integrity_rejects_forged_signature() -> Result<(), Box<dyn std::error::Error>> {
        let signer = signer()?;
        let snapshot = signed_snapshot()?;
        let mut attestation = signer.attest_snapshot(&snapshot);
        attestation.signature_ed25519 = String::from(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        assert_eq!(
            verify_snapshot_artifact_integrity(&snapshot, Some(&attestation)),
            Err(ArtifactIntegrityError::SignatureVerificationFailed)
        );
        Ok(())
    }

    #[test]
    fn signer_identity_is_trimmed_and_blank_identity_is_rejected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signer = ArtifactSigner::from_signing_key_hex(
            "  control-plane  ",
            TEST_SIGNING_KEY_ED25519,
        )?;
        assert_eq!(signer.signer_identity(), TEST_SIGNER_IDENTITY);
        assert!(matches!(
            ArtifactSigner::from_signing_key_hex("   ", TEST_SIGNING_KEY_ED25519),
            Err(ArtifactSigningError::EmptySignerIdentity)
        ));
        Ok(())
    }

    #[test]
    fn trusted_signer_config_normalizes_identity_and_verification_uses_trimmed_match(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signer = signer()?;
        let mut config = WorkspaceConfig::foundation();
        config.security.artifact_verification.trusted_signers = vec![
            TrustedArtifactSignerConfig::new("  control-plane  ", signer.trusted_signer().public_key_ed25519),
        ];
        let snapshot = config.compile_snapshot()?;
        let attestation = signer.attest_snapshot(&snapshot);

        assert!(verify_snapshot_artifact_integrity(&snapshot, Some(&attestation)).is_ok());
        Ok(())
    }
}
