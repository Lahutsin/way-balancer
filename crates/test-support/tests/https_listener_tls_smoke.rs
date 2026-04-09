use std::fs;
use std::time::{Duration, SystemTime};

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

struct CertificateFixtures {
    ca_pem: String,
    leaf_pem: String,
    leaf_key_pem: String,
    now_unix_secs: i64,
}

#[test]
fn https_listener_example_loads_tls_material_and_validates_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = certificate_fixtures()?;
    let temp_dir = std::env::temp_dir().join(format!(
        "way-balancer-https-listener-{}",
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir_all(&temp_dir)?;
    let cert_path = temp_dir.join("server.pem");
    let key_path = temp_dir.join("server.key");
    fs::write(&cert_path, &fixtures.leaf_pem)?;
    fs::write(&key_path, &fixtures.leaf_key_pem)?;

    let config_json = format!(
        r#"{{
            "api_version": "v1_alpha1",
            "name": "edge-https-test",
            "listeners": [
                {{
                    "name": "public-https",
                    "class": "public",
                    "bind_address": "127.0.0.1:8443",
                    "protocol": "https",
                    "tls_termination": {{
                        "certificate_source": {{
                            "type": "files",
                            "cert_path": "{cert_path}",
                            "key_path": "{key_path}"
                        }}
                    }},
                    "routes": ["web"]
                }}
            ],
            "routes": [
                {{
                    "name": "web",
                    "match": {{ "type": "path_prefix", "prefix": "/" }},
                    "upstream_cluster": "frontend"
                }}
            ],
            "upstream_clusters": [
                {{
                    "name": "frontend",
                    "endpoints": [
                        {{
                            "id": "frontend-a",
                            "address": "127.0.0.1:8081",
                            "state": "ready",
                            "weight": 1
                        }}
                    ]
                }}
            ]
        }}"#,
        cert_path = cert_path.display(),
        key_path = key_path.display(),
    );

    let config = lb_config_model::WorkspaceConfig::parse_json_str(&config_json)?;
    config.validate()?;
    let snapshot = config.compile_snapshot()?;
    let listener = &snapshot.compiled_listeners()[0];
    let tls_termination = listener.tls_termination.as_ref().ok_or("missing tls_termination")?;
    let loaded = lb_proto_tls::load_tls_identity_from_files(
        &tls_termination.cert_path,
        &tls_termination.key_path,
    )?;

    assert_eq!(loaded.certificate_chain_der.len(), 1);
    assert!(!loaded.private_key_der.is_empty());

    let mut validator =
        lb_proto_tls::CertificateValidator::from_trust_anchors_pem(&fixtures.ca_pem)?;
    let identity = validator.validate_peer_certificates_pem(
        &fixtures.leaf_pem,
        &lb_proto_tls::CertificateValidationPolicy::privileged_channel_server(Some(
            String::from("edge.internal"),
        )),
        fixtures.now_unix_secs,
    )?;

    assert_eq!(identity.common_name.as_deref(), Some("edge.internal"));

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_dir(&temp_dir);
    Ok(())
}

fn certificate_fixtures() -> Result<CertificateFixtures, Box<dyn std::error::Error>> {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, "way-balancer Test Root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.not_before = (now - Duration::from_secs(30 * 24 * 60 * 60)).into();
    ca_params.not_after = (now + Duration::from_secs(365 * 24 * 60 * 60)).into();
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut leaf_params = CertificateParams::new(vec![String::from("edge.internal")])?;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params.distinguished_name.push(DnType::CommonName, "edge.internal");
    leaf_params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
    leaf_params.not_after = (now + Duration::from_secs(14 * 24 * 60 * 60)).into();
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate()?;
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;

    Ok(CertificateFixtures {
        ca_pem: ca_cert.pem(),
        leaf_pem: leaf_cert.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
        now_unix_secs: i64::try_from(now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs())?,
    })
}