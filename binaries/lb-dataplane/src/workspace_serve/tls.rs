#[derive(Debug)]
struct FallbackServerCertResolver {
    default_key: Arc<rustls::sign::CertifiedKey>,
    sni_keys: BTreeMap<String, Arc<rustls::sign::CertifiedKey>>,
}

#[derive(Debug)]
struct DisabledTicketer;

impl ProducesTickets for DisabledTicketer {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

impl ResolvesServerCert for FallbackServerCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        client_hello
            .server_name()
            .and_then(|name| self.sni_keys.get(&name.to_ascii_lowercase()).cloned())
            .or_else(|| Some(Arc::clone(&self.default_key)))
    }
}

#[derive(Debug, Clone)]
enum ManagedProxyConfig {
    Http1(lb_runtime::Http1ProxyConfig),
    Http2(lb_runtime::Http2ProxyConfig),
    Https(ManagedHttpsProxyConfig),
    Http3(ManagedHttp3ProxyConfig),
}

#[derive(Debug, Clone)]
struct ManagedHttpsProxyConfig {
    http1: lb_runtime::Http1ProxyConfig,
    http2: lb_runtime::Http2ProxyConfig,
    tls_server_config: Arc<rustls::ServerConfig>,
    tls_status: ListenerTlsStatus,
}

#[derive(Debug, Clone)]
struct ManagedHttp3ProxyConfig {
    http1: lb_runtime::Http1ProxyConfig,
    quic_server_config: Arc<quinn::ServerConfig>,
}

#[derive(Debug, Clone)]
struct ManagedAdminTlsConfig {
    tls_server_config: Arc<rustls::ServerConfig>,
    tls_status: ListenerTlsStatus,
}

fn build_tls_server_config(
    tls_termination: &lb_config_model::ListenerTlsTerminationConfig,
) -> Result<rustls::ServerConfig, DynError> {
    ensure_rustls_crypto_provider();
    let cert_resolver = build_tls_cert_resolver(tls_termination)?;
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(
        protocol_versions_for_minimum(tls_termination.minimum_version),
    )
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(cert_resolver));
    config.alpn_protocols =
        tls_termination.alpn_protocols.iter().map(|protocol| protocol.wire_id().to_vec()).collect();
    apply_tls_session_resumption_policy(&mut config, &tls_termination.session_resumption)?;
    Ok(config)
}

fn apply_tls_session_resumption_policy(
    config: &mut rustls::ServerConfig,
    session_resumption: &lb_config_model::ListenerTlsSessionResumptionConfig,
) -> Result<(), DynError> {
    match session_resumption.mode {
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Disabled => {
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.ticketer = Arc::new(DisabledTicketer);
            config.send_tls13_tickets = 0;
        }
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Stateful => {
            config.session_storage = rustls::server::ServerSessionMemoryCache::new(
                session_resumption.session_cache_size,
            );
            config.ticketer = Arc::new(DisabledTicketer);
            config.send_tls13_tickets = 0;
        }
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Tickets => {
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().map_err(to_dyn_error)?;
            config.send_tls13_tickets = session_resumption.tls13_ticket_count;
        }
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Hybrid => {
            config.session_storage = rustls::server::ServerSessionMemoryCache::new(
                session_resumption.session_cache_size,
            );
            config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().map_err(to_dyn_error)?;
            config.send_tls13_tickets = session_resumption.tls13_ticket_count;
        }
    }
    Ok(())
}

fn build_tls_cert_resolver(
    tls_termination: &lb_config_model::ListenerTlsTerminationConfig,
) -> Result<FallbackServerCertResolver, DynError> {
    let default_key =
        Arc::new(load_certified_key_from_source(&tls_termination.certificate_source)?);
    let mut sni_keys = BTreeMap::new();
    for certificate in &tls_termination.sni_certificates {
        let certified_key =
            Arc::new(load_certified_key_from_source(&certificate.certificate_source)?);
        for server_name in &certificate.server_names {
            let normalized = lb_proto_http::canonicalize_host(server_name).map_err(to_dyn_error)?;
            sni_keys.insert(normalized, Arc::clone(&certified_key));
        }
    }
    Ok(FallbackServerCertResolver { default_key, sni_keys })
}

fn load_certified_key_from_source(
    certificate_source: &lb_config_model::ListenerCertificateSourceConfig,
) -> Result<rustls::sign::CertifiedKey, DynError> {
    let loaded = lb_proto_tls::load_tls_identity_from_files(
        certificate_source.cert_path(),
        certificate_source.key_path(),
    )
    .map_err(to_dyn_error)?;
    let certificates =
        loaded.certificate_chain_der.into_iter().map(CertificateDer::from).collect::<Vec<_>>();
    let private_key = PrivateKeyDer::try_from(loaded.private_key_der).map_err(to_dyn_error)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut certified_key =
        rustls::sign::CertifiedKey::from_der(certificates, private_key, &provider)
            .map_err(to_dyn_error)?;
    if let Some(ocsp_path) = certificate_source.ocsp_path() {
        certified_key.ocsp = Some(fs::read(ocsp_path).map_err(to_dyn_error)?);
    }
    Ok(certified_key)
}

fn build_listener_tls_status(
    tls_termination: &lb_config_model::ListenerTlsTerminationConfig,
) -> Result<ListenerTlsStatus, DynError> {
    let default_certificate =
        build_tls_certificate_status("default", Vec::new(), &tls_termination.certificate_source)?;
    let mut sni_certificates = Vec::with_capacity(tls_termination.sni_certificates.len());
    let mut reason_codes = Vec::new();

    merge_tls_reason_codes(&mut reason_codes, &default_certificate);
    for certificate in &tls_termination.sni_certificates {
        let status = build_tls_certificate_status(
            "sni",
            certificate.server_names.clone(),
            &certificate.certificate_source,
        )?;
        merge_tls_reason_codes(&mut reason_codes, &status);
        sni_certificates.push(status);
    }

    let state = if reason_codes.iter().any(|reason| reason == "tls_certificate_expired") {
        "expired"
    } else if reason_codes.iter().any(|reason| reason == "tls_certificate_not_yet_valid") {
        "not_yet_valid"
    } else if reason_codes.iter().any(|reason| reason == "tls_certificate_expiring_soon") {
        "expiring_soon"
    } else {
        "healthy"
    };

    Ok(ListenerTlsStatus {
        state: String::from(state),
        warning_window_secs: TLS_STATUS_EXPIRY_WARNING_WINDOW.as_secs(),
        minimum_version: String::from(tls_minimum_version_name(tls_termination.minimum_version)),
        alpn_protocols: tls_termination
            .alpn_protocols
            .iter()
            .map(|protocol| String::from(tls_alpn_protocol_name(*protocol)))
            .collect(),
        session_resumption: ListenerTlsSessionResumptionStatus {
            mode: String::from(tls_session_resumption_mode_name(
                tls_termination.session_resumption.mode,
            )),
            session_cache_size: tls_termination.session_resumption.session_cache_size,
            tls13_ticket_count: tls_termination.session_resumption.tls13_ticket_count,
        },
        default_certificate,
        sni_certificates,
        reason_codes,
    })
}

fn build_tls_certificate_status(
    label: &str,
    server_names: Vec<String>,
    certificate_source: &lb_config_model::ListenerCertificateSourceConfig,
) -> Result<ListenerTlsCertificateStatus, DynError> {
    match certificate_source {
        lb_config_model::ListenerCertificateSourceConfig::Files {
            cert_path,
            key_path,
            ocsp_path,
        } => {
            let metadata = lb_proto_tls::inspect_tls_identity_from_files(
                cert_path,
                key_path,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs() as i64)
                    .unwrap_or_default(),
                TLS_STATUS_EXPIRY_WARNING_WINDOW,
            )
            .map_err(to_dyn_error)?;
            Ok(ListenerTlsCertificateStatus {
                label: String::from(label),
                server_names,
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                ocsp_path: ocsp_path.clone(),
                common_name: metadata.common_name,
                san_dns_names: metadata.san_dns_names,
                fingerprint_sha256: metadata.fingerprint_sha256,
                not_before_unix_secs: metadata.not_before_unix_secs,
                not_after_unix_secs: metadata.not_after_unix_secs,
                not_yet_valid: metadata.not_yet_valid,
                expired: metadata.expired,
                expires_within_warning_window: metadata.expires_within_warning_window,
            })
        }
    }
}

fn merge_tls_reason_codes(
    reason_codes: &mut Vec<String>,
    certificate: &ListenerTlsCertificateStatus,
) {
    if certificate.expired {
        push_unique_reason(reason_codes, "tls_certificate_expired");
    }
    if certificate.not_yet_valid {
        push_unique_reason(reason_codes, "tls_certificate_not_yet_valid");
    }
    if certificate.expires_within_warning_window {
        push_unique_reason(reason_codes, "tls_certificate_expiring_soon");
    }
}

fn tls_minimum_version_name(
    minimum_version: lb_config_model::ListenerTlsMinimumVersionConfig,
) -> &'static str {
    match minimum_version {
        lb_config_model::ListenerTlsMinimumVersionConfig::Tls12 => "tls12",
        lb_config_model::ListenerTlsMinimumVersionConfig::Tls13 => "tls13",
    }
}

fn tls_session_resumption_mode_name(
    mode: lb_config_model::ListenerTlsSessionResumptionModeConfig,
) -> &'static str {
    match mode {
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Disabled => "disabled",
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Stateful => "stateful",
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Tickets => "tickets",
        lb_config_model::ListenerTlsSessionResumptionModeConfig::Hybrid => "hybrid",
    }
}

fn tls_alpn_protocol_name(protocol: lb_config_model::ListenerAlpnProtocolConfig) -> &'static str {
    match protocol {
        lb_config_model::ListenerAlpnProtocolConfig::Http2 => "http2",
        lb_config_model::ListenerAlpnProtocolConfig::Http11 => "http11",
        lb_config_model::ListenerAlpnProtocolConfig::Http3 => "http3",
    }
}

fn protocol_versions_for_minimum(
    minimum_version: lb_config_model::ListenerTlsMinimumVersionConfig,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match minimum_version {
        lb_config_model::ListenerTlsMinimumVersionConfig::Tls12 => &TLS12_AND_TLS13,
        lb_config_model::ListenerTlsMinimumVersionConfig::Tls13 => &TLS13_ONLY,
    }
}

