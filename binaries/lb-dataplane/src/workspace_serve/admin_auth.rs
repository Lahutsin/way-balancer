fn admin_auth_error_contract(error: &AdminAuthFailure) -> (lb_admin_api::AdminApiErrorCode, bool) {
    match (error.status, error.outcome) {
        ("503 Service Unavailable", _) => (lb_admin_api::AdminApiErrorCode::Misconfigured, false),
        ("409 Conflict", _) => (lb_admin_api::AdminApiErrorCode::ReplayRejected, false),
        ("403 Forbidden", _) => (lb_admin_api::AdminApiErrorCode::Forbidden, false),
        _ => (lb_admin_api::AdminApiErrorCode::Unauthorized, false),
    }
}

fn consume_admin_rate_limit(
    key: AdminRateLimitKey,
    policy: &CompiledAdminPolicy,
    rate_limit_state: &StdMutex<AdminRateLimitState>,
) -> bool {
    let now = Instant::now();
    let mut guard = rate_limit_state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.buckets.retain(|_, bucket| {
        now.saturating_duration_since(bucket.last_refill) <= Duration::from_secs(600)
    });
    let bucket = guard.buckets.entry(key).or_insert(AdminTokenBucket {
        tokens: f64::from(policy.rate_limit.burst),
        last_refill: now,
    });
    let refill_rate_per_sec = f64::from(policy.rate_limit.requests_per_minute) / 60.0;
    let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens =
        (bucket.tokens + elapsed * refill_rate_per_sec).min(f64::from(policy.rate_limit.burst));
    bucket.last_refill = now;
    if bucket.tokens < 1.0 {
        return false;
    }
    bucket.tokens -= 1.0;
    true
}

struct AdminAuthFailure {
    status: &'static str,
    headers: Vec<&'static str>,
    body: String,
    actor: String,
    auth_mode: String,
    outcome: &'static str,
    detail: String,
}

struct ResolvedSecretMaterial {
    value: String,
    source_kind: &'static str,
    source_reference: String,
    supports_rotation_without_reload: bool,
}

struct SecretMaterialResolutionError {
    source_kind: &'static str,
    source_reference: String,
    state: &'static str,
    detail: String,
}

struct ResolvedAdminSecret {
    value: String,
    actor: String,
    auth_mode: &'static str,
}

fn authenticate_admin_request(
    request: &crate::DemoRequestHead,
    request_body: &[u8],
    action: AdminRequestAction,
    source_ip: IpAddr,
    policy: &CompiledAdminPolicy,
    replay_state: &StdMutex<AdminReplayState>,
    legacy_admin_secret: &str,
    request_id: &str,
) -> Result<AdminRequestContext, AdminAuthFailure> {
    let required_permission = action.permission();
    match &policy.auth {
        CompiledAdminAuthPolicy::Bearer { secret_env, permissions } => {
            let Some(bearer_token) = request.authorization_bearer.as_deref() else {
                return Err(AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: vec!["WWW-Authenticate: Bearer"],
                    body: String::from("admin authorization required\n"),
                    actor: String::from("anonymous"),
                    auth_mode: String::from("bearer"),
                    outcome: "unauthenticated",
                    detail: String::from("missing bearer token"),
                });
            };
            let expected =
                resolve_admin_secret(secret_env, legacy_admin_secret, "bearer", "shared-bearer")?;
            if !crate::constant_time_eq(bearer_token.as_bytes(), expected.value.as_bytes()) {
                return Err(AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: vec!["WWW-Authenticate: Bearer"],
                    body: String::from("admin authorization required\n"),
                    actor: String::from("shared-bearer"),
                    auth_mode: String::from("bearer"),
                    outcome: "unauthenticated",
                    detail: String::from("bearer token mismatch"),
                });
            }
            if !permissions.contains(&required_permission) {
                return Err(AdminAuthFailure {
                    status: "403 Forbidden",
                    headers: Vec::new(),
                    body: String::from("admin action not permitted\n"),
                    actor: String::from("shared-bearer"),
                    auth_mode: String::from("bearer"),
                    outcome: "forbidden",
                    detail: format!(
                        "shared bearer lacks {} permission",
                        admin_permission_name(required_permission)
                    ),
                });
            }
            Ok(AdminRequestContext {
                request_id: String::from(request_id),
                actor: expected.actor,
                auth_mode: String::from(expected.auth_mode),
                source: source_ip,
            })
        }
        CompiledAdminAuthPolicy::SignedHeaders { operators, max_clock_skew, nonce_ttl } => {
            let actor = request
                .header_value("x-lb-admin-actor")
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: String::from("anonymous"),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("missing x-lb-admin-actor header"),
                })?;
            let operator = operators.get(actor).ok_or_else(|| AdminAuthFailure {
                status: "401 Unauthorized",
                headers: Vec::new(),
                body: String::from("signed admin authorization required\n"),
                actor: actor.to_string(),
                auth_mode: String::from("signed_headers"),
                outcome: "unauthenticated",
                detail: String::from("unknown admin operator"),
            })?;
            if !operator.permissions.contains(&required_permission) {
                return Err(AdminAuthFailure {
                    status: "403 Forbidden",
                    headers: Vec::new(),
                    body: String::from("admin action not permitted\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "forbidden",
                    detail: format!(
                        "operator lacks {} permission",
                        admin_permission_name(required_permission)
                    ),
                });
            }

            let timestamp_header =
                request.header_value("x-lb-admin-timestamp").ok_or_else(|| AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("missing x-lb-admin-timestamp header"),
                })?;
            let timestamp = timestamp_header.parse::<u64>().map_err(|_| AdminAuthFailure {
                status: "401 Unauthorized",
                headers: Vec::new(),
                body: String::from("signed admin authorization required\n"),
                actor: actor.to_string(),
                auth_mode: String::from("signed_headers"),
                outcome: "unauthenticated",
                detail: String::from("invalid x-lb-admin-timestamp header"),
            })?;
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default();
            let skew = now_secs.abs_diff(timestamp);
            if skew > max_clock_skew.as_secs() {
                return Err(AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin timestamp rejected\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "rejected",
                    detail: String::from("signed admin timestamp exceeded clock skew allowance"),
                });
            }

            let nonce = request
                .header_value("x-lb-admin-nonce")
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("missing x-lb-admin-nonce header"),
                })?;
            let signature = request
                .header_value("x-lb-admin-signature")
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("missing x-lb-admin-signature header"),
                })?;

            let expected_secret = resolve_admin_secret(
                &operator.secret_env,
                legacy_admin_secret,
                "signed_headers",
                actor,
            )?;
            let expected = sign_admin_request(
                &expected_secret.value,
                actor,
                request.method.as_str(),
                request.target.as_str(),
                timestamp,
                nonce,
                request_body,
            );
            if !crate::constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
                return Err(AdminAuthFailure {
                    status: "401 Unauthorized",
                    headers: Vec::new(),
                    body: String::from("signed admin authorization required\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "unauthenticated",
                    detail: String::from("signed admin signature mismatch"),
                });
            }

            let nonce_key = format!("{actor}:{nonce}");
            let mut guard = replay_state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            guard.nonces.retain(|_, seen_at| now.saturating_duration_since(*seen_at) <= *nonce_ttl);
            if guard.nonces.contains_key(&nonce_key) {
                return Err(AdminAuthFailure {
                    status: "409 Conflict",
                    headers: Vec::new(),
                    body: String::from("admin command replay rejected\n"),
                    actor: actor.to_string(),
                    auth_mode: String::from("signed_headers"),
                    outcome: "replay_rejected",
                    detail: String::from("signed admin nonce has already been used"),
                });
            }
            guard.nonces.insert(nonce_key, now);

            Ok(AdminRequestContext {
                request_id: String::from(request_id),
                actor: actor.to_string(),
                auth_mode: String::from("signed_headers"),
                source: source_ip,
            })
        }
    }
}

fn resolve_admin_secret(
    secret_env: &str,
    legacy_admin_secret: &str,
    auth_mode: &'static str,
    actor: &str,
) -> Result<ResolvedAdminSecret, AdminAuthFailure> {
    let value = resolve_secret_material(secret_env, legacy_admin_secret).map_err(|error| {
        AdminAuthFailure {
            status: "503 Service Unavailable",
            headers: Vec::new(),
            body: String::from("admin authorization unavailable\n"),
            actor: actor.to_string(),
            auth_mode: String::from(auth_mode),
            outcome: "misconfigured",
            detail: error.detail,
        }
    })?;

    Ok(ResolvedAdminSecret { value: value.value, actor: actor.to_string(), auth_mode })
}

fn resolve_secret_material(
    secret_env: &str,
    legacy_admin_secret: &str,
) -> Result<ResolvedSecretMaterial, SecretMaterialResolutionError> {
    let secret_file_env = format!("{secret_env}_FILE");
    if let Ok(secret_file_path) = std::env::var(&secret_file_env) {
        let secret_file_path = secret_file_path.trim().to_string();
        if !secret_file_path.is_empty() {
            let value = fs::read_to_string(&secret_file_path).map_err(|error| {
                SecretMaterialResolutionError {
                    source_kind: "file",
                    source_reference: secret_file_path.clone(),
                    state: "read_failed",
                    detail: format!(
                        "admin secret file {secret_file_path} from {secret_file_env} could not be read: {error}"
                    ),
                }
            })?;
            let value = trim_secret_material(&value);
            if value.is_empty() {
                return Err(SecretMaterialResolutionError {
                    source_kind: "file",
                    source_reference: secret_file_path,
                    state: "empty",
                    detail: format!("admin secret file configured via {secret_file_env} was empty"),
                });
            }
            return Ok(ResolvedSecretMaterial {
                value,
                source_kind: "file",
                source_reference: secret_file_path,
                supports_rotation_without_reload: true,
            });
        }
    }

    let value = std::env::var(secret_env).unwrap_or_else(|_| {
        if secret_env == "LB_CTL_ADMIN_SECRET" {
            String::from(legacy_admin_secret)
        } else {
            String::new()
        }
    });

    if value.is_empty() {
        return Err(SecretMaterialResolutionError {
            source_kind: "env",
            source_reference: String::from(secret_env),
            state: "missing",
            detail: format!("admin secret env {secret_env} is not configured"),
        });
    }

    Ok(ResolvedSecretMaterial {
        value,
        source_kind: "env",
        source_reference: String::from(secret_env),
        supports_rotation_without_reload: false,
    })
}

fn inspect_secret_material(secret_env: &str, legacy_admin_secret: &str) -> AdminSecretHealthStatus {
    match resolve_secret_material(secret_env, legacy_admin_secret) {
        Ok(material) => AdminSecretHealthStatus {
            listener: String::new(),
            actor: String::new(),
            auth_mode: String::new(),
            secret_env: String::from(secret_env),
            source_kind: String::from(material.source_kind),
            source_reference: material.source_reference,
            supports_rotation_without_reload: material.supports_rotation_without_reload,
            healthy: true,
            state: String::from("loaded"),
            detail: String::from("secret material loaded"),
        },
        Err(error) => AdminSecretHealthStatus {
            listener: String::new(),
            actor: String::new(),
            auth_mode: String::new(),
            secret_env: String::from(secret_env),
            source_kind: String::from(error.source_kind),
            source_reference: error.source_reference,
            supports_rotation_without_reload: matches!(error.source_kind, "file"),
            healthy: false,
            state: String::from(error.state),
            detail: error.detail,
        },
    }
}

fn trim_secret_material(value: &str) -> String {
    value.trim_end_matches(['\r', '\n']).to_string()
}

fn sign_admin_request(
    secret: &str,
    actor: &str,
    method: &str,
    target: &str,
    timestamp: u64,
    nonce: &str,
    body: &[u8],
) -> String {
    let block_size = 64;
    let mut key = secret.as_bytes().to_vec();
    if key.len() > block_size {
        key = Sha256::digest(&key).to_vec();
    }
    key.resize(block_size, 0);

    let mut inner_pad = vec![0x36_u8; block_size];
    let mut outer_pad = vec![0x5c_u8; block_size];
    for (index, key_byte) in key.iter().enumerate() {
        inner_pad[index] ^= *key_byte;
        outer_pad[index] ^= *key_byte;
    }

    let payload = format!(
        "{actor}\n{method}\n{target}\n{timestamp}\n{nonce}\n{}\n",
        request_body_digest(body)
    );
    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    inner.update(payload.as_bytes());
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}

fn request_body_digest(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}

fn admin_permission_name(permission: AdminPermission) -> &'static str {
    match permission {
        AdminPermission::Read => "read",
        AdminPermission::Audit => "audit",
        AdminPermission::Write => "write",
    }
}

