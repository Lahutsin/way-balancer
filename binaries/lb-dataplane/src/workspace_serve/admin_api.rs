#[derive(Debug, Clone)]
struct AdminRequestContext {
    request_id: String,
    actor: String,
    auth_mode: String,
    source: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AdminApiRequestMode {
    Legacy { canonical_target: String },
    V1 { canonical_target: String },
    UnsupportedVersion { canonical_target: String, requested_version: String, detail: String },
}

impl AdminApiRequestMode {
    fn canonical_target(&self) -> &str {
        match self {
            Self::Legacy { canonical_target }
            | Self::V1 { canonical_target }
            | Self::UnsupportedVersion { canonical_target, .. } => canonical_target,
        }
    }

    const fn uses_versioned_contract(&self) -> bool {
        !matches!(self, Self::Legacy { .. })
    }
}

#[derive(Debug, Clone, Copy)]
enum AdminRequestAction {
    Healthz,
    Readyz,
    Status,
    Validate,
    Audit,
    Reload,
    Restart,
    CachePurge,
    CacheInvalidate,
    Unknown,
}

impl AdminRequestAction {
    fn permission(self) -> AdminPermission {
        match self {
            Self::Audit => AdminPermission::Audit,
            Self::Reload | Self::Restart | Self::CachePurge | Self::CacheInvalidate => {
                AdminPermission::Write
            }
            Self::Healthz | Self::Readyz | Self::Status | Self::Validate | Self::Unknown => {
                AdminPermission::Read
            }
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Healthz => "healthz",
            Self::Readyz => "readyz",
            Self::Status => "status",
            Self::Validate => "validate",
            Self::Audit => "audit",
            Self::Reload => "reload",
            Self::Restart => "restart",
            Self::CachePurge => "cache_purge",
            Self::CacheInvalidate => "cache_invalidate",
            Self::Unknown => "unknown",
        }
    }
}

fn negotiate_admin_api_request(request: &crate::DemoRequestHead) -> AdminApiRequestMode {
    let path_version = versioned_admin_target_parts(request.target.as_str());
    let header_version = request
        .header_value("x-lb-admin-api-version")
        .and_then(normalize_admin_api_version)
        .map(|version| (version, request.target.clone()));

    match (path_version, header_version) {
        (None, None) => AdminApiRequestMode::Legacy { canonical_target: request.target.clone() },
        (Some((path_version, canonical_target)), None) => {
            admin_api_request_mode_for_version(path_version, canonical_target)
        }
        (None, Some((header_version, canonical_target))) => {
            admin_api_request_mode_for_version(header_version, canonical_target)
        }
        (Some((path_version, canonical_target)), Some((header_version, _))) => {
            if path_version == header_version {
                admin_api_request_mode_for_version(path_version, canonical_target)
            } else {
                AdminApiRequestMode::UnsupportedVersion {
                    canonical_target,
                    requested_version: header_version.clone(),
                    detail: format!(
                        "conflicting admin api versions requested in path ({path_version}) and header ({header_version})"
                    ),
                }
            }
        }
    }
}

fn admin_api_request_mode_for_version(
    version: String,
    canonical_target: String,
) -> AdminApiRequestMode {
    if version == lb_admin_api::STABLE_ADMIN_API_VERSION {
        AdminApiRequestMode::V1 { canonical_target }
    } else {
        AdminApiRequestMode::UnsupportedVersion {
            canonical_target,
            requested_version: version.clone(),
            detail: format!("unsupported admin api version {version}"),
        }
    }
}

fn versioned_admin_target_parts(target: &str) -> Option<(String, String)> {
    let trimmed = target.strip_prefix('/')?;
    let (segment, remainder) = match trimmed.split_once('/') {
        Some((segment, remainder)) => (segment, format!("/{remainder}")),
        None => (trimmed, String::from("/")),
    };
    if segment.len() < 2
        || !segment.starts_with('v')
        || !segment[1..].chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((segment.to_ascii_lowercase(), remainder))
}

fn normalize_admin_api_version(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if normalized.starts_with('v') {
        return Some(normalized);
    }
    Some(format!("v{normalized}"))
}

fn versioned_admin_response_headers(extra_headers: &[&'static str]) -> Vec<&'static str> {
    let mut headers = Vec::with_capacity(extra_headers.len().saturating_add(1));
    headers.push("X-LB-Admin-Api-Version: v1");
    headers.extend_from_slice(extra_headers);
    headers
}

async fn write_versioned_admin_success<S, T>(
    stream: &mut S,
    status: &'static str,
    extra_headers: &[&'static str],
    request_id: &str,
    data: T,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_string(&lb_admin_api::VersionedAdminApiSuccessEnvelope::new(
        request_id.to_string(),
        data,
    ))
    .map_err(|error| io::Error::other(error.to_string()))?;
    let headers = versioned_admin_response_headers(extra_headers);
    crate::write_http_response_with_headers(
        stream,
        status,
        "application/json",
        headers.as_slice(),
        body.as_bytes(),
    )
    .await
}

async fn write_versioned_admin_error<S>(
    stream: &mut S,
    status: &'static str,
    extra_headers: &[&'static str],
    request_id: &str,
    code: lb_admin_api::AdminApiErrorCode,
    message: impl Into<String>,
    retryable: bool,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = serde_json::to_string(&lb_admin_api::VersionedAdminApiErrorEnvelope::new(
        request_id.to_string(),
        lb_admin_api::VersionedAdminApiError::new(code, message, retryable),
    ))
    .map_err(|error| io::Error::other(error.to_string()))?;
    let headers = versioned_admin_response_headers(extra_headers);
    crate::write_http_response_with_headers(
        stream,
        status,
        "application/json",
        headers.as_slice(),
        body.as_bytes(),
    )
    .await
}

fn json_body_to_value(body: &str) -> io::Result<serde_json::Value> {
    serde_json::from_str(body).map_err(|error| io::Error::other(error.to_string()))
}

async fn handle_workspace_admin_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    listener_name: String,
    state: Arc<WorkspaceServeState>,
    admin_runtime: AdminRuntimeHandles,
    admin_secret: Arc<String>,
    supervisor: ServeSupervisor,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    state.admin_requests.fetch_add(1, Ordering::SeqCst);
    let request = crate::read_http_request_head_and_body(&mut stream).await?;
    let Some((request, request_body)) = request else {
        return Ok(());
    };

    let policy = admin_runtime.shared_policy.read().await.clone();
    let api_mode = negotiate_admin_api_request(&request);
    let action =
        classify_admin_request_action(request.method.as_str(), api_mode.canonical_target());
    let request_id = state.next_admin_request_id();
    let source_ip = peer_addr.ip();

    if !admin_source_allowed(source_ip, &policy) {
        record_admin_audit(
            &state,
            AdminAuditEvent {
                observed_at_unix_ms: unix_time_ms(),
                request_id: request_id.clone(),
                listener: listener_name,
                actor: String::from("anonymous"),
                auth_mode: String::from("source_policy"),
                action: String::from(action.as_str()),
                code: admin_audit_code(action.as_str(), "denied"),
                source: source_ip.to_string(),
                outcome: String::from("denied"),
                detail: String::from("source address is outside the admin allow-list"),
            },
        )
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
        return if api_mode.uses_versioned_contract() {
            write_versioned_admin_error(
                &mut stream,
                "403 Forbidden",
                &[],
                &request_id,
                lb_admin_api::AdminApiErrorCode::Forbidden,
                "admin source not allowed",
                false,
            )
            .await
        } else {
            crate::write_http_response(
                &mut stream,
                "403 Forbidden",
                "text/plain; charset=utf-8",
                b"admin source not allowed\n",
            )
            .await
        };
    }

    let request_context = match authenticate_admin_request(
        &request,
        &request_body,
        action,
        source_ip,
        &policy,
        &admin_runtime.replay_state,
        admin_secret.as_str(),
        &request_id,
    ) {
        Ok(request_context) => request_context,
        Err(auth_error) => {
            record_admin_audit(
                &state,
                AdminAuditEvent {
                    observed_at_unix_ms: unix_time_ms(),
                    request_id: request_id.clone(),
                    listener: listener_name,
                    actor: auth_error.actor.clone(),
                    auth_mode: auth_error.auth_mode.clone(),
                    action: String::from(action.as_str()),
                    code: admin_audit_code(action.as_str(), auth_error.outcome),
                    source: source_ip.to_string(),
                    outcome: String::from(auth_error.outcome),
                    detail: auth_error.detail.clone(),
                },
            )
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
            let (error_code, retryable) = admin_auth_error_contract(&auth_error);
            return if api_mode.uses_versioned_contract() {
                write_versioned_admin_error(
                    &mut stream,
                    auth_error.status,
                    auth_error.headers.as_slice(),
                    &request_id,
                    error_code,
                    auth_error.body.trim(),
                    retryable,
                )
                .await
            } else {
                crate::write_http_response_with_headers(
                    &mut stream,
                    auth_error.status,
                    "text/plain; charset=utf-8",
                    auth_error.headers.as_slice(),
                    auth_error.body.as_bytes(),
                )
                .await
            };
        }
    };

    if !consume_admin_rate_limit(
        AdminRateLimitKey {
            source: source_ip,
            actor: request_context.actor.clone(),
            auth_mode: request_context.auth_mode.clone(),
        },
        &policy,
        &admin_runtime.rate_limit_state,
    ) {
        record_admin_audit(
            &state,
            AdminAuditEvent {
                observed_at_unix_ms: unix_time_ms(),
                request_id: request_context.request_id.clone(),
                listener: listener_name,
                actor: request_context.actor.clone(),
                auth_mode: request_context.auth_mode.clone(),
                action: String::from(action.as_str()),
                code: admin_audit_code(action.as_str(), "rate_limited"),
                source: source_ip.to_string(),
                outcome: String::from("rate_limited"),
                detail: String::from("admin identity exceeded configured rate limits"),
            },
        )
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
        return if api_mode.uses_versioned_contract() {
            write_versioned_admin_error(
                &mut stream,
                "429 Too Many Requests",
                &[],
                &request_context.request_id,
                lb_admin_api::AdminApiErrorCode::RateLimited,
                "admin rate limit exceeded",
                true,
            )
            .await
        } else {
            crate::write_http_response(
                &mut stream,
                "429 Too Many Requests",
                "text/plain; charset=utf-8",
                b"admin rate limit exceeded\n",
            )
            .await
        };
    }

    let action_name = String::from(action.as_str());
    let audit_outcome = if let AdminApiRequestMode::UnsupportedVersion { detail, .. } = &api_mode {
        write_versioned_admin_error(
            &mut stream,
            "406 Not Acceptable",
            &[],
            &request_context.request_id,
            lb_admin_api::AdminApiErrorCode::UnsupportedApiVersion,
            detail.clone(),
            false,
        )
        .await?;
        (String::from("failed"), detail.clone())
    } else {
        match action {
            AdminRequestAction::Healthz => {
                if api_mode.uses_versioned_contract() {
                    write_versioned_admin_success(
                        &mut stream,
                        "200 OK",
                        &[],
                        &request_context.request_id,
                        serde_json::json!({
                            "status": "ok",
                            "live": true,
                        }),
                    )
                    .await?;
                } else {
                    crate::write_http_response(
                        &mut stream,
                        "200 OK",
                        "text/plain; charset=utf-8",
                        b"ok\n",
                    )
                    .await?;
                }
                (String::from("served"), String::from("health check completed"))
            }
            AdminRequestAction::Readyz => {
                let listener_statuses = supervisor.listener_statuses().await;
                let readiness =
                    evaluate_workspace_readiness(&listener_statuses, state.reload_health());
                let response_status =
                    if readiness.ready { "200 OK" } else { "503 Service Unavailable" };
                let detail = if readiness.ready {
                    String::from("readiness check completed: ready")
                } else {
                    format!(
                        "readiness check completed: not ready ({})",
                        readiness.reason_codes.join(", ")
                    )
                };
                if api_mode.uses_versioned_contract() {
                    write_versioned_admin_success(
                        &mut stream,
                        response_status,
                        &[],
                        &request_context.request_id,
                        json_body_to_value(&readiness.to_json())?,
                    )
                    .await?;
                } else {
                    let body = format!("{}\n", readiness.to_json());
                    crate::write_http_response(
                        &mut stream,
                        response_status,
                        "application/json",
                        body.as_bytes(),
                    )
                    .await?;
                }
                (String::from(if readiness.ready { "served" } else { "degraded" }), detail)
            }
            AdminRequestAction::Validate => match supervisor.validate_current_config().await {
                Ok(preview) => {
                    if api_mode.uses_versioned_contract() {
                        write_versioned_admin_success(
                            &mut stream,
                            "200 OK",
                            &[],
                            &request_context.request_id,
                            preview,
                        )
                        .await?;
                    } else {
                        let body = preview
                            .render_json()
                            .map_err(|error| io::Error::other(error.to_string()))?;
                        crate::write_http_response(
                            &mut stream,
                            "200 OK",
                            "application/json",
                            body.as_bytes(),
                        )
                        .await?;
                    }
                    (String::from("served"), String::from("validation preview generated"))
                }
                Err(error) => {
                    let detail = format!("validation preview failed: {error}");
                    if api_mode.uses_versioned_contract() {
                        write_versioned_admin_error(
                            &mut stream,
                            "400 Bad Request",
                            &[],
                            &request_context.request_id,
                            lb_admin_api::AdminApiErrorCode::ValidationFailed,
                            detail.clone(),
                            false,
                        )
                        .await?;
                    } else {
                        crate::write_http_response(
                            &mut stream,
                            "400 Bad Request",
                            "text/plain; charset=utf-8",
                            format!("{detail}\n").as_bytes(),
                        )
                        .await?;
                    }
                    (String::from("failed"), detail)
                }
            },
            AdminRequestAction::Status => {
                let body = state.status_body(&supervisor).await;
                if api_mode.uses_versioned_contract() {
                    write_versioned_admin_success(
                        &mut stream,
                        "200 OK",
                        &[],
                        &request_context.request_id,
                        json_body_to_value(&body)?,
                    )
                    .await?;
                } else {
                    crate::write_http_response(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        body.as_bytes(),
                    )
                    .await?;
                }
                (String::from("served"), String::from("status response generated"))
            }
            AdminRequestAction::Audit => {
                let body = state
                    .audit_body()
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
                if api_mode.uses_versioned_contract() {
                    write_versioned_admin_success(
                        &mut stream,
                        "200 OK",
                        &[],
                        &request_context.request_id,
                        json_body_to_value(&body)?,
                    )
                    .await?;
                } else {
                    crate::write_http_response(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        body.as_bytes(),
                    )
                    .await?;
                }
                (String::from("served"), String::from("audit log response generated"))
            }
            AdminRequestAction::Reload => {
                let reload_plan = supervisor.describe_reload_audit_plan().await.ok();
                let started_detail = reload_plan.as_ref().map_or_else(
                    || String::from("reload started; plan preview unavailable before apply"),
                    ReloadAuditPlan::start_detail,
                );
                let started_code = reload_plan.as_ref().map_or_else(
                    || String::from("reload_started_unknown"),
                    |plan| String::from(plan.start_code()),
                );
                record_admin_audit(
                    &state,
                    AdminAuditEvent {
                        observed_at_unix_ms: unix_time_ms(),
                        request_id: request_context.request_id.clone(),
                        listener: listener_name.clone(),
                        actor: request_context.actor.clone(),
                        auth_mode: request_context.auth_mode.clone(),
                        action: action_name.clone(),
                        code: started_code,
                        source: request_context.source.to_string(),
                        outcome: String::from("started"),
                        detail: started_detail,
                    },
                )
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;

                match supervisor.reload().await {
                    Ok(outcome) => {
                        let success_code = reload_plan.as_ref().map_or_else(
                            || String::from(outcome.generic_success_code()),
                            |plan| String::from(plan.success_code(&outcome)),
                        );
                        let success_detail = reload_plan.as_ref().map_or_else(
                            || outcome.generic_success_detail(),
                            |plan| plan.success_detail(&outcome),
                        );
                        *state.last_reload_outcome_code.lock().await = success_code;
                        *state.last_reload_result.lock().await = success_detail.clone();
                        if api_mode.uses_versioned_contract() {
                            let last_reload_outcome_code =
                                state.last_reload_outcome_code.lock().await.clone();
                            let last_reload_result = state.last_reload_result.lock().await.clone();
                            write_versioned_admin_success(
                                &mut stream,
                                "200 OK",
                                &[],
                                &request_context.request_id,
                                serde_json::json!({
                                    "result": "configuration_applied",
                                    "outcome_code": last_reload_outcome_code,
                                    "detail": last_reload_result,
                                    "reload_health": reload_health_name(state.reload_health()),
                                    "degraded": outcome.timed_out_during_drain(),
                                }),
                            )
                            .await?;
                        } else {
                            crate::write_http_response(
                                &mut stream,
                                "200 OK",
                                "text/plain; charset=utf-8",
                                b"configuration applied\n",
                            )
                            .await?;
                        }
                        (String::from("executed"), success_detail)
                    }
                    Err(error) => {
                        let failure_code = reload_plan.as_ref().map_or_else(
                            || String::from("reload_failed_apply"),
                            |plan| String::from(plan.failure_code()),
                        );
                        *state.last_reload_outcome_code.lock().await = failure_code;
                        let detail = reload_plan.as_ref().map_or_else(
                            || format!("reload failed: {error}"),
                            |plan| plan.failure_detail(&error),
                        );
                        if api_mode.uses_versioned_contract() {
                            let error_code = if state.last_reload_outcome_code.lock().await.as_str()
                                == "reload_failed_blocked_change"
                            {
                                lb_admin_api::AdminApiErrorCode::UnsupportedMutation
                            } else {
                                lb_admin_api::AdminApiErrorCode::ReloadFailed
                            };
                            write_versioned_admin_error(
                                &mut stream,
                                "500 Internal Server Error",
                                &[],
                                &request_context.request_id,
                                error_code,
                                detail.clone(),
                                false,
                            )
                            .await?;
                        } else {
                            crate::write_http_response(
                                &mut stream,
                                "500 Internal Server Error",
                                "text/plain; charset=utf-8",
                                format!("{detail}\n").as_bytes(),
                            )
                            .await?;
                        }
                        (String::from("failed"), detail)
                    }
                }
            }
            AdminRequestAction::Restart => {
                let restart_plan = supervisor.describe_restart_audit_plan().await.ok();
                let started_detail = restart_plan.as_ref().map_or_else(
                    || String::from("warm restart started; plan preview unavailable before apply"),
                    ReloadAuditPlan::restart_start_detail,
                );
                let started_code = restart_plan.as_ref().map_or_else(
                    || String::from("restart_started_unknown"),
                    |plan| String::from(plan.restart_start_code()),
                );
                record_admin_audit(
                    &state,
                    AdminAuditEvent {
                        observed_at_unix_ms: unix_time_ms(),
                        request_id: request_context.request_id.clone(),
                        listener: listener_name.clone(),
                        actor: request_context.actor.clone(),
                        auth_mode: request_context.auth_mode.clone(),
                        action: action_name.clone(),
                        code: started_code,
                        source: request_context.source.to_string(),
                        outcome: String::from("started"),
                        detail: started_detail,
                    },
                )
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;

                match supervisor.warm_restart().await {
                    Ok(outcome) => {
                        let success_code = restart_plan.as_ref().map_or_else(
                            || String::from("restart_applied"),
                            |plan| String::from(plan.restart_success_code(&outcome)),
                        );
                        let success_detail = restart_plan.as_ref().map_or_else(
                            || String::from("warm restart applied"),
                            |plan| plan.restart_success_detail(&outcome),
                        );
                        *state.last_restart_outcome_code.lock().await = success_code;
                        *state.last_restart_result.lock().await = success_detail.clone();
                        if api_mode.uses_versioned_contract() {
                            let last_restart_outcome_code =
                                state.last_restart_outcome_code.lock().await.clone();
                            let last_restart_result =
                                state.last_restart_result.lock().await.clone();
                            write_versioned_admin_success(
                                &mut stream,
                                "200 OK",
                                &[],
                                &request_context.request_id,
                                serde_json::json!({
                                    "result": "warm_restart_applied",
                                    "outcome_code": last_restart_outcome_code,
                                    "detail": last_restart_result,
                                    "restarted_listeners": outcome.restarted_listener_count,
                                    "completed_drains": outcome.completed_drain_count,
                                    "drain_timeouts": outcome.drain_timeout_count,
                                    "degraded": outcome.timed_out_during_drain(),
                                }),
                            )
                            .await?;
                        } else {
                            crate::write_http_response(
                                &mut stream,
                                "200 OK",
                                "text/plain; charset=utf-8",
                                b"warm restart applied\n",
                            )
                            .await?;
                        }
                        (String::from("executed"), success_detail)
                    }
                    Err(error) => {
                        let failure_code = restart_plan.as_ref().map_or_else(
                            || String::from("restart_failed_apply"),
                            |plan| String::from(plan.restart_failure_code()),
                        );
                        *state.last_restart_outcome_code.lock().await = failure_code;
                        let detail = restart_plan.as_ref().map_or_else(
                            || format!("warm restart failed: {error}"),
                            |plan| plan.restart_failure_detail(&error),
                        );
                        if api_mode.uses_versioned_contract() {
                            write_versioned_admin_error(
                                &mut stream,
                                "500 Internal Server Error",
                                &[],
                                &request_context.request_id,
                                lb_admin_api::AdminApiErrorCode::ReloadFailed,
                                detail.clone(),
                                false,
                            )
                            .await?;
                        } else {
                            crate::write_http_response(
                                &mut stream,
                                "500 Internal Server Error",
                                "text/plain; charset=utf-8",
                                format!("{detail}\n").as_bytes(),
                            )
                            .await?;
                        }
                        (String::from("failed"), detail)
                    }
                }
            }
            AdminRequestAction::CachePurge => {
                match handle_admin_cache_purge(&state, &request_body).await {
                    Ok(response) => {
                        if api_mode.uses_versioned_contract() {
                            write_versioned_admin_success(
                                &mut stream,
                                "200 OK",
                                &[],
                                &request_context.request_id,
                                &response,
                            )
                            .await?;
                        } else {
                            let body = serde_json::to_string_pretty(&response)
                                .map_err(|error| io::Error::other(error.to_string()))?;
                            crate::write_http_response(
                                &mut stream,
                                "200 OK",
                                "application/json",
                                body.as_bytes(),
                            )
                            .await?;
                        }
                        (
                            String::from(if response.degraded { "degraded" } else { "executed" }),
                            format!(
                                "cache purge for scope {} purged {} entries",
                                response.scope, response.purged_entries
                            ),
                        )
                    }
                    Err(error) => {
                        if api_mode.uses_versioned_contract() {
                            write_versioned_admin_error(
                                &mut stream,
                                "400 Bad Request",
                                &[],
                                &request_context.request_id,
                                lb_admin_api::AdminApiErrorCode::ValidationFailed,
                                error.clone(),
                                false,
                            )
                            .await?;
                        } else {
                            crate::write_http_response(
                                &mut stream,
                                "400 Bad Request",
                                "text/plain; charset=utf-8",
                                format!("{error}\n").as_bytes(),
                            )
                            .await?;
                        }
                        (String::from("failed"), error)
                    }
                }
            }
            AdminRequestAction::CacheInvalidate => {
                match handle_admin_cache_invalidate(&state, &request_body).await {
                    Ok(response) => {
                        if api_mode.uses_versioned_contract() {
                            write_versioned_admin_success(
                                &mut stream,
                                "200 OK",
                                &[],
                                &request_context.request_id,
                                &response,
                            )
                            .await?;
                        } else {
                            let body = serde_json::to_string(&response)
                                .map_err(|error| io::Error::other(error.to_string()))?;
                            crate::write_http_response(
                                &mut stream,
                                "200 OK",
                                "application/json",
                                body.as_bytes(),
                            )
                            .await?;
                        }
                        (
                            String::from(match response.result {
                                lb_admin_api::HttpCachePeerInvalidationResult::Applied => {
                                    "executed"
                                }
                                lb_admin_api::HttpCachePeerInvalidationResult::Duplicate => {
                                    "duplicate"
                                }
                            }),
                            format!(
                                "cache invalidation for scope {} applied with {} purged entries",
                                response.scope, response.purged_entries
                            ),
                        )
                    }
                    Err(error) => {
                        if api_mode.uses_versioned_contract() {
                            write_versioned_admin_error(
                                &mut stream,
                                "400 Bad Request",
                                &[],
                                &request_context.request_id,
                                lb_admin_api::AdminApiErrorCode::ValidationFailed,
                                error.clone(),
                                false,
                            )
                            .await?;
                        } else {
                            crate::write_http_response(
                                &mut stream,
                                "400 Bad Request",
                                "text/plain; charset=utf-8",
                                format!("{error}\n").as_bytes(),
                            )
                            .await?;
                        }
                        (String::from("failed"), error)
                    }
                }
            }
            AdminRequestAction::Unknown => {
                if api_mode.uses_versioned_contract() {
                    write_versioned_admin_error(
                        &mut stream,
                        "404 Not Found",
                        &[],
                        &request_context.request_id,
                        lb_admin_api::AdminApiErrorCode::NotFound,
                        "unknown admin endpoint",
                        false,
                    )
                    .await?;
                } else {
                    crate::write_http_response(
                        &mut stream,
                        "404 Not Found",
                        "text/plain; charset=utf-8",
                        b"not found\n",
                    )
                    .await?;
                }
                (String::from("not_found"), String::from("unknown admin endpoint"))
            }
        }
    };

    let audit_code = match action {
        AdminRequestAction::Reload => state.last_reload_outcome_code.lock().await.clone(),
        AdminRequestAction::Restart => state.last_restart_outcome_code.lock().await.clone(),
        _ => admin_audit_code(&action_name, &audit_outcome.0),
    };

    record_admin_audit(
        &state,
        AdminAuditEvent {
            observed_at_unix_ms: unix_time_ms(),
            request_id: request_context.request_id,
            listener: listener_name,
            actor: request_context.actor,
            auth_mode: request_context.auth_mode,
            action: action_name,
            code: audit_code,
            source: request_context.source.to_string(),
            outcome: audit_outcome.0,
            detail: audit_outcome.1,
        },
    )
    .await
    .map_err(|error| io::Error::other(error.to_string()))?;

    Ok(())
}

fn classify_admin_request_action(method: &str, target: &str) -> AdminRequestAction {
    match (method, target) {
        ("GET", "/healthz") => AdminRequestAction::Healthz,
        ("GET", "/readyz") => AdminRequestAction::Readyz,
        ("GET", "/status") => AdminRequestAction::Status,
        ("GET", "/validate") => AdminRequestAction::Validate,
        ("GET", "/audit") => AdminRequestAction::Audit,
        ("POST", "/reload") => AdminRequestAction::Reload,
        ("POST", "/restart") => AdminRequestAction::Restart,
        ("POST", "/cache/purge") => AdminRequestAction::CachePurge,
        ("POST", "/cache/invalidate") => AdminRequestAction::CacheInvalidate,
        _ => AdminRequestAction::Unknown,
    }
}

fn admin_audit_code(action: &str, outcome: &str) -> String {
    format!("{}_{}", action, outcome)
}

fn admin_source_allowed(source_ip: IpAddr, policy: &CompiledAdminPolicy) -> bool {
    policy.allowed_source_cidrs.is_empty()
        || policy.allowed_source_cidrs.iter().any(|cidr| cidr.contains(&source_ip))
}

#[cfg(test)]
mod admin_api_tests {
    use super::{
        admin_audit_code, admin_source_allowed, classify_admin_request_action,
        compile_admin_policy, handle_workspace_admin_connection, negotiate_admin_api_request,
        versioned_admin_response_headers, write_versioned_admin_error,
        write_versioned_admin_success, AdminApiRequestMode, AdminPermission, AdminRateLimitState,
        AdminReplayState, AdminRequestAction, AdminRuntimeHandles, CompiledAdminPolicy,
        ServeSupervisor, ServeSupervisorInner, ServeSupervisorShared, WorkspaceServeState,
    };
    use crate::{DemoHeader, DemoRequestHead};
    use std::fs;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{Mutex, RwLock};

    const TEST_SECRET_ENV: &str = "LB_TEST_ADMIN_API_SECRET_COVERAGE";
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static TEST_JOURNAL_COUNTER: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    struct JournalCleanup(String);

    impl Drop for JournalCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(format!("{}.control-plane.json", self.0));
        }
    }

    fn request(target: &str, version: Option<&str>) -> DemoRequestHead {
        let mut headers = Vec::new();
        if let Some(version) = version {
            headers.push(DemoHeader {
                name: String::from("x-lb-admin-api-version"),
                value: String::from(version),
            });
        }
        DemoRequestHead {
            method: String::from("GET"),
            target: String::from(target),
            headers,
            authorization_bearer: None,
        }
    }

    fn test_admin_policy() -> CompiledAdminPolicy {
        let mut listener = lb_config_model::ListenerResourceConfig::foundation(
            "admin-test",
            lb_config_model::ListenerClassConfig::Admin,
            0,
        );
        let mut config = serde_json::to_value(&listener).unwrap();
        config["admin"]["auth"] = serde_json::to_value(&listener.admin.auth).unwrap();
        config["admin"]["auth"]["secret_env"] = serde_json::json!(TEST_SECRET_ENV);
        listener = serde_json::from_value(config).unwrap();
        compile_admin_policy(&listener).unwrap()
    }

    fn test_setup(
    ) -> (Arc<WorkspaceServeState>, AdminRuntimeHandles, ServeSupervisor, JournalCleanup) {
        let config_path = format!(
            "target/admin-api-coverage-{}-{}",
            std::process::id(),
            TEST_JOURNAL_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let cleanup = JournalCleanup(config_path.clone());
        let state = Arc::new(WorkspaceServeState::new(config_path.clone()).unwrap());
        let runtime = AdminRuntimeHandles {
            shared_policy: Arc::new(RwLock::new(test_admin_policy())),
            shared_tls: Arc::new(RwLock::new(None)),
            rate_limit_state: Arc::new(StdMutex::new(AdminRateLimitState::default())),
            replay_state: Arc::new(StdMutex::new(AdminReplayState::default())),
        };
        let supervisor = ServeSupervisor {
            shared: Arc::new(ServeSupervisorShared {
                config_path,
                admin_secret: Arc::new(String::new()),
                state: Arc::clone(&state),
                reload_guard: Mutex::new(()),
                inner: Mutex::new(ServeSupervisorInner::default()),
            }),
        };
        (state, runtime, supervisor, cleanup)
    }

    async fn send_admin_request(
        target: &str,
        headers: &str,
        body: &[u8],
        state: Arc<WorkspaceServeState>,
        runtime: AdminRuntimeHandles,
        supervisor: ServeSupervisor,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let (mut client, server) = tokio::io::duplex(8192);
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Length: {}\r\n\r\n",
            body.len()
        );
        client.write_all(request.as_bytes()).await?;
        client.write_all(body).await?;
        client.shutdown().await?;
        handle_workspace_admin_connection(
            server,
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            String::from("admin-test"),
            Arc::clone(&state),
            runtime,
            Arc::new(String::new()),
            supervisor,
        )
        .await?;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await?;
        assert!(state.admin_requests.load(Ordering::SeqCst) > 0);
        Ok(String::from_utf8(response)?)
    }

    #[test]
    fn api_version_negotiation_canonicalizes_targets_and_rejects_conflicts() {
        assert_eq!(
            negotiate_admin_api_request(&request("/healthz", None)),
            AdminApiRequestMode::Legacy { canonical_target: String::from("/healthz") }
        );
        assert_eq!(
            negotiate_admin_api_request(&request("/v1/status", None)),
            AdminApiRequestMode::V1 { canonical_target: String::from("/status") }
        );
        assert_eq!(
            negotiate_admin_api_request(&request("/status", Some(" 1 "))),
            AdminApiRequestMode::V1 { canonical_target: String::from("/status") }
        );
        assert_eq!(
            negotiate_admin_api_request(&request("/v1/status", Some("V1"))),
            AdminApiRequestMode::V1 { canonical_target: String::from("/status") }
        );
        let unsupported = negotiate_admin_api_request(&request("/v2/status", None));
        assert!(matches!(
            unsupported,
            AdminApiRequestMode::UnsupportedVersion {
                requested_version,
                canonical_target,
                ..
            } if requested_version == "v2" && canonical_target == "/status"
        ));
        let conflict = negotiate_admin_api_request(&request("/v1/status", Some("v2")));
        assert!(matches!(conflict, AdminApiRequestMode::UnsupportedVersion { .. }));
        assert_eq!(
            negotiate_admin_api_request(&request("/status", Some(" "))),
            AdminApiRequestMode::Legacy { canonical_target: String::from("/status") }
        );
    }

    #[test]
    fn actions_permissions_audit_codes_and_source_allow_lists_are_consistent() {
        for (method, path, expected) in [
            ("GET", "/healthz", AdminRequestAction::Healthz),
            ("GET", "/readyz", AdminRequestAction::Readyz),
            ("GET", "/status", AdminRequestAction::Status),
            ("GET", "/validate", AdminRequestAction::Validate),
            ("GET", "/audit", AdminRequestAction::Audit),
            ("POST", "/reload", AdminRequestAction::Reload),
            ("POST", "/restart", AdminRequestAction::Restart),
            ("POST", "/cache/purge", AdminRequestAction::CachePurge),
            ("POST", "/cache/invalidate", AdminRequestAction::CacheInvalidate),
        ] {
            assert!(
                std::mem::discriminant(&classify_admin_request_action(method, path))
                    == std::mem::discriminant(&expected)
            );
        }
        assert_eq!(classify_admin_request_action("DELETE", "/status").as_str(), "unknown");
        assert_eq!(
            classify_admin_request_action("GET", "/audit").permission(),
            AdminPermission::Audit
        );
        assert_eq!(
            classify_admin_request_action("POST", "/reload").permission(),
            AdminPermission::Write
        );
        assert_eq!(
            classify_admin_request_action("GET", "/status").permission(),
            AdminPermission::Read
        );
        assert_eq!(admin_audit_code("reload", "failed"), "reload_failed");
        let mut policy = test_admin_policy();
        assert!(admin_source_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), &policy));
        policy.allowed_source_cidrs.push("10.0.0.0/8".parse().unwrap());
        assert!(!admin_source_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), &policy));
        assert!(admin_source_allowed("10.1.2.3".parse().unwrap(), &policy));
    }

    #[tokio::test]
    async fn versioned_envelopes_include_contract_and_request_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut success_reader, mut success_stream) = tokio::io::duplex(4096);
        write_versioned_admin_success(
            &mut success_stream,
            "200 OK",
            &["Cache-Control: no-store"],
            "request-7",
            serde_json::json!({"status": "ok"}),
        )
        .await?;
        drop(success_stream);
        let mut success_bytes = Vec::new();
        success_reader.read_to_end(&mut success_bytes).await?;
        let success = String::from_utf8(success_bytes)?;
        assert!(success.contains("X-LB-Admin-Api-Version: v1"));
        assert!(success.contains("Cache-Control: no-store"));
        assert!(success.contains("\"request_id\":\"request-7\""));
        assert_eq!(versioned_admin_response_headers(&[]), ["X-LB-Admin-Api-Version: v1"]);

        let (mut error_reader, mut error_stream) = tokio::io::duplex(4096);
        write_versioned_admin_error(
            &mut error_stream,
            "400 Bad Request",
            &[],
            "request-8",
            lb_admin_api::AdminApiErrorCode::ValidationFailed,
            "invalid request",
            false,
        )
        .await?;
        drop(error_stream);
        let mut error_bytes = Vec::new();
        error_reader.read_to_end(&mut error_bytes).await?;
        let error = String::from_utf8(error_bytes)?;
        assert!(error.contains("400 Bad Request"));
        assert!(error.contains("\"request_id\":\"request-8\""));
        assert!(error.contains("invalid request"));
        Ok(())
    }

    #[tokio::test]
    async fn admin_connection_handles_legacy_versioned_and_unsupported_health_requests(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _env_guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(TEST_SECRET_ENV, "api-secret");
        let (state, runtime, supervisor, _cleanup) = test_setup();
        let response = send_admin_request(
            "/healthz",
            "Authorization: Bearer api-secret\r\n",
            b"",
            Arc::clone(&state),
            runtime.clone(),
            supervisor.clone(),
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ok\n"));

        let response = send_admin_request(
            "/v1/healthz",
            "Authorization: Bearer api-secret\r\n",
            b"",
            Arc::clone(&state),
            runtime.clone(),
            supervisor.clone(),
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("X-LB-Admin-Api-Version: v1"));
        assert!(response.contains("\"live\":true"));

        let response = send_admin_request(
            "/v2/healthz",
            "Authorization: Bearer api-secret\r\n",
            b"",
            Arc::clone(&state),
            runtime.clone(),
            supervisor.clone(),
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 406 Not Acceptable"), "{response:?}");
        assert!(response.contains("unsupported admin api version v2"));

        let response = send_admin_request(
            "/missing",
            "Authorization: Bearer api-secret\r\n",
            b"",
            state,
            runtime,
            supervisor,
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        std::env::remove_var(TEST_SECRET_ENV);
        Ok(())
    }

    #[tokio::test]
    async fn admin_connection_rejects_denied_sources_and_missing_credentials(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _env_guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(TEST_SECRET_ENV, "api-secret");
        let (state, runtime, supervisor, _cleanup) = test_setup();
        runtime.shared_policy.write().await.allowed_source_cidrs = vec!["10.0.0.0/8".parse()?];
        let response = send_admin_request(
            "/healthz",
            "Authorization: Bearer api-secret\r\n",
            b"",
            Arc::clone(&state),
            runtime.clone(),
            supervisor.clone(),
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("admin source not allowed"));

        runtime.shared_policy.write().await.allowed_source_cidrs.clear();
        let response = send_admin_request("/healthz", "", b"", state, runtime, supervisor).await?;
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
        std::env::remove_var(TEST_SECRET_ENV);
        Ok(())
    }

    #[tokio::test]
    async fn admin_connection_ignores_clients_that_disconnect_before_sending_a_request(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, runtime, supervisor, _cleanup) = test_setup();
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        handle_workspace_admin_connection(
            server,
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            String::from("admin-test"),
            Arc::clone(&state),
            runtime,
            Arc::new(String::new()),
            supervisor,
        )
        .await?;
        assert_eq!(state.admin_requests.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn malformed_admin_json_is_reported_without_panicking() {
        assert_eq!(
            super::json_body_to_value(r#"{"ready":true}"#).unwrap()["ready"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(super::json_body_to_value("{").unwrap_err().kind(), io::ErrorKind::Other);
    }
}
