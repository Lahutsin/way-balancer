#[derive(Debug, Clone)]
pub(crate) struct ServeSupervisor {
    shared: Arc<ServeSupervisorShared>,
}

#[derive(Debug)]
struct ServeSupervisorShared {
    config_path: String,
    admin_secret: Arc<String>,
    state: Arc<WorkspaceServeState>,
    reload_guard: Mutex<()>,
    inner: Mutex<ServeSupervisorInner>,
}

#[derive(Debug, Default)]
struct ServeSupervisorInner {
    source_label: String,
    active_snapshot: Option<lb_config_model::WorkspaceSnapshot>,
    listeners: BTreeMap<String, ManagedListenerSlot>,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigSafetyWarning {
    code: String,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigApplyPreview {
    strategy: String,
    rollback_safe: bool,
    summary: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigCompatibilityPreview {
    active_api_version: Option<lb_config_model::ConfigApiVersion>,
    candidate_api_version: lb_config_model::ConfigApiVersion,
    snapshot_format_version: String,
    migration_strategy: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigValidationPreview {
    config_path: String,
    active_snapshot: Option<lb_config_model::WorkspaceSnapshotView>,
    candidate_snapshot: lb_config_model::WorkspaceSnapshotView,
    diff_preview: Option<lb_config_model::WorkspaceSnapshotDiff>,
    warnings: Vec<ConfigSafetyWarning>,
    apply_preview: ConfigApplyPreview,
    compatibility: ConfigCompatibilityPreview,
}

#[derive(Debug, Clone, Default)]
struct ReloadAuditPlan {
    supported_replacements: Vec<String>,
    blocked_replacements: Vec<String>,
    expected_completion_within_ms: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct ReloadApplyOutcome {
    drained_listener_count: usize,
    completed_drain_count: usize,
    drain_timeout_count: usize,
    drain_timed_out_replacements: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct WarmRestartApplyOutcome {
    restarted_listener_count: usize,
    completed_drain_count: usize,
    drain_timeout_count: usize,
    drain_timed_out_replacements: Vec<String>,
}

impl WarmRestartApplyOutcome {
    fn timed_out_during_drain(&self) -> bool {
        self.drain_timeout_count > 0 || !self.drain_timed_out_replacements.is_empty()
    }
}

impl From<ReloadApplyOutcome> for WarmRestartApplyOutcome {
    fn from(value: ReloadApplyOutcome) -> Self {
        Self {
            restarted_listener_count: value.drained_listener_count,
            completed_drain_count: value.completed_drain_count,
            drain_timeout_count: value.drain_timeout_count,
            drain_timed_out_replacements: value.drain_timed_out_replacements,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyMode {
    Reload,
    WarmRestart,
}

impl ApplyMode {
    const fn force_replace_matching(self) -> bool {
        matches!(self, Self::WarmRestart)
    }

    const fn force_replace_listener(self, current: &CurrentListenerIdentity) -> bool {
        self.force_replace_matching()
            && matches!(current.class, lb_config_model::ListenerClassConfig::Public)
    }
}

impl ReloadApplyOutcome {
    fn timed_out_during_drain(&self) -> bool {
        !self.drain_timed_out_replacements.is_empty()
    }

    fn generic_success_code(&self) -> &'static str {
        if self.timed_out_during_drain() {
            "reload_applied_with_drain_timeout"
        } else {
            "reload_applied"
        }
    }

    fn generic_success_detail(&self) -> String {
        if self.timed_out_during_drain() {
            format!(
                "configuration applied; drained_listeners={} completed_drains={} drain_timeouts={} (timed out replacements: {})",
                self.drained_listener_count,
                self.completed_drain_count,
                self.drain_timeout_count,
                self.drain_timed_out_replacements.join(", ")
            )
        } else {
            format!(
                "configuration applied; drained_listeners={} completed_drains={} drain_timeouts=0",
                self.drained_listener_count,
                self.completed_drain_count
            )
        }
    }
}

impl ReloadAuditPlan {
    fn from_candidate(
        current_identities: &BTreeMap<String, CurrentListenerIdentity>,
        candidate_listeners: &BTreeMap<String, CompiledServeListener>,
    ) -> Self {
        let supported_replacements =
            collect_supported_listener_replacements(current_identities, candidate_listeners);
        Self {
            expected_completion_within_ms: supported_replacements
                .iter()
                .filter_map(|listener_name| candidate_listeners.get(listener_name))
                .map(|listener| listener.drain_timeout().as_millis().try_into().unwrap_or(u64::MAX))
                .max(),
            supported_replacements,
            blocked_replacements: collect_blocked_listener_replacements(
                current_identities,
                candidate_listeners,
            ),
        }
    }

    fn from_restart_candidate(
        current_identities: &BTreeMap<String, CurrentListenerIdentity>,
        candidate_listeners: &BTreeMap<String, CompiledServeListener>,
    ) -> Self {
        let mut supported_replacements = Vec::new();
        let mut blocked_replacements = Vec::new();
        for (name, spec) in candidate_listeners {
            let Some(current) = current_identities.get(name) else {
                continue;
            };
            if !matches!(current.class, lb_config_model::ListenerClassConfig::Public) {
                continue;
            }
            if current.can_stage_replacement(spec) {
                supported_replacements.push(name.clone());
            } else {
                blocked_replacements.push(name.clone());
            }
        }

        Self {
            expected_completion_within_ms: supported_replacements
                .iter()
                .filter_map(|listener_name| candidate_listeners.get(listener_name))
                .map(|listener| listener.drain_timeout().as_millis().try_into().unwrap_or(u64::MAX))
                .max(),
            supported_replacements,
            blocked_replacements,
        }
    }

    fn start_detail(&self) -> String {
        if !self.blocked_replacements.is_empty() {
            format!(
                "reload started; candidate still contains disruptive listener changes for: {}",
                self.blocked_replacements.join(", ")
            )
        } else if !self.supported_replacements.is_empty() {
            format!(
                "reload started; overlap-and-drain replacement planned for: {}; inspect GET /status for live drain progress",
                self.supported_replacements.join(", ")
            )
        } else {
            String::from("reload started; apply plan is in-place or additive")
        }
    }

    fn start_code(&self) -> &'static str {
        if !self.blocked_replacements.is_empty() {
            "reload_started_blocked_candidate"
        } else if !self.supported_replacements.is_empty() {
            "reload_started_overlap_drain"
        } else {
            "reload_started_in_place"
        }
    }

    fn success_detail(&self, outcome: &ReloadApplyOutcome) -> String {
        if outcome.timed_out_during_drain() {
            format!(
                "configuration applied; replacement stayed active but drain timeout expired for: {} (drained_listeners={} completed_drains={} drain_timeouts={})",
                outcome.drain_timed_out_replacements.join(", "),
                outcome.drained_listener_count,
                outcome.completed_drain_count,
                outcome.drain_timeout_count,
            )
        } else if !self.supported_replacements.is_empty() {
            format!(
                "configuration applied; overlap-and-drain replacement completed for: {} (drained_listeners={} completed_drains={} drain_timeouts=0)",
                self.supported_replacements.join(", "),
                outcome.drained_listener_count,
                outcome.completed_drain_count,
            )
        } else {
            format!(
                "configuration applied; drained_listeners={} completed_drains={} drain_timeouts=0",
                outcome.drained_listener_count,
                outcome.completed_drain_count
            )
        }
    }

    fn success_code(&self, outcome: &ReloadApplyOutcome) -> &'static str {
        if outcome.timed_out_during_drain() {
            "reload_applied_overlap_drain_timeout"
        } else if !self.supported_replacements.is_empty() {
            "reload_applied_overlap_drain"
        } else {
            "reload_applied_in_place"
        }
    }

    fn failure_detail(&self, error: &dyn std::fmt::Display) -> String {
        if !self.blocked_replacements.is_empty() {
            format!(
                "reload failed: {error}; candidate still required disruptive retirement for: {}",
                self.blocked_replacements.join(", ")
            )
        } else if !self.supported_replacements.is_empty() {
            format!(
                "reload failed: {error}; active listeners were preserved while replacement stayed rollback-safe for: {}",
                self.supported_replacements.join(", ")
            )
        } else {
            format!("reload failed: {error}")
        }
    }

    fn failure_code(&self) -> &'static str {
        if !self.blocked_replacements.is_empty() {
            "reload_failed_blocked_change"
        } else if !self.supported_replacements.is_empty() {
            "reload_failed_rollback_preserved"
        } else {
            "reload_failed_apply"
        }
    }

    fn restart_start_detail(&self) -> String {
        if !self.blocked_replacements.is_empty() {
            format!(
                "warm restart started; replacement cannot be staged safely for: {}",
                self.blocked_replacements.join(", ")
            )
        } else if !self.supported_replacements.is_empty() {
            format!(
                "warm restart started; overlap-and-drain restart planned for: {}",
                self.supported_replacements.join(", ")
            )
        } else {
            String::from("warm restart started; no replacement-capable listeners found")
        }
    }

    fn restart_start_code(&self) -> &'static str {
        if !self.blocked_replacements.is_empty() {
            "restart_started_blocked"
        } else if !self.supported_replacements.is_empty() {
            "restart_started_overlap_drain"
        } else {
            "restart_started_noop"
        }
    }

    fn restart_success_code(&self, outcome: &WarmRestartApplyOutcome) -> &'static str {
        if outcome.timed_out_during_drain() {
            "restart_applied_overlap_drain_timeout"
        } else if outcome.restarted_listener_count > 0 {
            "restart_applied_overlap_drain"
        } else {
            "restart_applied_noop"
        }
    }

    fn restart_success_detail(&self, outcome: &WarmRestartApplyOutcome) -> String {
        if outcome.timed_out_during_drain() {
            format!(
                "warm restart applied with drain timeout; restarted_listeners={} completed_drains={} drain_timeouts={} timed_out_listeners={}",
                outcome.restarted_listener_count,
                outcome.completed_drain_count,
                outcome.drain_timeout_count,
                outcome.drain_timed_out_replacements.join(", ")
            )
        } else {
            format!(
                "warm restart applied; restarted_listeners={} completed_drains={} drain_timeouts=0",
                outcome.restarted_listener_count,
                outcome.completed_drain_count
            )
        }
    }

    fn restart_failure_code(&self) -> &'static str {
        if !self.blocked_replacements.is_empty() {
            "restart_failed_blocked"
        } else {
            "restart_failed_apply"
        }
    }

    fn restart_failure_detail(&self, error: &dyn std::fmt::Display) -> String {
        if !self.blocked_replacements.is_empty() {
            format!(
                "warm restart failed: {error}; replacement cannot be staged for: {}",
                self.blocked_replacements.join(", ")
            )
        } else {
            format!("warm restart failed: {error}")
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct AdminAuthStatus {
    secret_sources: Vec<AdminSecretHealthStatus>,
}

impl AdminAuthStatus {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("{\"secret_sources\":[]}"))
    }
}

#[derive(Debug, Clone, Serialize)]
struct AdminSecretHealthStatus {
    listener: String,
    actor: String,
    auth_mode: String,
    secret_env: String,
    source_kind: String,
    source_reference: String,
    supports_rotation_without_reload: bool,
    healthy: bool,
    state: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct ListenerTlsStatus {
    state: String,
    warning_window_secs: u64,
    minimum_version: String,
    alpn_protocols: Vec<String>,
    session_resumption: ListenerTlsSessionResumptionStatus,
    default_certificate: ListenerTlsCertificateStatus,
    sni_certificates: Vec<ListenerTlsCertificateStatus>,
    reason_codes: Vec<String>,
}

impl ListenerTlsStatus {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("null"))
    }
}

#[derive(Debug, Clone, Serialize)]
struct ListenerTlsSessionResumptionStatus {
    mode: String,
    session_cache_size: usize,
    tls13_ticket_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ListenerTlsCertificateStatus {
    label: String,
    server_names: Vec<String>,
    cert_path: String,
    key_path: String,
    ocsp_path: Option<String>,
    common_name: Option<String>,
    san_dns_names: Vec<String>,
    fingerprint_sha256: String,
    not_before_unix_secs: i64,
    not_after_unix_secs: i64,
    not_yet_valid: bool,
    expired: bool,
    expires_within_warning_window: bool,
}

pub(crate) async fn serve_workspace_main(serve_args: &ServeArgs) -> Result<(), DynError> {
    let config_path =
        serve_args.config_path.clone().ok_or("workspace serve mode requires a config path")?;
    let admin_secret = Arc::new(admin_bearer_secret().map_err(to_dyn_error)?);
    let supervisor = ServeSupervisor::start(config_path, admin_secret).await?;

    for status in supervisor.listener_statuses().await {
        match status.class {
            lb_config_model::ListenerClassConfig::Public => {
                println!(
                    "public listener ready: name={} protocol={} addr={}",
                    status.name,
                    listener_protocol_name(status.protocol),
                    status.local_addr
                );
            }
            lb_config_model::ListenerClassConfig::Admin => {
                println!("admin listener ready: name={} addr={}", status.name, status.local_addr);
            }
        }
    }
    println!("reload with POST /reload on an admin listener or send SIGHUP");
    println!("validate with GET /validate on an admin listener before reload");
    println!("press Ctrl+C to stop");

    #[cfg(unix)]
    {
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        loop {
            tokio::select! {
                ctrl_c = tokio::signal::ctrl_c() => {
                    ctrl_c?;
                    break;
                }
                _ = sighup.recv() => {
                    if let Err(error) = supervisor.reload().await {
                        eprintln!("reload failed: {error}");
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    supervisor.shutdown().await?;
    Ok(())
}

impl ServeSupervisor {
    async fn start(config_path: String, admin_secret: Arc<String>) -> Result<Self, DynError> {
        let state = Arc::new(WorkspaceServeState::new(config_path.clone())?);
        state.restore_control_plane_journal().await?;
        let supervisor = Self {
            shared: Arc::new(ServeSupervisorShared {
                config_path,
                admin_secret,
                state,
                reload_guard: Mutex::new(()),
                inner: Mutex::new(ServeSupervisorInner::default()),
            }),
        };
        let _ = supervisor.reload_with_recovery_resolution(false).await?;
        let listener_statuses = supervisor.listener_statuses().await;
        supervisor.shared.state.reconcile_control_plane_recovery(&listener_statuses).await?;
        Ok(supervisor)
    }

    fn reload(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ReloadApplyOutcome, DynError>> + Send + '_>> {
        self.reload_with_recovery_resolution(true)
    }

    fn reload_with_recovery_resolution(
        &self,
        resolve_recovery: bool,
    ) -> Pin<Box<dyn Future<Output = Result<ReloadApplyOutcome, DynError>> + Send + '_>> {
        Box::pin(async move {
            let _guard = self.shared.reload_guard.lock().await;
            self.shared.state.reload_requests.fetch_add(1, Ordering::SeqCst);
            let started_at = Instant::now();

            let compiled = compile_workspace_runtime_with_telemetry(
                &self.shared.config_path,
                Some(&self.shared.state.telemetry),
            )?;
            let desired_snapshot =
                DurableSnapshotIdentity::from_snapshot(&compiled.source_label, &compiled.snapshot);
            let current_identities = {
                let inner = self.shared.inner.lock().await;
                inner
                    .listeners
                    .iter()
                    .map(|(name, listener)| (name.clone(), listener.current_identity()))
                    .collect::<BTreeMap<_, _>>()
            };
            let reload_plan =
                ReloadAuditPlan::from_candidate(&current_identities, &compiled.listeners);
            self.shared
                .state
                .prepare_reload_persistence(JournalInFlightOperation::from_reload_plan(
                    desired_snapshot.clone(),
                    &reload_plan,
                ))
                .await?;
            let result = self.apply_compiled_runtime(compiled).await;
            let duration_ms = elapsed_millis_at_least_one(started_at.elapsed());
            self.shared.state.record_reload_duration(duration_ms, result.is_ok());
            match &result {
                Ok(outcome) => {
                    self.shared.state.reload_success_count.fetch_add(1, Ordering::SeqCst);
                    self.shared.state.record_reload_drain_outcome(outcome);
                    self.shared
                        .state
                        .reload_health
                        .store(reload_health_index(ReloadHealthState::Healthy), Ordering::SeqCst);
                    *self.shared.state.last_reload_outcome_code.lock().await =
                        String::from(outcome.generic_success_code());
                    *self.shared.state.last_reload_result.lock().await =
                        outcome.generic_success_detail();
                    self.shared
                        .state
                        .finish_reload_persistence(Some(desired_snapshot.clone()), resolve_recovery)
                        .await?;
                }
                Err(error) => {
                    self.shared.state.reload_failure_count.fetch_add(1, Ordering::SeqCst);
                    self.shared
                        .state
                        .reload_health
                        .store(reload_health_index(ReloadHealthState::Failed), Ordering::SeqCst);
                    *self.shared.state.last_reload_outcome_code.lock().await =
                        String::from("reload_failed_apply");
                    *self.shared.state.last_reload_result.lock().await = error.to_string();
                    self.shared.state.finish_reload_persistence(None, resolve_recovery).await?;
                }
            }
            result
        })
    }

    async fn validate_current_config(&self) -> Result<ConfigValidationPreview, DynError> {
        let (active_snapshot, current_identities) = {
            let inner = self.shared.inner.lock().await;
            let current_identities = inner
                .listeners
                .iter()
                .map(|(name, listener)| (name.clone(), listener.current_identity()))
                .collect::<BTreeMap<_, _>>();
            (inner.active_snapshot.clone(), current_identities)
        };
        let candidate = compile_workspace_runtime_with_telemetry(
            &self.shared.config_path,
            Some(&self.shared.state.telemetry),
        )?;

        Ok(build_config_validation_preview(
            &self.shared.config_path,
            active_snapshot.as_ref(),
            &current_identities,
            &candidate,
        ))
    }

    async fn admin_auth_status(&self) -> AdminAuthStatus {
        let admin_policies = {
            let inner = self.shared.inner.lock().await;
            inner
                .listeners
                .iter()
                .filter_map(|(listener_name, slot)| match &slot.active.kind {
                    ManagedListenerKind::Admin { runtime, .. } => {
                        Some((listener_name.clone(), Arc::clone(&runtime.shared_policy)))
                    }
                    ManagedListenerKind::Public { .. } => None,
                })
                .collect::<Vec<_>>()
        };

        let mut secret_sources = Vec::new();
        for (listener_name, shared_policy) in admin_policies {
            let policy = shared_policy.read().await.clone();
            match policy.auth {
                CompiledAdminAuthPolicy::Bearer { secret_env, .. } => {
                    let mut status =
                        inspect_secret_material(&secret_env, self.shared.admin_secret.as_ref());
                    status.listener = listener_name.clone();
                    status.actor = String::from("shared-bearer");
                    status.auth_mode = String::from("bearer");
                    secret_sources.push(status);
                }
                CompiledAdminAuthPolicy::SignedHeaders { operators, .. } => {
                    for (actor, operator) in operators {
                        let mut status = inspect_secret_material(
                            &operator.secret_env,
                            self.shared.admin_secret.as_ref(),
                        );
                        status.listener = listener_name.clone();
                        status.actor = actor;
                        status.auth_mode = String::from("signed_headers");
                        secret_sources.push(status);
                    }
                }
            }
        }

        AdminAuthStatus { secret_sources }
    }

    async fn describe_reload_audit_plan(&self) -> Result<ReloadAuditPlan, DynError> {
        let current_identities = {
            let inner = self.shared.inner.lock().await;
            inner
                .listeners
                .iter()
                .map(|(name, listener)| (name.clone(), listener.current_identity()))
                .collect::<BTreeMap<_, _>>()
        };
        let candidate = compile_workspace_runtime_with_telemetry(
            &self.shared.config_path,
            Some(&self.shared.state.telemetry),
        )?;
        Ok(ReloadAuditPlan::from_candidate(&current_identities, &candidate.listeners))
    }

    async fn describe_restart_audit_plan(&self) -> Result<ReloadAuditPlan, DynError> {
        let current_identities = {
            let inner = self.shared.inner.lock().await;
            inner
                .listeners
                .iter()
                .map(|(name, listener)| (name.clone(), listener.current_identity()))
                .collect::<BTreeMap<_, _>>()
        };
        let candidate = compile_workspace_runtime_with_telemetry(
            &self.shared.config_path,
            Some(&self.shared.state.telemetry),
        )?;
        Ok(ReloadAuditPlan::from_restart_candidate(
            &current_identities,
            &candidate.listeners,
        ))
    }

    fn warm_restart(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<WarmRestartApplyOutcome, DynError>> + Send + '_>> {
        Box::pin(async move {
            let _guard = self.shared.reload_guard.lock().await;
            self.shared.state.restart_requests.fetch_add(1, Ordering::SeqCst);
            let started_at = Instant::now();

            let compiled = compile_workspace_runtime_with_telemetry(
                &self.shared.config_path,
                Some(&self.shared.state.telemetry),
            )?;
            let current_identities = {
                let inner = self.shared.inner.lock().await;
                inner
                    .listeners
                    .iter()
                    .map(|(name, listener)| (name.clone(), listener.current_identity()))
                    .collect::<BTreeMap<_, _>>()
            };
            let restart_plan =
                ReloadAuditPlan::from_restart_candidate(&current_identities, &compiled.listeners);
            let result = self
                .apply_compiled_runtime_with_mode(compiled, ApplyMode::WarmRestart)
                .await
                .map(WarmRestartApplyOutcome::from);
            let duration_ms = elapsed_millis_at_least_one(started_at.elapsed());
            self.shared.state.record_restart_duration(duration_ms, result.is_ok());

            match &result {
                Ok(outcome) => {
                    self.shared.state.restart_success_count.fetch_add(1, Ordering::SeqCst);
                    *self.shared.state.last_restart_outcome_code.lock().await =
                        String::from(restart_plan.restart_success_code(outcome));
                    *self.shared.state.last_restart_result.lock().await =
                        restart_plan.restart_success_detail(outcome);
                }
                Err(error) => {
                    self.shared.state.restart_failure_count.fetch_add(1, Ordering::SeqCst);
                    *self.shared.state.last_restart_outcome_code.lock().await =
                        String::from(restart_plan.restart_failure_code());
                    *self.shared.state.last_restart_result.lock().await =
                        restart_plan.restart_failure_detail(error);
                }
            }

            result
        })
    }

    async fn apply_compiled_runtime(
        &self,
        compiled: CompiledWorkspaceRuntime,
    ) -> Result<ReloadApplyOutcome, DynError> {
        self.apply_compiled_runtime_with_mode(compiled, ApplyMode::Reload)
            .await
    }

    async fn apply_compiled_runtime_with_mode(
        &self,
        compiled: CompiledWorkspaceRuntime,
        mode: ApplyMode,
    ) -> Result<ReloadApplyOutcome, DynError> {
        let CompiledWorkspaceRuntime { source_label, snapshot, listeners, http_cache_scopes } =
            compiled;
        self.shared.state.set_admin_audit_capacity(
            listeners
                .values()
                .filter_map(|listener| match listener {
                    CompiledServeListener::Admin { admin_policy, .. } => {
                        Some(admin_policy.audit_capacity)
                    }
                    CompiledServeListener::Public { .. } => None,
                })
                .max()
                .unwrap_or(ADMIN_AUDIT_DEFAULT_CAPACITY),
        );
        let current_identities = {
            let inner = self.shared.inner.lock().await;
            inner
                .listeners
                .iter()
                .map(|(name, listener)| (name.clone(), listener.current_identity()))
                .collect::<BTreeMap<_, _>>()
        };

        let mut start_specs = Vec::new();
        for (name, spec) in &listeners {
            match current_identities.get(name) {
                Some(current)
                    if mode.force_replace_listener(current) && current.can_stage_replacement(spec) =>
                {
                    start_specs.push((name.clone(), spec.clone()));
                }
                Some(current)
                    if mode.force_replace_listener(current) && !current.can_stage_replacement(spec) =>
                {
                    return Err(format!(
                        "warm restart cannot stage replacement for listener {name} on {}",
                        current.local_addr
                    )
                    .into());
                }
                Some(current) if current.matches_spec(spec) => {}
                Some(current) if current.can_stage_replacement(spec) => {
                    start_specs.push((name.clone(), spec.clone()));
                }
                Some(current) if current.needs_replacement(spec) => {
                    return Err(format!(
                        "reload would require retiring active listener {name} on {} before replacement can start; zero-downtime replacement is not available for this change",
                        current.local_addr
                    )
                    .into());
                }
                _ => start_specs.push((name.clone(), spec.clone())),
            }
        }

        let mut started = Vec::new();
        for (name, spec) in start_specs {
            match start_managed_listener(
                name.clone(),
                spec.clone(),
                Arc::clone(&self.shared.state),
                self.clone(),
            )
            .await
            {
                Ok(handle) => started.push((name, handle)),
                Err(error) => {
                    for (_started_name, listener) in started {
                        let _ = listener.shutdown().await;
                    }
                    let detail = error.to_string();
                    let mut inner = self.shared.inner.lock().await;
                    if let Some(slot) = inner.listeners.get_mut(&name) {
                        slot.record_failed_start(&spec, detail);
                    }
                    return Err(error);
                }
            }
        }
        for (_, listener) in &started {
            listener.prewarm().await;
        }

        let mut retired = Vec::new();
        {
            let mut inner = self.shared.inner.lock().await;

            for (name, spec) in &listeners {
                if let Some(slot) = inner.listeners.get_mut(name) {
                    if (!mode.force_replace_matching()
                        || matches!(slot.active.class, lb_config_model::ListenerClassConfig::Admin))
                        && slot.can_update_in_place(spec)
                    {
                        slot.apply_update(spec).await?;
                    }
                }
            }

            let retired_names = inner
                .listeners
                .keys()
                .filter(|name| !listeners.contains_key(*name))
                .cloned()
                .collect::<Vec<_>>();
            for name in retired_names {
                if let Some(slot) = inner.listeners.remove(&name) {
                    retired.push(slot.into_retired());
                }
            }

            for (name, listener) in started {
                if let Some(slot) = inner.listeners.get_mut(&name) {
                    retired.push(slot.activate_replacement(name.clone(), listener));
                } else {
                    inner.listeners.insert(name, ManagedListenerSlot::new(listener));
                }
            }
            inner.source_label = source_label;
            inner.active_snapshot = Some(snapshot);
        }

        self.shared.state.replace_http_cache_scopes(http_cache_scopes).await;

        let mut outcome = ReloadApplyOutcome::default();
        for retired_listener in retired {
            outcome.drained_listener_count = outcome.drained_listener_count.saturating_add(1);
            let drain_outcome = retired_listener.listener.shutdown().await?;
            match drain_outcome {
                ListenerDrainOutcome::Completed => {
                    outcome.completed_drain_count = outcome.completed_drain_count.saturating_add(1);
                }
                ListenerDrainOutcome::TimedOut => {
                    outcome.drain_timeout_count = outcome.drain_timeout_count.saturating_add(1);
                }
            }
            if let Some(slot_name) = retired_listener.slot_name {
                let mut inner = self.shared.inner.lock().await;
                if let Some(slot) = inner.listeners.get_mut(&slot_name) {
                    slot.finish_draining_with_outcome(retired_listener.identity, drain_outcome);
                }
                if matches!(drain_outcome, ListenerDrainOutcome::TimedOut)
                    && !outcome.drain_timed_out_replacements.iter().any(|name| name == &slot_name)
                {
                    outcome.drain_timed_out_replacements.push(slot_name);
                }
            }
        }

        Ok(outcome)
    }

    async fn shutdown(&self) -> Result<(), DynError> {
        let listeners = {
            let mut inner = self.shared.inner.lock().await;
            std::mem::take(&mut inner.listeners)
                .into_values()
                .map(ManagedListenerSlot::into_retired)
                .collect::<Vec<_>>()
        };
        for listener in listeners {
            listener.listener.shutdown().await?;
        }
        Ok(())
    }

    async fn listener_statuses(&self) -> Vec<ListenerStatus> {
        let listeners = {
            let inner = self.shared.inner.lock().await;
            inner
                .listeners
                .values()
                .map(|slot| {
                    (
                        slot.active.name.clone(),
                        slot.active.class,
                        slot.active.protocol,
                        slot.active.configured_bind,
                        slot.active.local_addr,
                        Arc::clone(&slot.active.counters),
                        Arc::clone(&slot.active.overload_runtime),
                        Arc::clone(&slot.active.abuse_policy),
                        Arc::clone(&slot.active.abuse_protection),
                        match &slot.active.kind {
                            ManagedListenerKind::Public { shared_proxy } => {
                                (Some(Arc::clone(shared_proxy)), None)
                            }
                            ManagedListenerKind::Admin { tls_status, .. } => {
                                (None, tls_status.clone())
                            }
                        },
                        slot.lifecycle.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };

        let mut statuses = Vec::with_capacity(listeners.len());
        for (
            name,
            class,
            protocol,
            configured_bind,
            local_addr,
            counters,
            overload_runtime,
            abuse_policy,
            abuse_protection,
            (shared_proxy, admin_tls_status),
            lifecycle,
        ) in listeners
        {
            let (overload_state, brownout_features, recent_overload_events) =
                snapshot_listener_overload_status(
                    self.shared.state.started_at.elapsed(),
                    &counters,
                    &overload_runtime,
                );
            let abuse_snapshot = abuse_protection.read().await.snapshot();
            let abuse_policy = abuse_policy.read().await.clone();
            let tls = if let Some(shared_proxy) = shared_proxy {
                match shared_proxy.read().await.clone() {
                    ManagedProxyConfig::Https(proxy) => Some(proxy.tls_status),
                    ManagedProxyConfig::Http1(_)
                    | ManagedProxyConfig::Http2(_)
                    | ManagedProxyConfig::Http3(_) => None,
                }
            } else {
                admin_tls_status
            };
            statuses.push(ListenerStatus {
                name,
                class,
                protocol,
                configured_bind,
                local_addr,
                state: counters.state.read().await.clone(),
                overload_state: String::from(overload_state_name(overload_state)),
                accepted_connections: counters.accepted_connections.load(Ordering::SeqCst),
                active_connections: counters.active_connections.load(Ordering::SeqCst),
                shed_connections: counters.shed_connections.load(Ordering::SeqCst),
                completed_connections: counters.completed_connections.load(Ordering::SeqCst),
                abuse_protection: ListenerAbuseProtectionStatus::from_runtime(
                    abuse_policy.as_ref(),
                    abuse_snapshot,
                ),
                brownout_features,
                recent_overload_events,
                replacement: ListenerReplacementStatus::from_lifecycle(&lifecycle),
                tls,
            });
        }
        statuses
    }
}

impl ManagedServeListener {
    async fn prewarm(&self) {
        match &self.kind {
            ManagedListenerKind::Public { shared_proxy } => {
                let mut proxy = shared_proxy.write().await;
                prewarm_proxy_route_backends(&mut proxy);
            }
            ManagedListenerKind::Admin { .. } => {}
        }
    }

    async fn apply_update(&mut self, spec: &CompiledServeListener) -> Result<(), DynError> {
        self.drain_timeout = spec.drain_timeout();
        self.admission_limit.store(spec.max_connections(), Ordering::SeqCst);
        *self.overload_runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            build_listener_overload_runtime(spec.overload_policy())?;
        *self.abuse_policy.write().await = spec.abuse_protection_policy().cloned();
        *self.abuse_protection.write().await =
            build_listener_abuse_protection_state(spec.abuse_protection_policy());
        if let (
            ManagedListenerKind::Public { shared_proxy },
            CompiledServeListener::Public { proxy, .. },
        ) = (&self.kind, spec)
        {
            *shared_proxy.write().await = proxy.clone();
        } else if let (
            ManagedListenerKind::Admin { runtime, .. },
            CompiledServeListener::Admin { admin_policy, .. },
        ) = (&self.kind, spec)
        {
            *runtime.shared_policy.write().await = admin_policy.clone();
        }
        Ok(())
    }

    async fn shutdown(self) -> io::Result<ListenerDrainOutcome> {
        let _ = self.shutdown_tx.send(true);
        self.join().await
    }

    async fn join(self) -> io::Result<ListenerDrainOutcome> {
        let outcome = match self.task.await {
            Ok(result) => result?,
            Err(error) => return Err(io::Error::other(error.to_string())),
        };
        if let Some(probe_task) = self.probe_task {
            probe_task.await.map_err(|error| io::Error::other(error.to_string()))?;
        }
        Ok(outcome)
    }
}

fn prewarm_proxy_route_backends(proxy: &mut ManagedProxyConfig) {
    fn prewarm_route_pools(pools: &BTreeMap<String, lb_runtime::RouteBackendPool>) {
        for pool in pools.values() {
            pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);
        }
    }

    match proxy {
        ManagedProxyConfig::Http1(config) => prewarm_route_pools(&config.route_backend_pools),
        ManagedProxyConfig::Http2(config) => prewarm_route_pools(&config.route_backend_pools),
        ManagedProxyConfig::Https(config) => {
            prewarm_route_pools(&config.http1.route_backend_pools);
            prewarm_route_pools(&config.http2.route_backend_pools);
        }
        ManagedProxyConfig::Http3(config) => prewarm_route_pools(&config.http1.route_backend_pools),
    }
}

