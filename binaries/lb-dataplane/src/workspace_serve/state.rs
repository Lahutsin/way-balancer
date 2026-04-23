#[derive(Debug)]
struct ListenerRuntimeCounters {
    accepted_connections: AtomicU64,
    shed_connections: AtomicU64,
    active_connections: AtomicUsize,
    completed_connections: AtomicU64,
    overload_state: AtomicUsize,
    state: RwLock<String>,
}

impl ListenerRuntimeCounters {
    fn new() -> Self {
        Self {
            accepted_connections: AtomicU64::new(0),
            shed_connections: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            completed_connections: AtomicU64::new(0),
            overload_state: AtomicUsize::new(overload_state_index(
                lb_runtime::OverloadState::Normal,
            )),
            state: RwLock::new(String::from("starting")),
        }
    }
}

#[derive(Debug)]
enum ManagedListenerKind {
    Public { shared_proxy: Arc<RwLock<ManagedProxyConfig>> },
    Admin { runtime: AdminRuntimeHandles, tls_status: Option<ListenerTlsStatus> },
}

#[derive(Debug, Clone)]
struct AdminRuntimeHandles {
    shared_policy: Arc<RwLock<CompiledAdminPolicy>>,
    rate_limit_state: Arc<StdMutex<AdminRateLimitState>>,
    replay_state: Arc<StdMutex<AdminReplayState>>,
}

#[derive(Debug, Clone)]
struct CompiledAdminPolicy {
    auth: CompiledAdminAuthPolicy,
    allowed_source_cidrs: Vec<IpNet>,
    rate_limit: CompiledAdminRateLimit,
    audit_capacity: usize,
}

#[derive(Debug, Clone)]
enum CompiledAdminAuthPolicy {
    Bearer {
        secret_env: String,
        permissions: BTreeSet<AdminPermission>,
    },
    SignedHeaders {
        operators: BTreeMap<String, CompiledAdminOperator>,
        max_clock_skew: Duration,
        nonce_ttl: Duration,
    },
}

#[derive(Debug, Clone)]
struct CompiledAdminOperator {
    secret_env: String,
    permissions: BTreeSet<AdminPermission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AdminPermission {
    Read,
    Audit,
    Write,
}

#[derive(Debug, Clone, Copy)]
struct CompiledAdminRateLimit {
    requests_per_minute: u32,
    burst: u32,
}

#[derive(Debug, Default)]
struct AdminRateLimitState {
    buckets: BTreeMap<AdminRateLimitKey, AdminTokenBucket>,
}

#[derive(Debug, Clone, Copy)]
struct AdminTokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AdminRateLimitKey {
    source: IpAddr,
    actor: String,
    auth_mode: String,
}

#[derive(Debug, Default)]
struct AdminReplayState {
    nonces: BTreeMap<String, Instant>,
}

#[derive(Debug)]
struct WorkspaceServeState {
    started_at: Instant,
    config_path: String,
    telemetry: Arc<lb_runtime::RuntimeTelemetry>,
    proxied_connections: AtomicU64,
    proxied_requests: AtomicU64,
    admin_requests: AtomicU64,
    reload_requests: AtomicU64,
    reload_success_count: AtomicU64,
    reload_failure_count: AtomicU64,
    reload_total_duration_ms: AtomicU64,
    reload_max_duration_ms: AtomicU64,
    last_reload_duration_ms: AtomicU64,
    last_successful_reload_duration_ms: AtomicU64,
    last_failed_reload_duration_ms: AtomicU64,
    reload_health: AtomicUsize,
    admin_audit_sequence: AtomicU64,
    admin_audit_capacity: AtomicUsize,
    last_reload_outcome_code: Mutex<String>,
    last_reload_result: Mutex<String>,
    recent_admin_audit: Mutex<VecDeque<AdminAuditEvent>>,
    http_cache_scopes: RwLock<BTreeMap<String, HttpCacheScopeRuntime>>,
    control_plane_journal: Mutex<ControlPlaneJournalRuntime>,
}

impl WorkspaceServeState {
    fn new(config_path: String) -> Result<Self, DynError> {
        Ok(Self {
            started_at: Instant::now(),
            config_path: config_path.clone(),
            telemetry: Arc::new(lb_runtime::RuntimeTelemetry::new().map_err(to_dyn_error)?),
            proxied_connections: AtomicU64::new(0),
            proxied_requests: AtomicU64::new(0),
            admin_requests: AtomicU64::new(0),
            reload_requests: AtomicU64::new(0),
            reload_success_count: AtomicU64::new(0),
            reload_failure_count: AtomicU64::new(0),
            reload_total_duration_ms: AtomicU64::new(0),
            reload_max_duration_ms: AtomicU64::new(0),
            last_reload_duration_ms: AtomicU64::new(0),
            last_successful_reload_duration_ms: AtomicU64::new(0),
            last_failed_reload_duration_ms: AtomicU64::new(0),
            reload_health: AtomicUsize::new(reload_health_index(ReloadHealthState::NotRequested)),
            admin_audit_sequence: AtomicU64::new(1),
            admin_audit_capacity: AtomicUsize::new(ADMIN_AUDIT_DEFAULT_CAPACITY),
            last_reload_outcome_code: Mutex::new(String::from("not_requested")),
            last_reload_result: Mutex::new(String::from("not requested")),
            recent_admin_audit: Mutex::new(VecDeque::new()),
            http_cache_scopes: RwLock::new(BTreeMap::new()),
            control_plane_journal: Mutex::new(ControlPlaneJournalRuntime::new(&config_path)),
        })
    }

    async fn replace_http_cache_scopes(&self, scopes: BTreeMap<String, HttpCacheScopeRuntime>) {
        *self.http_cache_scopes.write().await = scopes;
    }

    async fn http_cache_scope(&self, scope: &str) -> Option<HttpCacheScopeRuntime> {
        self.http_cache_scopes.read().await.get(scope).cloned()
    }

    async fn status_body(&self, supervisor: &ServeSupervisor) -> String {
        let listener_statuses = supervisor.listener_statuses().await;
        let admin_auth_json = supervisor.admin_auth_status().await.to_json();
        let last_reload_outcome_code = self.last_reload_outcome_code.lock().await.clone();
        let last_reload_result = self.last_reload_result.lock().await.clone();
        let reload_health = self.reload_health();
        let readiness = evaluate_workspace_readiness(&listener_statuses, reload_health);
        let listeners_json =
            listener_statuses.iter().map(ListenerStatus::to_json).collect::<Vec<_>>().join(",\n");
        let overload_events_json = self
            .telemetry
            .snapshot()
            .events
            .into_iter()
            .filter(|event| event.category == lb_observability::TelemetryEventCategory::Overload)
            .map(|event| OverloadEventStatus::from_telemetry(event).to_json())
            .collect::<Vec<_>>()
            .join(",\n");
        let control_plane_journal_json = self.control_plane_journal.lock().await.to_status_json();

        format!(
            concat!(
                "{{\n",
                "  \"service\": \"lb-dataplane\",\n",
                "  \"mode\": \"workspace\",\n",
                "  \"config_path\": \"{}\",\n",
                "  \"uptime_secs\": {},\n",
                "  \"proxied_connections\": {},\n",
                "  \"proxied_requests\": {},\n",
                "  \"admin_requests\": {},\n",
                "  \"reload_requests\": {},\n",
                "  \"reload_success_count\": {},\n",
                "  \"reload_failure_count\": {},\n",
                "  \"reload_total_duration_ms\": {},\n",
                "  \"reload_max_duration_ms\": {},\n",
                "  \"reload_last_duration_ms\": {},\n",
                "  \"reload_last_success_duration_ms\": {},\n",
                "  \"reload_last_failure_duration_ms\": {},\n",
                "  \"reload_health\": \"{}\",\n",
                "  \"last_reload_outcome_code\": \"{}\",\n",
                "  \"admin_audit_events\": {},\n",
                "  \"last_reload_result\": \"{}\",\n",
                "  \"admin_auth\": {},\n",
                "  \"control_plane_journal\": {},\n",
                "  \"readiness\": {},\n",
                "  \"listeners\": [\n{}\n  ],\n",
                "  \"recent_overload_events\": [\n{}\n  ]\n",
                "}}\n"
            ),
            crate::escape_json_string(&self.config_path),
            self.started_at.elapsed().as_secs(),
            self.proxied_connections.load(Ordering::SeqCst),
            self.proxied_requests.load(Ordering::SeqCst),
            self.admin_requests.load(Ordering::SeqCst),
            self.reload_requests.load(Ordering::SeqCst),
            self.reload_success_count.load(Ordering::SeqCst),
            self.reload_failure_count.load(Ordering::SeqCst),
            self.reload_total_duration_ms.load(Ordering::SeqCst),
            self.reload_max_duration_ms.load(Ordering::SeqCst),
            self.last_reload_duration_ms.load(Ordering::SeqCst),
            self.last_successful_reload_duration_ms.load(Ordering::SeqCst),
            self.last_failed_reload_duration_ms.load(Ordering::SeqCst),
            reload_health_name(reload_health),
            crate::escape_json_string(&last_reload_outcome_code),
            self.recent_admin_audit.lock().await.len(),
            crate::escape_json_string(&last_reload_result),
            admin_auth_json,
            control_plane_journal_json,
            readiness.to_json(),
            if listeners_json.is_empty() { String::new() } else { format!("    {listeners_json}") },
            if overload_events_json.is_empty() {
                String::new()
            } else {
                format!("    {overload_events_json}")
            },
        )
    }

    fn reload_health(&self) -> ReloadHealthState {
        match self.reload_health.load(Ordering::SeqCst) {
            1 => ReloadHealthState::Healthy,
            2 => ReloadHealthState::Failed,
            _ => ReloadHealthState::NotRequested,
        }
    }

    fn record_reload_duration(&self, duration_ms: u64, succeeded: bool) {
        self.reload_total_duration_ms.fetch_add(duration_ms, Ordering::SeqCst);
        self.reload_max_duration_ms.fetch_max(duration_ms, Ordering::SeqCst);
        self.last_reload_duration_ms.store(duration_ms, Ordering::SeqCst);
        if succeeded {
            self.last_successful_reload_duration_ms.store(duration_ms, Ordering::SeqCst);
        } else {
            self.last_failed_reload_duration_ms.store(duration_ms, Ordering::SeqCst);
        }
    }

    fn record_overload_event(
        &self,
        listener_name: &str,
        kind: lb_observability::OverloadEventKind,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        let scope = overload_scope(listener_name);
        if let Err(error) = self.telemetry.record_overload_event(&lb_observability::OverloadEvent {
            kind,
            scope,
            detail,
        }) {
            eprintln!("overload telemetry emission failed: {error}");
        }
    }

    fn record_http3_request(&self, listener_name: &str, result: &str, reason: &str) {
        if let Err(error) =
            self.telemetry.record_http3_request(&http3_scope(listener_name), result, reason)
        {
            eprintln!("http3 telemetry emission failed: {error}");
        }
    }

    fn record_listener_abuse_rejection(
        &self,
        listener_name: &str,
        reason: lb_runtime::AbuseRejectionReason,
    ) {
        let detail = format!(
            "listener rejected hostile-edge connection: {} ({})",
            reason.code(),
            reason.detail(),
        );
        if let Err(error) =
            self.telemetry.record_listener_abuse_rejection(listener_name, reason, &detail)
        {
            eprintln!("listener abuse telemetry emission failed: {error}");
        }
    }

    async fn sync_listener_abuse_snapshot(
        &self,
        listener_name: &str,
        abuse_protection: &RwLock<lb_runtime::ListenerAbuseProtectionState>,
    ) {
        let snapshot = abuse_protection.read().await.snapshot();
        if let Err(error) = self.telemetry.record_listener_abuse_snapshot(listener_name, &snapshot)
        {
            eprintln!("listener abuse snapshot emission failed: {error}");
        }
    }

    fn set_admin_audit_capacity(&self, capacity: usize) {
        self.admin_audit_capacity.store(capacity.max(1), Ordering::SeqCst);
    }

    async fn record_admin_audit(&self, event: AdminAuditEvent) {
        let max_events = self.admin_audit_capacity.load(Ordering::SeqCst).max(1);
        let mut recent = self.recent_admin_audit.lock().await;
        recent.push_back(event);
        while recent.len() > max_events {
            recent.pop_front();
        }
        drop(recent);
        if let Err(error) = self.persist_control_plane_journal().await {
            eprintln!("control-plane journal persistence failed after audit update: {error}");
        }
    }

    async fn audit_body(&self) -> Result<String, DynError> {
        let recent = self.recent_admin_audit.lock().await;
        serde_json::to_string_pretty(&recent.iter().cloned().collect::<Vec<_>>())
            .map_err(to_dyn_error)
    }

    fn next_admin_request_id(&self) -> String {
        format!("admin-{:016x}", self.admin_audit_sequence.fetch_add(1, Ordering::SeqCst))
    }

    async fn prepare_reload_persistence(
        &self,
        operation: JournalInFlightOperation,
    ) -> Result<(), DynError> {
        let mut journal = self.control_plane_journal.lock().await;
        journal.desired_snapshot = Some(operation.desired_snapshot.clone());
        journal.in_flight_operation = Some(operation);
        drop(journal);
        self.persist_control_plane_journal().await
    }

    async fn finish_reload_persistence(
        &self,
        applied_snapshot: Option<DurableSnapshotIdentity>,
        resolve_recovery: bool,
    ) -> Result<(), DynError> {
        let current_reload_health = String::from(reload_health_name(self.reload_health()));
        let current_reload_outcome_code = self.last_reload_outcome_code.lock().await.clone();
        let mut journal = self.control_plane_journal.lock().await;
        if let Some(applied_snapshot) = applied_snapshot {
            journal.applied_snapshot = Some(applied_snapshot);
        }
        journal.in_flight_operation = None;
        if resolve_recovery && journal.recovery.state == "needs_operator_action" {
            journal.recovery.state = String::from("resolved");
            journal.recovery.detail =
                String::from("operator completed a subsequent reload after startup recovery");
            journal.recovery.last_persisted_at_unix_ms = Some(unix_time_ms());
            journal.recovery.restored_reload_health = Some(current_reload_health);
            journal.recovery.restored_last_reload_outcome_code = Some(current_reload_outcome_code);
            journal.recovery.in_flight_operation = None;
        }
        drop(journal);
        self.persist_control_plane_journal().await
    }

    async fn restore_control_plane_journal(&self) -> Result<(), DynError> {
        let journal_path = self.control_plane_journal.lock().await.journal_path.clone();
        if !Path::new(&journal_path).exists() {
            return Ok(());
        }

        let raw = fs::read_to_string(&journal_path).map_err(to_dyn_error)?;
        let envelope: ControlPlaneJournalEnvelope =
            serde_json::from_str(&raw).map_err(|error| {
                to_dyn_error(format!(
                    "control-plane journal at {journal_path} is unreadable: {error}"
                ))
            })?;
        if envelope.version != CONTROL_PLANE_JOURNAL_VERSION {
            return Err(to_dyn_error(format!(
                "control-plane journal at {journal_path} uses unsupported version {}",
                envelope.version
            )));
        }
        let expected_sha256 = sha256_hex(envelope.payload_json.as_bytes());
        if envelope.payload_sha256 != expected_sha256 {
            return Err(to_dyn_error(format!(
                "control-plane journal at {journal_path} failed checksum validation"
            )));
        }
        let payload: ControlPlaneJournalPayload = serde_json::from_str(&envelope.payload_json)
            .map_err(|error| {
                to_dyn_error(format!(
                    "control-plane journal payload at {journal_path} is invalid: {error}"
                ))
            })?;

        let mut restored_reload_health = reload_health_from_name(&payload.reload_health);
        let mut restored_last_reload_outcome_code = payload.last_reload_outcome_code.clone();
        let mut restored_last_reload_result = payload.last_reload_result.clone();
        let mut restored_recent_admin_audit = payload.recent_admin_audit.clone();
        if let Some(operation) = payload.in_flight_operation.as_ref() {
            restored_reload_health = ReloadHealthState::Failed;
            restored_last_reload_outcome_code = String::from(RECOVERY_UNFINISHED_RELOAD_CODE);
            restored_last_reload_result = format!(
                "startup recovery detected unfinished reload for desired snapshot {}; operator must validate and reload again",
                operation.desired_snapshot.digest_sha256
            );
            restored_recent_admin_audit.push(AdminAuditEvent {
                observed_at_unix_ms: unix_time_ms(),
                request_id: format!("recovery-{:016x}", unix_time_ms()),
                listener: String::from("system"),
                actor: String::from("system"),
                auth_mode: String::from("recovery"),
                action: String::from("reload_recovery"),
                code: String::from(RECOVERY_UNFINISHED_RELOAD_CODE),
                source: String::from("local"),
                outcome: String::from("needs_operator_action"),
                detail: restored_last_reload_result.clone(),
            });
        }
        let audit_capacity = self.admin_audit_capacity.load(Ordering::SeqCst).max(1);
        while restored_recent_admin_audit.len() > audit_capacity {
            restored_recent_admin_audit.remove(0);
        }

        self.reload_health.store(reload_health_index(restored_reload_health), Ordering::SeqCst);
        *self.last_reload_outcome_code.lock().await = restored_last_reload_outcome_code;
        *self.last_reload_result.lock().await = restored_last_reload_result;
        *self.recent_admin_audit.lock().await =
            restored_recent_admin_audit.iter().cloned().collect();
        self.admin_audit_sequence
            .store(next_admin_sequence_from_events(&restored_recent_admin_audit), Ordering::SeqCst);

        let mut journal = self.control_plane_journal.lock().await;
        journal.desired_snapshot = payload.desired_snapshot.clone();
        journal.applied_snapshot = payload.applied_snapshot.clone();
        journal.in_flight_operation = payload.in_flight_operation.clone();
        journal.recovery = ControlPlaneRecoveryInfo::restored(&payload);
        drop(journal);
        if payload.in_flight_operation.is_some() {
            self.persist_control_plane_journal().await?;
        }
        Ok(())
    }

    async fn persist_control_plane_journal(&self) -> Result<(), DynError> {
        let (journal_path, desired_snapshot, applied_snapshot, in_flight_operation) = {
            let journal = self.control_plane_journal.lock().await;
            (
                journal.journal_path.clone(),
                journal.desired_snapshot.clone(),
                journal.applied_snapshot.clone(),
                journal.in_flight_operation.clone(),
            )
        };
        let last_reload_outcome_code = self.last_reload_outcome_code.lock().await.clone();
        let last_reload_result = self.last_reload_result.lock().await.clone();
        let recent_admin_audit = self.recent_admin_audit.lock().await.iter().cloned().collect();
        let payload = ControlPlaneJournalPayload {
            persisted_at_unix_ms: unix_time_ms(),
            desired_snapshot,
            applied_snapshot,
            reload_health: String::from(reload_health_name(self.reload_health())),
            last_reload_outcome_code,
            last_reload_result,
            recent_admin_audit,
            in_flight_operation,
        };
        write_control_plane_journal_atomic(&journal_path, &payload)
    }

    async fn reconcile_control_plane_recovery(
        &self,
        listener_statuses: &[ListenerStatus],
    ) -> Result<(), DynError> {
        let mut journal = self.control_plane_journal.lock().await;
        journal.recovery.reconcile_with_listener_statuses(listener_statuses);
        drop(journal);
        self.persist_control_plane_journal().await
    }

    fn sync_listener_overload_snapshot(
        &self,
        listener_name: &str,
        counters: &ListenerRuntimeCounters,
        limit: usize,
        overload_runtime: &StdMutex<Option<ListenerOverloadRuntime>>,
        record_concurrency_signal: bool,
    ) {
        let (snapshot, _brownout_features) = snapshot_listener_overload(
            self.started_at.elapsed(),
            counters,
            limit,
            overload_runtime,
            record_concurrency_signal,
        );
        let next_state = overload_state_index(snapshot.state);
        let previous_state = counters.overload_state.swap(next_state, Ordering::SeqCst);
        if previous_state != next_state {
            self.record_overload_event(
                listener_name,
                lb_observability::OverloadEventKind::StateChanged,
                format!("listener overload state transitioned to {:?}", snapshot.state),
            );
        }
        if let Err(error) =
            self.telemetry.record_overload_snapshot(&overload_scope(listener_name), &snapshot)
        {
            eprintln!("overload snapshot emission failed: {error}");
        }
    }
}
