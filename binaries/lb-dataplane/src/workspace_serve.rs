#![allow(
    clippy::large_enum_variant,
    clippy::question_mark,
    clippy::result_large_err,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::useless_format
)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fs;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::Connection as H3Connection;
use ipnet::IpNet;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ProducesTickets, ResolvesServerCert};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{oneshot, watch, Mutex, RwLock};
use tokio::task::JoinSet;
use tokio::time;
use tokio_rustls::TlsAcceptor;

use crate::{
    admin_bearer_secret, compile_anonymous_source_filter, compile_trusted_client_ip, ServeArgs,
};

type DynError = Box<dyn Error + Send + Sync>;

static TLS12_AND_TLS13: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS13, &rustls::version::TLS12];
static TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
const ACTIVE_HEALTH_PROBE_INTERVAL: Duration = Duration::from_millis(500);
const ACTIVE_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_millis(150);
const ROUTE_BACKEND_WARMUP_DURATION: Duration = Duration::from_secs(1);
const PROXY_PROTOCOL_V1_MAX_LEN: usize = 108;
const PROXY_PROTOCOL_V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, b'Q', b'U', b'I', b'T', 0x0a,
];
const ADMIN_AUDIT_DEFAULT_CAPACITY: usize = 64;
const CONTROL_PLANE_JOURNAL_VERSION: u32 = 1;
const RECOVERY_UNFINISHED_RELOAD_CODE: &str = "reload_recovered_unfinished";
const TLS_STATUS_EXPIRY_WARNING_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);
static NEXT_CONTROL_PLANE_JOURNAL_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static RUSTLS_CRYPTO_PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();

fn to_dyn_error(error: impl std::fmt::Display) -> DynError {
    Box::new(io::Error::other(error.to_string()))
}

fn ensure_rustls_crypto_provider() {
    RUSTLS_CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

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

#[derive(Debug, Clone)]
struct CompiledListenerOverloadPolicy {
    signal_window: Duration,
    constrained_signal_threshold: u64,
    shedding_signal_threshold: u64,
    brownout_signal_threshold: u64,
    brownout_features: Vec<CompiledBrownoutFeature>,
}

#[derive(Debug, Clone)]
struct CompiledListenerAbuseProtectionPolicy {
    source_quota: Option<CompiledSourceQuotaPolicy>,
    handshake_guard: Option<CompiledHandshakeGuardPolicy>,
}

#[derive(Debug, Clone, Copy)]
struct CompiledSourceQuotaPolicy {
    aggregation: lb_runtime::SourceAggregation,
    max_active_per_source: usize,
    max_tracked_sources: usize,
}

#[derive(Debug, Clone, Copy)]
struct CompiledHandshakeGuardPolicy {
    max_inflight: usize,
    timeout: Duration,
}

#[derive(Debug, Clone)]
struct CompiledBrownoutFeature {
    name: String,
    priority: lb_runtime::TrafficClass,
}

#[derive(Debug)]
struct ListenerOverloadRuntime {
    manager: lb_runtime::OverloadManager,
}

impl ListenerOverloadRuntime {
    fn new(policy: &CompiledListenerOverloadPolicy) -> Result<Self, DynError> {
        Ok(Self {
            manager: lb_runtime::OverloadManager::new(
                lb_runtime::OverloadPolicy {
                    signal_window: policy.signal_window,
                    constrained_signal_threshold: policy.constrained_signal_threshold,
                    shedding_signal_threshold: policy.shedding_signal_threshold,
                    brownout_signal_threshold: policy.brownout_signal_threshold,
                },
                lb_runtime::BrownoutHookRegistry::new(
                    policy
                        .brownout_features
                        .iter()
                        .map(|feature| lb_runtime::BrownoutFeature {
                            name: feature.name.clone(),
                            priority: feature.priority,
                        })
                        .collect(),
                )
                .map_err(to_dyn_error)?,
            )
            .map_err(to_dyn_error)?,
        })
    }

    fn record_concurrency_signal(
        &self,
        observed_at: Duration,
    ) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
        let snapshot = self.manager.record_signal(
            observed_at,
            lb_runtime::OverloadSignal {
                concurrency_limited: true,
                ..lb_runtime::OverloadSignal::default()
            },
        );
        (snapshot, self.manager.disabled_features().into_iter().collect())
    }

    fn snapshot(&self, observed_at: Duration) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
        let snapshot = self.manager.snapshot(observed_at);
        (snapshot, self.manager.disabled_features().into_iter().collect())
    }

    fn recent_events(&self) -> Vec<lb_observability::OverloadEvent> {
        self.manager.recent_events()
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminAuditEvent {
    observed_at_unix_ms: u64,
    request_id: String,
    listener: String,
    actor: String,
    auth_mode: String,
    action: String,
    code: String,
    source: String,
    outcome: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DurableSnapshotIdentity {
    source_label: String,
    digest_sha256: String,
    api_version: String,
    snapshot_format_version: String,
}

impl DurableSnapshotIdentity {
    fn from_snapshot(source_label: &str, snapshot: &lb_config_model::WorkspaceSnapshot) -> Self {
        Self {
            source_label: source_label.to_string(),
            digest_sha256: snapshot.metadata().digest_sha256().to_owned(),
            api_version: serde_json::to_value(snapshot.metadata().api_version())
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| String::from("unknown")),
            snapshot_format_version: snapshot.metadata().format_version().to_string(),
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"source_label\":\"{}\",",
                "\"digest_sha256\":\"{}\",",
                "\"api_version\":\"{}\",",
                "\"snapshot_format_version\":\"{}\"",
                "}}"
            ),
            crate::escape_json_string(&self.source_label),
            crate::escape_json_string(&self.digest_sha256),
            crate::escape_json_string(&self.api_version),
            crate::escape_json_string(&self.snapshot_format_version),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct JournalInFlightOperation {
    kind: String,
    started_at_unix_ms: u64,
    desired_snapshot: DurableSnapshotIdentity,
    lifecycle_code: String,
    detail: String,
    expected_completion_within_ms: Option<u64>,
    affected_listeners: Vec<String>,
}

impl JournalInFlightOperation {
    fn from_reload_plan(desired_snapshot: DurableSnapshotIdentity, plan: &ReloadAuditPlan) -> Self {
        let affected_listeners = if !plan.supported_replacements.is_empty() {
            plan.supported_replacements.clone()
        } else {
            plan.blocked_replacements.clone()
        };
        Self {
            kind: String::from(if !plan.supported_replacements.is_empty() {
                "reload_overlap_drain"
            } else {
                "reload"
            }),
            started_at_unix_ms: unix_time_ms(),
            desired_snapshot,
            lifecycle_code: String::from(plan.start_code()),
            detail: plan.start_detail(),
            expected_completion_within_ms: plan.expected_completion_within_ms,
            affected_listeners,
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"kind\":\"{}\",",
                "\"started_at_unix_ms\":{},",
                "\"desired_snapshot\":{},",
                "\"lifecycle_code\":\"{}\",",
                "\"detail\":\"{}\",",
                "\"expected_completion_within_ms\":{},",
                "\"affected_listeners\":[{}]",
                "}}"
            ),
            crate::escape_json_string(&self.kind),
            self.started_at_unix_ms,
            self.desired_snapshot.to_json(),
            crate::escape_json_string(&self.lifecycle_code),
            crate::escape_json_string(&self.detail),
            optional_u64_json(self.expected_completion_within_ms),
            self.affected_listeners
                .iter()
                .map(|listener| format!("\"{}\"", crate::escape_json_string(listener)))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlPlaneJournalPayload {
    persisted_at_unix_ms: u64,
    desired_snapshot: Option<DurableSnapshotIdentity>,
    applied_snapshot: Option<DurableSnapshotIdentity>,
    reload_health: String,
    last_reload_outcome_code: String,
    last_reload_result: String,
    recent_admin_audit: Vec<AdminAuditEvent>,
    in_flight_operation: Option<JournalInFlightOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlPlaneJournalEnvelope {
    version: u32,
    payload_json: String,
    payload_sha256: String,
}

#[derive(Debug, Clone)]
struct ControlPlaneRecoveryInfo {
    state: String,
    detail: String,
    last_persisted_at_unix_ms: Option<u64>,
    restored_reload_health: Option<String>,
    restored_last_reload_outcome_code: Option<String>,
    in_flight_operation: Option<JournalInFlightOperation>,
    reconciled_listeners: Vec<RecoveredListenerStatus>,
}

#[derive(Debug, Clone)]
struct RecoveryOperatorGuidance {
    recommended_action: String,
    urgency: String,
    operation_age_ms: Option<u64>,
    expected_completion_within_ms: Option<u64>,
    exceeded_expected_completion: bool,
}

impl RecoveryOperatorGuidance {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"recommended_action\":\"{}\",",
                "\"urgency\":\"{}\",",
                "\"operation_age_ms\":{},",
                "\"expected_completion_within_ms\":{},",
                "\"exceeded_expected_completion\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.recommended_action),
            crate::escape_json_string(&self.urgency),
            optional_u64_json(self.operation_age_ms),
            optional_u64_json(self.expected_completion_within_ms),
            self.exceeded_expected_completion,
        )
    }
}

#[derive(Debug, Clone)]
struct RecoveryReconciliationSummary {
    overall_verdict: String,
    recommended_action: String,
    settled_count: usize,
    draining_count: usize,
    failed_preserved_count: usize,
    drain_timeout_count: usize,
    missing_count: usize,
    needs_review_count: usize,
}

impl RecoveryReconciliationSummary {
    fn from_reconciled_listeners(listeners: &[RecoveredListenerStatus]) -> Self {
        let mut summary = Self {
            overall_verdict: String::from("none"),
            recommended_action: String::from("none"),
            settled_count: 0,
            draining_count: 0,
            failed_preserved_count: 0,
            drain_timeout_count: 0,
            missing_count: 0,
            needs_review_count: 0,
        };
        for listener in listeners {
            match listener.reconciliation_verdict.as_str() {
                "settled" => summary.settled_count += 1,
                "replacement_still_draining" => summary.draining_count += 1,
                "replacement_failed_preserved" => summary.failed_preserved_count += 1,
                "replacement_drain_timeout" => summary.drain_timeout_count += 1,
                "missing" => summary.missing_count += 1,
                _ => summary.needs_review_count += 1,
            }
        }
        summary.overall_verdict = if listeners.is_empty() {
            String::from("none")
        } else if summary.missing_count > 0 || summary.needs_review_count > 0 {
            String::from("needs_review")
        } else if summary.failed_preserved_count > 0 {
            String::from("replacement_failed_preserved")
        } else if summary.drain_timeout_count > 0 {
            String::from("replacement_drain_timeout")
        } else if summary.draining_count > 0 {
            String::from("replacement_still_draining")
        } else {
            String::from("settled")
        };
        summary.recommended_action = match summary.overall_verdict.as_str() {
            "none" => String::from("none"),
            "settled" => String::from("observe_only"),
            "replacement_still_draining" => String::from("wait_for_drain_completion"),
            "replacement_failed_preserved" => String::from("validate_and_retry_reload"),
            "replacement_drain_timeout" => String::from("investigate_drain_timeout"),
            _ => String::from("investigate_and_validate_reload"),
        };
        summary
    }

    fn urgency(&self) -> &'static str {
        match self.overall_verdict.as_str() {
            "none" | "settled" => "none",
            "replacement_still_draining" => "watch",
            "replacement_failed_preserved" => "action_required",
            "replacement_drain_timeout" | "needs_review" => "urgent",
            _ => "urgent",
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"overall_verdict\":\"{}\",",
                "\"recommended_action\":\"{}\",",
                "\"settled_count\":{},",
                "\"draining_count\":{},",
                "\"failed_preserved_count\":{},",
                "\"drain_timeout_count\":{},",
                "\"missing_count\":{},",
                "\"needs_review_count\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.overall_verdict),
            crate::escape_json_string(&self.recommended_action),
            self.settled_count,
            self.draining_count,
            self.failed_preserved_count,
            self.drain_timeout_count,
            self.missing_count,
            self.needs_review_count,
        )
    }
}

#[derive(Debug, Clone)]
struct RecoveredListenerStatus {
    name: String,
    listener_state: String,
    replacement_state: String,
    reconciliation_verdict: String,
}

impl RecoveredListenerStatus {
    fn new(name: String, listener_state: String, replacement_state: String) -> Self {
        let reconciliation_verdict = match (listener_state.as_str(), replacement_state.as_str()) {
            ("running", "stable") => String::from("settled"),
            ("running", "replacement_draining") => String::from("replacement_still_draining"),
            ("missing", "missing") => String::from("missing"),
            (_, "failed_start_preserved") => String::from("replacement_failed_preserved"),
            (_, "drain_timeout_expired") => String::from("replacement_drain_timeout"),
            _ => String::from("needs_review"),
        };
        Self { name, listener_state, replacement_state, reconciliation_verdict }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"name\":\"{}\",",
                "\"listener_state\":\"{}\",",
                "\"replacement_state\":\"{}\",",
                "\"reconciliation_verdict\":\"{}\"",
                "}}"
            ),
            crate::escape_json_string(&self.name),
            crate::escape_json_string(&self.listener_state),
            crate::escape_json_string(&self.replacement_state),
            crate::escape_json_string(&self.reconciliation_verdict),
        )
    }
}

impl Default for ControlPlaneRecoveryInfo {
    fn default() -> Self {
        Self {
            state: String::from("none"),
            detail: String::from("no durable control-plane state recovered"),
            last_persisted_at_unix_ms: None,
            restored_reload_health: None,
            restored_last_reload_outcome_code: None,
            in_flight_operation: None,
            reconciled_listeners: Vec::new(),
        }
    }
}

impl ControlPlaneRecoveryInfo {
    fn restored(payload: &ControlPlaneJournalPayload) -> Self {
        let (state, detail) = match &payload.in_flight_operation {
            Some(operation) => (
                String::from("needs_operator_action"),
                format!(
                    "recovered unfinished {} for desired snapshot {}",
                    operation.kind, operation.desired_snapshot.digest_sha256
                ),
            ),
            None => (
                String::from("restored"),
                String::from("restored durable control-plane state from local journal"),
            ),
        };
        Self {
            state,
            detail,
            last_persisted_at_unix_ms: Some(payload.persisted_at_unix_ms),
            restored_reload_health: Some(payload.reload_health.clone()),
            restored_last_reload_outcome_code: Some(payload.last_reload_outcome_code.clone()),
            in_flight_operation: payload.in_flight_operation.clone(),
            reconciled_listeners: Vec::new(),
        }
    }

    fn reconcile_with_listener_statuses(&mut self, listener_statuses: &[ListenerStatus]) {
        let Some(operation) = self.in_flight_operation.as_ref() else {
            self.reconciled_listeners.clear();
            return;
        };
        self.reconciled_listeners = operation
            .affected_listeners
            .iter()
            .map(|listener_name| {
                listener_statuses
                    .iter()
                    .find(|status| &status.name == listener_name)
                    .map(|status| {
                        RecoveredListenerStatus::new(
                            listener_name.clone(),
                            status.state.clone(),
                            status.replacement.state.clone(),
                        )
                    })
                    .unwrap_or_else(|| {
                        RecoveredListenerStatus::new(
                            listener_name.clone(),
                            String::from("missing"),
                            String::from("missing"),
                        )
                    })
            })
            .collect();
    }

    fn operator_guidance_at(&self, now_ms: u64) -> RecoveryOperatorGuidance {
        let reconciliation_summary =
            RecoveryReconciliationSummary::from_reconciled_listeners(&self.reconciled_listeners);
        let operation_age_ms = self
            .in_flight_operation
            .as_ref()
            .map(|operation| now_ms.saturating_sub(operation.started_at_unix_ms));
        let expected_completion_within_ms = self
            .in_flight_operation
            .as_ref()
            .and_then(|operation| operation.expected_completion_within_ms);
        let exceeded_expected_completion = match (operation_age_ms, expected_completion_within_ms) {
            (Some(age_ms), Some(expected_ms)) => age_ms > expected_ms,
            _ => false,
        };
        if self.state == "needs_operator_action" {
            let (recommended_action, urgency) = match reconciliation_summary
                .overall_verdict
                .as_str()
            {
                "replacement_still_draining" if exceeded_expected_completion => {
                    ("investigate_stalled_drain", "action_required")
                }
                "replacement_still_draining" => ("wait_for_drain_completion", "watch"),
                "replacement_failed_preserved" => ("validate_and_retry_reload", "action_required"),
                "replacement_drain_timeout" => ("investigate_drain_timeout", "urgent"),
                "needs_review" => ("investigate_and_validate_reload", "urgent"),
                _ => ("validate_and_retry_reload", "action_required"),
            };
            return RecoveryOperatorGuidance {
                recommended_action: String::from(recommended_action),
                urgency: String::from(urgency),
                operation_age_ms,
                expected_completion_within_ms,
                exceeded_expected_completion,
            };
        }

        let urgency = reconciliation_summary.urgency();
        RecoveryOperatorGuidance {
            recommended_action: reconciliation_summary.recommended_action,
            urgency: String::from(urgency),
            operation_age_ms,
            expected_completion_within_ms,
            exceeded_expected_completion,
        }
    }

    fn operator_guidance(&self) -> RecoveryOperatorGuidance {
        self.operator_guidance_at(unix_time_ms())
    }

    fn to_json(&self) -> String {
        let reconciliation_summary =
            RecoveryReconciliationSummary::from_reconciled_listeners(&self.reconciled_listeners);
        let operator_guidance = self.operator_guidance();
        format!(
            concat!(
                "{{",
                "\"state\":\"{}\",",
                "\"detail\":\"{}\",",
                "\"last_persisted_at_unix_ms\":{},",
                "\"restored_reload_health\":{},",
                "\"restored_last_reload_outcome_code\":{},",
                "\"in_flight_operation\":{},",
                "\"operator_guidance\":{},",
                "\"reconciled_listeners\":[{}],",
                "\"reconciliation_summary\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.state),
            crate::escape_json_string(&self.detail),
            optional_u64_json(self.last_persisted_at_unix_ms),
            optional_string_json(self.restored_reload_health.as_deref()),
            optional_string_json(self.restored_last_reload_outcome_code.as_deref()),
            self.in_flight_operation
                .as_ref()
                .map_or_else(|| String::from("null"), JournalInFlightOperation::to_json),
            operator_guidance.to_json(),
            self.reconciled_listeners
                .iter()
                .map(RecoveredListenerStatus::to_json)
                .collect::<Vec<_>>()
                .join(","),
            reconciliation_summary.to_json(),
        )
    }
}

#[derive(Debug, Clone)]
struct ControlPlaneJournalRuntime {
    journal_path: String,
    desired_snapshot: Option<DurableSnapshotIdentity>,
    applied_snapshot: Option<DurableSnapshotIdentity>,
    in_flight_operation: Option<JournalInFlightOperation>,
    recovery: ControlPlaneRecoveryInfo,
}

impl ControlPlaneJournalRuntime {
    fn new(config_path: &str) -> Self {
        Self {
            journal_path: control_plane_journal_path(config_path),
            desired_snapshot: None,
            applied_snapshot: None,
            in_flight_operation: None,
            recovery: ControlPlaneRecoveryInfo::default(),
        }
    }

    fn to_status_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"path\":\"{}\",",
                "\"desired_snapshot\":{},",
                "\"applied_snapshot\":{},",
                "\"recovery\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.journal_path),
            self.desired_snapshot
                .as_ref()
                .map_or_else(|| String::from("null"), DurableSnapshotIdentity::to_json),
            self.applied_snapshot
                .as_ref()
                .map_or_else(|| String::from("null"), DurableSnapshotIdentity::to_json),
            self.recovery.to_json(),
        )
    }
}

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
    CachePurge,
    CacheInvalidate,
    Unknown,
}

impl AdminRequestAction {
    fn permission(self) -> AdminPermission {
        match self {
            Self::Audit => AdminPermission::Audit,
            Self::Reload | Self::CachePurge | Self::CacheInvalidate => AdminPermission::Write,
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
            Self::CachePurge => "cache_purge",
            Self::CacheInvalidate => "cache_invalidate",
            Self::Unknown => "unknown",
        }
    }
}

fn negotiate_admin_api_request(request: &crate::DemoRequestHead) -> AdminApiRequestMode {
    let path_version = versioned_admin_target_parts(request.target.as_str())
        .map(|(version, canonical_target)| (version, canonical_target));
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

fn admin_auth_error_contract(error: &AdminAuthFailure) -> (lb_admin_api::AdminApiErrorCode, bool) {
    match (error.status, error.outcome) {
        ("503 Service Unavailable", _) => (lb_admin_api::AdminApiErrorCode::Misconfigured, false),
        ("409 Conflict", _) => (lb_admin_api::AdminApiErrorCode::ReplayRejected, false),
        ("403 Forbidden", _) => (lb_admin_api::AdminApiErrorCode::Forbidden, false),
        _ => (lb_admin_api::AdminApiErrorCode::Unauthorized, false),
    }
}

#[derive(Clone)]
struct HttpCacheScopeRuntime {
    service: Arc<Mutex<lb_admin_api::HttpCacheAdminService>>,
    store: Arc<lb_runtime::HttpCacheStore>,
}

impl std::fmt::Debug for HttpCacheScopeRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HttpCacheScopeRuntime(..)")
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AdminHttpCachePurgeTarget {
    ExactKey { key_material: String },
    PathPrefix { path_prefix: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminHttpCachePurgeRequest {
    scope: String,
    target: AdminHttpCachePurgeTarget,
    requested_by: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminHttpCachePurgeResponse {
    action: String,
    result: String,
    scope: String,
    purged_entries: usize,
    fanout_transport: Option<String>,
    fanout_subscriber_count: usize,
    fanout_delivery_success_count: usize,
    fanout_delivery_failure_count: usize,
    fanout_duplicate_count: usize,
    fanout_failed_targets: Vec<String>,
    degraded: bool,
    invalidation_event_id: Option<String>,
    occurred_at_unix_ms: u64,
}

#[derive(Debug)]
struct ManagedServeListener {
    name: String,
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
    configured_bind: SocketAddr,
    bind_mode: lb_net_core::ListenerBindMode,
    local_addr: SocketAddr,
    drain_timeout: Duration,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    abuse_policy: Arc<RwLock<Option<CompiledListenerAbuseProtectionPolicy>>>,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
    counters: Arc<ListenerRuntimeCounters>,
    kind: ManagedListenerKind,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<io::Result<ListenerDrainOutcome>>,
    probe_task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerDrainOutcome {
    Completed,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListenerIdentity {
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
    configured_bind: SocketAddr,
    bind_mode: lb_net_core::ListenerBindMode,
}

impl ListenerIdentity {
    fn from_spec(spec: &CompiledServeListener) -> Self {
        Self {
            class: spec.class(),
            protocol: spec.protocol(),
            proxy_protocol: spec.proxy_protocol(),
            configured_bind: spec.bind_address(),
            bind_mode: spec.bind_mode(),
        }
    }

    fn from_listener(listener: &ManagedServeListener) -> Self {
        Self {
            class: listener.class,
            protocol: listener.protocol,
            proxy_protocol: listener.proxy_protocol,
            configured_bind: listener.configured_bind,
            bind_mode: listener.bind_mode,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerLifecycleState {
    Active,
    Draining,
    Retired,
    FailedStart,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ListenerLifecycleEntry {
    identity: ListenerIdentity,
    state: ListenerLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FailedListenerStart {
    identity: ListenerIdentity,
    detail: String,
}

#[derive(Debug, Clone)]
struct ListenerLifecycleModel {
    desired_identity: ListenerIdentity,
    active_identity: Option<ListenerIdentity>,
    draining_identities: Vec<ListenerIdentity>,
    retired_identities: Vec<ListenerIdentity>,
    drain_timed_out_identities: Vec<ListenerIdentity>,
    failed_start: Option<FailedListenerStart>,
}

impl ListenerLifecycleModel {
    fn new_active(identity: ListenerIdentity) -> Self {
        Self {
            desired_identity: identity,
            active_identity: Some(identity),
            draining_identities: Vec::new(),
            retired_identities: Vec::new(),
            drain_timed_out_identities: Vec::new(),
            failed_start: None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn active_identity(&self) -> Option<ListenerIdentity> {
        self.active_identity
    }

    fn apply_in_place(&mut self, identity: ListenerIdentity) {
        self.desired_identity = identity;
        self.active_identity = Some(identity);
        self.failed_start = None;
    }

    fn activate_replacement(&mut self, identity: ListenerIdentity) -> Option<ListenerIdentity> {
        let previous = self.active_identity.replace(identity);
        if let Some(previous) = previous {
            self.draining_identities.push(previous);
        }
        self.desired_identity = identity;
        self.failed_start = None;
        previous
    }

    fn finish_draining(&mut self, identity: ListenerIdentity, outcome: ListenerDrainOutcome) {
        if let Some(index) =
            self.draining_identities.iter().position(|candidate| *candidate == identity)
        {
            let retired = self.draining_identities.remove(index);
            self.push_retired(retired);
            if matches!(outcome, ListenerDrainOutcome::TimedOut) {
                self.push_drain_timed_out(retired);
            }
        }
    }

    fn retire_active(&mut self) -> Option<ListenerIdentity> {
        let retired = self.active_identity.take()?;
        self.push_retired(retired);
        self.failed_start = None;
        Some(retired)
    }

    fn record_failed_start(&mut self, identity: ListenerIdentity, detail: String) {
        self.failed_start = Some(FailedListenerStart { identity, detail });
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn entries(&self) -> Vec<ListenerLifecycleEntry> {
        let mut entries = Vec::new();
        if let Some(identity) = self.active_identity {
            entries
                .push(ListenerLifecycleEntry { identity, state: ListenerLifecycleState::Active });
        }
        entries.extend(self.draining_identities.iter().copied().map(|identity| {
            ListenerLifecycleEntry { identity, state: ListenerLifecycleState::Draining }
        }));
        entries.extend(self.retired_identities.iter().copied().map(|identity| {
            ListenerLifecycleEntry { identity, state: ListenerLifecycleState::Retired }
        }));
        if let Some(failed_start) = &self.failed_start {
            entries.push(ListenerLifecycleEntry {
                identity: failed_start.identity,
                state: ListenerLifecycleState::FailedStart,
            });
        }
        entries
    }

    fn push_retired(&mut self, identity: ListenerIdentity) {
        const MAX_RETIRED_IDENTITIES: usize = 4;

        if self.retired_identities.len() == MAX_RETIRED_IDENTITIES {
            let _ = self.retired_identities.remove(0);
        }
        self.retired_identities.push(identity);
    }

    fn push_drain_timed_out(&mut self, identity: ListenerIdentity) {
        const MAX_DRAIN_TIMEOUT_IDENTITIES: usize = 4;

        if self.drain_timed_out_identities.len() == MAX_DRAIN_TIMEOUT_IDENTITIES {
            let _ = self.drain_timed_out_identities.remove(0);
        }
        self.drain_timed_out_identities.push(identity);
    }
}

#[derive(Debug)]
struct RetiredManagedListener {
    slot_name: Option<String>,
    identity: ListenerIdentity,
    listener: ManagedServeListener,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CurrentListenerIdentity {
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
    configured_bind: SocketAddr,
    bind_mode: lb_net_core::ListenerBindMode,
    local_addr: SocketAddr,
}

impl CurrentListenerIdentity {
    fn matches_spec(&self, spec: &CompiledServeListener) -> bool {
        self.class == spec.class()
            && self.protocol == spec.protocol()
            && self.proxy_protocol == spec.proxy_protocol()
            && self.configured_bind == spec.bind_address()
            && self.bind_mode == spec.bind_mode()
    }

    fn needs_replacement(&self, spec: &CompiledServeListener) -> bool {
        !self.matches_spec(spec)
    }

    fn can_stage_replacement(&self, spec: &CompiledServeListener) -> bool {
        spec.bind_address() != self.local_addr
    }
}

#[derive(Debug)]
struct ManagedListenerSlot {
    lifecycle: ListenerLifecycleModel,
    active: ManagedServeListener,
}

impl ManagedListenerSlot {
    fn new(listener: ManagedServeListener) -> Self {
        let identity = ListenerIdentity::from_listener(&listener);
        Self { lifecycle: ListenerLifecycleModel::new_active(identity), active: listener }
    }

    fn current_identity(&self) -> CurrentListenerIdentity {
        CurrentListenerIdentity {
            class: self.active.class,
            protocol: self.active.protocol,
            proxy_protocol: self.active.proxy_protocol,
            configured_bind: self.active.configured_bind,
            bind_mode: self.active.bind_mode,
            local_addr: self.active.local_addr,
        }
    }

    fn can_update_in_place(&self, spec: &CompiledServeListener) -> bool {
        self.active.class == spec.class()
            && self.active.protocol == spec.protocol()
            && self.active.proxy_protocol == spec.proxy_protocol()
            && self.active.configured_bind == spec.bind_address()
            && self.active.bind_mode == spec.bind_mode()
    }

    async fn apply_update(&mut self, spec: &CompiledServeListener) -> Result<(), DynError> {
        self.active.apply_update(spec).await?;
        self.lifecycle.apply_in_place(ListenerIdentity::from_spec(spec));
        Ok(())
    }

    fn activate_replacement(
        &mut self,
        slot_name: String,
        replacement: ManagedServeListener,
    ) -> RetiredManagedListener {
        let retired_identity = ListenerIdentity::from_listener(&self.active);
        let replacement_identity = ListenerIdentity::from_listener(&replacement);
        let _ = self.lifecycle.activate_replacement(replacement_identity);
        let listener = std::mem::replace(&mut self.active, replacement);
        RetiredManagedListener { slot_name: Some(slot_name), identity: retired_identity, listener }
    }

    fn into_retired(mut self) -> RetiredManagedListener {
        let identity = self
            .lifecycle
            .retire_active()
            .unwrap_or_else(|| ListenerIdentity::from_listener(&self.active));
        RetiredManagedListener { slot_name: None, identity, listener: self.active }
    }

    fn record_failed_start(&mut self, spec: &CompiledServeListener, detail: String) {
        self.lifecycle.record_failed_start(ListenerIdentity::from_spec(spec), detail);
    }

    fn finish_draining_with_outcome(
        &mut self,
        identity: ListenerIdentity,
        outcome: ListenerDrainOutcome,
    ) {
        self.lifecycle.finish_draining(identity, outcome);
    }
}

#[derive(Debug, Clone)]
enum CompiledServeListener {
    Public {
        class: lb_config_model::ListenerClassConfig,
        protocol: lb_config_model::ListenerProtocolConfig,
        proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
        bind_address: SocketAddr,
        bind_mode: lb_net_core::ListenerBindMode,
        max_connections: usize,
        drain_timeout: Duration,
        overload_policy: Option<CompiledListenerOverloadPolicy>,
        abuse_protection_policy: Option<CompiledListenerAbuseProtectionPolicy>,
        proxy: ManagedProxyConfig,
    },
    Admin {
        protocol: lb_config_model::ListenerProtocolConfig,
        proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
        bind_address: SocketAddr,
        bind_mode: lb_net_core::ListenerBindMode,
        max_connections: usize,
        drain_timeout: Duration,
        overload_policy: Option<CompiledListenerOverloadPolicy>,
        abuse_protection_policy: Option<CompiledListenerAbuseProtectionPolicy>,
        admin_policy: CompiledAdminPolicy,
        tls: Option<ManagedAdminTlsConfig>,
    },
}

impl CompiledServeListener {
    fn class(&self) -> lb_config_model::ListenerClassConfig {
        match self {
            Self::Public { class, .. } => *class,
            Self::Admin { .. } => lb_config_model::ListenerClassConfig::Admin,
        }
    }

    fn protocol(&self) -> lb_config_model::ListenerProtocolConfig {
        match self {
            Self::Public { protocol, .. } => *protocol,
            Self::Admin { protocol, .. } => *protocol,
        }
    }

    fn proxy_protocol(&self) -> lb_config_model::ProxyProtocolModeConfig {
        match self {
            Self::Public { proxy_protocol, .. } => *proxy_protocol,
            Self::Admin { proxy_protocol, .. } => *proxy_protocol,
        }
    }

    fn bind_address(&self) -> SocketAddr {
        match self {
            Self::Public { bind_address, .. } | Self::Admin { bind_address, .. } => *bind_address,
        }
    }

    fn bind_mode(&self) -> lb_net_core::ListenerBindMode {
        match self {
            Self::Public { bind_mode, .. } | Self::Admin { bind_mode, .. } => *bind_mode,
        }
    }

    fn drain_timeout(&self) -> Duration {
        match self {
            Self::Public { drain_timeout, .. } | Self::Admin { drain_timeout, .. } => {
                *drain_timeout
            }
        }
    }

    fn max_connections(&self) -> usize {
        match self {
            Self::Public { max_connections, .. } | Self::Admin { max_connections, .. } => {
                *max_connections
            }
        }
    }

    fn overload_policy(&self) -> Option<&CompiledListenerOverloadPolicy> {
        match self {
            Self::Public { overload_policy, .. } | Self::Admin { overload_policy, .. } => {
                overload_policy.as_ref()
            }
        }
    }

    fn abuse_protection_policy(&self) -> Option<&CompiledListenerAbuseProtectionPolicy> {
        match self {
            Self::Public { abuse_protection_policy, .. }
            | Self::Admin { abuse_protection_policy, .. } => abuse_protection_policy.as_ref(),
        }
    }
}

#[derive(Debug)]
struct CompiledWorkspaceRuntime {
    source_label: String,
    snapshot: lb_config_model::WorkspaceSnapshot,
    listeners: BTreeMap<String, CompiledServeListener>,
    http_cache_scopes: BTreeMap<String, HttpCacheScopeRuntime>,
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

#[derive(Debug, Clone)]
struct OverloadEventStatus {
    code: String,
    scope: String,
    detail: String,
}

impl OverloadEventStatus {
    fn from_telemetry(event: lb_observability::TelemetryEvent) -> Self {
        Self { code: String::from(event.code.as_str()), scope: event.scope, detail: event.detail }
    }

    fn from_overload_event(event: lb_observability::OverloadEvent) -> Self {
        Self {
            code: String::from(match event.kind {
                lb_observability::OverloadEventKind::StateChanged => "overload.state.changed",
                lb_observability::OverloadEventKind::RequestShed => "overload.request.shed",
                lb_observability::OverloadEventKind::BrownoutFeaturesChanged => {
                    "overload.brownout.features_changed"
                }
            }),
            scope: event.scope,
            detail: event.detail,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"code\":\"{}\",\"scope\":\"{}\",\"detail\":\"{}\"}}",
            crate::escape_json_string(&self.code),
            crate::escape_json_string(&self.scope),
            crate::escape_json_string(&self.detail),
        )
    }
}

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
    drain_timed_out_replacements: Vec<String>,
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
                "configuration applied; drain timeout expired for: {}",
                self.drain_timed_out_replacements.join(", ")
            )
        } else {
            String::from("configuration applied")
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
                "configuration applied; replacement stayed active but drain timeout expired for: {}",
                outcome.drain_timed_out_replacements.join(", ")
            )
        } else if !self.supported_replacements.is_empty() {
            format!(
                "configuration applied; overlap-and-drain replacement completed for: {}",
                self.supported_replacements.join(", ")
            )
        } else {
            String::from("configuration applied")
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

#[derive(Debug, Clone)]
struct ListenerStatus {
    name: String,
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    configured_bind: SocketAddr,
    local_addr: SocketAddr,
    state: String,
    overload_state: String,
    accepted_connections: u64,
    active_connections: usize,
    completed_connections: u64,
    shed_connections: u64,
    abuse_protection: ListenerAbuseProtectionStatus,
    brownout_features: Vec<String>,
    recent_overload_events: Vec<OverloadEventStatus>,
    replacement: ListenerReplacementStatus,
    tls: Option<ListenerTlsStatus>,
}

#[derive(Debug, Clone)]
struct ListenerAbuseProtectionStatus {
    state: String,
    source_quota: Option<SourceQuotaStatus>,
    handshake_guard: Option<HandshakeGuardStatus>,
    source_quota_rejections: u64,
    tracked_source_limit_rejections: u64,
    handshake_guard_rejections: u64,
    tracked_sources: usize,
    active_handshakes: usize,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone)]
struct SourceQuotaStatus {
    aggregation: String,
    max_active_per_source: usize,
    max_tracked_sources: usize,
}

#[derive(Debug, Clone)]
struct HandshakeGuardStatus {
    max_inflight: usize,
    timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadHealthState {
    NotRequested,
    Healthy,
    Failed,
}

#[derive(Debug, Clone)]
struct ListenerReadinessStatus {
    name: String,
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    configured_bind: SocketAddr,
    ready: bool,
    status: String,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone)]
struct WorkspaceReadinessStatus {
    ready: bool,
    status: String,
    evaluated_listener_scope: String,
    reload_status: String,
    reason_codes: Vec<String>,
    listeners: Vec<ListenerReadinessStatus>,
}

#[derive(Debug, Clone)]
struct ListenerIdentityStatus {
    class: lb_config_model::ListenerClassConfig,
    protocol: lb_config_model::ListenerProtocolConfig,
    configured_bind: SocketAddr,
    bind_mode: lb_net_core::ListenerBindMode,
}

impl From<ListenerIdentity> for ListenerIdentityStatus {
    fn from(identity: ListenerIdentity) -> Self {
        Self {
            class: identity.class,
            protocol: identity.protocol,
            configured_bind: identity.configured_bind,
            bind_mode: identity.bind_mode,
        }
    }
}

impl ListenerIdentityStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"class\":\"{}\",",
                "\"protocol\":\"{}\",",
                "\"configured_bind\":\"{}\",",
                "\"bind_mode\":\"{}\"",
                "}}"
            ),
            listener_class_name(self.class),
            listener_protocol_name(self.protocol),
            self.configured_bind,
            listener_bind_mode_name(self.bind_mode),
        )
    }
}

impl ListenerReadinessStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"name\":\"{}\",",
                "\"class\":\"{}\",",
                "\"protocol\":\"{}\",",
                "\"configured_bind\":\"{}\",",
                "\"ready\":{},",
                "\"status\":\"{}\",",
                "\"reason_codes\":[{}]",
                "}}"
            ),
            crate::escape_json_string(&self.name),
            listener_class_name(self.class),
            listener_protocol_name(self.protocol),
            self.configured_bind,
            self.ready,
            crate::escape_json_string(&self.status),
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", crate::escape_json_string(code)))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

impl WorkspaceReadinessStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"ready\":{},",
                "\"status\":\"{}\",",
                "\"evaluated_listener_scope\":\"{}\",",
                "\"reload_status\":\"{}\",",
                "\"reason_codes\":[{}],",
                "\"listeners\":[{}]",
                "}}"
            ),
            self.ready,
            crate::escape_json_string(&self.status),
            crate::escape_json_string(&self.evaluated_listener_scope),
            crate::escape_json_string(&self.reload_status),
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", crate::escape_json_string(code)))
                .collect::<Vec<_>>()
                .join(","),
            self.listeners
                .iter()
                .map(ListenerReadinessStatus::to_json)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

#[derive(Debug, Clone)]
struct FailedListenerStartStatus {
    identity: ListenerIdentityStatus,
    detail: String,
}

impl FailedListenerStartStatus {
    fn to_json(&self) -> String {
        format!(
            "{{\"identity\":{},\"detail\":\"{}\"}}",
            self.identity.to_json(),
            crate::escape_json_string(&self.detail),
        )
    }
}

#[derive(Debug, Clone)]
struct ListenerReplacementStatus {
    state: String,
    desired: ListenerIdentityStatus,
    draining: Vec<ListenerIdentityStatus>,
    retired_recent: Vec<ListenerIdentityStatus>,
    drain_timeout_recent: Vec<ListenerIdentityStatus>,
    failed_start: Option<FailedListenerStartStatus>,
}

impl ListenerReplacementStatus {
    fn from_lifecycle(lifecycle: &ListenerLifecycleModel) -> Self {
        let state = if !lifecycle.draining_identities.is_empty() {
            "replacement_draining"
        } else if lifecycle.failed_start.is_some() {
            "failed_start_preserved"
        } else if !lifecycle.drain_timed_out_identities.is_empty() {
            "drain_timeout_expired"
        } else {
            "stable"
        };

        Self {
            state: String::from(state),
            desired: lifecycle.desired_identity.into(),
            draining: lifecycle
                .draining_identities
                .iter()
                .copied()
                .map(ListenerIdentityStatus::from)
                .collect(),
            retired_recent: lifecycle
                .retired_identities
                .iter()
                .copied()
                .map(ListenerIdentityStatus::from)
                .collect(),
            drain_timeout_recent: lifecycle
                .drain_timed_out_identities
                .iter()
                .copied()
                .map(ListenerIdentityStatus::from)
                .collect(),
            failed_start: lifecycle.failed_start.as_ref().map(|failed_start| {
                FailedListenerStartStatus {
                    identity: failed_start.identity.into(),
                    detail: failed_start.detail.clone(),
                }
            }),
        }
    }

    fn to_json(&self) -> String {
        let draining =
            self.draining.iter().map(ListenerIdentityStatus::to_json).collect::<Vec<_>>().join(",");
        let retired_recent = self
            .retired_recent
            .iter()
            .map(ListenerIdentityStatus::to_json)
            .collect::<Vec<_>>()
            .join(",");
        let drain_timeout_recent = self
            .drain_timeout_recent
            .iter()
            .map(ListenerIdentityStatus::to_json)
            .collect::<Vec<_>>()
            .join(",");
        let failed_start = self
            .failed_start
            .as_ref()
            .map_or_else(|| String::from("null"), FailedListenerStartStatus::to_json);

        format!(
            concat!(
                "{{",
                "\"state\":\"{}\",",
                "\"desired\":{},",
                "\"draining\":[{}],",
                "\"retired_recent\":[{}],",
                "\"drain_timeout_recent\":[{}],",
                "\"failed_start\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.state),
            self.desired.to_json(),
            draining,
            retired_recent,
            drain_timeout_recent,
            failed_start,
        )
    }
}

impl ListenerStatus {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"name\":\"{}\",",
                "\"class\":\"{}\",",
                "\"protocol\":\"{}\",",
                "\"configured_bind\":\"{}\",",
                "\"local_addr\":\"{}\",",
                "\"state\":\"{}\",",
                "\"overload_state\":\"{}\",",
                "\"accepted_connections\":{},",
                "\"active_connections\":{},",
                "\"shed_connections\":{},",
                "\"completed_connections\":{},",
                "\"abuse_protection\":{},",
                "\"brownout_features\":[{}],",
                "\"recent_overload_events\":[{}],",
                "\"replacement\":{},",
                "\"tls\":{}",
                "}}"
            ),
            crate::escape_json_string(&self.name),
            listener_class_name(self.class),
            listener_protocol_name(self.protocol),
            self.configured_bind,
            self.local_addr,
            crate::escape_json_string(&self.state),
            crate::escape_json_string(&self.overload_state),
            self.accepted_connections,
            self.active_connections,
            self.shed_connections,
            self.completed_connections,
            self.abuse_protection.to_json(),
            self.brownout_features
                .iter()
                .map(|feature| format!("\"{}\"", crate::escape_json_string(feature)))
                .collect::<Vec<_>>()
                .join(","),
            self.recent_overload_events
                .iter()
                .map(OverloadEventStatus::to_json)
                .collect::<Vec<_>>()
                .join(","),
            self.replacement.to_json(),
            self.tls.as_ref().map_or_else(|| String::from("null"), ListenerTlsStatus::to_json),
        )
    }
}

impl ListenerAbuseProtectionStatus {
    fn from_runtime(
        policy: Option<&CompiledListenerAbuseProtectionPolicy>,
        snapshot: lb_runtime::ListenerAbuseProtectionSnapshot,
    ) -> Self {
        let mut reason_codes = Vec::new();
        if snapshot.source_quota_rejections > 0 {
            push_unique_reason(
                &mut reason_codes,
                lb_runtime::AbuseRejectionReason::SourceQuotaExceeded.code(),
            );
        }
        if snapshot.tracked_source_limit_rejections > 0 {
            push_unique_reason(
                &mut reason_codes,
                lb_runtime::AbuseRejectionReason::TrackedSourceLimitReached.code(),
            );
        }
        if snapshot.handshake_guard_rejections > 0 {
            push_unique_reason(
                &mut reason_codes,
                lb_runtime::AbuseRejectionReason::HandshakeLimitReached.code(),
            );
        }

        let source_quota = policy.and_then(|policy| {
            policy.source_quota.map(|source_quota| SourceQuotaStatus {
                aggregation: String::from(source_aggregation_name(source_quota.aggregation)),
                max_active_per_source: source_quota.max_active_per_source,
                max_tracked_sources: source_quota.max_tracked_sources,
            })
        });
        if source_quota.as_ref().is_some_and(|source_quota| {
            snapshot.tracked_sources >= source_quota.max_tracked_sources
        }) {
            push_unique_reason(&mut reason_codes, "tracked_source_capacity_saturated");
        }

        let handshake_guard = policy.and_then(|policy| {
            policy.handshake_guard.map(|handshake_guard| HandshakeGuardStatus {
                max_inflight: handshake_guard.max_inflight,
                timeout_ms: handshake_guard.timeout.as_millis() as u64,
            })
        });
        if handshake_guard.as_ref().is_some_and(|handshake_guard| {
            snapshot.active_handshakes >= handshake_guard.max_inflight
        }) {
            push_unique_reason(&mut reason_codes, "handshake_guard_saturated");
        }

        let state = if policy.is_none() {
            "disabled"
        } else if reason_codes.iter().any(|reason| {
            reason == "tracked_source_capacity_saturated" || reason == "handshake_guard_saturated"
        }) {
            "constrained"
        } else {
            "enforcing"
        };

        Self {
            state: String::from(state),
            source_quota,
            handshake_guard,
            source_quota_rejections: snapshot.source_quota_rejections,
            tracked_source_limit_rejections: snapshot.tracked_source_limit_rejections,
            handshake_guard_rejections: snapshot.handshake_guard_rejections,
            tracked_sources: snapshot.tracked_sources,
            active_handshakes: snapshot.active_handshakes,
            reason_codes,
        }
    }

    fn to_json(&self) -> String {
        let source_quota = self.source_quota.as_ref().map_or_else(
            || String::from("null"),
            |source_quota| {
                format!(
                    concat!(
                        "{{",
                        "\"aggregation\":\"{}\",",
                        "\"max_active_per_source\":{},",
                        "\"max_tracked_sources\":{}",
                        "}}"
                    ),
                    crate::escape_json_string(&source_quota.aggregation),
                    source_quota.max_active_per_source,
                    source_quota.max_tracked_sources,
                )
            },
        );
        let handshake_guard = self.handshake_guard.as_ref().map_or_else(
            || String::from("null"),
            |handshake_guard| {
                format!(
                    concat!("{{", "\"max_inflight\":{},", "\"timeout_ms\":{}", "}}"),
                    handshake_guard.max_inflight, handshake_guard.timeout_ms,
                )
            },
        );

        format!(
            concat!(
                "{{",
                "\"state\":\"{}\",",
                "\"source_quota\":{},",
                "\"handshake_guard\":{},",
                "\"source_quota_rejections\":{},",
                "\"tracked_source_limit_rejections\":{},",
                "\"handshake_guard_rejections\":{},",
                "\"tracked_sources\":{},",
                "\"active_handshakes\":{},",
                "\"reason_codes\":[{}]",
                "}}"
            ),
            crate::escape_json_string(&self.state),
            source_quota,
            handshake_guard,
            self.source_quota_rejections,
            self.tracked_source_limit_rejections,
            self.handshake_guard_rejections,
            self.tracked_sources,
            self.active_handshakes,
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", crate::escape_json_string(code)))
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

fn evaluate_workspace_readiness(
    listener_statuses: &[ListenerStatus],
    reload_health: ReloadHealthState,
) -> WorkspaceReadinessStatus {
    let evaluate_public_only = listener_statuses
        .iter()
        .any(|listener| listener.class == lb_config_model::ListenerClassConfig::Public);
    let evaluated_listener_scope = if evaluate_public_only { "public" } else { "all" };
    let listeners = listener_statuses
        .iter()
        .filter(|listener| {
            !evaluate_public_only || listener.class == lb_config_model::ListenerClassConfig::Public
        })
        .map(reduce_listener_readiness)
        .collect::<Vec<_>>();
    let mut reason_codes = Vec::new();

    if matches!(reload_health, ReloadHealthState::Failed) {
        push_unique_reason(&mut reason_codes, "reload_failed");
    }
    if listeners.is_empty() {
        push_unique_reason(&mut reason_codes, "no_serving_listeners");
    }
    for listener in &listeners {
        for reason in &listener.reason_codes {
            push_unique_reason(&mut reason_codes, reason);
        }
    }

    WorkspaceReadinessStatus {
        ready: reason_codes.is_empty(),
        status: String::from(if reason_codes.is_empty() { "ready" } else { "not_ready" }),
        evaluated_listener_scope: String::from(evaluated_listener_scope),
        reload_status: String::from(reload_health_name(reload_health)),
        reason_codes,
        listeners,
    }
}

fn reduce_listener_readiness(listener: &ListenerStatus) -> ListenerReadinessStatus {
    let mut reason_codes = Vec::new();

    match listener.state.as_str() {
        "running" => {}
        "draining" => push_unique_reason(&mut reason_codes, "listener_draining"),
        _ => push_unique_reason(&mut reason_codes, "listener_not_running"),
    }

    match listener.overload_state.as_str() {
        "shedding" => push_unique_reason(&mut reason_codes, "listener_overload_shedding"),
        "brownout" => push_unique_reason(&mut reason_codes, "listener_overload_brownout"),
        _ => {}
    }

    if listener.replacement.failed_start.is_some()
        || listener.replacement.state == "failed_start_preserved"
    {
        push_unique_reason(&mut reason_codes, "listener_replacement_failed");
    }

    for reason in &listener.abuse_protection.reason_codes {
        match reason.as_str() {
            "tracked_source_capacity_saturated" => {
                push_unique_reason(&mut reason_codes, "listener_abuse_source_tracking_saturated");
            }
            "handshake_guard_saturated" => {
                push_unique_reason(&mut reason_codes, "listener_abuse_handshake_saturated");
            }
            _ => {}
        }
    }

    ListenerReadinessStatus {
        name: listener.name.clone(),
        class: listener.class,
        protocol: listener.protocol,
        configured_bind: listener.configured_bind,
        ready: reason_codes.is_empty(),
        status: String::from(if reason_codes.is_empty() { "ready" } else { "not_ready" }),
        reason_codes,
    }
}

fn push_unique_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(String::from(reason));
    }
}

impl ConfigValidationPreview {
    fn render_json(&self) -> Result<String, DynError> {
        serde_json::to_string_pretty(self).map_err(to_dyn_error)
    }
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

    async fn apply_compiled_runtime(
        &self,
        compiled: CompiledWorkspaceRuntime,
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

        let mut retired = Vec::new();
        {
            let mut inner = self.shared.inner.lock().await;

            for (name, spec) in &listeners {
                if let Some(slot) = inner.listeners.get_mut(name) {
                    if slot.can_update_in_place(spec) {
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
            let drain_outcome = retired_listener.listener.shutdown().await?;
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

async fn start_managed_listener(
    name: String,
    spec: CompiledServeListener,
    state: Arc<WorkspaceServeState>,
    supervisor: ServeSupervisor,
) -> Result<ManagedServeListener, DynError> {
    let drain_timeout = spec.drain_timeout();
    let admission_limit = Arc::new(AtomicUsize::new(spec.max_connections()));
    let overload_runtime =
        Arc::new(StdMutex::new(build_listener_overload_runtime(spec.overload_policy())?));
    let abuse_policy = Arc::new(RwLock::new(spec.abuse_protection_policy().cloned()));
    let abuse_protection = Arc::new(RwLock::new(build_listener_abuse_protection_state(
        spec.abuse_protection_policy(),
    )));
    let counters = Arc::new(ListenerRuntimeCounters::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    match spec {
        CompiledServeListener::Public {
            class,
            protocol,
            proxy_protocol,
            bind_address,
            bind_mode,
            proxy,
            ..
        } => {
            if let ManagedProxyConfig::Http3(proxy) = proxy.clone() {
                let socket = lb_runtime::bind_udp_socket(bind_address, bind_mode)?;
                let local_addr = socket.local_addr()?;
                let (ready_tx, ready_rx) = oneshot::channel();
                let shared_proxy = Arc::new(RwLock::new(ManagedProxyConfig::Http3(proxy)));
                let task = tokio::spawn(run_public_http3_listener_loop(
                    socket,
                    name.clone(),
                    shared_proxy.read().await.clone(),
                    Arc::clone(&admission_limit),
                    Arc::clone(&overload_runtime),
                    Arc::clone(&abuse_protection),
                    Arc::clone(&counters),
                    Arc::clone(&state),
                    shutdown_rx,
                    drain_timeout,
                    ready_tx,
                ));
                return await_managed_listener_ready(
                    ManagedServeListener {
                        name,
                        class,
                        protocol,
                        proxy_protocol,
                        configured_bind: bind_address,
                        bind_mode,
                        local_addr,
                        drain_timeout,
                        admission_limit,
                        overload_runtime,
                        abuse_policy,
                        abuse_protection,
                        counters,
                        kind: ManagedListenerKind::Public { shared_proxy },
                        shutdown_tx,
                        task,
                        probe_task: None,
                    },
                    ready_rx,
                )
                .await;
            }

            let listener = lb_runtime::bind_tcp_listener(bind_address, bind_mode)?;
            let local_addr = listener.local_addr()?;
            let (ready_tx, ready_rx) = oneshot::channel();
            let shared_proxy = Arc::new(RwLock::new(proxy));
            let task = tokio::spawn(run_public_listener_loop(
                listener,
                name.clone(),
                proxy_protocol,
                Arc::clone(&shared_proxy),
                Arc::clone(&admission_limit),
                Arc::clone(&overload_runtime),
                Arc::clone(&abuse_protection),
                Arc::clone(&counters),
                Arc::clone(&state),
                shutdown_rx,
                drain_timeout,
                ready_tx,
            ));
            let probe_task = Some(tokio::spawn(run_active_health_probe_loop(
                Arc::clone(&shared_proxy),
                shutdown_tx.subscribe(),
            )));
            await_managed_listener_ready(
                ManagedServeListener {
                    name,
                    class,
                    protocol,
                    proxy_protocol,
                    configured_bind: bind_address,
                    bind_mode,
                    local_addr,
                    drain_timeout,
                    admission_limit,
                    overload_runtime,
                    abuse_policy,
                    abuse_protection,
                    counters,
                    kind: ManagedListenerKind::Public { shared_proxy },
                    shutdown_tx,
                    task,
                    probe_task,
                },
                ready_rx,
            )
            .await
        }
        CompiledServeListener::Admin {
            protocol,
            proxy_protocol,
            bind_address,
            bind_mode,
            admin_policy,
            tls,
            ..
        } => {
            let listener = lb_runtime::bind_tcp_listener(bind_address, bind_mode)?;
            let local_addr = listener.local_addr()?;
            let (ready_tx, ready_rx) = oneshot::channel();
            let admin_runtime = AdminRuntimeHandles {
                shared_policy: Arc::new(RwLock::new(admin_policy)),
                rate_limit_state: Arc::new(StdMutex::new(AdminRateLimitState::default())),
                replay_state: Arc::new(StdMutex::new(AdminReplayState::default())),
            };
            let task = tokio::spawn(run_admin_listener_loop(
                listener,
                name.clone(),
                Arc::clone(&admission_limit),
                Arc::clone(&overload_runtime),
                Arc::clone(&abuse_protection),
                Arc::clone(&counters),
                Arc::clone(&state),
                shutdown_rx,
                drain_timeout,
                admin_runtime.clone(),
                tls.clone(),
                Arc::clone(&supervisor.shared.admin_secret),
                supervisor,
                ready_tx,
            ));
            await_managed_listener_ready(
                ManagedServeListener {
                    name,
                    class: lb_config_model::ListenerClassConfig::Admin,
                    protocol,
                    proxy_protocol,
                    configured_bind: bind_address,
                    bind_mode,
                    local_addr,
                    drain_timeout,
                    admission_limit,
                    overload_runtime,
                    abuse_policy,
                    abuse_protection,
                    counters,
                    kind: ManagedListenerKind::Admin {
                        runtime: admin_runtime,
                        tls_status: tls.as_ref().map(|config| config.tls_status.clone()),
                    },
                    shutdown_tx,
                    task,
                    probe_task: None,
                },
                ready_rx,
            )
            .await
        }
    }
}

fn proxy_preface_timeout(proxy: &ManagedProxyConfig) -> Duration {
    match proxy {
        ManagedProxyConfig::Http1(config) => config.timeouts.preface_timeout,
        ManagedProxyConfig::Http2(config) => config.timeouts.preface_timeout,
        ManagedProxyConfig::Https(config) => config.http1.timeouts.preface_timeout,
        ManagedProxyConfig::Http3(_) => Duration::from_secs(5),
    }
}

async fn resolve_downstream_addr_from_proxy_protocol(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    mode: lb_config_model::ProxyProtocolModeConfig,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    let source_addr = match mode {
        lb_config_model::ProxyProtocolModeConfig::Disabled => None,
        lb_config_model::ProxyProtocolModeConfig::V1 => {
            time::timeout(timeout, read_proxy_protocol_v1(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy protocol v1 timeout"))??
        }
        lb_config_model::ProxyProtocolModeConfig::V2 => {
            time::timeout(timeout, read_proxy_protocol_v2(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy protocol v2 timeout"))??
        }
    };
    Ok(source_addr.unwrap_or(peer_addr))
}

async fn read_proxy_protocol_v1(stream: &mut TcpStream) -> io::Result<Option<SocketAddr>> {
    let mut line = Vec::with_capacity(PROXY_PROTOCOL_V1_MAX_LEN);
    loop {
        if line.len() >= PROXY_PROTOCOL_V1_MAX_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy protocol v1 header too long",
            ));
        }
        let byte = stream.read_u8().await?;
        line.push(byte);
        if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
            break;
        }
    }
    parse_proxy_protocol_v1_line(&line)
}

async fn read_proxy_protocol_v2(stream: &mut TcpStream) -> io::Result<Option<SocketAddr>> {
    let mut header = [0_u8; 16];
    stream.read_exact(&mut header).await?;
    let payload_len = parse_proxy_protocol_v2_header(&header)?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    parse_proxy_protocol_v2_payload(&header, &payload)
}

fn parse_proxy_protocol_v1_line(line: &[u8]) -> io::Result<Option<SocketAddr>> {
    let line = std::str::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 utf8"))?;
    let line = line
        .strip_suffix("\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 newline"))?;
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 || parts[0] != "PROXY" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v1 preface",
        ));
    }
    match parts[1] {
        "UNKNOWN" => Ok(None),
        "TCP4" | "TCP6" => {
            if parts.len() != 6 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy protocol v1 address fields",
                ));
            }
            let source_ip: IpAddr = parts[2]
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 source ip"))?;
            let _destination_ip: IpAddr = parts[3].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 destination ip")
            })?;
            let source_port: u16 = parts[4].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 source port")
            })?;
            let _destination_port: u16 = parts[5].parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy protocol v1 destination port")
            })?;
            Ok(Some(SocketAddr::new(source_ip, source_port)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v1 transport",
        )),
    }
}

fn parse_proxy_protocol_v2_header(header: &[u8; 16]) -> io::Result<usize> {
    if header[..12] != PROXY_PROTOCOL_V2_SIGNATURE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v2 signature",
        ));
    }
    if header[12] >> 4 != 0x2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v2 version",
        ));
    }
    Ok(u16::from_be_bytes([header[14], header[15]]) as usize)
}

fn parse_proxy_protocol_v2_payload(
    header: &[u8; 16],
    payload: &[u8],
) -> io::Result<Option<SocketAddr>> {
    let command = header[12] & 0x0f;
    if command == 0x00 {
        return Ok(None);
    }
    if command != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v2 command",
        ));
    }
    match header[13] {
        0x11 => {
            if payload.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy protocol v2 ipv4 payload",
                ));
            }
            let source_ip = IpAddr::from([payload[0], payload[1], payload[2], payload[3]]);
            let source_port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(SocketAddr::new(source_ip, source_port)))
        }
        0x21 => {
            if payload.len() < 36 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy protocol v2 ipv6 payload",
                ));
            }
            let mut source = [0_u8; 16];
            source.copy_from_slice(&payload[..16]);
            let source_port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(SocketAddr::new(IpAddr::from(source), source_port)))
        }
        0x00 => Ok(None),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy protocol v2 transport",
        )),
    }
}

async fn await_managed_listener_ready(
    listener: ManagedServeListener,
    ready_rx: oneshot::Receiver<()>,
) -> Result<ManagedServeListener, DynError> {
    match ready_rx.await {
        Ok(()) => Ok(listener),
        Err(_) => {
            let _ = listener.shutdown_tx.send(true);
            match listener.join().await {
                Ok(_) => Err(to_dyn_error("listener exited before becoming ready")),
                Err(error) => Err(to_dyn_error(error)),
            }
        }
    }
}

async fn run_active_health_probe_loop(
    shared_proxy: Arc<RwLock<ManagedProxyConfig>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = time::interval(ACTIVE_HEALTH_PROBE_INTERVAL);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    ticker.tick().await;
    let mut last_tick = Instant::now();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(last_tick);
                last_tick = now;
                let pools = {
                    let proxy = shared_proxy.read().await.clone();
                    collect_active_probe_pools(&proxy)
                };

                for pool in pools {
                    pool.advance_time(elapsed);
                    let probe_targets = match pool.active_probe_targets() {
                        Ok(probe_targets) => probe_targets,
                        Err(_) => continue,
                    };
                    for probe_target in probe_targets {
                        let probe_result = time::timeout(
                            ACTIVE_HEALTH_PROBE_TIMEOUT,
                            TcpStream::connect(probe_target.address),
                        )
                        .await;
                        match probe_result {
                            Ok(Ok(stream)) => {
                                drop(stream);
                                let _ = pool.note_active_success(&probe_target.endpoint_id);
                            }
                            _ => {
                                let _ = pool.note_active_failure(&probe_target.endpoint_id);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn collect_active_probe_pools(proxy: &ManagedProxyConfig) -> Vec<lb_runtime::RouteBackendPool> {
    let mut pools_by_scope = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();
    let mut insert_pool = |pool: &lb_runtime::RouteBackendPool| {
        let key = pool
            .cluster_names()
            .into_iter()
            .map(|cluster_name| cluster_name.to_string())
            .collect::<Vec<_>>()
            .join(",");
        pools_by_scope.entry(key).or_insert_with(|| pool.clone());
    };

    match proxy {
        ManagedProxyConfig::Http1(config) => {
            for pool in config.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
        ManagedProxyConfig::Http2(config) => {
            for pool in config.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
        ManagedProxyConfig::Https(config) => {
            for pool in config.http1.route_backend_pools.values() {
                insert_pool(pool);
            }
            for pool in config.http2.route_backend_pools.values() {
                insert_pool(pool);
            }
        }
        ManagedProxyConfig::Http3(_) => {}
    }

    pools_by_scope.into_values().collect()
}

async fn run_public_http3_listener_loop(
    socket: UdpSocket,
    listener_name: String,
    proxy: ManagedProxyConfig,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
    counters: Arc<ListenerRuntimeCounters>,
    state: Arc<WorkspaceServeState>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
    ready_tx: oneshot::Sender<()>,
) -> io::Result<ListenerDrainOutcome> {
    let ManagedProxyConfig::Http3(proxy) = proxy else {
        return Err(io::Error::other("http3 listener requires http3 proxy config"));
    };
    let runtime = quinn::TokioRuntime;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some((*proxy.quic_server_config).clone()),
        socket.into_std()?,
        Arc::new(runtime),
    )
    .map_err(io::Error::other)?;

    *counters.state.write().await = String::from("running");
    let _ = ready_tx.send(());
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                counters.accepted_connections.fetch_add(1, Ordering::SeqCst);
                if !try_acquire_listener_slot(&counters, &admission_limit) {
                    counters.shed_connections.fetch_add(1, Ordering::SeqCst);
                    state.record_overload_event(
                        &listener_name,
                        lb_observability::OverloadEventKind::RequestShed,
                        format!(
                            "listener shed http3 connection at capacity {}",
                            admission_limit.load(Ordering::SeqCst)
                        ),
                    );
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        true,
                    );
                    continue;
                }
                state.sync_listener_overload_snapshot(
                    &listener_name,
                    &counters,
                    admission_limit.load(Ordering::SeqCst),
                    &overload_runtime,
                    false,
                );

                let counters = Arc::clone(&counters);
                let state = Arc::clone(&state);
                let abuse_protection = Arc::clone(&abuse_protection);
                let overload_runtime = Arc::clone(&overload_runtime);
                let admission_limit = Arc::clone(&admission_limit);
                let listener_name = listener_name.clone();
                let proxy = proxy.clone();

                tasks.spawn(async move {
                    let result = handle_http3_connecting(
                        incoming,
                        &listener_name,
                        proxy,
                        &state,
                        Arc::clone(&abuse_protection),
                    )
                    .await;
                    if let Ok(request_count) = result {
                        state.proxied_connections.fetch_add(1, Ordering::SeqCst);
                        state.proxied_requests.fetch_add(request_count, Ordering::SeqCst);
                    }
                    counters.active_connections.fetch_sub(1, Ordering::SeqCst);
                    counters.completed_connections.fetch_add(1, Ordering::SeqCst);
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        false,
                    );
                    state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                });
            }
        }
    }

    endpoint.close(0u32.into(), b"server shutdown");
    *counters.state.write().await = String::from("draining");
    let drain_outcome =
        if time::timeout(drain_timeout, async { while tasks.join_next().await.is_some() {} })
            .await
            .is_ok()
        {
            *counters.state.write().await = String::from("stopped");
            ListenerDrainOutcome::Completed
        } else {
            *counters.state.write().await = String::from("drain_timeout_expired");
            ListenerDrainOutcome::TimedOut
        };
    Ok(drain_outcome)
}

async fn handle_http3_connecting(
    connecting: quinn::Incoming,
    listener_name: &str,
    proxy: ManagedHttp3ProxyConfig,
    state: &WorkspaceServeState,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
) -> io::Result<u64> {
    let connecting = connecting.accept().map_err(io::Error::other)?;
    let connection = connecting.await.map_err(io::Error::other)?;
    let remote_addr = connection.remote_address();
    let _source_lease = {
        let protection = abuse_protection.read().await;
        protection.try_acquire_source(remote_addr).map_err(|reason| io::Error::other(reason.detail()))?
    };
    let mut h3_conn = h3::server::builder()
        .build(H3Connection::new(connection))
        .await
        .map_err(io::Error::other)?;
    let mut request_count = 0_u64;

    while let Some(resolver) = h3_conn.accept().await.map_err(io::Error::other)? {
        let (request, mut stream) = resolver.resolve_request().await.map_err(io::Error::other)?;
        request_count += 1;
        handle_http3_request(listener_name, state, &proxy, remote_addr, request, &mut stream)
            .await?;
    }

    Ok(request_count)
}

async fn handle_http3_request(
    listener_name: &str,
    state: &WorkspaceServeState,
    proxy: &ManagedHttp3ProxyConfig,
    downstream_addr: SocketAddr,
    request: http1::Request<()>,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> io::Result<()> {
    let mut headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| lb_proto_http::HttpHeader {
                name: name.as_str().to_ascii_lowercase(),
                value: value.to_string(),
            })
        })
        .collect::<Vec<_>>();
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    let route_input = lb_proto_http::RouteMatchInput {
        target: target.clone(),
        host: request.uri().authority().map(|authority| authority.as_str().to_string()),
        method: Some(request.method().as_str().to_string()),
        headers: headers.clone(),
        source_ip: Some(downstream_addr.ip()),
    };
    let route = lb_proto_http::match_route_request_with_context(&route_input, &proxy.http1.routes);

    let mut request_body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(io::Error::other)? {
        let chunk_bytes = chunk.copy_to_bytes(chunk.remaining());
        request_body.extend_from_slice(&chunk_bytes);
    }
    if !request_body.is_empty() {
        headers.retain(|header| !header.name.eq_ignore_ascii_case("content-length"));
        headers.push(lb_proto_http::HttpHeader {
            name: String::from("content-length"),
            value: request_body.len().to_string(),
        });
    }

    let response = lb_runtime::proxy_http1_request_with_downstream_addr(
        &proxy.http1,
        downstream_addr,
        lb_proto_http::Http1RequestHead {
            method: request.method().as_str().to_string(),
            target,
            version: lb_proto_http::SupportedHttpVersion::Http1,
            headers,
            body_kind: if request_body.is_empty() {
                lb_proto_http::BodyKind::None
            } else {
                lb_proto_http::BodyKind::ContentLength(request_body.len() as u64)
            },
            keep_alive: false,
            route,
        },
        &request_body,
    )
    .await
    .map_err(|error| {
        state.record_http3_request(listener_name, "failed", "bridge_failed");
        io::Error::other(error)
    })?;

    let status_reason = match response.head.status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    };

    let mut response_builder = http1::Response::builder().status(response.head.status);
    for header in &response.head.headers {
        response_builder = response_builder.header(&header.name, &header.value);
    }
    let response_head = response_builder.body(()).map_err(|error| {
        state.record_http3_request(listener_name, "failed", "response_build_failed");
        io::Error::other(error)
    })?;
    stream.send_response(response_head).await.map_err(|error| {
        state.record_http3_request(listener_name, "failed", "response_head_write_failed");
        io::Error::other(error)
    })?;
    if !response.body.is_empty() {
        stream.send_data(Bytes::from(response.body)).await.map_err(|error| {
            state.record_http3_request(listener_name, "failed", "response_body_write_failed");
            io::Error::other(error)
        })?;
    }
    stream.finish().await.map_err(|error| {
        state.record_http3_request(listener_name, "failed", "response_finish_failed");
        io::Error::other(error)
    })?;
    state.record_http3_request(listener_name, "served", status_reason);
    Ok(())
}

async fn run_public_listener_loop(
    listener: TcpListener,
    listener_name: String,
    proxy_protocol: lb_config_model::ProxyProtocolModeConfig,
    shared_proxy: Arc<RwLock<ManagedProxyConfig>>,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
    counters: Arc<ListenerRuntimeCounters>,
    state: Arc<WorkspaceServeState>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
    ready_tx: oneshot::Sender<()>,
) -> io::Result<ListenerDrainOutcome> {
    *counters.state.write().await = String::from("running");
    let _ = ready_tx.send(());
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut stream, peer_addr) = accepted?;
                let proxy = shared_proxy.read().await.clone();
                let downstream_addr = match resolve_downstream_addr_from_proxy_protocol(
                    &mut stream,
                    peer_addr,
                    proxy_protocol,
                    proxy_preface_timeout(&proxy),
                )
                .await
                {
                    Ok(downstream_addr) => downstream_addr,
                    Err(_) => continue,
                };
                let source_lease = {
                    let protection = abuse_protection.read().await;
                    match protection.try_acquire_source(downstream_addr) {
                        Ok(source_lease) => source_lease,
                        Err(reason) => {
                            state.record_listener_abuse_rejection(&listener_name, reason);
                            state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                            if matches!(&proxy, ManagedProxyConfig::Http1(_)) {
                                let _ = write_abuse_rejection_response(&mut stream, reason).await;
                            }
                            continue;
                        }
                    }
                };
                let mut handshake_permit = {
                    let protection = abuse_protection.read().await;
                    match protection.try_acquire_handshake() {
                        Ok(handshake_permit) => handshake_permit,
                        Err(reason) => {
                            drop(source_lease);
                            state.record_listener_abuse_rejection(&listener_name, reason);
                            state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                            if matches!(&proxy, ManagedProxyConfig::Http1(_)) {
                                let _ = write_abuse_rejection_response(&mut stream, reason).await;
                            }
                            continue;
                        }
                    }
                };
                if !matches!(&proxy, ManagedProxyConfig::Https(_)) {
                    if let Some(handshake_permit) = handshake_permit.as_mut() {
                        handshake_permit.release();
                    }
                }
                state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                counters.accepted_connections.fetch_add(1, Ordering::SeqCst);
                if !try_acquire_listener_slot(&counters, &admission_limit) {
                    drop(source_lease);
                    drop(handshake_permit);
                    counters.shed_connections.fetch_add(1, Ordering::SeqCst);
                    state.record_overload_event(
                        &listener_name,
                        lb_observability::OverloadEventKind::RequestShed,
                        format!(
                            "listener shed public connection at capacity {}",
                            admission_limit.load(Ordering::SeqCst)
                        ),
                    );
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        true,
                    );
                    if matches!(&proxy, ManagedProxyConfig::Http1(_)) {
                        let _ = write_overload_response(&mut stream).await;
                    }
                    continue;
                }
                state.sync_listener_overload_snapshot(
                    &listener_name,
                    &counters,
                    admission_limit.load(Ordering::SeqCst),
                    &overload_runtime,
                    false,
                );
                let counters = Arc::clone(&counters);
                let state = Arc::clone(&state);
                let listener_name = listener_name.clone();
                let admission_limit = Arc::clone(&admission_limit);
                let overload_runtime = Arc::clone(&overload_runtime);
                let abuse_protection = Arc::clone(&abuse_protection);
                tasks.spawn(async move {
                    let _source_lease = source_lease;
                    let result: io::Result<u64> = match proxy {
                        ManagedProxyConfig::Http1(config) => {
                            lb_runtime::proxy_http1_connection_with_downstream_addr(
                                stream,
                                downstream_addr,
                                &config,
                            )
                            .await
                            .map(|report| report.metrics.request_count)
                            .map_err(|error| io::Error::other(error.to_string()))
                        }
                        ManagedProxyConfig::Http2(config) => {
                            lb_runtime::proxy_http2_connection_with_downstream_addr(
                                stream,
                                downstream_addr,
                                &config,
                            )
                            .await
                            .map(|report| report.metrics.request_count)
                            .map_err(|error| io::Error::other(error.to_string()))
                        }
                        ManagedProxyConfig::Https(config) => {
                            proxy_https_connection(stream, downstream_addr, config, handshake_permit)
                                .await
                        }
                        ManagedProxyConfig::Http3(_) => {
                            Err(io::Error::other("http3 proxy config cannot run on tcp listener loop"))
                        }
                    };
                    if let Ok(request_count) = result {
                        state.proxied_connections.fetch_add(1, Ordering::SeqCst);
                        state.proxied_requests.fetch_add(request_count, Ordering::SeqCst);
                    }
                    counters.active_connections.fetch_sub(1, Ordering::SeqCst);
                    counters.completed_connections.fetch_add(1, Ordering::SeqCst);
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        false,
                    );
                    state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                });
            }
        }
    }

    *counters.state.write().await = String::from("draining");
    let drain_outcome =
        if time::timeout(drain_timeout, async { while tasks.join_next().await.is_some() {} })
            .await
            .is_ok()
        {
            *counters.state.write().await = String::from("stopped");
            ListenerDrainOutcome::Completed
        } else {
            *counters.state.write().await = String::from("drain_timeout_expired");
            ListenerDrainOutcome::TimedOut
        };
    Ok(drain_outcome)
}

async fn run_admin_listener_loop(
    listener: TcpListener,
    listener_name: String,
    admission_limit: Arc<AtomicUsize>,
    overload_runtime: Arc<StdMutex<Option<ListenerOverloadRuntime>>>,
    abuse_protection: Arc<RwLock<lb_runtime::ListenerAbuseProtectionState>>,
    counters: Arc<ListenerRuntimeCounters>,
    state: Arc<WorkspaceServeState>,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout: Duration,
    admin_runtime: AdminRuntimeHandles,
    admin_tls: Option<ManagedAdminTlsConfig>,
    admin_secret: Arc<String>,
    supervisor: ServeSupervisor,
    ready_tx: oneshot::Sender<()>,
) -> io::Result<ListenerDrainOutcome> {
    *counters.state.write().await = String::from("running");
    let _ = ready_tx.send(());
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut stream, peer_addr) = accepted?;
                let source_lease = {
                    let protection = abuse_protection.read().await;
                    match protection.try_acquire_source(peer_addr) {
                        Ok(source_lease) => source_lease,
                        Err(reason) => {
                            state.record_listener_abuse_rejection(&listener_name, reason);
                            state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                            if admin_tls.is_none() {
                                let _ = write_abuse_rejection_response(&mut stream, reason).await;
                            }
                            continue;
                        }
                    }
                };
                let mut handshake_permit = {
                    let protection = abuse_protection.read().await;
                    match protection.try_acquire_handshake() {
                        Ok(handshake_permit) => handshake_permit,
                        Err(reason) => {
                            drop(source_lease);
                            state.record_listener_abuse_rejection(&listener_name, reason);
                            state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                            if admin_tls.is_none() {
                                let _ = write_abuse_rejection_response(&mut stream, reason).await;
                            }
                            continue;
                        }
                    }
                };
                if admin_tls.is_none() {
                    if let Some(handshake_permit) = handshake_permit.as_mut() {
                        handshake_permit.release();
                    }
                }
                state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                counters.accepted_connections.fetch_add(1, Ordering::SeqCst);
                if !try_acquire_listener_slot(&counters, &admission_limit) {
                    drop(source_lease);
                    drop(handshake_permit);
                    counters.shed_connections.fetch_add(1, Ordering::SeqCst);
                    state.record_overload_event(
                        &listener_name,
                        lb_observability::OverloadEventKind::RequestShed,
                        format!(
                            "listener shed admin connection at capacity {}",
                            admission_limit.load(Ordering::SeqCst)
                        ),
                    );
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        true,
                    );
                    if admin_tls.is_none() {
                        let _ = write_overload_response(&mut stream).await;
                    }
                    continue;
                }
                state.sync_listener_overload_snapshot(
                    &listener_name,
                    &counters,
                    admission_limit.load(Ordering::SeqCst),
                    &overload_runtime,
                    false,
                );
                let counters = Arc::clone(&counters);
                let state = Arc::clone(&state);
                let admin_runtime = admin_runtime.clone();
                let admin_secret = Arc::clone(&admin_secret);
                let supervisor = supervisor.clone();
                let listener_name = listener_name.clone();
                let admission_limit = Arc::clone(&admission_limit);
                let overload_runtime = Arc::clone(&overload_runtime);
                let abuse_protection = Arc::clone(&abuse_protection);
                let admin_tls = admin_tls.clone();
                tasks.spawn(async move {
                    let _source_lease = source_lease;
                    let state_for_connection = Arc::clone(&state);
                    let _ = match admin_tls {
                        Some(config) => {
                            handle_workspace_admin_tls_connection(
                                stream,
                                peer_addr,
                                listener_name.clone(),
                                state_for_connection,
                                admin_runtime,
                                admin_secret,
                                supervisor,
                                config,
                                handshake_permit,
                            )
                            .await
                        }
                        None => {
                            handle_workspace_admin_connection(
                                stream,
                                peer_addr,
                                listener_name.clone(),
                                state_for_connection,
                                admin_runtime,
                                admin_secret,
                                supervisor,
                            )
                            .await
                        }
                    };
                    counters.active_connections.fetch_sub(1, Ordering::SeqCst);
                    counters.completed_connections.fetch_add(1, Ordering::SeqCst);
                    state.sync_listener_overload_snapshot(
                        &listener_name,
                        &counters,
                        admission_limit.load(Ordering::SeqCst),
                        &overload_runtime,
                        false,
                    );
                    state.sync_listener_abuse_snapshot(&listener_name, &abuse_protection).await;
                });
            }
        }
    }

    *counters.state.write().await = String::from("draining");
    let drain_outcome =
        if time::timeout(drain_timeout, async { while tasks.join_next().await.is_some() {} })
            .await
            .is_ok()
        {
            *counters.state.write().await = String::from("stopped");
            ListenerDrainOutcome::Completed
        } else {
            *counters.state.write().await = String::from("drain_timeout_expired");
            ListenerDrainOutcome::TimedOut
        };
    Ok(drain_outcome)
}

async fn handle_workspace_admin_tls_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    listener_name: String,
    state: Arc<WorkspaceServeState>,
    admin_runtime: AdminRuntimeHandles,
    admin_secret: Arc<String>,
    supervisor: ServeSupervisor,
    config: ManagedAdminTlsConfig,
    mut handshake_permit: Option<lb_runtime::HandshakePermit>,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::clone(&config.tls_server_config));
    let tls_stream =
        acceptor.accept(stream).await.map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(handshake_permit) = handshake_permit.as_mut() {
        handshake_permit.release();
    }

    handle_workspace_admin_connection(
        tls_stream,
        peer_addr,
        listener_name,
        state,
        admin_runtime,
        admin_secret,
        supervisor,
    )
    .await
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

    let audit_code = if matches!(action, AdminRequestAction::Reload) {
        state.last_reload_outcome_code.lock().await.clone()
    } else {
        admin_audit_code(&action_name, &audit_outcome.0)
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

async fn handle_admin_cache_purge(
    state: &WorkspaceServeState,
    request_body: &[u8],
) -> Result<AdminHttpCachePurgeResponse, String> {
    let request = serde_json::from_slice::<AdminHttpCachePurgeRequest>(request_body)
        .map_err(|error| format!("invalid cache purge request body: {error}"))?;
    let scope = state
        .http_cache_scope(&request.scope)
        .await
        .ok_or_else(|| format!("unknown cache scope {}", request.scope))?;
    let target = match request.target {
        AdminHttpCachePurgeTarget::ExactKey { key_material } => {
            lb_admin_api::HttpCachePurgeTarget::ExactKey(
                lb_runtime::HttpCacheKey::new(key_material)
                    .map_err(|error| format!("invalid exact cache key material: {error}"))?,
            )
        }
        AdminHttpCachePurgeTarget::PathPrefix { path_prefix } => {
            lb_admin_api::HttpCachePurgeTarget::PathPrefix(path_prefix)
        }
    };
    let telemetry = Arc::clone(&state.telemetry);
    let service = Arc::clone(&scope.service);
    let response = tokio::task::spawn_blocking(move || {
        service.blocking_lock().purge(
            lb_admin_api::HttpCachePurgeRequest {
                target,
                requested_by: request.requested_by,
                reason: request.reason,
            },
            Some(telemetry.as_ref()),
        )
    })
    .await
    .map_err(|error| format!("cache purge task failed: {error}"))?
    .map_err(|error| error.to_string())?;
    Ok(AdminHttpCachePurgeResponse {
        action: match response.action {
            lb_admin_api::HttpCachePurgeActionKind::ExactKey => String::from("exact_key"),
            lb_admin_api::HttpCachePurgeActionKind::PathPrefix => String::from("path_prefix"),
        },
        result: match response.result {
            lb_admin_api::HttpCachePurgeResultKind::Purged => String::from("purged"),
            lb_admin_api::HttpCachePurgeResultKind::NoMatch => String::from("no_match"),
            lb_admin_api::HttpCachePurgeResultKind::Rejected => String::from("rejected"),
        },
        scope: response.scope,
        purged_entries: response.purged_entries,
        fanout_transport: response.fanout_transport,
        fanout_subscriber_count: response.fanout_subscriber_count,
        fanout_delivery_success_count: response.fanout_delivery_success_count,
        fanout_delivery_failure_count: response.fanout_delivery_failure_count,
        fanout_duplicate_count: response.fanout_duplicate_count,
        fanout_failed_targets: response.fanout_failed_targets,
        degraded: response.degraded,
        invalidation_event_id: response.invalidation_event_id,
        occurred_at_unix_ms: response.occurred_at_unix_ms,
    })
}

async fn handle_admin_cache_invalidate(
    state: &WorkspaceServeState,
    request_body: &[u8],
) -> Result<lb_admin_api::HttpCachePeerInvalidationResponse, String> {
    let event = serde_json::from_slice::<lb_runtime::HttpCacheInvalidationEvent>(request_body)
        .map_err(|error| format!("invalid cache invalidation event body: {error}"))?;
    let scope = state
        .http_cache_scope(&event.scope)
        .await
        .ok_or_else(|| format!("unknown cache scope {}", event.scope))?;
    let apply = scope.store.apply_invalidation_event(&event).map_err(|error| error.to_string())?;
    let (result, purged_entries) = match apply {
        lb_runtime::HttpCacheInvalidationApplyResult::Applied { purged_entries } => {
            (lb_admin_api::HttpCachePeerInvalidationResult::Applied, purged_entries)
        }
        lb_runtime::HttpCacheInvalidationApplyResult::Duplicate => {
            (lb_admin_api::HttpCachePeerInvalidationResult::Duplicate, 0)
        }
    };
    Ok(lb_admin_api::HttpCachePeerInvalidationResponse {
        result,
        event_id: event.event_id,
        scope: event.scope,
        purged_entries,
        occurred_at_unix_ms: event.occurred_at_unix_ms,
    })
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

async fn record_admin_audit(
    state: &WorkspaceServeState,
    event: AdminAuditEvent,
) -> Result<(), DynError> {
    state.record_admin_audit(event).await;
    Ok(())
}

fn optional_string_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", crate::escape_json_string(value)))
        .unwrap_or_else(|| String::from("null"))
}

fn optional_u64_json(value: Option<u64>) -> String {
    value.map_or_else(|| String::from("null"), |value| value.to_string())
}

fn control_plane_journal_path(config_path: &str) -> String {
    format!("{config_path}.control-plane.json")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_control_plane_journal_atomic(
    journal_path: &str,
    payload: &ControlPlaneJournalPayload,
) -> Result<(), DynError> {
    let payload_json = serde_json::to_string_pretty(payload).map_err(to_dyn_error)?;
    let envelope = ControlPlaneJournalEnvelope {
        version: CONTROL_PLANE_JOURNAL_VERSION,
        payload_sha256: sha256_hex(payload_json.as_bytes()),
        payload_json,
    };
    let serialized = serde_json::to_vec_pretty(&envelope).map_err(to_dyn_error)?;
    let write_sequence = NEXT_CONTROL_PLANE_JOURNAL_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_path =
        format!("{journal_path}.tmp-{}-{}-{write_sequence}", std::process::id(), unix_time_ms());
    fs::write(&temporary_path, serialized).map_err(to_dyn_error)?;
    fs::rename(&temporary_path, journal_path).map_err(to_dyn_error)?;
    Ok(())
}

fn reload_health_from_name(name: &str) -> ReloadHealthState {
    match name {
        "healthy" => ReloadHealthState::Healthy,
        "failed" => ReloadHealthState::Failed,
        _ => ReloadHealthState::NotRequested,
    }
}

fn next_admin_sequence_from_events(events: &[AdminAuditEvent]) -> u64 {
    events
        .iter()
        .filter_map(|event| {
            event
                .request_id
                .strip_prefix("admin-")
                .and_then(|suffix| u64::from_str_radix(suffix, 16).ok())
        })
        .max()
        .map_or(1, |sequence| sequence.saturating_add(1))
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn try_acquire_listener_slot(
    counters: &ListenerRuntimeCounters,
    admission_limit: &AtomicUsize,
) -> bool {
    loop {
        let active = counters.active_connections.load(Ordering::SeqCst);
        let limit = admission_limit.load(Ordering::SeqCst);
        if active >= limit {
            return false;
        }

        if counters
            .active_connections
            .compare_exchange(active, active + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return true;
        }
    }
}

async fn write_overload_response(stream: &mut TcpStream) -> io::Result<()> {
    crate::write_http_response(
        stream,
        "503 Service Unavailable",
        "text/plain; charset=utf-8",
        b"listener overloaded\n",
    )
    .await?;
    stream.shutdown().await
}

async fn write_abuse_rejection_response(
    stream: &mut TcpStream,
    reason: lb_runtime::AbuseRejectionReason,
) -> io::Result<()> {
    let body = format!("listener rejected connection: {}\n", reason.code());
    let response = format!(
        concat!(
            "HTTP/1.1 503 Service Unavailable\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n",
            "X-LB-Abuse-Reason: {}\r\n\r\n",
            "{}"
        ),
        body.len(),
        reason.code(),
        body,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn build_listener_abuse_protection_state(
    policy: Option<&CompiledListenerAbuseProtectionPolicy>,
) -> lb_runtime::ListenerAbuseProtectionState {
    lb_runtime::ListenerAbuseProtectionState::new(policy.map_or_else(
        lb_runtime::ListenerAbuseProtectionPolicy::default,
        |policy| lb_runtime::ListenerAbuseProtectionPolicy {
            source_quota: policy.source_quota.map(|source_quota| {
                lb_runtime::SourceQuotaPolicy::new(
                    source_quota.aggregation,
                    source_quota.max_active_per_source,
                    source_quota.max_tracked_sources,
                )
            }),
            handshake_guard: policy.handshake_guard.map(|handshake_guard| {
                lb_runtime::HandshakeGuardPolicy::new(
                    handshake_guard.max_inflight,
                    handshake_guard.timeout,
                )
            }),
        },
    ))
}

fn build_listener_overload_runtime(
    policy: Option<&CompiledListenerOverloadPolicy>,
) -> Result<Option<ListenerOverloadRuntime>, DynError> {
    policy.map(ListenerOverloadRuntime::new).transpose()
}

fn snapshot_listener_overload(
    observed_at: Duration,
    counters: &ListenerRuntimeCounters,
    limit: usize,
    overload_runtime: &StdMutex<Option<ListenerOverloadRuntime>>,
    record_concurrency_signal: bool,
) -> (lb_runtime::OverloadSnapshot, Vec<String>) {
    let guard = overload_runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(runtime) = guard.as_ref() {
        if record_concurrency_signal {
            runtime.record_concurrency_signal(observed_at)
        } else {
            runtime.snapshot(observed_at)
        }
    } else {
        let active = counters.active_connections.load(Ordering::SeqCst);
        let shed = counters.shed_connections.load(Ordering::SeqCst);
        let state = if active >= limit {
            lb_runtime::OverloadState::Shedding
        } else {
            lb_runtime::OverloadState::Normal
        };
        (
            lb_runtime::OverloadSnapshot {
                state,
                active_signal_count: if matches!(state, lb_runtime::OverloadState::Shedding) {
                    1
                } else {
                    0
                },
                rate_limited_count: 0,
                concurrency_limited_count: active as u64,
                breaker_open_count: 0,
                retry_budget_exhausted_count: 0,
                shed_request_count: shed,
                brownout_feature_count: 0,
            },
            Vec::new(),
        )
    }
}

fn snapshot_listener_overload_status(
    observed_at: Duration,
    counters: &ListenerRuntimeCounters,
    overload_runtime: &StdMutex<Option<ListenerOverloadRuntime>>,
) -> (lb_runtime::OverloadState, Vec<String>, Vec<OverloadEventStatus>) {
    let fallback_state = match counters.overload_state.load(Ordering::SeqCst) {
        1 => lb_runtime::OverloadState::Constrained,
        2 => lb_runtime::OverloadState::Shedding,
        3 => lb_runtime::OverloadState::Brownout,
        _ => lb_runtime::OverloadState::Normal,
    };
    let guard = overload_runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .as_ref()
        .map(|runtime| {
            let (snapshot, brownout_features) = runtime.snapshot(observed_at);
            (
                snapshot.state,
                brownout_features,
                runtime
                    .recent_events()
                    .into_iter()
                    .map(OverloadEventStatus::from_overload_event)
                    .collect(),
            )
        })
        .unwrap_or((fallback_state, Vec::new(), Vec::new()))
}

fn reload_health_name(state: ReloadHealthState) -> &'static str {
    match state {
        ReloadHealthState::NotRequested => "not_requested",
        ReloadHealthState::Healthy => "healthy",
        ReloadHealthState::Failed => "failed",
    }
}

fn elapsed_millis_at_least_one(duration: Duration) -> u64 {
    let millis = match u64::try_from(duration.as_millis()) {
        Ok(millis) => millis,
        Err(_) => u64::MAX,
    };
    millis.max(1)
}

const fn reload_health_index(state: ReloadHealthState) -> usize {
    match state {
        ReloadHealthState::NotRequested => 0,
        ReloadHealthState::Healthy => 1,
        ReloadHealthState::Failed => 2,
    }
}

fn build_config_validation_preview(
    config_path: &str,
    active_snapshot: Option<&lb_config_model::WorkspaceSnapshot>,
    current_identities: &BTreeMap<String, CurrentListenerIdentity>,
    candidate: &CompiledWorkspaceRuntime,
) -> ConfigValidationPreview {
    let diff_preview = active_snapshot.map(|active| active.diff(&candidate.snapshot));
    let warnings = build_config_safety_warnings(active_snapshot, current_identities, candidate);
    let blocked_replacements =
        collect_blocked_listener_replacements(current_identities, &candidate.listeners);
    let supported_replacements =
        collect_supported_listener_replacements(current_identities, &candidate.listeners);
    let apply_preview = if !blocked_replacements.is_empty() {
        ConfigApplyPreview {
            strategy: String::from("blocked_requires_rebind"),
            rollback_safe: true,
            summary: format!(
                "reload would still be blocked because these listeners cannot be overlap-replaced on their current live socket: {}",
                blocked_replacements.join(", ")
            ),
        }
    } else if !supported_replacements.is_empty() {
        ConfigApplyPreview {
            strategy: String::from("overlap_and_drain_replacement"),
            rollback_safe: true,
            summary: format!(
                "replacement listeners can be started before retirement for: {}; failed replacement startup leaves the active runtime unchanged",
                supported_replacements.join(", ")
            ),
        }
    } else {
        ConfigApplyPreview {
            strategy: String::from("in_place_or_additive_swap"),
            rollback_safe: true,
            summary: String::from(
                "candidate config compiles before apply; new listeners are started before old listeners retire, and failed reloads leave the active runtime unchanged",
            ),
        }
    };

    ConfigValidationPreview {
        config_path: config_path.to_string(),
        active_snapshot: active_snapshot.map(lb_config_model::WorkspaceSnapshot::view),
        candidate_snapshot: candidate.snapshot.view(),
        diff_preview,
        warnings,
        apply_preview,
        compatibility: ConfigCompatibilityPreview {
            active_api_version: active_snapshot.map(|snapshot| snapshot.metadata().api_version()),
            candidate_api_version: candidate.snapshot.metadata().api_version(),
            snapshot_format_version: candidate
                .snapshot
                .metadata()
                .format_version()
                .to_string(),
            migration_strategy: String::from(
                "candidate configs must compile to the current snapshot format and supported api_version before apply; unsupported version jumps fail during validation and the active snapshot remains available for rollback",
            ),
        },
    }
}

fn build_config_safety_warnings(
    active_snapshot: Option<&lb_config_model::WorkspaceSnapshot>,
    current_identities: &BTreeMap<String, CurrentListenerIdentity>,
    candidate: &CompiledWorkspaceRuntime,
) -> Vec<ConfigSafetyWarning> {
    let mut warnings = Vec::new();

    if let Some(active_snapshot) = active_snapshot {
        let diff = active_snapshot.diff(&candidate.snapshot);
        if !diff.listener_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("listener_topology_changed"),
                message: format!(
                    "listener changes detected: {}",
                    summarize_snapshot_changes(&diff.listener_changes)
                ),
            });
        }
        if !diff.route_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("route_table_changed"),
                message: format!(
                    "route matching changes detected: {}",
                    summarize_snapshot_changes(&diff.route_changes)
                ),
            });
        }
        if !diff.upstream_cluster_changes.is_empty() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("upstream_clusters_changed"),
                message: format!(
                    "upstream topology changes detected: {}",
                    summarize_snapshot_changes(&diff.upstream_cluster_changes)
                ),
            });
        }
        if active_snapshot.security() != candidate.snapshot.security() {
            warnings.push(ConfigSafetyWarning {
                code: String::from("security_posture_changed"),
                message: String::from(
                    "workspace security settings changed; review trusted proxy, anonymous-source, and artifact verification posture before apply",
                ),
            });
        }
    } else {
        warnings.push(ConfigSafetyWarning {
            code: String::from("bootstrap_apply"),
            message: String::from(
                "no active snapshot is loaded yet; this validation is for the first apply and has no prior diff baseline",
            ),
        });
    }

    for listener_name in
        collect_supported_listener_replacements(current_identities, &candidate.listeners)
    {
        warnings.push(ConfigSafetyWarning {
            code: String::from("listener_replacement_planned"),
            message: format!(
                "listener {listener_name} changes bind or protocol semantics and will be staged through replacement plus drain instead of an in-place swap"
            ),
        });
    }

    for listener_name in
        collect_blocked_listener_replacements(current_identities, &candidate.listeners)
    {
        warnings.push(ConfigSafetyWarning {
            code: String::from("listener_rebind_required"),
            message: format!(
                "listener {listener_name} cannot be staged safely on a new socket before retiring the current live listener, so reload will still be rejected"
            ),
        });
    }

    warnings
}

fn collect_supported_listener_replacements(
    current_identities: &BTreeMap<String, CurrentListenerIdentity>,
    candidate_listeners: &BTreeMap<String, CompiledServeListener>,
) -> Vec<String> {
    let mut supported = Vec::new();
    for (name, spec) in candidate_listeners {
        if let Some(current) = current_identities.get(name) {
            if current.needs_replacement(spec) && current.can_stage_replacement(spec) {
                supported.push(name.clone());
            }
        }
    }
    supported
}

fn collect_blocked_listener_replacements(
    current_identities: &BTreeMap<String, CurrentListenerIdentity>,
    candidate_listeners: &BTreeMap<String, CompiledServeListener>,
) -> Vec<String> {
    let mut blocked = Vec::new();
    for (name, spec) in candidate_listeners {
        if let Some(current) = current_identities.get(name) {
            if current.needs_replacement(spec) && !current.can_stage_replacement(spec) {
                blocked.push(name.clone());
            }
        }
    }
    blocked
}

fn summarize_snapshot_changes(changes: &[lb_config_model::SnapshotResourceChange]) -> String {
    changes
        .iter()
        .map(|change| format!("{}:{:?}", change.name, change.kind))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg_attr(not(test), allow(dead_code))]
fn compile_workspace_runtime(config_path: &str) -> Result<CompiledWorkspaceRuntime, DynError> {
    compile_workspace_runtime_with_telemetry(config_path, None)
}

fn compile_workspace_runtime_with_telemetry(
    config_path: &str,
    telemetry: Option<&Arc<lb_runtime::RuntimeTelemetry>>,
) -> Result<CompiledWorkspaceRuntime, DynError> {
    let config = crate::load_workspace_config(config_path).map_err(to_dyn_error)?;
    let snapshot = config.compile_snapshot().map_err(to_dyn_error)?;
    let compiled_listeners = config.compile_listeners()?;
    let compiled_routes = config.compile_http_route_rules()?;
    let mut listeners = BTreeMap::new();
    let mut http_cache_scopes = BTreeMap::new();

    for (listener, compiled_listener) in config.listeners.iter().zip(compiled_listeners.iter()) {
        let http_cache_scope =
            if matches!(listener.class, lb_config_model::ListenerClassConfig::Public)
                && matches!(
                    listener.protocol,
                    lb_config_model::ListenerProtocolConfig::Http1
                        | lb_config_model::ListenerProtocolConfig::Https
                )
            {
                resolve_listener_http_cache_policy(&config, listener)?
                    .map(|(_policy_name, policy)| -> Result<_, DynError> {
                        let store = build_http_cache_store(&policy)?;
                        Ok((
                            HttpCacheScopeRuntime {
                                service: Arc::new(Mutex::new(
                                    lb_admin_api::HttpCacheAdminService::new(
                                        listener.name.clone(),
                                        policy.purge_enabled,
                                        Arc::clone(&store),
                                    ),
                                )),
                                store,
                            },
                            policy,
                        ))
                    })
                    .transpose()?
            } else {
                None
            };
        let compiled = match (listener.class, listener.protocol) {
            (
                lb_config_model::ListenerClassConfig::Public,
                lb_config_model::ListenerProtocolConfig::Http1,
            ) => CompiledServeListener::Public {
                class: listener.class,
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                proxy: ManagedProxyConfig::Http1(compile_http1_proxy_config(
                    &config,
                    listener,
                    &compiled_routes,
                    http_cache_scope.as_ref().map(|(scope_runtime, policy)| {
                        (policy.clone(), Arc::clone(&scope_runtime.store))
                    }),
                    telemetry,
                )?),
            },
            (
                lb_config_model::ListenerClassConfig::Public,
                lb_config_model::ListenerProtocolConfig::Http2,
            ) => CompiledServeListener::Public {
                class: listener.class,
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                proxy: ManagedProxyConfig::Http2(compile_http2_proxy_config(
                    &config,
                    listener,
                    &compiled_routes,
                )?),
            },
            (
                lb_config_model::ListenerClassConfig::Public,
                lb_config_model::ListenerProtocolConfig::Https,
            ) => CompiledServeListener::Public {
                class: listener.class,
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                proxy: ManagedProxyConfig::Https(compile_https_proxy_config(
                    &config,
                    listener,
                    compiled_listener,
                    &compiled_routes,
                    http_cache_scope.as_ref().map(|(scope_runtime, policy)| {
                        (policy.clone(), Arc::clone(&scope_runtime.store))
                    }),
                    telemetry,
                )?),
            },
            (
                lb_config_model::ListenerClassConfig::Public,
                lb_config_model::ListenerProtocolConfig::Http3,
            ) => CompiledServeListener::Public {
                class: listener.class,
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                proxy: ManagedProxyConfig::Http3(compile_http3_proxy_config(
                    &config,
                    listener,
                    &compiled_routes,
                )?),
            },
            (lb_config_model::ListenerClassConfig::Public, protocol) => {
                return Err(format!(
                    "listener {} uses unsupported public protocol {:?} in serve mode",
                    listener.name, protocol
                )
                .into());
            }
            (
                lb_config_model::ListenerClassConfig::Admin,
                lb_config_model::ListenerProtocolConfig::Http1,
            ) => CompiledServeListener::Admin {
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                admin_policy: compile_admin_policy(listener)?,
                tls: None,
            },
            (
                lb_config_model::ListenerClassConfig::Admin,
                lb_config_model::ListenerProtocolConfig::Https,
            ) => CompiledServeListener::Admin {
                protocol: listener.protocol,
                proxy_protocol: listener.proxy_protocol,
                bind_address: compiled_listener.bind_address,
                bind_mode: compiled_listener.bind_mode,
                max_connections: compiled_listener.max_connections,
                drain_timeout: compiled_listener.drain_timeout,
                overload_policy: compile_listener_overload_policy(&config, listener)?,
                abuse_protection_policy: compile_listener_abuse_protection_policy(
                    &config, listener,
                )?,
                admin_policy: compile_admin_policy(listener)?,
                tls: Some(ManagedAdminTlsConfig {
                    tls_server_config: Arc::new(build_tls_server_config(
                        listener.tls_termination.as_ref().ok_or_else(|| {
                            to_dyn_error(format!(
                                "listener {} is missing tls_termination",
                                listener.name
                            ))
                        })?,
                    )?),
                    tls_status: build_listener_tls_status(
                        listener.tls_termination.as_ref().ok_or_else(|| {
                            to_dyn_error(format!(
                                "listener {} is missing tls_termination",
                                listener.name
                            ))
                        })?,
                    )?,
                }),
            },
            (lb_config_model::ListenerClassConfig::Admin, protocol) => {
                return Err(format!(
                    "listener {} uses unsupported admin protocol {:?} in serve mode",
                    listener.name, protocol
                )
                .into());
            }
        };

        if let Some((scope_runtime, _policy)) = http_cache_scope {
            http_cache_scopes.insert(listener.name.clone(), scope_runtime);
        }

        listeners.insert(listener.name.clone(), compiled);
    }

    Ok(CompiledWorkspaceRuntime {
        source_label: format!("config_path={config_path}"),
        snapshot,
        listeners,
        http_cache_scopes,
    })
}

fn compile_admin_policy(
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<CompiledAdminPolicy, DynError> {
    let auth = match &listener.admin.auth {
        lb_config_model::AdminAuthPolicyConfig::Bearer { secret_env, permissions } => {
            CompiledAdminAuthPolicy::Bearer {
                secret_env: secret_env.clone(),
                permissions: compile_admin_permissions(permissions),
            }
        }
        lb_config_model::AdminAuthPolicyConfig::SignedHeaders {
            operators,
            max_clock_skew_secs,
            nonce_ttl_secs,
        } => CompiledAdminAuthPolicy::SignedHeaders {
            operators: operators
                .iter()
                .map(|operator| {
                    (
                        operator.id.clone(),
                        CompiledAdminOperator {
                            secret_env: operator.secret_env.clone(),
                            permissions: compile_admin_permissions(&operator.permissions),
                        },
                    )
                })
                .collect(),
            max_clock_skew: Duration::from_secs(*max_clock_skew_secs),
            nonce_ttl: Duration::from_secs(*nonce_ttl_secs),
        },
    };

    Ok(CompiledAdminPolicy {
        auth,
        allowed_source_cidrs: listener
            .admin
            .allowed_source_cidrs
            .iter()
            .map(|cidr| cidr.parse::<IpNet>().map_err(to_dyn_error))
            .collect::<Result<Vec<_>, _>>()?,
        rate_limit: CompiledAdminRateLimit {
            requests_per_minute: listener.admin.rate_limit.requests_per_minute,
            burst: listener.admin.rate_limit.burst,
        },
        audit_capacity: listener.admin.audit.max_retained_events,
    })
}

fn compile_admin_permissions(
    permissions: &[lb_config_model::AdminAuthorizationScopeConfig],
) -> BTreeSet<AdminPermission> {
    permissions
        .iter()
        .map(|permission| match permission {
            lb_config_model::AdminAuthorizationScopeConfig::Read => AdminPermission::Read,
            lb_config_model::AdminAuthorizationScopeConfig::Audit => AdminPermission::Audit,
            lb_config_model::AdminAuthorizationScopeConfig::Write => AdminPermission::Write,
        })
        .collect()
}

fn resolve_listener_http_cache_policy(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<Option<(String, lb_config_model::HttpCachePolicyConfig)>, DynError> {
    if let Some(cache_policy_name) = listener.policies.cache_policy.as_ref() {
        let policy = config
            .policies
            .http_caches
            .iter()
            .find(|policy| policy.name == *cache_policy_name)
            .ok_or_else(|| {
                to_dyn_error(format!(
                    "listener {} references unknown http cache policy {}",
                    listener.name, cache_policy_name
                ))
            })?;
        return Ok(Some((policy.name.clone(), policy.spec.clone())));
    }

    let mut route_cache_policy_names = listener
        .routes
        .iter()
        .filter_map(|route_name| {
            config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .and_then(|route| route.policies.cache_policy.clone())
        })
        .collect::<BTreeSet<_>>();

    if route_cache_policy_names.is_empty() {
        return Ok(None);
    }
    if route_cache_policy_names.len() > 1 {
        return Err(to_dyn_error(format!(
            "listener {} references multiple route-level http cache policies, which serve mode does not support on a single listener",
            listener.name
        )));
    }
    let Some(cache_policy_name) = route_cache_policy_names.pop_first() else {
        return Ok(None);
    };
    let policy = config
        .policies
        .http_caches
        .iter()
        .find(|policy| policy.name == cache_policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!(
                "listener {} references unknown http cache policy {}",
                listener.name, cache_policy_name
            ))
        })?;
    Ok(Some((policy.name.clone(), policy.spec.clone())))
}

fn resolve_listener_request_transforms(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<
    (
        Option<lb_config_model::RequestTransformConfig>,
        Vec<(String, lb_config_model::RequestTransformConfig)>,
    ),
    DynError,
> {
    let listener_request_transform = listener
        .policies
        .transform_policy
        .as_deref()
        .map(|policy_name| resolve_named_request_transform(config, policy_name, &listener.name))
        .transpose()?;

    let route_request_transforms = listener
        .routes
        .iter()
        .filter_map(|route_name| {
            config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .and_then(|route| {
                    route.policies.transform_policy.as_deref().map(|policy_name| {
                        (route.name.clone(), policy_name.to_string())
                    })
                })
        })
        .map(|(route_name, policy_name)| {
            resolve_named_request_transform(config, &policy_name, &route_name)
                .map(|transform| (route_name, transform))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((listener_request_transform, route_request_transforms))
}

fn resolve_named_request_transform(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
    referrer_name: &str,
) -> Result<lb_config_model::RequestTransformConfig, DynError> {
    config
        .policies
        .transforms
        .iter()
        .find(|policy| policy.name == policy_name)
        .map(|policy| policy.spec.request.clone())
        .ok_or_else(|| {
            to_dyn_error(format!(
                "resource {} references unknown transform policy {}",
                referrer_name, policy_name
            ))
        })
}

fn resolve_listener_response_transforms(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<
    (
        Option<lb_config_model::ResponseTransformConfig>,
        Vec<(String, lb_config_model::ResponseTransformConfig)>,
    ),
    DynError,
> {
    let listener_response_transform = listener
        .policies
        .transform_policy
        .as_deref()
        .map(|policy_name| resolve_named_response_transform(config, policy_name, &listener.name))
        .transpose()?;

    let route_response_transforms = listener
        .routes
        .iter()
        .filter_map(|route_name| {
            config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .and_then(|route| {
                    route.policies.transform_policy.as_deref().map(|policy_name| {
                        (route.name.clone(), policy_name.to_string())
                    })
                })
        })
        .map(|(route_name, policy_name)| {
            resolve_named_response_transform(config, &policy_name, &route_name)
                .map(|transform| (route_name, transform))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((listener_response_transform, route_response_transforms))
}

fn resolve_named_response_transform(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
    referrer_name: &str,
) -> Result<lb_config_model::ResponseTransformConfig, DynError> {
    config
        .policies
        .transforms
        .iter()
        .find(|policy| policy.name == policy_name)
        .map(|policy| policy.spec.response.clone())
        .ok_or_else(|| {
            to_dyn_error(format!(
                "resource {} references unknown transform policy {}",
                referrer_name, policy_name
            ))
        })
}

fn compile_route_destination_policy_runtime(
    config: &lb_config_model::WorkspaceConfig,
    route_backend_policy_diagnostics: &BTreeMap<String, Vec<lb_runtime::EffectiveRouteDestinationPolicy>>,
) -> Result<BTreeMap<String, BTreeMap<String, lb_runtime::RouteDestinationPolicyRuntime>>, DynError>
{
    let mut shared_rate_limiters = BTreeMap::<String, Arc<lb_runtime::LocalRateLimiter>>::new();
    let mut shared_concurrency_limiters =
        BTreeMap::<String, Arc<lb_runtime::LocalConcurrencyLimiter>>::new();
    let mut shared_failure_managers = BTreeMap::<String, Arc<lb_runtime::FailureManager>>::new();

    route_backend_policy_diagnostics
        .iter()
        .map(|(route_name, diagnostics)| {
            let destination_runtime = diagnostics
                .iter()
                .map(|diagnostic| {
                    let rate_limiters = diagnostic
                        .local_rate_limits
                        .iter()
                        .map(|policy_name| {
                            resolve_named_local_rate_limiter(
                                config,
                                &mut shared_rate_limiters,
                                policy_name,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let concurrency_limiters = diagnostic
                        .local_concurrency_limits
                        .iter()
                        .map(|policy_name| {
                            resolve_named_local_concurrency_limiter(
                                config,
                                &mut shared_concurrency_limiters,
                                policy_name,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let failure_manager = resolve_destination_failure_manager(
                        config,
                        &mut shared_failure_managers,
                        diagnostic,
                    )?;

                    Ok((
                        diagnostic.upstream_cluster.clone(),
                        lb_runtime::RouteDestinationPolicyRuntime {
                            request_transform: diagnostic.effective_request_transform.clone(),
                            response_transform: diagnostic.effective_response_transform.clone(),
                            traffic_mirror: diagnostic.traffic_mirror.as_ref().map(|policy_name| {
                                config
                                    .policies
                                    .traffic_mirrors
                                    .iter()
                                    .find(|policy| policy.name == *policy_name)
                                    .expect("validated traffic mirroring policy reference")
                                    .spec
                                    .clone()
                            }),
                                    fault_injection: diagnostic.fault_injection.as_ref().map(|policy_name| {
                                    config
                                        .policies
                                        .fault_injections
                                        .iter()
                                        .find(|policy| policy.name == *policy_name)
                                        .expect("validated fault injection policy reference")
                                        .spec
                                        .clone()
                                    }),
                            rate_limiters,
                            concurrency_limiters,
                            failure_manager,
                            enforce_retry_budget: diagnostic.retry_budget.is_some(),
                            enforce_timeout_hierarchy: diagnostic.timeout_hierarchy.is_some(),
                            enforce_circuit_breaker: diagnostic.circuit_breaker.is_some(),
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, DynError>>()?;
            Ok((route_name.clone(), destination_runtime))
        })
        .collect()
}

fn resolve_named_local_rate_limiter(
    config: &lb_config_model::WorkspaceConfig,
    cache: &mut BTreeMap<String, Arc<lb_runtime::LocalRateLimiter>>,
    policy_name: &str,
) -> Result<Arc<lb_runtime::LocalRateLimiter>, DynError> {
    if let Some(limiter) = cache.get(policy_name) {
        return Ok(Arc::clone(limiter));
    }

    let policy = config
        .policies
        .local_rate_limits
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| to_dyn_error(format!("unknown local rate-limit policy {policy_name}")))?;
    let limiter = Arc::new(
        lb_runtime::LocalRateLimiter::new(lb_runtime::LocalRateLimitConfig {
            scope: compile_local_limit_scope(&policy.spec.scope),
            key_kind: compile_local_limit_key_kind(policy.spec.key_kind),
            requests_per_window: policy.spec.requests_per_window,
            window: Duration::from_millis(policy.spec.window_ms),
            max_tracked_keys: policy.spec.max_tracked_keys,
        })
        .map_err(to_dyn_error)?,
    );
    cache.insert(policy_name.to_string(), Arc::clone(&limiter));
    Ok(limiter)
}

fn resolve_destination_failure_manager(
    config: &lb_config_model::WorkspaceConfig,
    cache: &mut BTreeMap<String, Arc<lb_runtime::FailureManager>>,
    diagnostic: &lb_runtime::EffectiveRouteDestinationPolicy,
) -> Result<Option<Arc<lb_runtime::FailureManager>>, DynError> {
    if diagnostic.retry_budget.is_none()
        && diagnostic.timeout_hierarchy.is_none()
        && diagnostic.circuit_breaker.is_none()
    {
        return Ok(None);
    }

    let key = format!(
        "retry={:?}|timeout={:?}|breaker={:?}",
        diagnostic.retry_budget, diagnostic.timeout_hierarchy, diagnostic.circuit_breaker
    );
    if let Some(manager) = cache.get(&key) {
        return Ok(Some(Arc::clone(manager)));
    }

    let retry_budget = diagnostic
        .retry_budget
        .as_deref()
        .map(|policy_name| resolve_named_retry_budget_policy(config, policy_name))
        .transpose()?
        .unwrap_or_else(default_retry_budget_policy);
    let timeout_hierarchy = diagnostic
        .timeout_hierarchy
        .as_deref()
        .map(|policy_name| resolve_named_timeout_hierarchy(config, policy_name))
        .transpose()?
        .unwrap_or_else(default_timeout_hierarchy);
    let circuit_breaker = diagnostic
        .circuit_breaker
        .as_deref()
        .map(|policy_name| resolve_named_circuit_breaker_policy(config, policy_name))
        .transpose()?
        .unwrap_or_else(default_circuit_breaker_policy);

    let manager = Arc::new(
        lb_runtime::FailureManager::new(retry_budget, timeout_hierarchy, circuit_breaker)
            .map_err(to_dyn_error)?,
    );
    cache.insert(key, Arc::clone(&manager));
    Ok(Some(manager))
}

fn resolve_named_retry_budget_policy(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
) -> Result<lb_runtime::RetryBudgetPolicy, DynError> {
    let policy = config
        .policies
        .retry_budgets
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| to_dyn_error(format!("unknown retry-budget policy {policy_name}")))?;
    Ok(lb_runtime::RetryBudgetPolicy {
        min_retry_tokens: policy.spec.min_retry_tokens,
        retry_percent: policy.spec.retry_percent,
        window: Duration::from_millis(policy.spec.window_ms),
    })
}

fn resolve_named_timeout_hierarchy(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
) -> Result<lb_runtime::TimeoutHierarchy, DynError> {
    let policy = config
        .policies
        .timeout_hierarchies
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| to_dyn_error(format!("unknown timeout hierarchy policy {policy_name}")))?;
    Ok(lb_runtime::TimeoutHierarchy {
        request_timeout: Duration::from_millis(policy.spec.request_timeout_ms),
        attempt_timeout: Duration::from_millis(policy.spec.attempt_timeout_ms),
        connect_timeout: Duration::from_millis(policy.spec.connect_timeout_ms),
        idle_timeout: Duration::from_millis(policy.spec.idle_timeout_ms),
    })
}

fn resolve_named_circuit_breaker_policy(
    config: &lb_config_model::WorkspaceConfig,
    policy_name: &str,
) -> Result<lb_runtime::CircuitBreakerPolicy, DynError> {
    let policy = config
        .policies
        .circuit_breakers
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| to_dyn_error(format!("unknown circuit-breaker policy {policy_name}")))?;
    Ok(lb_runtime::CircuitBreakerPolicy {
        open_failure_threshold: policy.spec.open_failure_threshold,
        open_duration: Duration::from_millis(policy.spec.open_duration_ms),
        half_open_success_threshold: policy.spec.half_open_success_threshold,
    })
}

fn default_retry_budget_policy() -> lb_runtime::RetryBudgetPolicy {
    lb_runtime::RetryBudgetPolicy::default()
}

fn default_timeout_hierarchy() -> lb_runtime::TimeoutHierarchy {
    let defaults = lb_net_core::ConnectionTimeouts::default();
    let attempt_timeout = defaults.idle_timeout.max(defaults.connect_timeout);
    lb_runtime::TimeoutHierarchy {
        request_timeout: attempt_timeout,
        attempt_timeout,
        connect_timeout: defaults.connect_timeout,
        idle_timeout: defaults.idle_timeout.min(attempt_timeout),
    }
}

fn default_circuit_breaker_policy() -> lb_runtime::CircuitBreakerPolicy {
    lb_runtime::CircuitBreakerPolicy::default()
}

fn resolve_named_local_concurrency_limiter(
    config: &lb_config_model::WorkspaceConfig,
    cache: &mut BTreeMap<String, Arc<lb_runtime::LocalConcurrencyLimiter>>,
    policy_name: &str,
) -> Result<Arc<lb_runtime::LocalConcurrencyLimiter>, DynError> {
    if let Some(limiter) = cache.get(policy_name) {
        return Ok(Arc::clone(limiter));
    }

    let policy = config
        .policies
        .local_concurrency_limits
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!("unknown local concurrency-limit policy {policy_name}"))
        })?;
    let limiter = Arc::new(
        lb_runtime::LocalConcurrencyLimiter::new(lb_runtime::LocalConcurrencyLimitConfig {
            scope: compile_local_limit_scope(&policy.spec.scope),
            key_kind: compile_local_limit_key_kind(policy.spec.key_kind),
            max_concurrent: policy.spec.max_concurrent,
            max_tracked_keys: policy.spec.max_tracked_keys,
        })
        .map_err(to_dyn_error)?,
    );
    cache.insert(policy_name.to_string(), Arc::clone(&limiter));
    Ok(limiter)
}

fn compile_local_limit_scope(
    scope: &lb_config_model::LocalLimitScopeConfig,
) -> lb_runtime::LocalLimitScope {
    match scope {
        lb_config_model::LocalLimitScopeConfig::Listener { name } => {
            lb_runtime::LocalLimitScope::Listener { name: name.clone() }
        }
        lb_config_model::LocalLimitScopeConfig::Route { name } => {
            lb_runtime::LocalLimitScope::Route { name: name.clone() }
        }
        lb_config_model::LocalLimitScopeConfig::RouteDestination {
            route,
            upstream_cluster,
        } => lb_runtime::LocalLimitScope::RouteDestination {
            route: route.clone(),
            upstream_cluster: upstream_cluster.clone(),
        },
        lb_config_model::LocalLimitScopeConfig::UpstreamCluster { name } => {
            lb_runtime::LocalLimitScope::UpstreamCluster { name: name.clone() }
        }
    }
}

fn compile_local_limit_key_kind(
    key_kind: lb_config_model::LocalLimitKeyKindConfig,
) -> lb_runtime::LocalLimitKeyKind {
    match key_kind {
        lb_config_model::LocalLimitKeyKindConfig::Global => lb_runtime::LocalLimitKeyKind::Global,
        lb_config_model::LocalLimitKeyKindConfig::SourceIp => {
            lb_runtime::LocalLimitKeyKind::SourceIp
        }
        lb_config_model::LocalLimitKeyKindConfig::RouteName => {
            lb_runtime::LocalLimitKeyKind::RouteName
        }
        lb_config_model::LocalLimitKeyKindConfig::UpstreamCluster => {
            lb_runtime::LocalLimitKeyKind::UpstreamCluster
        }
    }
}

fn merge_request_transform_layers(
    listener: Option<&lb_config_model::RequestTransformConfig>,
    route: Option<&lb_config_model::RequestTransformConfig>,
    destination: Option<&lb_config_model::RequestTransformConfig>,
) -> Option<lb_config_model::RequestTransformConfig> {
    let mut merged = listener.cloned().unwrap_or_default();
    let mut has_any = listener.is_some();

    for layer in [route, destination].into_iter().flatten() {
        has_any = true;
        if layer.path_rewrite.is_some() {
            merged.path_rewrite = layer.path_rewrite.clone();
        }
        if layer.host_rewrite.is_some() {
            merged.host_rewrite = layer.host_rewrite.clone();
        }
        merged.header_mutations.extend(layer.header_mutations.clone());
    }

    has_any.then_some(merged)
}

fn merge_response_transform_layers(
    listener: Option<&lb_config_model::ResponseTransformConfig>,
    route: Option<&lb_config_model::ResponseTransformConfig>,
    destination: Option<&lb_config_model::ResponseTransformConfig>,
) -> Option<lb_config_model::ResponseTransformConfig> {
    let mut merged = listener.cloned().unwrap_or_default();
    let mut has_any = listener.is_some();

    for layer in [route, destination].into_iter().flatten() {
        has_any = true;
        merged.header_mutations.extend(layer.header_mutations.clone());
    }

    has_any.then_some(merged)
}

fn pick_effective_policy_name(
    listener: Option<&String>,
    route: Option<&String>,
    destination: Option<&String>,
) -> Option<String> {
    destination
        .cloned()
        .or_else(|| route.cloned())
        .or_else(|| listener.cloned())
}

fn merge_effective_policy_refs(
    listener: &[String],
    route: &[String],
    destination: &[String],
) -> Vec<String> {
    listener
        .iter()
        .chain(route.iter())
        .chain(destination.iter())
        .cloned()
        .collect()
}

fn resolve_effective_route_backend_policy_diagnostics(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<BTreeMap<String, Vec<lb_runtime::EffectiveRouteDestinationPolicy>>, DynError> {
    let listener_transform_name = listener.policies.transform_policy.as_deref();
    let listener_request_transform = listener_transform_name
        .map(|policy_name| resolve_named_request_transform(config, policy_name, &listener.name))
        .transpose()?;
    let listener_response_transform = listener_transform_name
        .map(|policy_name| resolve_named_response_transform(config, policy_name, &listener.name))
        .transpose()?;

    listener
        .routes
        .iter()
        .map(|route_name| {
            let route = config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .ok_or_else(|| {
                    to_dyn_error(format!(
                        "listener {} references unknown route {}",
                        listener.name, route_name
                    ))
                })?;

            let route_transform_name = route.policies.transform_policy.as_deref();
            let route_request_transform = route_transform_name
                .map(|policy_name| resolve_named_request_transform(config, policy_name, &route.name))
                .transpose()?;
            let route_response_transform = route_transform_name
                .map(|policy_name| resolve_named_response_transform(config, policy_name, &route.name))
                .transpose()?;

            let diagnostics = route
                .normalized_destinations()
                .into_iter()
                .map(|destination| {
                    let destination_transform_name = destination.policies.transform_policy.as_deref();
                    let destination_request_transform = destination_transform_name
                        .map(|policy_name| {
                            resolve_named_request_transform(
                                config,
                                policy_name,
                                &format!("{}->{}", route.name, destination.upstream_cluster),
                            )
                        })
                        .transpose()?;
                    let destination_response_transform = destination_transform_name
                        .map(|policy_name| {
                            resolve_named_response_transform(
                                config,
                                policy_name,
                                &format!("{}->{}", route.name, destination.upstream_cluster),
                            )
                        })
                        .transpose()?;

                    Ok(lb_runtime::EffectiveRouteDestinationPolicy {
                        upstream_cluster: destination.upstream_cluster.clone(),
                        retry_budget: pick_effective_policy_name(
                            listener.policies.retry_budget.as_ref(),
                            route.policies.retry_budget.as_ref(),
                            destination.policies.retry_budget.as_ref(),
                        ),
                        timeout_hierarchy: pick_effective_policy_name(
                            listener.policies.timeout_hierarchy.as_ref(),
                            route.policies.timeout_hierarchy.as_ref(),
                            destination.policies.timeout_hierarchy.as_ref(),
                        ),
                        circuit_breaker: pick_effective_policy_name(
                            listener.policies.circuit_breaker.as_ref(),
                            route.policies.circuit_breaker.as_ref(),
                            destination.policies.circuit_breaker.as_ref(),
                        ),
                        transform_policy: pick_effective_policy_name(
                            listener.policies.transform_policy.as_ref(),
                            route.policies.transform_policy.as_ref(),
                            destination.policies.transform_policy.as_ref(),
                        ),
                        traffic_mirror: pick_effective_policy_name(
                            listener.policies.traffic_mirror.as_ref(),
                            route.policies.traffic_mirror.as_ref(),
                            destination.policies.traffic_mirror.as_ref(),
                        ),
                        fault_injection: pick_effective_policy_name(
                            listener.policies.fault_injection.as_ref(),
                            route.policies.fault_injection.as_ref(),
                            destination.policies.fault_injection.as_ref(),
                        ),
                        local_rate_limits: merge_effective_policy_refs(
                            &listener.policies.local_rate_limits,
                            &route.policies.local_rate_limits,
                            &destination.policies.local_rate_limits,
                        ),
                        local_concurrency_limits: merge_effective_policy_refs(
                            &listener.policies.local_concurrency_limits,
                            &route.policies.local_concurrency_limits,
                            &destination.policies.local_concurrency_limits,
                        ),
                        effective_request_transform: merge_request_transform_layers(
                            listener_request_transform.as_ref(),
                            route_request_transform.as_ref(),
                            destination_request_transform.as_ref(),
                        ),
                        effective_response_transform: merge_response_transform_layers(
                            listener_response_transform.as_ref(),
                            route_response_transform.as_ref(),
                            destination_response_transform.as_ref(),
                        ),
                    })
                })
                .collect::<Result<Vec<_>, DynError>>()?;

            Ok((route.name.clone(), diagnostics))
        })
        .collect()
}

fn resolve_listener_upgrade_policies(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> (
    Vec<lb_config_model::UpgradeProtocolConfig>,
    Vec<(String, Vec<lb_config_model::UpgradeProtocolConfig>)>,
) {
    let route_upgrade_protocols = listener
        .routes
        .iter()
        .filter_map(|route_name| {
            config
                .routes
                .iter()
                .find(|route| route.name == *route_name)
                .filter(|route| !route.upgrade.protocols.is_empty())
                .map(|route| (route.name.clone(), route.upgrade.protocols.clone()))
        })
        .collect::<Vec<_>>();

    (listener.upgrade.protocols.clone(), route_upgrade_protocols)
}

fn build_http_cache_store(
    policy: &lb_config_model::HttpCachePolicyConfig,
) -> Result<Arc<lb_runtime::HttpCacheStore>, DynError> {
    let (max_entries, max_bytes) = match policy.storage {
        lb_config_model::HttpCacheStorageConfig::Memory { max_entries, max_bytes } => {
            (max_entries, usize::try_from(max_bytes).map_err(to_dyn_error)?)
        }
    };
    let max_object_bytes = usize::try_from(policy.max_object_bytes).map_err(to_dyn_error)?;
    lb_runtime::HttpCacheStore::new(lb_runtime::HttpCacheStoreConfig {
        max_entries,
        max_bytes,
        max_object_bytes,
    })
    .map(Arc::new)
    .map_err(to_dyn_error)
}

fn compile_http1_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
    response_cache: Option<(
        lb_config_model::HttpCachePolicyConfig,
        Arc<lb_runtime::HttpCacheStore>,
    )>,
    upgrade_telemetry: Option<&Arc<lb_runtime::RuntimeTelemetry>>,
) -> Result<lb_runtime::Http1ProxyConfig, DynError> {
    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http1_route_backends(config, listener, compiled_routes)?;
    let mirror_backend_pools = compile_mirror_backend_pools(config)?;
    let (listener_request_transform, route_request_transforms) =
        resolve_listener_request_transforms(config, listener)?;
    let (listener_response_transform, route_response_transforms) =
        resolve_listener_response_transforms(config, listener)?;
    let route_backend_policy_diagnostics =
        resolve_effective_route_backend_policy_diagnostics(config, listener)?;
    let route_destination_policies =
        compile_route_destination_policy_runtime(config, &route_backend_policy_diagnostics)?;
    let (listener_upgrade_protocols, route_upgrade_protocols) =
        resolve_listener_upgrade_policies(config, listener);
    let mut proxy = lb_runtime::Http1ProxyConfig::new(primary_upstream);
    proxy.routes = route_rules;
    proxy = proxy
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools)
        .with_mirror_backend_pools(mirror_backend_pools)
        .with_request_transforms(listener_request_transform, route_request_transforms)
        .with_response_transforms(listener_response_transform, route_response_transforms)
        .with_route_destination_policies(route_destination_policies)
        .with_route_backend_policy_diagnostics(route_backend_policy_diagnostics)
        .with_upgrade_policies(listener_upgrade_protocols, route_upgrade_protocols)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(telemetry) = upgrade_telemetry {
        proxy = proxy.with_upgrade_telemetry(listener.name.clone(), Arc::clone(telemetry));
    }
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        proxy = proxy.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        proxy = proxy.with_anonymous_source_filter(filter);
    }
    if let Some((policy, store)) = response_cache {
        proxy = proxy.with_response_cache(lb_runtime::Http1ResponseCacheConfig::new(policy, store));
    }
    Ok(proxy)
}

fn compile_http2_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<lb_runtime::Http2ProxyConfig, DynError> {
    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http2_route_backends(config, listener, compiled_routes)?;
    let mirror_backend_pools = compile_mirror_backend_pools(config)?;
    let (listener_request_transform, route_request_transforms) =
        resolve_listener_request_transforms(config, listener)?;
    let (listener_response_transform, route_response_transforms) =
        resolve_listener_response_transforms(config, listener)?;
    let route_backend_policy_diagnostics =
        resolve_effective_route_backend_policy_diagnostics(config, listener)?;
    let route_destination_policies =
        compile_route_destination_policy_runtime(config, &route_backend_policy_diagnostics)?;
    let mut proxy = lb_runtime::Http2ProxyConfig::new(primary_upstream);
    proxy.routes = route_rules;
    proxy.limits = config.defaults.http.http2_limits();
    proxy = proxy
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools)
        .with_mirror_backend_pools(mirror_backend_pools)
        .with_request_transforms(listener_request_transform, route_request_transforms)
        .with_response_transforms(listener_response_transform, route_response_transforms)
        .with_route_destination_policies(route_destination_policies)
        .with_route_backend_policy_diagnostics(route_backend_policy_diagnostics)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        proxy = proxy.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        proxy = proxy.with_anonymous_source_filter(filter);
    }
    Ok(proxy)
}

fn compile_https_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_listener: &lb_net_core::ListenerConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
    response_cache: Option<(
        lb_config_model::HttpCachePolicyConfig,
        Arc<lb_runtime::HttpCacheStore>,
    )>,
    upgrade_telemetry: Option<&Arc<lb_runtime::RuntimeTelemetry>>,
) -> Result<ManagedHttpsProxyConfig, DynError> {
    let _compiled_tls_termination =
        compiled_listener.tls_termination.as_ref().ok_or_else(|| {
            to_dyn_error(format!("listener {} is missing tls_termination", listener.name))
        })?;
    let tls_termination = listener.tls_termination.as_ref().ok_or_else(|| {
        to_dyn_error(format!("listener {} is missing tls_termination", listener.name))
    })?;

    let (route_rules, route_upstreams, route_backend_pools, primary_upstream) =
        compile_http1_route_backends(config, listener, compiled_routes)?;
    let mirror_backend_pools = compile_mirror_backend_pools(config)?;
    let (listener_request_transform, route_request_transforms) =
        resolve_listener_request_transforms(config, listener)?;
    let (listener_response_transform, route_response_transforms) =
        resolve_listener_response_transforms(config, listener)?;
    let route_backend_policy_diagnostics =
        resolve_effective_route_backend_policy_diagnostics(config, listener)?;
    let route_destination_policies =
        compile_route_destination_policy_runtime(config, &route_backend_policy_diagnostics)?;
    let (listener_upgrade_protocols, route_upgrade_protocols) =
        resolve_listener_upgrade_policies(config, listener);
    let route_upstreams_http2 = route_upstreams
        .iter()
        .map(|upstream| lb_runtime::Http2RouteUpstream {
            route_label: upstream.route_label.clone(),
            upstream: upstream.upstream.clone(),
        })
        .collect::<Vec<_>>();

    let mut http1 = lb_runtime::Http1ProxyConfig::new(primary_upstream.clone());
    http1.routes = route_rules.clone();
    http1 = http1
        .with_route_upstreams(route_upstreams)
        .with_route_backend_pools(route_backend_pools.clone())
        .with_mirror_backend_pools(mirror_backend_pools.clone())
        .with_request_transforms(
            listener_request_transform.clone(),
            route_request_transforms.clone(),
        )
        .with_response_transforms(
            listener_response_transform.clone(),
            route_response_transforms.clone(),
        )
        .with_route_destination_policies(route_destination_policies.clone())
        .with_route_backend_policy_diagnostics(route_backend_policy_diagnostics.clone())
        .with_upgrade_policies(listener_upgrade_protocols, route_upgrade_protocols)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(telemetry) = upgrade_telemetry {
        http1 = http1.with_upgrade_telemetry(listener.name.clone(), Arc::clone(telemetry));
    }
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        http1 = http1.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        http1 = http1.with_anonymous_source_filter(filter);
    }
    if let Some((policy, store)) = response_cache.clone() {
        http1 = http1.with_response_cache(lb_runtime::Http1ResponseCacheConfig::new(policy, store));
    }

    let mut http2 = lb_runtime::Http2ProxyConfig::new(primary_upstream);
    http2.routes = route_rules;
    http2.limits = config.defaults.http.http2_limits();
    http2 = http2
        .with_route_upstreams(route_upstreams_http2)
        .with_route_backend_pools(route_backend_pools)
        .with_mirror_backend_pools(mirror_backend_pools)
        .with_request_transforms(listener_request_transform, route_request_transforms)
        .with_response_transforms(listener_response_transform, route_response_transforms)
        .with_route_destination_policies(route_destination_policies)
        .with_route_backend_policy_diagnostics(route_backend_policy_diagnostics)
        .with_route_enumeration_protection(default_route_enumeration_policy())
        .rejecting_unmatched_routes();
    if let Some(policy) =
        compile_trusted_client_ip(&config.security.trusted_client_ip).map_err(to_dyn_error)?
    {
        http2 = http2.with_trusted_client_ip(policy);
    }
    if let Some(filter) = compile_anonymous_source_filter(&config.security.anonymous_source_filter)
        .map_err(to_dyn_error)?
    {
        http2 = http2.with_anonymous_source_filter(filter);
    }

    Ok(ManagedHttpsProxyConfig {
        http1,
        http2,
        tls_server_config: Arc::new(build_tls_server_config(tls_termination)?),
        tls_status: build_listener_tls_status(tls_termination)?,
    })
}

fn compile_http3_proxy_config(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<ManagedHttp3ProxyConfig, DynError> {
    let tls_termination = listener.tls_termination.as_ref().ok_or_else(|| {
        to_dyn_error(format!("listener {} is missing tls_termination", listener.name))
    })?;
    let http1 = compile_http1_proxy_config(config, listener, compiled_routes, None, None)?;
    let tls_server_config = Arc::new(build_tls_server_config(tls_termination)?);
    let quic_server_config = Arc::new(build_quic_server_config(Arc::clone(&tls_server_config))?);
    let _ = config;

    Ok(ManagedHttp3ProxyConfig {
        http1,
        quic_server_config,
    })
}

fn build_quic_server_config(
    tls_server_config: Arc<rustls::ServerConfig>,
) -> Result<quinn::ServerConfig, DynError> {
    let crypto = QuicServerConfig::try_from((*tls_server_config).clone()).map_err(to_dyn_error)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(32_u8.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
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

async fn proxy_https_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: ManagedHttpsProxyConfig,
    mut handshake_permit: Option<lb_runtime::HandshakePermit>,
) -> io::Result<u64> {
    let acceptor = TlsAcceptor::from(Arc::clone(&config.tls_server_config));
    let tls_stream =
        acceptor.accept(stream).await.map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(handshake_permit) = handshake_permit.as_mut() {
        handshake_permit.release();
    }
    let negotiated_h2 =
        tls_stream.get_ref().1.alpn_protocol().is_some_and(|protocol| protocol == b"h2");

    if negotiated_h2 {
        lb_runtime::proxy_http2_connection_with_downstream_addr(
            tls_stream,
            peer_addr,
            &config.http2,
        )
        .await
        .map(|report| report.metrics.request_count)
        .map_err(|error| io::Error::other(error.to_string()))
    } else {
        lb_runtime::proxy_http1_connection_with_downstream_addr(
            tls_stream,
            peer_addr,
            &config.http1,
        )
        .await
        .map(|report| report.metrics.request_count)
        .map_err(|error| io::Error::other(error.to_string()))
    }
}

fn compile_http1_route_backends(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<
    (
        Vec<lb_proto_http::RoutePrefixRule>,
        Vec<lb_runtime::Http1RouteUpstream>,
        Vec<(String, lb_runtime::RouteBackendPool)>,
        lb_net_core::UpstreamTarget,
    ),
    DynError,
> {
    let mut route_rules = Vec::with_capacity(listener.routes.len());
    let mut route_upstreams = Vec::new();
    let mut route_backend_pools = Vec::new();
    let mut pools_by_cluster = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();

    for route_name in &listener.routes {
        let route =
            config.routes.iter().find(|route| route.name == *route_name).ok_or_else(|| {
                format!("listener {} references unknown route {route_name}", listener.name)
            })?;
        let compiled_route = compiled_routes
            .iter()
            .find(|compiled| compiled.label == *route_name)
            .ok_or_else(|| format!("compiled route {route_name} is missing"))?;
        route_rules.push(compiled_route.clone());
        let mut route_destinations = Vec::new();
        for destination in route.normalized_destinations() {
            let cluster = config
                .upstream_clusters
                .iter()
                .find(|cluster| cluster.name == destination.upstream_cluster)
                .ok_or_else(|| {
                    format!(
                        "route {} references unknown upstream cluster {}",
                        route.name, destination.upstream_cluster
                    )
                })?;
            if cluster.endpoints.is_empty() {
                return Err(format!(
                    "upstream cluster {} must declare at least one endpoint",
                    cluster.name
                )
                .into());
            }

            route_upstreams.extend(cluster.endpoints.iter().map(|endpoint| {
                lb_runtime::Http1RouteUpstream {
                    route_label: route.name.clone(),
                    upstream: lb_net_core::UpstreamTarget::new(
                        format!("{}:{}", cluster.name, endpoint.id),
                        endpoint.address,
                    ),
                }
            }));
            let pool = match pools_by_cluster.get(&cluster.name) {
                Some(pool) => pool.clone(),
                None => {
                    let pool = compile_route_backend_pool(cluster)?;
                    pools_by_cluster.insert(cluster.name.clone(), pool.clone());
                    pool
                }
            };
            route_destinations.push(lb_runtime::WeightedRouteDestination {
                weight: destination.weight,
                pool,
            });
        }

        let route_backend_pool = if route_destinations.len() == 1 {
            route_destinations.remove(0).pool
        } else {
            lb_runtime::RouteBackendPool::from_weighted_destinations(route_destinations)
                .map_err(to_dyn_error)?
        };
        route_backend_pools.push((route.name.clone(), route_backend_pool));
    }

    let primary_upstream =
        route_upstreams.first().map(|route_upstream| route_upstream.upstream.clone()).ok_or_else(
            || format!("public listener {} must reference at least one route", listener.name),
        )?;
    Ok((route_rules, route_upstreams, route_backend_pools, primary_upstream))
}

fn compile_http2_route_backends(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
    compiled_routes: &[lb_proto_http::RoutePrefixRule],
) -> Result<
    (
        Vec<lb_proto_http::RoutePrefixRule>,
        Vec<lb_runtime::Http2RouteUpstream>,
        Vec<(String, lb_runtime::RouteBackendPool)>,
        lb_net_core::UpstreamTarget,
    ),
    DynError,
> {
    let mut route_rules = Vec::with_capacity(listener.routes.len());
    let mut route_upstreams = Vec::new();
    let mut route_backend_pools = Vec::new();
    let mut pools_by_cluster = BTreeMap::<String, lb_runtime::RouteBackendPool>::new();

    for route_name in &listener.routes {
        let route =
            config.routes.iter().find(|route| route.name == *route_name).ok_or_else(|| {
                format!("listener {} references unknown route {route_name}", listener.name)
            })?;
        let compiled_route = compiled_routes
            .iter()
            .find(|compiled| compiled.label == *route_name)
            .ok_or_else(|| format!("compiled route {route_name} is missing"))?;
        route_rules.push(compiled_route.clone());
        let mut route_destinations = Vec::new();
        for destination in route.normalized_destinations() {
            let cluster = config
                .upstream_clusters
                .iter()
                .find(|cluster| cluster.name == destination.upstream_cluster)
                .ok_or_else(|| {
                    format!(
                        "route {} references unknown upstream cluster {}",
                        route.name, destination.upstream_cluster
                    )
                })?;
            if cluster.endpoints.is_empty() {
                return Err(format!(
                    "upstream cluster {} must declare at least one endpoint",
                    cluster.name
                )
                .into());
            }

            route_upstreams.extend(cluster.endpoints.iter().map(|endpoint| {
                lb_runtime::Http2RouteUpstream {
                    route_label: route.name.clone(),
                    upstream: lb_net_core::UpstreamTarget::new(
                        format!("{}:{}", cluster.name, endpoint.id),
                        endpoint.address,
                    ),
                }
            }));
            let pool = match pools_by_cluster.get(&cluster.name) {
                Some(pool) => pool.clone(),
                None => {
                    let pool = compile_route_backend_pool(cluster)?;
                    pools_by_cluster.insert(cluster.name.clone(), pool.clone());
                    pool
                }
            };
            route_destinations.push(lb_runtime::WeightedRouteDestination {
                weight: destination.weight,
                pool,
            });
        }

        let route_backend_pool = if route_destinations.len() == 1 {
            route_destinations.remove(0).pool
        } else {
            lb_runtime::RouteBackendPool::from_weighted_destinations(route_destinations)
                .map_err(to_dyn_error)?
        };
        route_backend_pools.push((route.name.clone(), route_backend_pool));
    }

    let primary_upstream =
        route_upstreams.first().map(|route_upstream| route_upstream.upstream.clone()).ok_or_else(
            || format!("public listener {} must reference at least one route", listener.name),
        )?;
    Ok((route_rules, route_upstreams, route_backend_pools, primary_upstream))
}

fn compile_route_backend_pool(
    cluster: &lb_config_model::UpstreamClusterConfig,
) -> Result<lb_runtime::RouteBackendPool, DynError> {
    let cluster_name =
        lb_net_core::UpstreamClusterName::new(cluster.name.clone()).map_err(to_dyn_error)?;
    let endpoints = cluster
        .endpoints
        .iter()
        .map(|endpoint| {
            lb_net_core::UpstreamEndpoint::new(
                lb_net_core::UpstreamEndpointId::new(endpoint.id.clone()).map_err(to_dyn_error)?,
                endpoint.address,
                match endpoint.state {
                    lb_config_model::EndpointStateConfig::Ready => {
                        lb_net_core::EndpointState::Ready
                    }
                    lb_config_model::EndpointStateConfig::Draining => {
                        lb_net_core::EndpointState::Draining
                    }
                    lb_config_model::EndpointStateConfig::Unavailable => {
                        lb_net_core::EndpointState::Unavailable
                    }
                },
                lb_net_core::EndpointMetadata {
                    zone: endpoint.zone.clone(),
                    locality: endpoint.locality.clone(),
                    weight: endpoint.weight,
                },
            )
            .map_err(to_dyn_error)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_dyn_error)?;
    let cluster_model =
        lb_net_core::UpstreamCluster::new(cluster_name, endpoints).map_err(to_dyn_error)?;
    lb_runtime::RouteBackendPool::from_cluster(
        cluster_model,
        lb_runtime::EndpointHealthPolicy {
            warmup_duration: ROUTE_BACKEND_WARMUP_DURATION,
            ..lb_runtime::EndpointHealthPolicy::default()
        },
        lb_runtime::UpstreamSelectionPolicy {
            algorithm: match cluster.traffic_policy.algorithm {
                lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin => {
                    lb_runtime::LoadBalancingAlgorithm::RoundRobin
                }
                lb_config_model::LoadBalancingAlgorithmConfig::WeightedRoundRobin => {
                    lb_runtime::LoadBalancingAlgorithm::WeightedRoundRobin
                }
                lb_config_model::LoadBalancingAlgorithmConfig::PowerOfTwoChoices => {
                    lb_runtime::LoadBalancingAlgorithm::PowerOfTwoChoices
                }
            },
            locality: match cluster.traffic_policy.locality {
                lb_config_model::LocalityRoutingConfig::Disabled => {
                    lb_runtime::LocalityRoutingPolicy::Disabled
                }
                lb_config_model::LocalityRoutingConfig::PreferLocality => {
                    lb_runtime::LocalityRoutingPolicy::PreferLocality
                }
                lb_config_model::LocalityRoutingConfig::PreferZone => {
                    lb_runtime::LocalityRoutingPolicy::PreferZone
                }
                lb_config_model::LocalityRoutingConfig::PreferLocalityThenZone => {
                    lb_runtime::LocalityRoutingPolicy::PreferLocalityThenZone
                }
            },
            no_healthy_fallback: match cluster.traffic_policy.no_healthy_fallback {
                lb_config_model::NoHealthyFallbackConfig::Fail => {
                    lb_runtime::NoHealthyFallback::Fail
                }
                lb_config_model::NoHealthyFallbackConfig::IncludeUnhealthy => {
                    lb_runtime::NoHealthyFallback::IncludeUnhealthy
                }
            },
            affinity: cluster.traffic_policy.affinity.as_ref().map(|affinity| match affinity {
                lb_config_model::AffinityPolicyConfig::HeaderHash { header_name, fallback } => {
                    lb_runtime::AffinityPolicy::HeaderHash {
                        header_name: header_name.clone(),
                        fallback: match fallback {
                            lb_config_model::AffinityFallbackConfig::BalanceHealthy => {
                                lb_runtime::AffinityFallbackPolicy::BalanceHealthy
                            }
                        },
                    }
                }
                lb_config_model::AffinityPolicyConfig::CookieHash { cookie_name, fallback } => {
                    lb_runtime::AffinityPolicy::CookieHash {
                        cookie_name: cookie_name.clone(),
                        fallback: match fallback {
                            lb_config_model::AffinityFallbackConfig::BalanceHealthy => {
                                lb_runtime::AffinityFallbackPolicy::BalanceHealthy
                            }
                        },
                    }
                }
            }),
        },
    )
    .map_err(to_dyn_error)
}

fn compile_mirror_backend_pools(
    config: &lb_config_model::WorkspaceConfig,
) -> Result<Vec<(String, lb_runtime::RouteBackendPool)>, DynError> {
    config
        .upstream_clusters
        .iter()
        .map(|cluster| Ok((cluster.name.clone(), compile_route_backend_pool(cluster)?)))
        .collect()
}

fn default_route_enumeration_policy() -> lb_runtime::RouteEnumerationProtectionPolicy {
    lb_runtime::RouteEnumerationProtectionPolicy {
        source_aggregation: lb_runtime::SourceAggregation::ExactIp,
        evaluation_window: Duration::from_secs(30),
        max_unmatched_route_events: 3,
        max_distinct_query_signatures_per_route: 6,
        base_ban_duration: Duration::from_secs(60),
        max_ban_duration: Duration::from_secs(15 * 60),
        max_tracked_sources: 4096,
    }
}

fn listener_class_name(class: lb_config_model::ListenerClassConfig) -> &'static str {
    match class {
        lb_config_model::ListenerClassConfig::Public => "public",
        lb_config_model::ListenerClassConfig::Admin => "admin",
    }
}

fn listener_protocol_name(protocol: lb_config_model::ListenerProtocolConfig) -> &'static str {
    match protocol {
        lb_config_model::ListenerProtocolConfig::Tcp => "tcp",
        lb_config_model::ListenerProtocolConfig::Http1 => "http1",
        lb_config_model::ListenerProtocolConfig::Https => "https",
        lb_config_model::ListenerProtocolConfig::Http2 => "http2",
        lb_config_model::ListenerProtocolConfig::Http3 => "http3",
        lb_config_model::ListenerProtocolConfig::Auto => "auto",
    }
}

fn listener_bind_mode_name(bind_mode: lb_net_core::ListenerBindMode) -> &'static str {
    match bind_mode {
        lb_net_core::ListenerBindMode::SingleStack => "single_stack",
        lb_net_core::ListenerBindMode::DualStack => "dual_stack",
        lb_net_core::ListenerBindMode::Ipv6Only => "ipv6_only",
    }
}

fn source_aggregation_name(aggregation: lb_runtime::SourceAggregation) -> &'static str {
    match aggregation {
        lb_runtime::SourceAggregation::ExactIp => "exact_ip",
        lb_runtime::SourceAggregation::Ipv4Subnet24 => "ipv4_subnet_24",
        lb_runtime::SourceAggregation::Ipv6Subnet64 => "ipv6_subnet_64",
    }
}

fn overload_state_name(state: lb_runtime::OverloadState) -> &'static str {
    match state {
        lb_runtime::OverloadState::Normal => "normal",
        lb_runtime::OverloadState::Constrained => "constrained",
        lb_runtime::OverloadState::Shedding => "shedding",
        lb_runtime::OverloadState::Brownout => "brownout",
    }
}

fn overload_scope(listener_name: &str) -> String {
    format!("workspace_listener_{}", listener_name)
}

fn http3_scope(listener_name: &str) -> String {
    format!("workspace_http3_{}", listener_name)
}

const fn overload_state_index(state: lb_runtime::OverloadState) -> usize {
    match state {
        lb_runtime::OverloadState::Normal => 0,
        lb_runtime::OverloadState::Constrained => 1,
        lb_runtime::OverloadState::Shedding => 2,
        lb_runtime::OverloadState::Brownout => 3,
    }
}

fn compile_listener_overload_policy(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<Option<CompiledListenerOverloadPolicy>, DynError> {
    let Some(policy_name) = listener.policies.overload_response.as_deref() else {
        return Ok(None);
    };

    let policy = config
        .policies
        .overload_responses
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!(
                "listener {} references unknown overload response policy {policy_name}",
                listener.name,
            ))
        })?;

    Ok(Some(CompiledListenerOverloadPolicy {
        signal_window: Duration::from_millis(policy.spec.signal_window_ms),
        constrained_signal_threshold: policy.spec.constrained_signal_threshold,
        shedding_signal_threshold: policy.spec.shedding_signal_threshold,
        brownout_signal_threshold: policy.spec.brownout_signal_threshold,
        brownout_features: policy
            .spec
            .brownout_features
            .iter()
            .map(|feature| CompiledBrownoutFeature {
                name: feature.name.clone(),
                priority: match feature.priority {
                    lb_config_model::TrafficClassConfig::Critical => {
                        lb_runtime::TrafficClass::Critical
                    }
                    lb_config_model::TrafficClassConfig::Default => {
                        lb_runtime::TrafficClass::Default
                    }
                    lb_config_model::TrafficClassConfig::BestEffort => {
                        lb_runtime::TrafficClass::BestEffort
                    }
                },
            })
            .collect(),
    }))
}

fn compile_listener_abuse_protection_policy(
    config: &lb_config_model::WorkspaceConfig,
    listener: &lb_config_model::ListenerResourceConfig,
) -> Result<Option<CompiledListenerAbuseProtectionPolicy>, DynError> {
    let Some(policy_name) = listener.policies.hostile_edge_protection.as_deref() else {
        return Ok(None);
    };

    let policy = config
        .policies
        .hostile_edge_protections
        .iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| {
            to_dyn_error(format!(
                "listener {} references unknown hostile-edge protection policy {policy_name}",
                listener.name,
            ))
        })?;

    Ok(Some(CompiledListenerAbuseProtectionPolicy {
        source_quota: policy.spec.source_quota.as_ref().map(|source_quota| {
            CompiledSourceQuotaPolicy {
                aggregation: match source_quota.aggregation {
                    lb_config_model::HostileEdgeSourceAggregationConfig::ExactIp => {
                        lb_runtime::SourceAggregation::ExactIp
                    }
                    lb_config_model::HostileEdgeSourceAggregationConfig::Ipv4Subnet24 => {
                        lb_runtime::SourceAggregation::Ipv4Subnet24
                    }
                    lb_config_model::HostileEdgeSourceAggregationConfig::Ipv6Subnet64 => {
                        lb_runtime::SourceAggregation::Ipv6Subnet64
                    }
                },
                max_active_per_source: source_quota.max_active_per_source,
                max_tracked_sources: source_quota.max_tracked_sources,
            }
        }),
        handshake_guard: policy.spec.handshake_guard.as_ref().map(|handshake_guard| {
            CompiledHandshakeGuardPolicy {
                max_inflight: handshake_guard.max_inflight,
                timeout: Duration::from_millis(handshake_guard.timeout_ms),
            }
        }),
    }))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use bytes::{Buf, Bytes};
    use h3::client as h3_client;
    use h2::{client as h2_client, server};
    use http::{Request, Response, StatusCode};
    use quinn::crypto::rustls::QuicClientConfig;
    use rcgen::generate_simple_self_signed;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    use super::{
        build_tls_server_config, collect_blocked_listener_replacements,
        collect_supported_listener_replacements, compile_route_backend_pool,
        compile_workspace_runtime, control_plane_journal_path, evaluate_workspace_readiness,
        ensure_rustls_crypto_provider, reload_health_name, sign_admin_request, to_dyn_error,
        unix_time_ms,
        write_control_plane_journal_atomic, AdminAuditEvent, CompiledServeListener,
        ControlPlaneJournalEnvelope, ControlPlaneJournalPayload, ControlPlaneRecoveryInfo,
        CurrentListenerIdentity, DurableSnapshotIdentity, DynError, JournalInFlightOperation,
        ListenerAbuseProtectionStatus, ListenerDrainOutcome, ListenerIdentity,
        ListenerIdentityStatus, ListenerLifecycleEntry, ListenerLifecycleModel,
        ListenerLifecycleState, ListenerReplacementStatus, ListenerStatus, ManagedProxyConfig,
        RecoveredListenerStatus, RecoveryReconciliationSummary, ReloadHealthState,
        ServeSupervisor, ACTIVE_HEALTH_PROBE_INTERVAL, CONTROL_PLANE_JOURNAL_VERSION,
        RECOVERY_UNFINISHED_RELOAD_CODE, ROUTE_BACKEND_WARMUP_DURATION,
    };

    static NEXT_TEST_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn unique_test_file_suffix() -> Result<String, DynError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sequence = NEXT_TEST_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(format!("{}-{now}-{sequence}", std::process::id()))
    }

    #[test]
    fn listener_lifecycle_model_transitions_are_deterministic() -> Result<(), DynError> {
        let active = ListenerIdentity {
            class: lb_config_model::ListenerClassConfig::Public,
            protocol: lb_config_model::ListenerProtocolConfig::Http1,
            proxy_protocol: lb_config_model::ProxyProtocolModeConfig::Disabled,
            configured_bind: "127.0.0.1:8080".parse()?,
            bind_mode: lb_net_core::ListenerBindMode::SingleStack,
        };
        let replacement = ListenerIdentity {
            class: lb_config_model::ListenerClassConfig::Public,
            protocol: lb_config_model::ListenerProtocolConfig::Http2,
            proxy_protocol: lb_config_model::ProxyProtocolModeConfig::V1,
            configured_bind: "127.0.0.1:8080".parse()?,
            bind_mode: lb_net_core::ListenerBindMode::SingleStack,
        };
        let mut lifecycle = ListenerLifecycleModel::new_active(active);

        assert_eq!(
            lifecycle.entries(),
            vec![ListenerLifecycleEntry {
                identity: active,
                state: ListenerLifecycleState::Active,
            }]
        );

        let drained = lifecycle.activate_replacement(replacement);
        assert_eq!(drained, Some(active));
        assert_eq!(
            lifecycle.entries(),
            vec![
                ListenerLifecycleEntry {
                    identity: replacement,
                    state: ListenerLifecycleState::Active,
                },
                ListenerLifecycleEntry {
                    identity: active,
                    state: ListenerLifecycleState::Draining,
                },
            ]
        );

        lifecycle.finish_draining(active, ListenerDrainOutcome::Completed);
        assert_eq!(
            lifecycle.entries(),
            vec![
                ListenerLifecycleEntry {
                    identity: replacement,
                    state: ListenerLifecycleState::Active,
                },
                ListenerLifecycleEntry { identity: active, state: ListenerLifecycleState::Retired },
            ]
        );
        Ok(())
    }

    #[test]
    fn proxy_protocol_v1_parser_extracts_source_address() -> Result<(), DynError> {
        let parsed = super::parse_proxy_protocol_v1_line(
            b"PROXY TCP4 198.51.100.7 203.0.113.10 45678 8080\r\n",
        )?;

        assert_eq!(parsed, Some("198.51.100.7:45678".parse()?));
        Ok(())
    }

    #[test]
    fn proxy_protocol_v2_parser_extracts_source_address() -> Result<(), DynError> {
        let mut header = [0_u8; 16];
        header[..12].copy_from_slice(&super::PROXY_PROTOCOL_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x11;
        header[14..16].copy_from_slice(&(12_u16).to_be_bytes());
        let payload = [198, 51, 100, 7, 203, 0, 113, 10, 31, 144, 35, 130];

        let parsed = super::parse_proxy_protocol_v2_payload(&header, &payload)?;

        assert_eq!(parsed, Some("198.51.100.7:8080".parse()?));
        Ok(())
    }

    #[test]
    fn proxy_protocol_v2_parser_rejects_bad_signature() {
        let header = [0_u8; 16];

        let error =
            super::parse_proxy_protocol_v2_header(&header).expect_err("bad signature must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn recovered_listener_status_assigns_machine_readable_verdicts() {
        let cases = [
            ("running", "stable", "settled"),
            ("running", "replacement_draining", "replacement_still_draining"),
            ("running", "failed_start_preserved", "replacement_failed_preserved"),
            ("running", "drain_timeout_expired", "replacement_drain_timeout"),
            ("missing", "missing", "missing"),
            ("draining", "stable", "needs_review"),
        ];

        for (listener_state, replacement_state, expected_verdict) in cases {
            let recovered = RecoveredListenerStatus::new(
                String::from("public"),
                String::from(listener_state),
                String::from(replacement_state),
            );
            assert_eq!(recovered.reconciliation_verdict, expected_verdict);
        }
    }

    #[test]
    fn recovery_reconciliation_summary_aggregates_verdicts() {
        let listeners = vec![
            RecoveredListenerStatus::new(
                String::from("a"),
                String::from("running"),
                String::from("stable"),
            ),
            RecoveredListenerStatus::new(
                String::from("b"),
                String::from("running"),
                String::from("replacement_draining"),
            ),
            RecoveredListenerStatus::new(
                String::from("c"),
                String::from("missing"),
                String::from("missing"),
            ),
        ];

        let summary = RecoveryReconciliationSummary::from_reconciled_listeners(&listeners);
        assert_eq!(summary.overall_verdict, "needs_review");
        assert_eq!(summary.recommended_action, "investigate_and_validate_reload");
        assert_eq!(summary.settled_count, 1);
        assert_eq!(summary.draining_count, 1);
        assert_eq!(summary.missing_count, 1);
        assert_eq!(summary.failed_preserved_count, 0);
        assert_eq!(summary.drain_timeout_count, 0);
        assert_eq!(summary.needs_review_count, 0);
    }

    #[test]
    fn recovery_reconciliation_summary_recommends_next_action() {
        let cases = [
            (
                vec![RecoveredListenerStatus::new(
                    String::from("a"),
                    String::from("running"),
                    String::from("stable"),
                )],
                "settled",
                "observe_only",
            ),
            (
                vec![RecoveredListenerStatus::new(
                    String::from("a"),
                    String::from("running"),
                    String::from("replacement_draining"),
                )],
                "replacement_still_draining",
                "wait_for_drain_completion",
            ),
            (
                vec![RecoveredListenerStatus::new(
                    String::from("a"),
                    String::from("running"),
                    String::from("failed_start_preserved"),
                )],
                "replacement_failed_preserved",
                "validate_and_retry_reload",
            ),
            (
                vec![RecoveredListenerStatus::new(
                    String::from("a"),
                    String::from("running"),
                    String::from("drain_timeout_expired"),
                )],
                "replacement_drain_timeout",
                "investigate_drain_timeout",
            ),
        ];

        for (listeners, expected_verdict, expected_action) in cases {
            let summary = RecoveryReconciliationSummary::from_reconciled_listeners(&listeners);
            assert_eq!(summary.overall_verdict, expected_verdict);
            assert_eq!(summary.recommended_action, expected_action);
        }
    }

    #[test]
    fn recovery_operator_guidance_defaults_plain_unfinished_reload_to_retry() {
        let recovery = ControlPlaneRecoveryInfo {
            state: String::from("needs_operator_action"),
            detail: String::from("recovered unfinished reload"),
            last_persisted_at_unix_ms: None,
            restored_reload_health: Some(String::from("healthy")),
            restored_last_reload_outcome_code: Some(String::from("reload_started_in_place")),
            in_flight_operation: Some(JournalInFlightOperation {
                kind: String::from("reload"),
                started_at_unix_ms: 1,
                desired_snapshot: DurableSnapshotIdentity {
                    source_label: String::from("test"),
                    digest_sha256: String::from("abc123"),
                    api_version: String::from("v1alpha1"),
                    snapshot_format_version: String::from("1"),
                },
                lifecycle_code: String::from("reload_started_in_place"),
                detail: String::from("reload started"),
                expected_completion_within_ms: None,
                affected_listeners: Vec::new(),
            }),
            reconciled_listeners: Vec::new(),
        };

        let guidance = recovery.operator_guidance_at(101);
        assert_eq!(guidance.recommended_action, "validate_and_retry_reload");
        assert_eq!(guidance.urgency, "action_required");
        assert_eq!(guidance.operation_age_ms, Some(100));
        assert_eq!(guidance.expected_completion_within_ms, None);
        assert!(!guidance.exceeded_expected_completion);
    }

    #[test]
    fn recovery_operator_guidance_escalates_stale_replacement_drain() {
        let recovery = ControlPlaneRecoveryInfo {
            state: String::from("needs_operator_action"),
            detail: String::from("recovered unfinished overlap drain"),
            last_persisted_at_unix_ms: None,
            restored_reload_health: Some(String::from("healthy")),
            restored_last_reload_outcome_code: Some(String::from("reload_started_overlap_drain")),
            in_flight_operation: Some(JournalInFlightOperation {
                kind: String::from("reload_overlap_drain"),
                started_at_unix_ms: 1,
                desired_snapshot: DurableSnapshotIdentity {
                    source_label: String::from("test"),
                    digest_sha256: String::from("abc123"),
                    api_version: String::from("v1alpha1"),
                    snapshot_format_version: String::from("1"),
                },
                lifecycle_code: String::from("reload_started_overlap_drain"),
                detail: String::from("reload started"),
                expected_completion_within_ms: Some(50),
                affected_listeners: vec![String::from("public")],
            }),
            reconciled_listeners: vec![RecoveredListenerStatus::new(
                String::from("public"),
                String::from("running"),
                String::from("replacement_draining"),
            )],
        };

        let guidance = recovery.operator_guidance_at(101);
        assert_eq!(guidance.recommended_action, "investigate_stalled_drain");
        assert_eq!(guidance.urgency, "action_required");
        assert_eq!(guidance.operation_age_ms, Some(100));
        assert_eq!(guidance.expected_completion_within_ms, Some(50));
        assert!(guidance.exceeded_expected_completion);
    }

    #[test]
    fn recovery_operator_guidance_allows_fresh_replacement_drain_to_continue() {
        let recovery = ControlPlaneRecoveryInfo {
            state: String::from("needs_operator_action"),
            detail: String::from("recovered unfinished overlap drain"),
            last_persisted_at_unix_ms: None,
            restored_reload_health: Some(String::from("healthy")),
            restored_last_reload_outcome_code: Some(String::from("reload_started_overlap_drain")),
            in_flight_operation: Some(JournalInFlightOperation {
                kind: String::from("reload_overlap_drain"),
                started_at_unix_ms: 75,
                desired_snapshot: DurableSnapshotIdentity {
                    source_label: String::from("test"),
                    digest_sha256: String::from("abc123"),
                    api_version: String::from("v1alpha1"),
                    snapshot_format_version: String::from("1"),
                },
                lifecycle_code: String::from("reload_started_overlap_drain"),
                detail: String::from("reload started"),
                expected_completion_within_ms: Some(50),
                affected_listeners: vec![String::from("public")],
            }),
            reconciled_listeners: vec![RecoveredListenerStatus::new(
                String::from("public"),
                String::from("running"),
                String::from("replacement_draining"),
            )],
        };

        let guidance = recovery.operator_guidance_at(101);
        assert_eq!(guidance.recommended_action, "wait_for_drain_completion");
        assert_eq!(guidance.urgency, "watch");
        assert_eq!(guidance.operation_age_ms, Some(26));
        assert_eq!(guidance.expected_completion_within_ms, Some(50));
        assert!(!guidance.exceeded_expected_completion);
    }

    #[test]
    fn listener_lifecycle_failed_start_keeps_active_identity() -> Result<(), DynError> {
        let active = ListenerIdentity {
            class: lb_config_model::ListenerClassConfig::Public,
            protocol: lb_config_model::ListenerProtocolConfig::Http1,
            proxy_protocol: lb_config_model::ProxyProtocolModeConfig::Disabled,
            configured_bind: "127.0.0.1:8080".parse()?,
            bind_mode: lb_net_core::ListenerBindMode::SingleStack,
        };
        let attempted = ListenerIdentity {
            class: lb_config_model::ListenerClassConfig::Public,
            protocol: lb_config_model::ListenerProtocolConfig::Https,
            proxy_protocol: lb_config_model::ProxyProtocolModeConfig::V1,
            configured_bind: "127.0.0.1:8443".parse()?,
            bind_mode: lb_net_core::ListenerBindMode::SingleStack,
        };
        let mut lifecycle = ListenerLifecycleModel::new_active(active);

        lifecycle.record_failed_start(attempted, String::from("bind failed"));

        assert_eq!(lifecycle.active_identity(), Some(active));
        assert_eq!(
            lifecycle.entries(),
            vec![
                ListenerLifecycleEntry { identity: active, state: ListenerLifecycleState::Active },
                ListenerLifecycleEntry {
                    identity: attempted,
                    state: ListenerLifecycleState::FailedStart,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_accepts_http2_public_listener() -> Result<(), DynError> {
        let path = write_temp_config(
            "http2-runtime",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http2", "127.0.0.1:19080"),
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;

        assert_eq!(compiled.listeners.len(), 2);
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_accepts_http3_public_listener(
    ) -> Result<(), DynError> {
        let (cert_path, key_path, _cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "http3-runtime",
            &workspace_config_json_with_http3_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "127.0.0.1:19080",
                &cert_path,
                &key_path,
            ),
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;

        assert_eq!(compiled.listeners.len(), 2);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_serves_http3_public_listener() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("upstream-a").await?;
        let (cert_path, key_path, cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "http3-supervisor",
            &workspace_config_json_with_http3_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &cert_path,
                &key_path,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let (status, body) = send_http3_request(public_addr, &cert_der, "localhost", "/").await?;
        assert_eq!(status, 200);
    assert!(body.contains("upstream-a"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[test]
    fn bind_mode_change_on_same_listener_bind_requires_rebind() -> Result<(), DynError> {
        let path = write_temp_config(
            "bind-mode-rebind-required",
            &workspace_config_json_with_bind_mode(
                "[::]:8080",
                "127.0.0.1:0",
                "http1",
                "127.0.0.1:19080",
                "dual_stack",
                true,
            ),
        )?;
        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;

        let current_identities = std::iter::once((
            String::from("public"),
            CurrentListenerIdentity {
                class: lb_config_model::ListenerClassConfig::Public,
                protocol: lb_config_model::ListenerProtocolConfig::Http1,
                proxy_protocol: lb_config_model::ProxyProtocolModeConfig::Disabled,
                configured_bind: "[::]:8080".parse()?,
                bind_mode: lb_net_core::ListenerBindMode::SingleStack,
                local_addr: "[::]:8080".parse()?,
            },
        ))
        .collect::<std::collections::BTreeMap<_, _>>();

        let supported =
            collect_supported_listener_replacements(&current_identities, &compiled.listeners);
        let blocked =
            collect_blocked_listener_replacements(&current_identities, &compiled.listeners);

        assert!(supported.is_empty());
        assert_eq!(blocked, vec![String::from("public")]);
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_respects_weighted_round_robin_policy() -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![
                lb_config_model::UpstreamEndpointConfig {
                    id: String::from("a"),
                    address: "127.0.0.1:18081".parse()?,
                    state: lb_config_model::EndpointStateConfig::Ready,
                    zone: None,
                    locality: None,
                    weight: 3,
                },
                lb_config_model::UpstreamEndpointConfig {
                    id: String::from("b"),
                    address: "127.0.0.1:18082".parse()?,
                    state: lb_config_model::EndpointStateConfig::Ready,
                    zone: None,
                    locality: None,
                    weight: 1,
                },
            ],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::WeightedRoundRobin,
                locality: lb_config_model::LocalityRoutingConfig::Disabled,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
                affinity: None,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;
        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);

        let selected = (0..8)
            .map(|request_hash| pool.select_upstream(request_hash).map(|upstream| upstream.name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_dyn_error)?;

        assert_eq!(
            selected,
            vec![
                String::from("frontend:a"),
                String::from("frontend:a"),
                String::from("frontend:b"),
                String::from("frontend:a"),
                String::from("frontend:a"),
                String::from("frontend:a"),
                String::from("frontend:b"),
                String::from("frontend:a"),
            ]
        );
        Ok(())
    }

    fn test_listener_status(
        class: lb_config_model::ListenerClassConfig,
        state: &str,
        overload_state: &str,
    ) -> Result<ListenerStatus, DynError> {
        let configured_bind: SocketAddr = "127.0.0.1:8080".parse()?;
        Ok(ListenerStatus {
            name: String::from("listener-under-test"),
            class,
            protocol: lb_config_model::ListenerProtocolConfig::Http1,
            configured_bind,
            local_addr: configured_bind,
            state: String::from(state),
            overload_state: String::from(overload_state),
            accepted_connections: 0,
            active_connections: 0,
            completed_connections: 0,
            shed_connections: 0,
            abuse_protection: ListenerAbuseProtectionStatus {
                state: String::from("disabled"),
                source_quota: None,
                handshake_guard: None,
                source_quota_rejections: 0,
                tracked_source_limit_rejections: 0,
                handshake_guard_rejections: 0,
                tracked_sources: 0,
                active_handshakes: 0,
                reason_codes: Vec::new(),
            },
            brownout_features: Vec::new(),
            recent_overload_events: Vec::new(),
            replacement: ListenerReplacementStatus {
                state: String::from("stable"),
                desired: ListenerIdentityStatus {
                    class,
                    protocol: lb_config_model::ListenerProtocolConfig::Http1,
                    configured_bind,
                    bind_mode: lb_net_core::ListenerBindMode::SingleStack,
                },
                draining: Vec::new(),
                retired_recent: Vec::new(),
                drain_timeout_recent: Vec::new(),
                failed_start: None,
            },
            tls: None,
        })
    }

    #[test]
    fn workspace_readiness_is_ready_for_running_public_listener() -> Result<(), DynError> {
        let readiness = evaluate_workspace_readiness(
            &[test_listener_status(
                lb_config_model::ListenerClassConfig::Public,
                "running",
                "normal",
            )?],
            ReloadHealthState::Healthy,
        );

        assert!(readiness.ready);
        assert_eq!(readiness.status, "ready");
        assert_eq!(readiness.reload_status, reload_health_name(ReloadHealthState::Healthy));
        assert!(readiness.reason_codes.is_empty());
        Ok(())
    }

    #[test]
    fn workspace_readiness_is_not_ready_for_draining_public_listener() -> Result<(), DynError> {
        let readiness = evaluate_workspace_readiness(
            &[test_listener_status(
                lb_config_model::ListenerClassConfig::Public,
                "draining",
                "normal",
            )?],
            ReloadHealthState::Healthy,
        );

        assert!(!readiness.ready);
        assert_eq!(readiness.reason_codes, vec![String::from("listener_draining")]);
        Ok(())
    }

    #[test]
    fn workspace_readiness_is_not_ready_for_failed_reload_and_shedding_listener(
    ) -> Result<(), DynError> {
        let readiness = evaluate_workspace_readiness(
            &[test_listener_status(
                lb_config_model::ListenerClassConfig::Public,
                "running",
                "shedding",
            )?],
            ReloadHealthState::Failed,
        );

        assert!(!readiness.ready);
        assert_eq!(
            readiness.reason_codes,
            vec![String::from("reload_failed"), String::from("listener_overload_shedding"),]
        );
        Ok(())
    }

    #[test]
    fn workspace_readiness_evaluates_public_listeners_only_when_present() -> Result<(), DynError> {
        let readiness = evaluate_workspace_readiness(
            &[
                test_listener_status(
                    lb_config_model::ListenerClassConfig::Public,
                    "running",
                    "normal",
                )?,
                test_listener_status(
                    lb_config_model::ListenerClassConfig::Admin,
                    "draining",
                    "normal",
                )?,
            ],
            ReloadHealthState::Healthy,
        );

        assert!(readiness.ready);
        assert_eq!(readiness.evaluated_listener_scope, "public");
        assert_eq!(readiness.listeners.len(), 1);
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_supports_locality_preferences() -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![
                lb_config_model::UpstreamEndpointConfig {
                    id: String::from("west"),
                    address: "127.0.0.1:18081".parse()?,
                    state: lb_config_model::EndpointStateConfig::Ready,
                    zone: Some(String::from("zone-west")),
                    locality: Some(String::from("edge-west")),
                    weight: 1,
                },
                lb_config_model::UpstreamEndpointConfig {
                    id: String::from("east"),
                    address: "127.0.0.1:18082".parse()?,
                    state: lb_config_model::EndpointStateConfig::Ready,
                    zone: Some(String::from("zone-east")),
                    locality: Some(String::from("edge-east")),
                    weight: 1,
                },
            ],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin,
                locality: lb_config_model::LocalityRoutingConfig::PreferLocalityThenZone,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
                affinity: None,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;
        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);

        let locality_selected = pool
            .select_upstream_with_context(&lb_runtime::SelectionContext {
                preferred_locality: Some(String::from("edge-west")),
                preferred_zone: Some(String::from("zone-east")),
                affinity_key: None,
                request_hash: 7,
            })
            .map_err(to_dyn_error)?;
        assert_eq!(locality_selected.name, "frontend:west");

        let zone_selected = pool
            .select_upstream_with_context(&lb_runtime::SelectionContext {
                preferred_locality: Some(String::from("missing-locality")),
                preferred_zone: Some(String::from("zone-east")),
                affinity_key: None,
                request_hash: 11,
            })
            .map_err(to_dyn_error)?;
        assert_eq!(zone_selected.name, "frontend:east");
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_keeps_power_of_two_choices_deterministic() -> Result<(), DynError>
    {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "a",
                    "127.0.0.1:18081".parse()?,
                ),
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "b",
                    "127.0.0.1:18082".parse()?,
                ),
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "c",
                    "127.0.0.1:18083".parse()?,
                ),
            ],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::PowerOfTwoChoices,
                locality: lb_config_model::LocalityRoutingConfig::Disabled,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
                affinity: None,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;
        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);

        let first = pool.select_upstream(0xfeed_beef).map_err(to_dyn_error)?;
        let second = pool.select_upstream(0xfeed_beef).map_err(to_dyn_error)?;
        let third = pool.select_upstream(0xfeed_beef).map_err(to_dyn_error)?;

        assert_eq!(first.name, second.name);
        assert_eq!(second.name, third.name);
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_applies_passive_failure_and_recovery_feedback(
    ) -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "a",
                    "127.0.0.1:18081".parse()?,
                ),
                lb_config_model::UpstreamEndpointConfig::foundation(
                    "b",
                    "127.0.0.1:18082".parse()?,
                ),
            ],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin,
                locality: lb_config_model::LocalityRoutingConfig::Disabled,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
                affinity: None,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;
        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);

        let first = pool.select_backend(1).map_err(to_dyn_error)?;
        assert_eq!(first.upstream().name, "frontend:a");

        first.note_passive_failure().map_err(to_dyn_error)?;
        first.note_passive_failure().map_err(to_dyn_error)?;

        let excluded = (0..3)
            .map(|request_hash| {
                pool.select_backend(request_hash).map(|backend| backend.upstream().name.clone())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_dyn_error)?;
        assert!(excluded.iter().all(|name| name == "frontend:b"));

        first.note_passive_success().map_err(to_dyn_error)?;
        first.note_passive_success().map_err(to_dyn_error)?;

        let recovered = (0..4)
            .map(|request_hash| {
                pool.select_backend(request_hash).map(|backend| backend.upstream().name.clone())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_dyn_error)?;
        assert!(recovered.iter().any(|name| name == "frontend:a"));
        Ok(())
    }

    #[test]
    fn compile_route_backend_pool_applies_active_recovery_and_warmup_progression(
    ) -> Result<(), DynError> {
        let pool = compile_route_backend_pool(&lb_config_model::UpstreamClusterConfig {
            name: String::from("frontend"),
            endpoints: vec![lb_config_model::UpstreamEndpointConfig {
                id: String::from("a"),
                address: "127.0.0.1:18081".parse()?,
                state: lb_config_model::EndpointStateConfig::Ready,
                zone: None,
                locality: None,
                weight: 10,
            }],
            traffic_policy: lb_config_model::UpstreamTrafficPolicyConfig {
                algorithm: lb_config_model::LoadBalancingAlgorithmConfig::RoundRobin,
                locality: lb_config_model::LocalityRoutingConfig::Disabled,
                no_healthy_fallback: lb_config_model::NoHealthyFallbackConfig::Fail,
                affinity: None,
            },
            policies: lb_config_model::PolicyBindingConfig::default(),
        })?;

        let initial = pool.active_probe_targets().map_err(to_dyn_error)?;
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].health.status, lb_runtime::EndpointHealthStatus::Warming);
        assert_eq!(initial[0].health.effective_weight, 1);

        pool.advance_time(Duration::from_millis(500));
        let midpoint = pool.active_probe_targets().map_err(to_dyn_error)?;
        assert_eq!(midpoint[0].health.status, lb_runtime::EndpointHealthStatus::Warming);
        assert!((1..10).contains(&midpoint[0].health.effective_weight));

        pool.advance_time(Duration::from_millis(500));
        let endpoint_id = pool.active_probe_targets().map_err(to_dyn_error)?[0].endpoint_id.clone();
        assert_eq!(
            pool.active_probe_targets().map_err(to_dyn_error)?[0].health.status,
            lb_runtime::EndpointHealthStatus::Healthy
        );

        assert_eq!(
            pool.note_active_failure(&endpoint_id).map_err(to_dyn_error)?.status,
            lb_runtime::EndpointHealthStatus::Degraded
        );
        assert_eq!(
            pool.note_active_failure(&endpoint_id).map_err(to_dyn_error)?.status,
            lb_runtime::EndpointHealthStatus::Unhealthy
        );
        assert_eq!(
            pool.note_active_success(&endpoint_id).map_err(to_dyn_error)?.status,
            lb_runtime::EndpointHealthStatus::Unhealthy
        );
        let recovering = pool.note_active_success(&endpoint_id).map_err(to_dyn_error)?;
        assert_eq!(recovering.status, lb_runtime::EndpointHealthStatus::Warming);
        assert!((1..10).contains(&recovering.effective_weight));

        pool.advance_time(ROUTE_BACKEND_WARMUP_DURATION);
        let healed = pool.active_probe_targets().map_err(to_dyn_error)?;
        assert_eq!(healed[0].health.status, lb_runtime::EndpointHealthStatus::Healthy);
        assert_eq!(healed[0].health.effective_weight, 10);
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_shares_cluster_health_across_routes() -> Result<(), DynError> {
        let path = write_temp_config(
            "shared-cluster-health",
            &format!(
                r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "127.0.0.1:0",
            "protocol": "http1",
            "routes": ["web-a", "web-b"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "127.0.0.1:0",
            "protocol": "http1"
        }}
    ],
    "routes": [
        {{
            "name": "web-a",
            "match": {{ "type": "path_prefix", "prefix": "/a" }},
            "upstream_cluster": "frontend"
        }},
        {{
            "name": "web-b",
            "match": {{ "type": "path_prefix", "prefix": "/b" }},
            "upstream_cluster": "frontend"
        }}
    ],
    "upstream_clusters": [
        {{
            "name": "frontend",
            "endpoints": [
                {{
                    "id": "a",
                    "address": "127.0.0.1:18081",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }},
                {{
                    "id": "b",
                    "address": "127.0.0.1:18082",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
            ),
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let CompiledServeListener::Public { proxy: ManagedProxyConfig::Http1(config), .. } =
            compiled.listeners.get("public").ok_or("missing public listener")?
        else {
            return Err("expected public HTTP/1 listener".into());
        };

        let first_pool = config
            .route_backend_pools
            .get("web-a")
            .ok_or("missing first route backend pool")?
            .clone();
        let second_pool = config
            .route_backend_pools
            .get("web-b")
            .ok_or("missing second route backend pool")?
            .clone();

        let selected = first_pool.select_backend(0).map_err(to_dyn_error)?;
        assert_eq!(selected.upstream().name, "frontend:a");
        selected.note_passive_failure().map_err(to_dyn_error)?;
        selected.note_passive_failure().map_err(to_dyn_error)?;

        let routed = (0_u64..4)
            .map(|request_hash| {
                second_pool
                    .select_backend(request_hash)
                    .map(|backend| backend.upstream().name.clone())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_dyn_error)?;
        assert!(routed.iter().all(|name| name == "frontend:b"));
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_attaches_request_transforms_to_http1_public_proxy(
    ) -> Result<(), DynError> {
        let path = write_temp_config(
            "workspace-request-transforms-http1.json",
            r#"{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {
            "name": "public",
            "class": "public",
            "bind_address": "127.0.0.1:28080",
            "protocol": "http1",
            "routes": ["web"],
            "policies": { "transform_policy": "listener-transform" }
        },
        {
            "name": "admin",
            "class": "admin",
            "bind_address": "127.0.0.1:29900",
            "protocol": "http1"
        }
    ],
    "routes": [
        {
            "name": "web",
            "match": { "type": "path_prefix", "prefix": "/edge" },
            "upstream_cluster": "frontend",
            "policies": { "transform_policy": "route-transform" }
        }
    ],
    "upstream_clusters": [
        {
            "name": "frontend",
            "endpoints": [
                {
                    "id": "frontend-a",
                    "address": "127.0.0.1:18081",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }
            ]
        }
    ],
    "policies": {
        "transforms": [
            {
                "name": "listener-transform",
                "spec": {
                    "request": {
                        "header_mutations": [{ "type": "set", "name": "x-listener", "value": "edge" }]
                    },
                    "response": {}
                }
            },
            {
                "name": "route-transform",
                "spec": {
                    "request": {
                        "path_rewrite": {
                            "type": "replace_prefix",
                            "match_prefix": "/edge",
                            "replacement": "/v1"
                        },
                        "host_rewrite": "backend.internal"
                    },
                    "response": {}
                }
            }
        ]
    }
}"#,
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let CompiledServeListener::Public { proxy: ManagedProxyConfig::Http1(config), .. } =
            compiled.listeners.get("public").ok_or("missing public listener")?
        else {
            return Err("expected public HTTP/1 listener".into());
        };

        assert_eq!(
            config
                .listener_request_transform
                .as_ref()
                .map(|transform| transform.header_mutations.len()),
            Some(1)
        );
        assert_eq!(
            config
                .route_request_transforms
                .get("web")
                .and_then(|transform| transform.host_rewrite.as_deref()),
            Some("backend.internal")
        );
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_attaches_request_transforms_to_http2_public_proxy(
    ) -> Result<(), DynError> {
        let path = write_temp_config(
            "workspace-request-transforms-http2.json",
            r#"{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {
            "name": "public",
            "class": "public",
            "bind_address": "127.0.0.1:28081",
            "protocol": "http2",
            "routes": ["web"],
            "policies": { "transform_policy": "listener-transform" }
        },
        {
            "name": "admin",
            "class": "admin",
            "bind_address": "127.0.0.1:29901",
            "protocol": "http1"
        }
    ],
    "routes": [
        {
            "name": "web",
            "match": { "type": "path_prefix", "prefix": "/edge" },
            "upstream_cluster": "frontend",
            "policies": { "transform_policy": "route-transform" }
        }
    ],
    "upstream_clusters": [
        {
            "name": "frontend",
            "endpoints": [
                {
                    "id": "frontend-a",
                    "address": "127.0.0.1:18082",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }
            ]
        }
    ],
    "policies": {
        "transforms": [
            {
                "name": "listener-transform",
                "spec": {
                    "request": {
                        "header_mutations": [{ "type": "set", "name": "x-listener", "value": "edge" }]
                    },
                    "response": {}
                }
            },
            {
                "name": "route-transform",
                "spec": {
                    "request": {
                        "path_rewrite": {
                            "type": "replace_prefix",
                            "match_prefix": "/edge",
                            "replacement": "/v1"
                        },
                        "host_rewrite": "backend.internal"
                    },
                    "response": {}
                }
            }
        ]
    }
}"#,
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let CompiledServeListener::Public { proxy: ManagedProxyConfig::Http2(config), .. } =
            compiled.listeners.get("public").ok_or("missing public listener")?
        else {
            return Err("expected public HTTP/2 listener".into());
        };

        assert_eq!(
            config
                .listener_request_transform
                .as_ref()
                .map(|transform| transform.header_mutations.len()),
            Some(1)
        );
        assert_eq!(
            config
                .route_request_transforms
                .get("web")
                .and_then(|transform| transform.host_rewrite.as_deref()),
            Some("backend.internal")
        );
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_attaches_response_transforms_to_http1_public_proxy(
    ) -> Result<(), DynError> {
        let path = write_temp_config(
            "workspace-response-transforms-http1.json",
            r#"{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {
            "name": "public",
            "class": "public",
            "bind_address": "127.0.0.1:28082",
            "protocol": "http1",
            "routes": ["web"],
            "policies": { "transform_policy": "listener-transform" }
        },
        {
            "name": "admin",
            "class": "admin",
            "bind_address": "127.0.0.1:29902",
            "protocol": "http1"
        }
    ],
    "routes": [
        {
            "name": "web",
            "match": { "type": "path_prefix", "prefix": "/edge" },
            "upstream_cluster": "frontend",
            "policies": { "transform_policy": "route-transform" }
        }
    ],
    "upstream_clusters": [
        {
            "name": "frontend",
            "endpoints": [
                {
                    "id": "frontend-a",
                    "address": "127.0.0.1:18083",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }
            ]
        }
    ],
    "policies": {
        "transforms": [
            {
                "name": "listener-transform",
                "spec": {
                    "request": {},
                    "response": {
                        "header_mutations": [{ "type": "set", "name": "x-listener-response", "value": "edge" }]
                    }
                }
            },
            {
                "name": "route-transform",
                "spec": {
                    "request": {},
                    "response": {
                        "header_mutations": [{ "type": "remove", "name": "x-remove-me" }]
                    }
                }
            }
        ]
    }
}"#,
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let CompiledServeListener::Public { proxy: ManagedProxyConfig::Http1(config), .. } =
            compiled.listeners.get("public").ok_or("missing public listener")?
        else {
            return Err("expected public HTTP/1 listener".into());
        };

        assert_eq!(
            config
                .listener_response_transform
                .as_ref()
                .map(|transform| transform.header_mutations.len()),
            Some(1)
        );
        assert_eq!(
            config
                .route_response_transforms
                .get("web")
                .map(|transform| transform.header_mutations.len()),
            Some(1)
        );
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_attaches_response_transforms_to_http2_public_proxy(
    ) -> Result<(), DynError> {
        let path = write_temp_config(
            "workspace-response-transforms-http2.json",
            r#"{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {
            "name": "public",
            "class": "public",
            "bind_address": "127.0.0.1:28083",
            "protocol": "http2",
            "routes": ["web"],
            "policies": { "transform_policy": "listener-transform" }
        },
        {
            "name": "admin",
            "class": "admin",
            "bind_address": "127.0.0.1:29903",
            "protocol": "http1"
        }
    ],
    "routes": [
        {
            "name": "web",
            "match": { "type": "path_prefix", "prefix": "/edge" },
            "upstream_cluster": "frontend",
            "policies": { "transform_policy": "route-transform" }
        }
    ],
    "upstream_clusters": [
        {
            "name": "frontend",
            "endpoints": [
                {
                    "id": "frontend-a",
                    "address": "127.0.0.1:18084",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }
            ]
        }
    ],
    "policies": {
        "transforms": [
            {
                "name": "listener-transform",
                "spec": {
                    "request": {},
                    "response": {
                        "header_mutations": [{ "type": "set", "name": "x-listener-response", "value": "edge" }]
                    }
                }
            },
            {
                "name": "route-transform",
                "spec": {
                    "request": {},
                    "response": {
                        "header_mutations": [{ "type": "remove", "name": "x-remove-me" }]
                    }
                }
            }
        ]
    }
}"#,
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let CompiledServeListener::Public { proxy: ManagedProxyConfig::Http2(config), .. } =
            compiled.listeners.get("public").ok_or("missing public listener")?
        else {
            return Err("expected public HTTP/2 listener".into());
        };

        assert_eq!(
            config
                .listener_response_transform
                .as_ref()
                .map(|transform| transform.header_mutations.len()),
            Some(1)
        );
        assert_eq!(
            config
                .route_response_transforms
                .get("web")
                .map(|transform| transform.header_mutations.len()),
            Some(1)
        );
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_exposes_effective_backend_policy_diagnostics_for_http1(
    ) -> Result<(), DynError> {
        let path = write_temp_config(
            "workspace-effective-backend-policies-http1.json",
            r#"{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {
            "name": "public",
            "class": "public",
            "bind_address": "127.0.0.1:28110",
            "protocol": "http1",
            "routes": ["web"],
            "policies": {
                "transform_policy": "listener-transform",
                "retry_budget": "listener-retry",
                "local_rate_limits": ["listener-rate"]
            }
        },
        {
            "name": "admin",
            "class": "admin",
            "bind_address": "127.0.0.1:29910",
            "protocol": "http1"
        }
    ],
    "routes": [
        {
            "name": "web",
            "match": { "type": "path_prefix", "prefix": "/edge" },
            "destinations": [
                {
                    "upstream_cluster": "frontend-stable",
                    "weight": 90
                },
                {
                    "upstream_cluster": "frontend-canary",
                    "weight": 10,
                    "policies": {
                        "transform_policy": "destination-transform",
                        "retry_budget": "destination-retry",
                        "circuit_breaker": "destination-breaker",
                        "local_rate_limits": ["destination-rate"],
                        "local_concurrency_limits": ["destination-concurrency"]
                    }
                }
            ],
            "policies": {
                "transform_policy": "route-transform",
                "timeout_hierarchy": "route-timeout",
                "local_rate_limits": ["route-rate"],
                "local_concurrency_limits": ["route-concurrency"]
            }
        }
    ],
    "upstream_clusters": [
        {
            "name": "frontend-stable",
            "endpoints": [
                {
                    "id": "frontend-stable-a",
                    "address": "127.0.0.1:18110",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }
            ]
        },
        {
            "name": "frontend-canary",
            "endpoints": [
                {
                    "id": "frontend-canary-a",
                    "address": "127.0.0.1:18111",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }
            ]
        }
    ],
    "policies": {
        "local_rate_limits": [
            {
                "name": "listener-rate",
                "spec": {
                    "scope": { "type": "listener", "name": "public" },
                    "key_kind": "source_ip",
                    "requests_per_window": 100,
                    "window_ms": 1000,
                    "max_tracked_keys": 1024
                }
            },
            {
                "name": "route-rate",
                "spec": {
                    "scope": { "type": "route", "name": "web" },
                    "key_kind": "route_name",
                    "requests_per_window": 50,
                    "window_ms": 1000,
                    "max_tracked_keys": 256
                }
            },
            {
                "name": "destination-rate",
                "spec": {
                    "scope": {
                        "type": "route_destination",
                        "route": "web",
                        "upstream_cluster": "frontend-canary"
                    },
                    "key_kind": "global",
                    "requests_per_window": 10,
                    "window_ms": 1000,
                    "max_tracked_keys": 64
                }
            }
        ],
        "local_concurrency_limits": [
            {
                "name": "route-concurrency",
                "spec": {
                    "scope": { "type": "route", "name": "web" },
                    "key_kind": "route_name",
                    "max_concurrent": 64,
                    "max_tracked_keys": 256
                }
            },
            {
                "name": "destination-concurrency",
                "spec": {
                    "scope": {
                        "type": "route_destination",
                        "route": "web",
                        "upstream_cluster": "frontend-canary"
                    },
                    "key_kind": "global",
                    "max_concurrent": 8,
                    "max_tracked_keys": 64
                }
            }
        ],
        "retry_budgets": [
            {
                "name": "listener-retry",
                "spec": {
                    "min_retry_tokens": 3,
                    "retry_percent": 20,
                    "window_ms": 10000
                }
            },
            {
                "name": "destination-retry",
                "spec": {
                    "min_retry_tokens": 2,
                    "retry_percent": 5,
                    "window_ms": 5000
                }
            }
        ],
        "timeout_hierarchies": [
            {
                "name": "route-timeout",
                "spec": {
                    "request_timeout_ms": 30000,
                    "attempt_timeout_ms": 10000,
                    "connect_timeout_ms": 1000,
                    "idle_timeout_ms": 5000
                }
            }
        ],
        "circuit_breakers": [
            {
                "name": "destination-breaker",
                "spec": {
                    "open_failure_threshold": 5,
                    "open_duration_ms": 30000,
                    "half_open_success_threshold": 2
                }
            }
        ],
        "transforms": [
            {
                "name": "listener-transform",
                "spec": {
                    "request": {
                        "header_mutations": [{ "type": "set", "name": "x-listener", "value": "edge" }]
                    },
                    "response": {
                        "header_mutations": [{ "type": "set", "name": "x-listener-response", "value": "edge" }]
                    }
                }
            },
            {
                "name": "route-transform",
                "spec": {
                    "request": {
                        "path_rewrite": {
                            "type": "replace_prefix",
                            "match_prefix": "/edge",
                            "replacement": "/v1"
                        },
                        "header_mutations": [{ "type": "set", "name": "x-route", "value": "api" }]
                    },
                    "response": {
                        "header_mutations": [{ "type": "set", "name": "x-route-response", "value": "api" }]
                    }
                }
            },
            {
                "name": "destination-transform",
                "spec": {
                    "request": {
                        "host_rewrite": "canary.internal",
                        "header_mutations": [{ "type": "set", "name": "x-destination", "value": "canary" }]
                    },
                    "response": {
                        "header_mutations": [{ "type": "set", "name": "x-destination-response", "value": "canary" }]
                    }
                }
            }
        ]
    }
}"#,
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let CompiledServeListener::Public { proxy: ManagedProxyConfig::Http1(config), .. } =
            compiled.listeners.get("public").ok_or("missing public listener")?
        else {
            return Err("expected public HTTP/1 listener".into());
        };

        let diagnostics = config
            .route_backend_policy_diagnostics
            .get("web")
            .ok_or("missing web backend diagnostics")?;
        let stable = diagnostics
            .iter()
            .find(|entry| entry.upstream_cluster == "frontend-stable")
            .ok_or("missing stable diagnostics")?;
        let canary = diagnostics
            .iter()
            .find(|entry| entry.upstream_cluster == "frontend-canary")
            .ok_or("missing canary diagnostics")?;

        assert_eq!(stable.retry_budget.as_deref(), Some("listener-retry"));
        assert_eq!(stable.timeout_hierarchy.as_deref(), Some("route-timeout"));
        assert_eq!(stable.transform_policy.as_deref(), Some("route-transform"));
        assert_eq!(stable.local_rate_limits, vec!["listener-rate", "route-rate"]);
        assert_eq!(
            stable
                .effective_request_transform
                .as_ref()
                .and_then(|transform| transform.path_rewrite.as_ref())
                .is_some(),
            true
        );
        assert_eq!(
            stable
                .effective_request_transform
                .as_ref()
                .map(|transform| transform.header_mutations.len()),
            Some(2)
        );

        assert_eq!(canary.retry_budget.as_deref(), Some("destination-retry"));
        assert_eq!(canary.timeout_hierarchy.as_deref(), Some("route-timeout"));
        assert_eq!(canary.circuit_breaker.as_deref(), Some("destination-breaker"));
        assert_eq!(canary.transform_policy.as_deref(), Some("destination-transform"));
        assert_eq!(
            canary.local_rate_limits,
            vec!["listener-rate", "route-rate", "destination-rate"]
        );
        assert_eq!(
            canary.local_concurrency_limits,
            vec!["route-concurrency", "destination-concurrency"]
        );
        assert_eq!(
            canary
                .effective_request_transform
                .as_ref()
                .and_then(|transform| transform.host_rewrite.as_deref()),
            Some("canary.internal")
        );
        assert_eq!(
            canary
                .effective_request_transform
                .as_ref()
                .map(|transform| transform.header_mutations.len()),
            Some(3)
        );
        assert_eq!(
            canary
                .effective_response_transform
                .as_ref()
                .map(|transform| transform.header_mutations.len()),
            Some(3)
        );

        let canary_runtime = config
            .route_destination_policies
            .get("web")
            .and_then(|policies| policies.get("frontend-canary"))
            .ok_or("missing canary destination runtime")?;
        assert_eq!(
            canary_runtime
                .request_transform
                .as_ref()
                .and_then(|transform| transform.host_rewrite.as_deref()),
            Some("canary.internal")
        );
        assert_eq!(canary_runtime.rate_limiters.len(), 3);
        assert_eq!(canary_runtime.concurrency_limiters.len(), 2);
        assert!(canary_runtime.failure_manager.is_some());
        assert!(canary_runtime.enforce_retry_budget);
        Ok(())
    }

    #[test]
    fn compile_workspace_runtime_exposes_effective_backend_policy_diagnostics_for_http2(
    ) -> Result<(), DynError> {
        let path = write_temp_config(
            "workspace-effective-backend-policies-http2.json",
            r#"{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {
            "name": "public",
            "class": "public",
            "bind_address": "127.0.0.1:28111",
            "protocol": "http2",
            "routes": ["web"],
            "policies": {
                "transform_policy": "listener-transform",
                "retry_budget": "listener-retry"
            }
        },
        {
            "name": "admin",
            "class": "admin",
            "bind_address": "127.0.0.1:29911",
            "protocol": "http1"
        }
    ],
    "routes": [
        {
            "name": "web",
            "match": { "type": "path_prefix", "prefix": "/edge" },
            "destinations": [
                {
                    "upstream_cluster": "frontend-canary",
                    "weight": 10,
                    "policies": {
                        "transform_policy": "destination-transform",
                        "retry_budget": "destination-retry"
                    }
                }
            ],
            "policies": {
                "transform_policy": "route-transform"
            }
        }
    ],
    "upstream_clusters": [
        {
            "name": "frontend-canary",
            "endpoints": [
                {
                    "id": "frontend-canary-a",
                    "address": "127.0.0.1:18112",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }
            ]
        }
    ],
    "policies": {
        "retry_budgets": [
            {
                "name": "listener-retry",
                "spec": {
                    "min_retry_tokens": 3,
                    "retry_percent": 20,
                    "window_ms": 10000
                }
            },
            {
                "name": "destination-retry",
                "spec": {
                    "min_retry_tokens": 2,
                    "retry_percent": 5,
                    "window_ms": 5000
                }
            }
        ],
        "transforms": [
            {
                "name": "listener-transform",
                "spec": {
                    "request": {
                        "header_mutations": [{ "type": "set", "name": "x-listener", "value": "edge" }]
                    },
                    "response": {}
                }
            },
            {
                "name": "route-transform",
                "spec": {
                    "request": {
                        "path_rewrite": {
                            "type": "replace_prefix",
                            "match_prefix": "/edge",
                            "replacement": "/v2"
                        }
                    },
                    "response": {}
                }
            },
            {
                "name": "destination-transform",
                "spec": {
                    "request": {
                        "host_rewrite": "canary.internal"
                    },
                    "response": {}
                }
            }
        ]
    }
}"#,
        )?;

        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let CompiledServeListener::Public { proxy: ManagedProxyConfig::Http2(config), .. } =
            compiled.listeners.get("public").ok_or("missing public listener")?
        else {
            return Err("expected public HTTP/2 listener".into());
        };

        let canary = config
            .route_backend_policy_diagnostics
            .get("web")
            .and_then(|entries| entries.first())
            .ok_or("missing canary diagnostics")?;
        assert_eq!(canary.retry_budget.as_deref(), Some("destination-retry"));
        assert_eq!(canary.transform_policy.as_deref(), Some("destination-transform"));
        assert_eq!(
            canary
                .effective_request_transform
                .as_ref()
                .and_then(|transform| transform.host_rewrite.as_deref()),
            Some("canary.internal")
        );
        assert_eq!(
            canary
                .effective_request_transform
                .as_ref()
                .and_then(|transform| transform.path_rewrite.as_ref())
                .is_some(),
            true
        );
        let canary_runtime = config
            .route_destination_policies
            .get("web")
            .and_then(|policies| policies.get("frontend-canary"))
            .ok_or("missing canary destination runtime")?;
        assert_eq!(
            canary_runtime
                .request_transform
                .as_ref()
                .and_then(|transform| transform.host_rewrite.as_deref()),
            Some("canary.internal")
        );
        assert!(canary_runtime.failure_manager.is_some());
        assert!(canary_runtime.enforce_retry_budget);
        Ok(())
    }

    #[test]
    fn tls_server_config_disables_session_resumption_when_requested() -> Result<(), DynError> {
        let (cert_path, key_path, _cert_der) = write_temp_tls_identity()?;
        let tls_termination = lb_config_model::ListenerTlsTerminationConfig {
            certificate_source: lb_config_model::ListenerCertificateSourceConfig::Files {
                cert_path,
                key_path,
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: lb_config_model::ListenerTlsSessionResumptionConfig {
                mode: lb_config_model::ListenerTlsSessionResumptionModeConfig::Disabled,
                session_cache_size: 256,
                tls13_ticket_count: 2,
            },
            minimum_version: lb_config_model::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![lb_config_model::ListenerAlpnProtocolConfig::Http11],
        };

        let config = build_tls_server_config(&tls_termination)?;

        assert!(!config.session_storage.can_cache());
        assert!(!config.ticketer.enabled());
        assert_eq!(config.send_tls13_tickets, 0);
        Ok(())
    }

    #[test]
    fn tls_server_config_enables_hybrid_session_resumption_when_requested() -> Result<(), DynError>
    {
        let (cert_path, key_path, _cert_der) = write_temp_tls_identity()?;
        let tls_termination = lb_config_model::ListenerTlsTerminationConfig {
            certificate_source: lb_config_model::ListenerCertificateSourceConfig::Files {
                cert_path,
                key_path,
                ocsp_path: None,
            },
            sni_certificates: Vec::new(),
            session_resumption: lb_config_model::ListenerTlsSessionResumptionConfig {
                mode: lb_config_model::ListenerTlsSessionResumptionModeConfig::Hybrid,
                session_cache_size: 64,
                tls13_ticket_count: 3,
            },
            minimum_version: lb_config_model::ListenerTlsMinimumVersionConfig::Tls12,
            alpn_protocols: vec![lb_config_model::ListenerAlpnProtocolConfig::Http11],
        };

        let config = build_tls_server_config(&tls_termination)?;

        assert!(config.session_storage.can_cache());
        assert!(config.ticketer.enabled());
        assert_eq!(config.send_tls13_tickets, 3);
        Ok(())
    }

    #[test]
    fn load_certified_key_from_source_attaches_ocsp_bytes() -> Result<(), DynError> {
        let (cert_path, key_path, _cert_der) = write_temp_tls_identity()?;
        let unique = unique_test_file_suffix()?;
        let ocsp_path = std::env::temp_dir().join(format!("way-balancer-ocsp-{unique}.der"));
        fs::write(&ocsp_path, b"fake-ocsp-response")?;

        let certified_key = super::load_certified_key_from_source(
            &lb_config_model::ListenerCertificateSourceConfig::Files {
                cert_path,
                key_path,
                ocsp_path: Some(ocsp_path.to_string_lossy().into_owned()),
            },
        )?;

        assert_eq!(certified_key.ocsp.as_deref(), Some(b"fake-ocsp-response".as_slice()));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_serves_http2_public_listener() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_h2_upstream("http2-ok").await?;
        let path = write_temp_config(
            "http2-supervisor",
            &workspace_config_json(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http2",
                &upstream_addr.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let mut client = connect_h2_client(public_addr).await?;
        let response = send_h2_request(&mut client, "/").await.map_err(to_dyn_error)?;
        let received = receive_h2_response(response).await?;
        assert_eq!(received.0, StatusCode::OK);
        assert_eq!(received.1, "http2-ok");

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_public_http1_listener_accepts_proxy_protocol_v1_preface(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, capture_rx) = spawn_capture_http1_upstream().await?;
        let path = write_temp_config(
            "proxy-protocol-v1-http1",
            &workspace_config_json_with_proxy_protocol(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                "v1",
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let response = send_prefixed_http1_request(
            public_addr,
            b"PROXY TCP4 198.51.100.7 203.0.113.10 45678 8080\r\n",
            "/",
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

        let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
        assert!(capture.to_ascii_lowercase().contains("x-forwarded-for: 198.51.100.7\r\n"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_public_http1_listener_trusts_forwarded_chain_from_proxy_protocol_source(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, capture_rx) = spawn_capture_http1_upstream().await?;
        let path = write_temp_config(
            "proxy-protocol-trusted-client-ip",
            &workspace_config_json_with_proxy_protocol_and_trusted_client_ip(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                "v1",
                &["203.0.113.0/24"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let response = send_prefixed_http1_request_with_headers(
            public_addr,
            b"PROXY TCP4 203.0.113.10 192.0.2.20 45678 8080\r\n",
            "/",
            &[
                ("Forwarded", "for=198.51.100.9"),
                ("X-Forwarded-For", "198.51.100.7"),
            ],
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

        let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
        let capture = capture.to_ascii_lowercase();
        assert!(capture.contains("x-forwarded-for: 198.51.100.9\r\n"));
        assert!(!capture.contains("x-forwarded-for: 198.51.100.7\r\n"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_public_http1_listener_rejects_forwarded_chain_from_untrusted_proxy_protocol_source(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, counter) = spawn_counting_http1_upstream().await?;
        let path = write_temp_config(
            "proxy-protocol-untrusted-client-ip",
            &workspace_config_json_with_proxy_protocol_and_trusted_client_ip(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                "v1",
                &["203.0.113.0/24"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let response = send_prefixed_http1_request_with_headers(
            public_addr,
            b"PROXY TCP4 198.18.0.10 192.0.2.20 45678 8080\r\n",
            "/",
            &[("X-Forwarded-For", "198.51.100.7")],
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_public_http1_listener_rejects_proxy_protocol_preface_when_disabled(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, counter) = spawn_counting_http1_upstream().await?;
        let path = write_temp_config(
            "proxy-protocol-disabled-http1",
            &workspace_config_json(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let response = send_prefixed_http1_request(
            public_addr,
            b"PROXY TCP4 198.51.100.7 203.0.113.10 45678 8080\r\n",
            "/",
        )
        .await?;
        assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_active_health_probes_fail_over_and_recover_http1_route_backends(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let failed_addr = reserve_unused_addr().await?;
        let healthy_addr = spawn_tagged_http1_upstream("healthy-active").await?;
        let endpoints = vec![
            (String::from("frontend-a"), failed_addr.to_string()),
            (String::from("frontend-b"), healthy_addr.to_string()),
        ];
        let path = write_temp_config(
            "active-health-route-backends",
            &workspace_config_json_with_upstream_endpoints(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &endpoints,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        time::sleep(ACTIVE_HEALTH_PROBE_INTERVAL * 2 + Duration::from_millis(150)).await;
        let healthy_response = send_http1_request(public_addr, "/").await?;
        assert!(healthy_response.ends_with("healthy-active"));

        let _recovered_addr =
            spawn_tagged_http1_upstream_on(failed_addr, "recovered-active").await?;
        time::sleep(ACTIVE_HEALTH_PROBE_INTERVAL * 2 + Duration::from_millis(150)).await;

        let mut saw_recovered = false;
        for _ in 0..6 {
            let response = send_http1_request(public_addr, "/").await?;
            if response.ends_with("recovered-active") {
                saw_recovered = true;
                break;
            }
        }
        assert!(saw_recovered, "recovered endpoint never re-entered rotation");

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_reload_swaps_http1_upstream_in_place() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "reload-runtime",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_a.to_string()),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let first = send_http1_request(public_addr, "/").await?;
        assert!(first.contains("upstream-a"));

        fs::write(
            &path,
            workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_b.to_string()),
        )?;
        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));

        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.contains("upstream-b"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_validate_previews_candidate_diff_and_warnings() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "validate-preview",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_a.to_string()),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_b.to_string()),
        )?;
        let preview = send_admin_validate(admin_addr).await?;
        assert!(preview.starts_with("HTTP/1.1 200 OK"));
        assert!(preview.contains("\"candidate_snapshot\""));
        assert!(preview.contains("\"diff_preview\""));
        assert!(preview.contains("\"upstream_clusters_changed\""));
        assert!(preview.contains("\"strategy\": \"in_place_or_additive_swap\""));
        assert!(preview.contains("\"rollback_safe\": true"));
        assert!(preview.contains("\"digest_sha256\""));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocked_rebind_reload_leaves_active_listener_unchanged() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_addr = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "validate-blocked-rebind",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_addr.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http2",
                &upstream_addr.to_string(),
            ),
        )?;

        let preview = send_admin_validate(admin_addr).await?;
        assert!(preview.starts_with("HTTP/1.1 200 OK"));
        assert!(preview.contains("\"listener_rebind_required\""));
        assert!(preview.contains("\"strategy\": \"blocked_requires_rebind\""));

        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(reload.contains("zero-downtime replacement is not available"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"last_reload_outcome_code\": \"reload_failed_blocked_change\""));
        let status_json = parse_http_json_body(&status)?;
        assert!(json_u64_field(&status_json, "reload_last_duration_ms")? >= 1);
        assert!(json_u64_field(&status_json, "reload_last_failure_duration_ms")? >= 1);
        assert!(json_u64_field(&status_json, "reload_last_success_duration_ms")? >= 1);

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.contains("\"code\": \"reload_started_blocked_candidate\""));
        assert!(audit.contains("\"code\": \"reload_failed_blocked_change\""));

        let response = send_http1_request(public_addr, "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("upstream-a"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn successful_reload_clears_prior_failed_reload_state() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "reload-recovery",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http2",
                &upstream_a.to_string(),
            ),
        )?;

        let failed_reload = send_admin_reload(admin_addr).await?;
        assert!(failed_reload.starts_with("HTTP/1.1 500 Internal Server Error"));

        let failed_readyz = send_admin_readyz(admin_addr).await?;
        assert!(failed_readyz.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(failed_readyz.contains("\"reload_failed\""));

        fs::write(
            &path,
            workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_b.to_string(),
            ),
        )?;

        let successful_reload = send_admin_reload(admin_addr).await?;
        assert!(successful_reload.starts_with("HTTP/1.1 200 OK"));

        let recovered_readyz = send_admin_readyz(admin_addr).await?;
        assert!(recovered_readyz.starts_with("HTTP/1.1 200 OK"));
        assert!(recovered_readyz.contains("\"status\":\"ready\""));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"reload_health\": \"healthy\""));
        assert!(status.contains("\"last_reload_outcome_code\": \"reload_applied_in_place\""));
        assert!(status.contains("\"last_reload_result\": \"configuration applied\""));
        assert!(!status.contains("reload_failed_rollback_preserved"));

        let response = send_http1_request(public_addr, "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("upstream-b"));

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.contains("\"code\": \"reload_failed_blocked_change\""));
        assert!(audit.contains("\"code\": \"reload_applied_in_place\""));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reload_metrics_accumulate_across_failed_then_successful_sequence(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "reload-metric-sequence",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let baseline_status = send_admin_status(admin_addr).await?;
        let baseline_json = parse_http_json_body(&baseline_status)?;
        let baseline_requests = json_u64_field(&baseline_json, "reload_requests")?;
        let baseline_success = json_u64_field(&baseline_json, "reload_success_count")?;
        let baseline_failure = json_u64_field(&baseline_json, "reload_failure_count")?;
        let baseline_total_duration = json_u64_field(&baseline_json, "reload_total_duration_ms")?;

        fs::write(
            &path,
            workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http2",
                &upstream_a.to_string(),
            ),
        )?;
        let failed_reload = send_admin_reload(admin_addr).await?;
        assert!(failed_reload.starts_with("HTTP/1.1 500 Internal Server Error"));

        fs::write(
            &path,
            workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_b.to_string(),
            ),
        )?;
        let successful_reload = send_admin_reload(admin_addr).await?;
        assert!(successful_reload.starts_with("HTTP/1.1 200 OK"));

        let final_status = send_admin_status(admin_addr).await?;
        let final_json = parse_http_json_body(&final_status)?;
        assert_eq!(json_u64_field(&final_json, "reload_requests")?, baseline_requests + 2);
        assert_eq!(json_u64_field(&final_json, "reload_success_count")?, baseline_success + 1);
        assert_eq!(json_u64_field(&final_json, "reload_failure_count")?, baseline_failure + 1);
        assert!(
            json_u64_field(&final_json, "reload_total_duration_ms")?
                >= baseline_total_duration
                    + json_u64_field(&final_json, "reload_last_success_duration_ms")?
        );
        assert!(json_u64_field(&final_json, "reload_last_success_duration_ms")? >= 1);
        assert!(json_u64_field(&final_json, "reload_last_failure_duration_ms")? >= 1);

        assert!(json_u64_field(&final_json, "reload_max_duration_ms")? >= 1);

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reload_counters_and_health_remain_monotonic_across_mixed_sequence(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let upstream_c = spawn_tagged_http1_upstream("upstream-c").await?;
        let path = write_temp_config(
            "reload-mixed-sequence",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let baseline_status = send_admin_status(admin_addr).await?;
        let baseline_json = parse_http_json_body(&baseline_status)?;
        let baseline_requests = json_u64_field(&baseline_json, "reload_requests")?;
        let baseline_success = json_u64_field(&baseline_json, "reload_success_count")?;
        let baseline_failure = json_u64_field(&baseline_json, "reload_failure_count")?;
        let baseline_total_duration = json_u64_field(&baseline_json, "reload_total_duration_ms")?;

        struct SequenceStep<'a> {
            protocol: &'a str,
            upstream: &'a str,
            expected_prefix: &'a str,
            expected_health: &'a str,
            expected_code: &'a str,
            success_delta: u64,
            failure_delta: u64,
        }

        let upstream_b_value = upstream_b.to_string();
        let upstream_c_value = upstream_c.to_string();
        let steps = [
            SequenceStep {
                protocol: "http1",
                upstream: &upstream_b_value,
                expected_prefix: "HTTP/1.1 200 OK",
                expected_health: "healthy",
                expected_code: "reload_applied_in_place",
                success_delta: 1,
                failure_delta: 0,
            },
            SequenceStep {
                protocol: "http2",
                upstream: &upstream_b_value,
                expected_prefix: "HTTP/1.1 500 Internal Server Error",
                expected_health: "failed",
                expected_code: "reload_failed_blocked_change",
                success_delta: 1,
                failure_delta: 1,
            },
            SequenceStep {
                protocol: "http1",
                upstream: &upstream_c_value,
                expected_prefix: "HTTP/1.1 200 OK",
                expected_health: "healthy",
                expected_code: "reload_applied_in_place",
                success_delta: 2,
                failure_delta: 1,
            },
        ];

        let mut last_total_duration = baseline_total_duration;
        for (index, step) in steps.iter().enumerate() {
            fs::write(
                &path,
                workspace_config_json(
                    &public_bind.to_string(),
                    &admin_bind.to_string(),
                    step.protocol,
                    step.upstream,
                ),
            )?;

            let reload_response = send_admin_reload(admin_addr).await?;
            assert!(reload_response.starts_with(step.expected_prefix));

            let status = send_admin_status(admin_addr).await?;
            let status_json = parse_http_json_body(&status)?;
            assert_eq!(
                json_u64_field(&status_json, "reload_requests")?,
                baseline_requests + index as u64 + 1
            );
            assert_eq!(
                json_u64_field(&status_json, "reload_success_count")?,
                baseline_success + step.success_delta
            );
            assert_eq!(
                json_u64_field(&status_json, "reload_failure_count")?,
                baseline_failure + step.failure_delta
            );
            assert!(status.contains(&format!("\"reload_health\": \"{}\"", step.expected_health)));
            assert!(status
                .contains(&format!("\"last_reload_outcome_code\": \"{}\"", step.expected_code)));

            let total_duration = json_u64_field(&status_json, "reload_total_duration_ms")?;
            assert!(total_duration >= last_total_duration);
            assert!(json_u64_field(&status_json, "reload_max_duration_ms")? >= 1);
            last_total_duration = total_duration;
        }

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restart_restores_control_plane_journal_state() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "control-plane-journal-restore",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let journal_path = control_plane_journal_path(path.to_str().ok_or("utf8 path")?);

        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;
        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_b.to_string(),
            ),
        )?;
        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));
        assert!(std::path::Path::new(&journal_path).exists());

        supervisor.shutdown().await?;

        let restarted = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;
        let restarted_admin_addr = restarted
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener after restart")?
            .local_addr;

        let status = send_admin_status(restarted_admin_addr).await?;
        let status_json = parse_http_json_body(&status)?;
        let journal = status_json
            .get("control_plane_journal")
            .ok_or_else(|| to_dyn_error("missing control_plane_journal"))?;
        assert_eq!(
            journal
                .get("path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing journal path"))?,
            journal_path
        );
        let recovery =
            journal.get("recovery").ok_or_else(|| to_dyn_error("missing recovery block"))?;
        assert_eq!(
            recovery
                .get("state")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing recovery state"))?,
            "restored"
        );
        assert_eq!(
            recovery
                .get("restored_last_reload_outcome_code")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing restored reload outcome code"))?,
            "reload_applied_in_place"
        );
        let desired_digest = journal
            .get("desired_snapshot")
            .and_then(|snapshot| snapshot.get("digest_sha256"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| to_dyn_error("missing desired snapshot digest"))?;
        let applied_digest = journal
            .get("applied_snapshot")
            .and_then(|snapshot| snapshot.get("digest_sha256"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| to_dyn_error("missing applied snapshot digest"))?;
        assert_eq!(desired_digest, applied_digest);

        let audit = send_admin_audit(restarted_admin_addr).await?;
        assert!(audit.contains("\"code\": \"reload_started_in_place\""));
        assert!(audit.contains("\"code\": \"reload_applied_in_place\""));

        restarted.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn corrupted_control_plane_journal_blocks_startup() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let path = write_temp_config(
            "control-plane-journal-corrupt",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", "127.0.0.1:1"),
        )?;
        let journal_path = control_plane_journal_path(path.to_str().ok_or("utf8 path")?);
        fs::write(&journal_path, b"{not-valid-json")?;

        let error = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await
        .expect_err("corrupted durable state must block startup");
        let error_text = error.to_string();
        assert!(error_text.contains("control-plane journal"));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unfinished_reload_recovery_surfaces_needs_operator_action_after_startup(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "control-plane-unfinished-reload",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let desired_snapshot =
            DurableSnapshotIdentity::from_snapshot(&compiled.source_label, &compiled.snapshot);
        let journal_path = control_plane_journal_path(path.to_str().ok_or("utf8 path")?);
        write_control_plane_journal_atomic(
            &journal_path,
            &ControlPlaneJournalPayload {
                persisted_at_unix_ms: unix_time_ms(),
                desired_snapshot: Some(desired_snapshot.clone()),
                applied_snapshot: Some(desired_snapshot.clone()),
                reload_health: String::from("healthy"),
                last_reload_outcome_code: String::from("reload_started_in_place"),
                last_reload_result: String::from("reload started before prior process exited"),
                recent_admin_audit: vec![AdminAuditEvent {
                    observed_at_unix_ms: unix_time_ms(),
                    request_id: String::from("admin-0000000000000001"),
                    listener: String::from("admin"),
                    actor: String::from("writer"),
                    auth_mode: String::from("signed_header"),
                    action: String::from("reload"),
                    code: String::from("reload_started_in_place"),
                    source: String::from("127.0.0.1"),
                    outcome: String::from("started"),
                    detail: String::from("reload started"),
                }],
                in_flight_operation: Some(JournalInFlightOperation {
                    kind: String::from("reload"),
                    started_at_unix_ms: unix_time_ms(),
                    desired_snapshot,
                    lifecycle_code: String::from("reload_started_in_place"),
                    detail: String::from("reload started"),
                    expected_completion_within_ms: None,
                    affected_listeners: Vec::new(),
                }),
            },
        )?;

        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;
        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let status = send_admin_status(admin_addr).await?;
        let status_json = parse_http_json_body(&status)?;
        let recovery = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .ok_or_else(|| to_dyn_error("missing recovery block"))?;
        assert_eq!(
            recovery
                .get("state")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing recovery state"))?,
            "needs_operator_action"
        );
        assert_eq!(
            recovery
                .get("in_flight_operation")
                .and_then(|value| value.get("kind"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing in-flight operation kind"))?,
            "reload"
        );
        assert_eq!(
            recovery
                .get("restored_last_reload_outcome_code")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing restored reload outcome code"))?,
            "reload_started_in_place"
        );
        assert_eq!(
            recovery
                .get("operator_guidance")
                .and_then(|value| value.get("recommended_action"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing operator guidance action"))?,
            "validate_and_retry_reload"
        );
        assert_eq!(
            recovery
                .get("operator_guidance")
                .and_then(|value| value.get("urgency"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing operator guidance urgency"))?,
            "action_required"
        );
        recovery
            .get("operator_guidance")
            .and_then(|value| value.get("operation_age_ms"))
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| to_dyn_error("missing operator guidance operation age"))?;
        assert!(recovery
            .get("operator_guidance")
            .and_then(|value| value.get("expected_completion_within_ms"))
            .map_or(true, serde_json::Value::is_null));
        assert!(!recovery
            .get("operator_guidance")
            .and_then(|value| value.get("exceeded_expected_completion"))
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| to_dyn_error("missing operator guidance exceeded flag"))?);

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.contains("\"code\": \"reload_started_in_place\""));
        assert!(audit.contains(&format!("\"code\": \"{}\"", RECOVERY_UNFINISHED_RELOAD_CODE)));
        assert!(audit.contains("needs_operator_action"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn checksum_mismatch_control_plane_journal_blocks_startup() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let path = write_temp_config(
            "control-plane-journal-checksum",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", "127.0.0.1:1"),
        )?;
        let journal_path = control_plane_journal_path(path.to_str().ok_or("utf8 path")?);
        let payload_json = serde_json::to_string_pretty(&ControlPlaneJournalPayload {
            persisted_at_unix_ms: unix_time_ms(),
            desired_snapshot: None,
            applied_snapshot: None,
            reload_health: String::from("not_requested"),
            last_reload_outcome_code: String::from("not_requested"),
            last_reload_result: String::from("not requested"),
            recent_admin_audit: Vec::new(),
            in_flight_operation: None,
        })?;
        let envelope = ControlPlaneJournalEnvelope {
            version: CONTROL_PLANE_JOURNAL_VERSION,
            payload_json,
            payload_sha256: String::from("deadbeef"),
        };
        fs::write(&journal_path, serde_json::to_vec_pretty(&envelope)?)?;

        let error = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await
        .expect_err("checksum mismatch must block startup");
        assert!(error.to_string().contains("checksum validation"));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn successful_operator_reload_resolves_prior_recovery_state() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "control-plane-recovery-resolve",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let desired_snapshot =
            DurableSnapshotIdentity::from_snapshot(&compiled.source_label, &compiled.snapshot);
        let journal_path = control_plane_journal_path(path.to_str().ok_or("utf8 path")?);
        write_control_plane_journal_atomic(
            &journal_path,
            &ControlPlaneJournalPayload {
                persisted_at_unix_ms: unix_time_ms(),
                desired_snapshot: Some(desired_snapshot.clone()),
                applied_snapshot: Some(desired_snapshot.clone()),
                reload_health: String::from("healthy"),
                last_reload_outcome_code: String::from("reload_started_in_place"),
                last_reload_result: String::from("reload started before prior process exited"),
                recent_admin_audit: Vec::new(),
                in_flight_operation: Some(JournalInFlightOperation {
                    kind: String::from("reload"),
                    started_at_unix_ms: unix_time_ms(),
                    desired_snapshot,
                    lifecycle_code: String::from("reload_started_in_place"),
                    detail: String::from("reload started before prior process exited"),
                    expected_completion_within_ms: None,
                    affected_listeners: Vec::new(),
                }),
            },
        )?;

        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;
        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_b.to_string(),
            ),
        )?;
        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));

        let status = send_admin_status(admin_addr).await?;
        let status_json = parse_http_json_body(&status)?;
        let recovery = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .ok_or_else(|| to_dyn_error("missing recovery block"))?;
        assert_eq!(
            recovery
                .get("state")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing recovery state"))?,
            "resolved"
        );
        assert_eq!(
            recovery.get("in_flight_operation").and_then(serde_json::Value::as_null),
            Some(())
        );

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.contains(&format!("\"code\": \"{}\"", RECOVERY_UNFINISHED_RELOAD_CODE)));
        assert!(audit.contains("\"code\": \"reload_applied_in_place\""));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unfinished_overlap_drain_recovery_surfaces_affected_listeners() -> Result<(), DynError>
    {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "control-plane-overlap-recovery",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let desired_snapshot =
            DurableSnapshotIdentity::from_snapshot(&compiled.source_label, &compiled.snapshot);
        let journal_path = control_plane_journal_path(path.to_str().ok_or("utf8 path")?);
        write_control_plane_journal_atomic(
            &journal_path,
            &ControlPlaneJournalPayload {
                persisted_at_unix_ms: unix_time_ms(),
                desired_snapshot: Some(desired_snapshot.clone()),
                applied_snapshot: Some(desired_snapshot.clone()),
                reload_health: String::from("healthy"),
                last_reload_outcome_code: String::from("reload_started_overlap_drain"),
                last_reload_result: String::from("replacement reload started before prior process exited"),
                recent_admin_audit: Vec::new(),
                in_flight_operation: Some(JournalInFlightOperation {
                    kind: String::from("reload_overlap_drain"),
                    started_at_unix_ms: unix_time_ms().saturating_sub(200),
                    desired_snapshot,
                    lifecycle_code: String::from("reload_started_overlap_drain"),
                    detail: String::from(
                        "reload started; overlap-and-drain replacement planned for: public; inspect GET /status for live drain progress",
                    ),
                    expected_completion_within_ms: Some(50),
                    affected_listeners: vec![String::from("public")],
                }),
            },
        )?;

        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;
        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let status = send_admin_status(admin_addr).await?;
        let status_json = parse_http_json_body(&status)?;
        let recovery_operation = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .and_then(|value| value.get("in_flight_operation"))
            .ok_or_else(|| to_dyn_error("missing recovery in-flight operation"))?;
        assert_eq!(
            recovery_operation
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing in-flight operation kind"))?,
            "reload_overlap_drain"
        );
        assert_eq!(
            recovery_operation
                .get("expected_completion_within_ms")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| to_dyn_error("missing recovery expected completion window"))?,
            50
        );
        assert_eq!(
            recovery_operation
                .get("lifecycle_code")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing recovery lifecycle code"))?,
            "reload_started_overlap_drain"
        );
        let affected_listeners = recovery_operation
            .get("affected_listeners")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| to_dyn_error("missing affected listeners"))?;
        assert_eq!(affected_listeners.len(), 1);
        assert_eq!(
            affected_listeners[0]
                .as_str()
                .ok_or_else(|| to_dyn_error("missing affected listener value"))?,
            "public"
        );
        let reconciled_listeners = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .and_then(|value| value.get("reconciled_listeners"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| to_dyn_error("missing reconciled listeners"))?;
        assert_eq!(reconciled_listeners.len(), 1);
        assert_eq!(
            reconciled_listeners[0]
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing reconciled listener name"))?,
            "public"
        );
        assert_eq!(
            reconciled_listeners[0]
                .get("listener_state")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing reconciled listener state"))?,
            "running"
        );
        assert_eq!(
            reconciled_listeners[0]
                .get("replacement_state")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing reconciled replacement state"))?,
            "stable"
        );
        assert_eq!(
            reconciled_listeners[0]
                .get("reconciliation_verdict")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing reconciliation verdict"))?,
            "settled"
        );
        let reconciliation_summary = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .and_then(|value| value.get("reconciliation_summary"))
            .ok_or_else(|| to_dyn_error("missing reconciliation summary"))?;
        assert_eq!(
            reconciliation_summary
                .get("overall_verdict")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing overall verdict"))?,
            "settled"
        );
        assert_eq!(
            reconciliation_summary
                .get("recommended_action")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing recommended_action"))?,
            "observe_only"
        );
        let operator_guidance = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .and_then(|value| value.get("operator_guidance"))
            .ok_or_else(|| to_dyn_error("missing operator guidance"))?;
        assert_eq!(
            operator_guidance
                .get("recommended_action")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing operator guidance action"))?,
            "validate_and_retry_reload"
        );
        assert_eq!(
            operator_guidance
                .get("urgency")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing operator guidance urgency"))?,
            "action_required"
        );
        assert!(
            operator_guidance
                .get("operation_age_ms")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| to_dyn_error("missing operator guidance operation age"))?
                > 0
        );
        assert_eq!(
            operator_guidance
                .get("expected_completion_within_ms")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| to_dyn_error(
                    "missing operator guidance expected completion window"
                ))?,
            50
        );
        assert!(operator_guidance
            .get("exceeded_expected_completion")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| to_dyn_error("missing operator guidance exceeded flag"))?);
        assert_eq!(
            reconciliation_summary
                .get("settled_count")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| to_dyn_error("missing settled_count"))?,
            1
        );

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn recovery_reconciliation_marks_missing_affected_listener() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let admin_bind = reserve_unused_addr().await?;
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "control-plane-missing-recovery-listener",
            &workspace_config_json(
                &public_bind.to_string(),
                &admin_bind.to_string(),
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let compiled = compile_workspace_runtime(path.to_str().ok_or("utf8 path")?)?;
        let desired_snapshot =
            DurableSnapshotIdentity::from_snapshot(&compiled.source_label, &compiled.snapshot);
        let journal_path = control_plane_journal_path(path.to_str().ok_or("utf8 path")?);
        write_control_plane_journal_atomic(
            &journal_path,
            &ControlPlaneJournalPayload {
                persisted_at_unix_ms: unix_time_ms(),
                desired_snapshot: Some(desired_snapshot.clone()),
                applied_snapshot: Some(desired_snapshot),
                reload_health: String::from("healthy"),
                last_reload_outcome_code: String::from("reload_started_overlap_drain"),
                last_reload_result: String::from(
                    "replacement reload started before prior process exited",
                ),
                recent_admin_audit: Vec::new(),
                in_flight_operation: Some(JournalInFlightOperation {
                    kind: String::from("reload_overlap_drain"),
                    started_at_unix_ms: unix_time_ms(),
                    desired_snapshot: DurableSnapshotIdentity::from_snapshot(
                        &compiled.source_label,
                        &compiled.snapshot,
                    ),
                    lifecycle_code: String::from("reload_started_overlap_drain"),
                    detail: String::from(
                        "reload started; overlap-and-drain replacement planned for: ghost-listener",
                    ),
                    expected_completion_within_ms: Some(50),
                    affected_listeners: vec![String::from("ghost-listener")],
                }),
            },
        )?;

        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;
        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let status = send_admin_status(admin_addr).await?;
        let status_json = parse_http_json_body(&status)?;
        let reconciled_listeners = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .and_then(|value| value.get("reconciled_listeners"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| to_dyn_error("missing reconciled listeners"))?;
        assert_eq!(reconciled_listeners.len(), 1);
        assert_eq!(
            reconciled_listeners[0]
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing reconciled listener name"))?,
            "ghost-listener"
        );
        assert_eq!(
            reconciled_listeners[0]
                .get("reconciliation_verdict")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing reconciliation verdict"))?,
            "missing"
        );
        let reconciliation_summary = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .and_then(|value| value.get("reconciliation_summary"))
            .ok_or_else(|| to_dyn_error("missing reconciliation summary"))?;
        assert_eq!(
            reconciliation_summary
                .get("overall_verdict")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing overall verdict"))?,
            "needs_review"
        );
        assert_eq!(
            reconciliation_summary
                .get("recommended_action")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing recommended_action"))?,
            "investigate_and_validate_reload"
        );
        let operator_guidance = status_json
            .get("control_plane_journal")
            .and_then(|value| value.get("recovery"))
            .and_then(|value| value.get("operator_guidance"))
            .ok_or_else(|| to_dyn_error("missing operator guidance"))?;
        assert_eq!(
            operator_guidance
                .get("recommended_action")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing operator guidance action"))?,
            "investigate_and_validate_reload"
        );
        assert_eq!(
            operator_guidance
                .get("urgency")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| to_dyn_error("missing operator guidance urgency"))?,
            "urgent"
        );
        assert!(
            operator_guidance
                .get("operation_age_ms")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| to_dyn_error("missing operator guidance operation age"))?
                > 0
        );
        assert_eq!(
            operator_guidance
                .get("expected_completion_within_ms")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| to_dyn_error(
                    "missing operator guidance expected completion window"
                ))?,
            50
        );
        assert!(!operator_guidance
            .get("exceeded_expected_completion")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| to_dyn_error("missing operator guidance exceeded flag"))?);

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bind_change_reload_stages_replacement_and_drains_old_listener() -> Result<(), DynError>
    {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let initial_public_bind = reserve_unused_addr().await?;
        let replacement_public_bind = reserve_unused_addr().await?;
        let (upstream_a, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "bind-replacement",
            &workspace_config_json(
                &initial_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;
        assert_eq!(public_addr, initial_public_bind);

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        fs::write(
            &path,
            workspace_config_json(
                &replacement_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_b.to_string(),
            ),
        )?;

        let preview = send_admin_validate(admin_addr).await?;
        assert!(preview.contains("\"listener_replacement_planned\""));
        assert!(preview.contains("\"strategy\": \"overlap_and_drain_replacement\""));

        let reload_task = tokio::spawn(send_admin_reload(admin_addr));
        let replacement_addr = loop {
            let post_reload_statuses = supervisor.listener_statuses().await;
            if let Some(status) = post_reload_statuses
                .iter()
                .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            {
                if status.local_addr == replacement_public_bind {
                    break status.local_addr;
                }
            }
            time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(replacement_addr, replacement_public_bind);

        let second = send_http1_request(replacement_addr, "/").await?;
        assert!(second.starts_with("HTTP/1.1 200 OK"));
        assert!(second.contains("upstream-b"));

        let _ = release_tx.send(());
        let reload = reload_task.await.map_err(to_dyn_error)??;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;
        let first_response = String::from_utf8(first_response).map_err(to_dyn_error)?;
        assert!(first_response.starts_with("HTTP/1.1 200 OK"));
        assert!(first_response.contains("upstream-a"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn replacement_drain_timeout_is_reported_in_status() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let initial_public_bind = reserve_unused_addr().await?;
        let replacement_public_bind = reserve_unused_addr().await?;
        let (upstream_a, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "drain-timeout-replacement",
            &workspace_config_json_with_drain_timeout(
                &initial_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_a.to_string(),
                50,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        fs::write(
            &path,
            workspace_config_json_with_drain_timeout(
                &replacement_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_b.to_string(),
                50,
            ),
        )?;

        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status
            .contains("\"last_reload_outcome_code\": \"reload_applied_overlap_drain_timeout\""));
        assert!(status.contains("drain timeout expired for: public"));
        assert!(status.contains("\"replacement\":{\"state\":\"drain_timeout_expired\""));
        assert!(status.contains("\"drain_timeout_recent\":[{"));
        assert!(status.contains(&format!("\"configured_bind\":\"{}\"", initial_public_bind)));

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.contains("\"code\": \"reload_applied_overlap_drain_timeout\""));
        assert!(audit.contains("replacement stayed active but drain timeout expired for: public"));

        let replacement_response = send_http1_request(replacement_public_bind, "/").await?;
        assert!(replacement_response.starts_with("HTTP/1.1 200 OK"));
        assert!(replacement_response.contains("upstream-b"));

        drop(first);
        let _ = release_tx.send(());
        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn protocol_change_reload_stages_replacement_after_successful_start(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_a, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_h2_upstream("upstream-b").await?;
        let path = write_temp_config(
            "protocol-replacement",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream_a.to_string()),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        fs::write(
            &path,
            workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http2", &upstream_b.to_string()),
        )?;

        let preview = send_admin_validate(admin_addr).await?;
        assert!(preview.contains("\"listener_replacement_planned\""));
        assert!(preview.contains("\"strategy\": \"overlap_and_drain_replacement\""));

        let reload_task = tokio::spawn(send_admin_reload(admin_addr));
        let public_status = loop {
            let post_reload_statuses = supervisor.listener_statuses().await;
            if let Some(status) = post_reload_statuses
                .iter()
                .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            {
                if status.protocol == lb_config_model::ListenerProtocolConfig::Http2
                    && status.local_addr != public_addr
                {
                    break status.clone();
                }
            }
            time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(public_status.protocol, lb_config_model::ListenerProtocolConfig::Http2);
        assert_ne!(public_status.local_addr, public_addr);

        let mut client = connect_h2_client(public_status.local_addr).await?;
        let response = send_h2_request(&mut client, "/").await.map_err(to_dyn_error)?;
        let received = receive_h2_response(response).await?;
        assert_eq!(received.0, StatusCode::OK);
        assert_eq!(received.1, "upstream-b");

        let _ = release_tx.send(());
        let reload = reload_task.await.map_err(to_dyn_error)??;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;
        let first_response = String::from_utf8(first_response).map_err(to_dyn_error)?;
        assert!(first_response.starts_with("HTTP/1.1 200 OK"));
        assert!(first_response.contains("upstream-a"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn replacement_bind_failure_preserves_old_listener() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let initial_public_bind = reserve_unused_addr().await?;
        let replacement_public_bind = reserve_unused_addr().await?;
        let guard_listener = TcpListener::bind(replacement_public_bind).await?;
        let upstream_addr = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "replacement-bind-failure",
            &workspace_config_json(
                &initial_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;
        assert_eq!(public_addr, initial_public_bind);

        fs::write(
            &path,
            workspace_config_json(
                &replacement_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
            ),
        )?;

        let preview = send_admin_validate(admin_addr).await?;
        assert!(preview.contains("\"listener_replacement_planned\""));
        assert!(preview.contains("\"strategy\": \"overlap_and_drain_replacement\""));

        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 500 Internal Server Error"));

        let readyz = send_admin_readyz(admin_addr).await?;
        assert!(readyz.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(readyz.contains("\"status\":\"not_ready\""));
        assert!(readyz.contains("\"reload_failed\""));

        let response = send_http1_request(public_addr, "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("upstream-a"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"reload_health\": \"failed\""));
        assert!(
            status.contains("\"last_reload_outcome_code\": \"reload_failed_rollback_preserved\"")
        );
        assert!(status.contains("\"last_reload_result\":"));
        assert!(status.contains("\"reload_failed\""));
        let status_json = parse_http_json_body(&status)?;
        assert!(json_u64_field(&status_json, "reload_last_duration_ms")? >= 1);
        assert!(json_u64_field(&status_json, "reload_last_failure_duration_ms")? >= 1);
        assert!(json_u64_field(&status_json, "reload_total_duration_ms")? >= 1);

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.contains("\"code\": \"reload_started_overlap_drain\""));
        assert!(audit.contains("\"code\": \"reload_failed_rollback_preserved\""));

        let post_reload_statuses = supervisor.listener_statuses().await;
        let current_public_addr = post_reload_statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener after failed replacement")?
            .local_addr;
        assert_eq!(current_public_addr, public_addr);

        drop(guard_listener);
        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_status_and_audit_surface_live_listener_replacement() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let initial_public_bind = reserve_unused_addr().await?;
        let replacement_public_bind = reserve_unused_addr().await?;
        let (upstream_a, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "replacement-status-audit",
            &workspace_config_json(
                &initial_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;
        assert_eq!(public_addr, initial_public_bind);

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        fs::write(
            &path,
            workspace_config_json(
                &replacement_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_b.to_string(),
            ),
        )?;

        let reload_task = tokio::spawn(send_admin_reload(admin_addr));

        let live_status = loop {
            let status = send_admin_status(admin_addr).await?;
            if status.contains("\"replacement\":{\"state\":\"replacement_draining\"") {
                break status;
            }
            time::sleep(Duration::from_millis(25)).await;
        };
        assert!(live_status.contains(&format!(
            "\"desired\":{{\"class\":\"public\",\"protocol\":\"http1\",\"configured_bind\":\"{}\",\"bind_mode\":\"single_stack\"}}",
            replacement_public_bind
        )));
        assert!(live_status.contains(&format!(
            "\"draining\":[{{\"class\":\"public\",\"protocol\":\"http1\",\"configured_bind\":\"{}\",\"bind_mode\":\"single_stack\"}}]",
            initial_public_bind
        )));

        let audit_during_reload = send_admin_audit(admin_addr).await?;
        assert!(audit_during_reload.starts_with("HTTP/1.1 200 OK"));
        assert!(audit_during_reload.contains("\"action\": \"reload\""));
        assert!(audit_during_reload.contains("\"outcome\": \"started\""));
        assert!(audit_during_reload.contains("\"code\": \"reload_started_overlap_drain\""));
        assert!(audit_during_reload.contains("overlap-and-drain replacement planned for: public"));

        let second = send_http1_request(replacement_public_bind, "/").await?;
        assert!(second.starts_with("HTTP/1.1 200 OK"));
        assert!(second.contains("upstream-b"));

        let _ = release_tx.send(());
        let reload = reload_task.await.map_err(to_dyn_error)??;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));
        assert!(reload.contains("configuration applied"));

        let audit_after_reload = send_admin_audit(admin_addr).await?;
        assert!(audit_after_reload.contains("\"outcome\": \"executed\""));
        assert!(audit_after_reload.contains("\"code\": \"reload_applied_overlap_drain\""));
        assert!(audit_after_reload.contains("replacement completed for: public"));

        let final_status = send_admin_status(admin_addr).await?;
        assert!(final_status.contains("\"replacement\":{\"state\":\"stable\""));
        assert!(
            final_status.contains("\"last_reload_outcome_code\": \"reload_applied_overlap_drain\"")
        );
        let final_status_json = parse_http_json_body(&final_status)?;
        assert!(json_u64_field(&final_status_json, "reload_last_duration_ms")? >= 1);
        assert!(json_u64_field(&final_status_json, "reload_last_success_duration_ms")? >= 1);
        assert!(json_u64_field(&final_status_json, "reload_total_duration_ms")? >= 1);
        assert!(
            json_u64_field(&final_status_json, "reload_max_duration_ms")?
                >= json_u64_field(&final_status_json, "reload_last_duration_ms")?
        );
        assert!(final_status.contains(&format!(
            "\"retired_recent\":[{{\"class\":\"public\",\"protocol\":\"http1\",\"configured_bind\":\"{}\",\"bind_mode\":\"single_stack\"}}]",
            initial_public_bind
        )));

        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;
        let first_response = String::from_utf8(first_response).map_err(to_dyn_error)?;
        assert!(first_response.starts_with("HTTP/1.1 200 OK"));
        assert!(first_response.contains("upstream-a"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reload_requests_are_serialized_without_state_loss() -> Result<(), DynError>
    {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let initial_public_bind = reserve_unused_addr().await?;
        let replacement_public_bind_one = reserve_unused_addr().await?;
        let replacement_public_bind_two = reserve_unused_addr().await?;
        let (upstream_a, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let upstream_c = spawn_tagged_http1_upstream("upstream-c").await?;
        let path = write_temp_config(
            "serialized-reloads",
            &workspace_config_json(
                &initial_public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_a.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;
        assert_eq!(public_addr, initial_public_bind);

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        fs::write(
            &path,
            workspace_config_json(
                &replacement_public_bind_one.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_b.to_string(),
            ),
        )?;

        let reload_one = tokio::spawn(send_admin_reload(admin_addr));
        let live_status = loop {
            let status = send_admin_status(admin_addr).await?;
            if status.contains("\"replacement\":{\"state\":\"replacement_draining\"") {
                break status;
            }
            time::sleep(Duration::from_millis(25)).await;
        };
        assert!(live_status.contains(&format!(
            "\"desired\":{{\"class\":\"public\",\"protocol\":\"http1\",\"configured_bind\":\"{}\",\"bind_mode\":\"single_stack\"}}",
            replacement_public_bind_one
        )));

        fs::write(
            &path,
            workspace_config_json(
                &replacement_public_bind_two.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_c.to_string(),
            ),
        )?;

        let reload_two = tokio::spawn(send_admin_reload(admin_addr));
        time::sleep(Duration::from_millis(75)).await;
        assert!(!reload_two.is_finished());

        let queued_status = send_admin_status(admin_addr).await?;
        assert!(queued_status.contains(&format!(
            "\"desired\":{{\"class\":\"public\",\"protocol\":\"http1\",\"configured_bind\":\"{}\",\"bind_mode\":\"single_stack\"}}",
            replacement_public_bind_one
        )));

        let _ = release_tx.send(());
        let reload_one_response = reload_one.await.map_err(to_dyn_error)??;
        assert!(
            reload_one_response.starts_with("HTTP/1.1 200 OK"),
            "unexpected first reload response: {reload_one_response}"
        );
        let reload_two_response = reload_two.await.map_err(to_dyn_error)??;
        assert!(reload_two_response.starts_with("HTTP/1.1 200 OK"));

        let final_public_status = loop {
            let statuses = supervisor.listener_statuses().await;
            if let Some(status) = statuses
                .iter()
                .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            {
                if status.local_addr == replacement_public_bind_two
                    && status.replacement.state == "stable"
                {
                    break status.clone();
                }
            }
            time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(final_public_status.local_addr, replacement_public_bind_two);

        let final_response = send_http1_request(replacement_public_bind_two, "/").await?;
        assert!(final_response.starts_with("HTTP/1.1 200 OK"));
        assert!(final_response.contains("upstream-c"));

        let final_status = send_admin_status(admin_addr).await?;
        let final_status_json = parse_http_json_body(&final_status)?;
        assert!(json_u64_field(&final_status_json, "reload_requests")? >= 3);
        assert!(json_u64_field(&final_status_json, "reload_success_count")? >= 3);
        assert_eq!(json_u64_field(&final_status_json, "reload_failure_count")?, 0);
        assert!(
            json_u64_field(&final_status_json, "reload_total_duration_ms")?
                >= json_u64_field(&final_status_json, "reload_last_duration_ms")?
        );

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.matches("\"code\": \"reload_started_overlap_drain\"").count() >= 2);
        assert!(audit.matches("\"code\": \"reload_applied_overlap_drain\"").count() >= 2);

        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;
        let first_response = String::from_utf8(first_response).map_err(to_dyn_error)?;
        assert!(first_response.starts_with("HTTP/1.1 200 OK"));
        assert!(first_response.contains("upstream-a"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_signed_headers_enforce_permissions_and_reload_with_writer(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_READ_SECRET", "reader-secret");
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let upstream_a = spawn_tagged_http1_upstream("upstream-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-b").await?;
        let path = write_temp_config(
            "signed-admin-authz",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_a.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let status = send_signed_admin_request(
            admin_addr,
            "reader-secret",
            "reader",
            "GET",
            "/status",
            "reader-status",
        )
        .await?;
        assert!(status.starts_with("HTTP/1.1 200 OK"));

        fs::write(
            &path,
            workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_b.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;

        let forbidden_reload = send_signed_admin_request(
            admin_addr,
            "reader-secret",
            "reader",
            "POST",
            "/reload",
            "reader-reload",
        )
        .await?;
        assert!(forbidden_reload.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(forbidden_reload.contains("admin action not permitted"));

        let unchanged = send_http1_request(public_addr, "/").await?;
        assert!(unchanged.contains("upstream-a"));

        let writer_reload = send_signed_admin_request(
            admin_addr,
            "writer-secret",
            "writer",
            "POST",
            "/reload",
            "writer-reload",
        )
        .await?;
        assert!(writer_reload.starts_with("HTTP/1.1 200 OK"));

        let updated = send_http1_request(public_addr, "/").await?;
        assert!(updated.contains("upstream-b"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_audit_endpoint_reports_forbidden_signed_action() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_READ_SECRET", "reader-secret");
        std::env::set_var("LB_CTL_OPERATOR_AUDIT_SECRET", "auditor-secret");
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let upstream_addr = spawn_tagged_http1_upstream("audit-upstream").await?;
        let path = write_temp_config(
            "signed-admin-audit",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let forbidden_reload = send_signed_admin_request(
            admin_addr,
            "reader-secret",
            "reader",
            "POST",
            "/reload",
            "audit-reload",
        )
        .await?;
        assert!(forbidden_reload.starts_with("HTTP/1.1 403 Forbidden"));

        let forbidden_audit = send_signed_admin_request(
            admin_addr,
            "reader-secret",
            "reader",
            "GET",
            "/audit",
            "reader-audit-denied",
        )
        .await?;
        assert!(forbidden_audit.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(forbidden_audit.contains("admin action not permitted"));

        let audit = send_signed_admin_request(
            admin_addr,
            "auditor-secret",
            "auditor",
            "GET",
            "/audit",
            "audit-read",
        )
        .await?;
        assert!(audit.starts_with("HTTP/1.1 200 OK"));
        assert!(audit.contains("\"actor\": \"reader\""));
        assert!(audit.contains("\"action\": \"reload\""));
        assert!(audit.contains("\"outcome\": \"forbidden\""));
        assert!(audit.contains("operator lacks write permission"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_signed_headers_missing_operator_secret_fails_closed() -> Result<(), DynError> {
        let upstream_addr = spawn_tagged_http1_upstream("missing-secret-upstream").await?;
        let path = write_temp_config(
            "signed-admin-missing-secret",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                r#",
            "admin": {
                "auth": {
                    "mode": "signed_headers",
                    "operators": [
                        {
                            "id": "reader",
                            "secret_env": "LB_CTL_OPERATOR_MISSING_SECRET",
                            "permissions": ["read"]
                        }
                    ],
                    "max_clock_skew_secs": 30,
                    "nonce_ttl_secs": 120
                }
            }"#,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let response =
            send_signed_admin_request(admin_addr, "", "reader", "GET", "/status", "missing-secret")
                .await?;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("admin authorization unavailable"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_invalid_requests_do_not_consume_authenticated_rate_limit_bucket(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let upstream_addr = spawn_tagged_http1_upstream("rate-limit-upstream").await?;
        let path = write_temp_config(
            "admin-rate-limit-authenticated-bucket",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                r#",
            "admin": {
                "auth": {
                    "mode": "signed_headers",
                    "operators": [
                        {
                            "id": "writer",
                            "secret_env": "LB_CTL_OPERATOR_WRITE_SECRET",
                            "permissions": ["read", "audit", "write"]
                        }
                    ]
                },
                "rate_limit": {
                    "requests_per_minute": 60,
                    "burst": 1
                }
            }"#,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let invalid = send_signed_admin_request(
            admin_addr,
            "wrong-secret",
            "writer",
            "GET",
            "/status",
            "bad-auth-first",
        )
        .await?;
        assert!(invalid.starts_with("HTTP/1.1 401 Unauthorized"));

        let valid = send_signed_admin_request(
            admin_addr,
            "writer-secret",
            "writer",
            "GET",
            "/status",
            "good-auth-second",
        )
        .await?;
        assert!(valid.starts_with("HTTP/1.1 200 OK"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_signed_headers_reject_replayed_nonce() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let upstream_addr = spawn_tagged_http1_upstream("replay-upstream").await?;
        let path = write_temp_config(
            "signed-admin-replay",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let first = send_signed_admin_request_with_timestamp(
            admin_addr,
            "writer-secret",
            "writer",
            "GET",
            "/status",
            timestamp,
            "reused-nonce",
        )
        .await?;
        assert!(first.starts_with("HTTP/1.1 200 OK"));

        let replay = send_signed_admin_request_with_timestamp(
            admin_addr,
            "writer-secret",
            "writer",
            "GET",
            "/status",
            timestamp,
            "reused-nonce",
        )
        .await?;
        assert!(replay.starts_with("HTTP/1.1 409 Conflict"));
        assert!(replay.contains("admin command replay rejected"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_source_allow_list_blocks_loopback_requests() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("source-policy-upstream").await?;
        let path = write_temp_config(
            "admin-source-allow-list",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                r#",
            "admin": {
                "allowed_source_cidrs": ["192.0.2.0/24"]
            }"#,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let status = send_admin_status(admin_addr).await?;
        assert!(status.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(status.contains("admin source not allowed"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_rate_limit_rejects_burst_excess() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("rate-limit-upstream").await?;
        let path = write_temp_config(
            "admin-rate-limit",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                r#",
            "admin": {
                "rate_limit": {
                    "requests_per_minute": 1,
                    "burst": 1
                }
            }"#,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let first = send_admin_status(admin_addr).await?;
        assert!(first.starts_with("HTTP/1.1 200 OK"));

        let second = send_admin_status(admin_addr).await?;
        assert!(second.starts_with("HTTP/1.1 429 Too Many Requests"));
        assert!(second.contains("admin rate limit exceeded"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_sheds_overloaded_http1_listener_and_reports_status() -> Result<(), DynError>
    {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("delayed-upstream").await?;

        let path = write_temp_config(
            "http1-overload",
            &workspace_config_json_with_limits(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(second.contains("listener overloaded"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.starts_with("HTTP/1.1 200 OK"));
        assert!(status.contains("\"readiness\": {"));
        assert!(status.contains("\"ready\":false"));
        assert!(status.contains("\"reason_codes\":[\"listener_overload_shedding\"]"));
        assert!(status.contains("\"name\":\"public\""));
        assert!(status.contains("\"shed_connections\":1"));
        assert!(status.contains("\"recent_overload_events\""));
        assert!(status.contains("overload.request.shed"));
        assert!(status.contains("workspace_listener_public"));

        let readyz = send_admin_readyz(admin_addr).await?;
        assert!(readyz.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(readyz.contains("\"status\":\"not_ready\""));
        assert!(readyz.contains("\"listener_overload_shedding\""));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;
        let first_response = String::from_utf8(first_response).map_err(to_dyn_error)?;
        assert!(first_response.starts_with("HTTP/1.1 200 OK"));
        assert!(first_response.contains("delayed-upstream"));

        let readyz_after = send_admin_readyz(admin_addr).await?;
        assert!(readyz_after.starts_with("HTTP/1.1 200 OK"));
        assert!(readyz_after.contains("\"status\":\"ready\""));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_applies_named_overload_policy_and_reports_brownout_features(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("policy-upstream").await?;
        let path = write_temp_config(
            "http1-overload-policy",
            &workspace_config_json_with_listener_overload_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
                "listener-overload",
                &["expensive_search"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.starts_with("HTTP/1.1 503 Service Unavailable"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"overload_state\":\"brownout\""));
        assert!(status.contains("\"brownout_features\":[\"expensive_search\"]"));
        assert!(status.contains("\"recent_overload_events\":[{"));
        assert!(status.contains("overload.brownout.features_changed"));
        assert!(status.contains("overload.request.shed"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_reload_updates_overload_policy_in_place() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("reload-policy-upstream").await?;
        let path = write_temp_config(
            "reload-overload-policy",
            &workspace_config_json_with_listener_overload_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
                "listener-overload-a",
                &["expensive_search"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json_with_listener_overload_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
                "listener-overload-b",
                &["cheap_reads"],
            ),
        )?;
        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));

        let post_reload_statuses = supervisor.listener_statuses().await;
        let reloaded_public_addr = post_reload_statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener after reload")?
            .local_addr;
        assert_eq!(reloaded_public_addr, public_addr);

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;
        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.starts_with("HTTP/1.1 503 Service Unavailable"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"brownout_features\":[\"cheap_reads\"]"));
        assert!(!status.contains("\"brownout_features\":[\"expensive_search\"]"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_enforces_hostile_edge_source_quota_and_reports_reason_codes(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("hostile-edge-upstream").await?;
        let path = write_temp_config(
            "hostile-edge-source-quota",
            &workspace_config_json_with_hostile_edge_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                "edge-default",
                1,
                64,
                16,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        let second = send_http1_request(public_addr, "/").await?;
        assert!(second.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(second.contains("X-LB-Abuse-Reason: source_quota_exceeded"));
        assert!(second.contains("listener rejected connection: source_quota_exceeded"));

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"abuse_protection\":{\"state\":\"enforcing\""));
        assert!(status.contains("\"source_quota\":{\"aggregation\":\"exact_ip\",\"max_active_per_source\":1,\"max_tracked_sources\":64}"));
        assert!(status.contains("\"handshake_guard\":{\"max_inflight\":16,\"timeout_ms\":5000}"));
        assert!(status.contains("\"source_quota_rejections\":1"));
        assert!(status.contains("\"reason_codes\":[\"source_quota_exceeded\"]"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_hostile_edge_source_quota_uses_proxy_protocol_client_ip(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx, request_count) =
            spawn_block_first_then_count_http1_upstream().await?;
        let path = write_temp_config(
            "hostile-edge-source-quota-proxy-protocol",
            &workspace_config_json_with_hostile_edge_policy_and_proxy_protocol(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                "edge-default",
                "v1",
                1,
                64,
                16,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_prefixed_http1_request(
            public_addr,
            b"PROXY TCP4 198.51.100.7 203.0.113.10 45678 8080\r\n",
            "/",
        )
        .await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        let second = send_prefixed_http1_request(
            public_addr,
            b"PROXY TCP4 198.51.100.8 203.0.113.10 45679 8080\r\n",
            "/",
        )
        .await?;
        assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(request_count.load(Ordering::SeqCst), 2);

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"abuse_protection\":{\"state\":\"enforcing\""));
        assert!(status.contains("\"source_quota\":{\"aggregation\":\"exact_ip\",\"max_active_per_source\":1,\"max_tracked_sources\":64}"));
        assert!(status.contains("\"source_quota_rejections\":0"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_reload_updates_hostile_edge_policy_in_place() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("reload-edge-upstream").await?;
        let path = write_temp_config(
            "reload-hostile-edge-policy",
            &workspace_config_json_with_hostile_edge_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                "edge-default-a",
                1,
                64,
                16,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json_with_hostile_edge_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                "edge-default-b",
                2,
                128,
                32,
            ),
        )?;
        let reload = send_admin_reload(admin_addr).await?;
        assert!(reload.starts_with("HTTP/1.1 200 OK"));

        let post_reload_statuses = supervisor.listener_statuses().await;
        let reloaded_public_addr = post_reload_statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener after reload")?
            .local_addr;
        assert_eq!(reloaded_public_addr, public_addr);

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"max_active_per_source\":2"));
        assert!(status.contains("\"max_tracked_sources\":128"));
        assert!(status.contains("\"max_inflight\":32"));
        assert!(!status.contains("\"max_active_per_source\":1"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_bounds_concurrent_overload_with_multiple_sheds() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("stress-upstream").await?;
        let path = write_temp_config(
            "http1-overload-stress",
            &workspace_config_json_with_limits(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                1,
                8,
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let mut first = start_http1_request(public_addr, "/").await?;
        accepted_rx.await.map_err(to_dyn_error)?;

        let mut tasks = Vec::new();
        for _ in 0..8 {
            tasks.push(tokio::spawn(send_http1_request(public_addr, "/")));
        }

        let mut shed_count = 0usize;
        for task in tasks {
            let response = task.await.map_err(to_dyn_error)??;
            if response.starts_with("HTTP/1.1 503 Service Unavailable") {
                shed_count += 1;
            }
        }
        assert_eq!(shed_count, 8);

        let status = send_admin_status(admin_addr).await?;
        assert!(status.contains("\"active_connections\":1"));
        assert!(status.contains("\"shed_connections\":8"));

        let _ = release_tx.send(());
        let mut first_response = Vec::new();
        first.read_to_end(&mut first_response).await?;

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_serves_https_public_listener() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-ok").await?;
        let (cert_path, key_path, cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "https-supervisor",
            &workspace_config_json_with_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &cert_path,
                &key_path,
                "tls12",
                &["http2", "http11"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let response = send_https_http1_request(public_addr, &cert_der, "localhost", "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("https-ok"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_serves_https_listener_with_http11_only_alpn() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-http11").await?;
        let (cert_path, key_path, cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "https-http11-only",
            &workspace_config_json_with_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &cert_path,
                &key_path,
                "tls13",
                &["http11"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let response = send_https_http1_request(public_addr, &cert_der, "localhost", "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("https-http11"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_rejects_tls12_client_when_https_listener_requires_tls13(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-tls13").await?;
        let (cert_path, key_path, cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "https-tls13-only",
            &workspace_config_json_with_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &cert_path,
                &key_path,
                "tls13",
                &["http11"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let result = send_https_http1_request_with_policy(
            public_addr,
            &[cert_der],
            "localhost",
            "/",
            &[&rustls::version::TLS12],
            &[b"http/1.1"],
        )
        .await;
        assert!(result.is_err());

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_selects_sni_certificate_for_named_host() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-sni").await?;
        let (default_cert_path, default_key_path, default_cert_der) =
            write_temp_tls_identity_for_host("fallback.local")?;
        let (tenant_cert_path, tenant_key_path, tenant_cert_der) =
            write_temp_tls_identity_for_host("tenant.local")?;
        let path = write_temp_config(
            "https-sni",
            &workspace_config_json_with_tls_and_sni(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &default_cert_path,
                &default_key_path,
                "tls12",
                &["http11"],
                &[(vec!["tenant.local"], tenant_cert_path.as_str(), tenant_key_path.as_str())],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let public_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;

        let tenant_response = send_https_http1_request_with_roots(
            public_addr,
            &[default_cert_der.clone(), tenant_cert_der.clone()],
            "tenant.local",
            "/",
        )
        .await?;
        assert!(tenant_response.starts_with("HTTP/1.1 200 OK"));
        assert!(tenant_response.contains("https-sni"));

        let fallback_response = send_https_http1_request_with_roots(
            public_addr,
            &[default_cert_der, tenant_cert_der],
            "fallback.local",
            "/",
        )
        .await?;
        assert!(fallback_response.starts_with("HTTP/1.1 200 OK"));
        assert!(fallback_response.contains("https-sni"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_cache_purge_endpoint_clears_listener_scoped_response_cache(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_addr, request_count) = spawn_counting_http1_upstream().await?;
        let path = write_temp_config(
            "cache-purge-endpoint",
            &workspace_config_json_with_admin_policy_and_cache(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                "",
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let first = send_http1_request(public_addr, "/catalog").await?;
        let second = send_http1_request(public_addr, "/catalog").await?;
        assert!(first.contains("count:1"));
        assert!(second.contains("count:1"));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        let purge = send_admin_json_request(
            admin_addr,
            "/cache/purge",
            r#"{"scope":"public","target":{"type":"path_prefix","path_prefix":"/catalog"},"requested_by":"admin-a","reason":"invalidate catalog"}"#,
        )
        .await?;
        assert!(purge.starts_with("HTTP/1.1 200 OK"));
        assert!(purge.contains("\"scope\": \"public\""));
        assert!(purge.contains("\"purged_entries\": 1"));

        let third = send_http1_request(public_addr, "/catalog").await?;
        assert!(third.contains("count:2"));
        assert_eq!(request_count.load(Ordering::SeqCst), 2);

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn signed_cache_invalidation_endpoint_applies_and_replays_safely() -> Result<(), DynError>
    {
        std::env::set_var("LB_CTL_OPERATOR_READ_SECRET", "reader-secret");
        std::env::set_var("LB_CTL_OPERATOR_AUDIT_SECRET", "auditor-secret");
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let (upstream_addr, request_count) = spawn_counting_http1_upstream().await?;
        let path = write_temp_config(
            "cache-invalidate-endpoint",
            &workspace_config_json_with_admin_policy_and_cache(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let first = send_http1_request(public_addr, "/catalog").await?;
        let second = send_http1_request(public_addr, "/catalog").await?;
        assert!(first.contains("count:1"));
        assert!(second.contains("count:1"));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        let event_body = r#"{"event_id":"node-a-1","scope":"public","issuer":"node-a","target":{"PathPrefix":"/catalog"},"occurred_at_unix_ms":1700000000000}"#;
        let applied = send_signed_admin_json_request(
            admin_addr,
            "writer-secret",
            "writer",
            "/cache/invalidate",
            "cache-invalidate-1",
            event_body,
        )
        .await?;
        assert!(applied.starts_with("HTTP/1.1 200 OK"));
        assert!(applied.contains("\"result\":\"applied\""));
        assert!(applied.contains("\"scope\":\"public\""));

        let third = send_http1_request(public_addr, "/catalog").await?;
        assert!(third.contains("count:2"));
        assert_eq!(request_count.load(Ordering::SeqCst), 2);

        let duplicate = send_signed_admin_json_request(
            admin_addr,
            "writer-secret",
            "writer",
            "/cache/invalidate",
            "cache-invalidate-2",
            event_body,
        )
        .await?;
        assert!(duplicate.starts_with("HTTP/1.1 200 OK"));
        assert!(duplicate.contains("\"result\":\"duplicate\""));

        supervisor.shutdown().await?;
        Ok(())
    }

    fn write_temp_config(prefix: &str, contents: &str) -> Result<PathBuf, DynError> {
        let unique = unique_test_file_suffix()?;
        let path = std::env::temp_dir().join(format!("way-balancer-{prefix}-{unique}.json"));
        fs::write(&path, contents)?;
        Ok(path)
    }

    fn write_temp_secret_file(prefix: &str, contents: &str) -> Result<PathBuf, DynError> {
        let unique = unique_test_file_suffix()?;
        let path = std::env::temp_dir().join(format!("way-balancer-{prefix}-{unique}.secret"));
        fs::write(&path, contents)?;
        Ok(path)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn versioned_status_endpoint_wraps_legacy_payload_in_stable_envelope(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "versioned-status-envelope",
            &workspace_config_json(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let response = send_bearer_admin_request(admin_addr, "GET", "/v1/status", &[], b"").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("X-LB-Admin-Api-Version: v1"));
        let envelope = parse_http_json_body(&response)?;
        assert_eq!(envelope.get("api_version").and_then(serde_json::Value::as_str), Some("v1"));
        assert_eq!(envelope.get("status").and_then(serde_json::Value::as_str), Some("ok"));
        assert_eq!(
            envelope
                .get("data")
                .and_then(|value| value.get("service"))
                .and_then(serde_json::Value::as_str),
            Some("lb-dataplane")
        );
        assert_eq!(
            envelope
                .get("data")
                .and_then(|value| value.get("mode"))
                .and_then(serde_json::Value::as_str),
            Some("workspace")
        );

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn versioned_status_reports_tls_listener_metadata() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("https-status").await?;
        let (cert_path, key_path, _cert_der) = write_temp_tls_identity()?;
        let path = write_temp_config(
            "versioned-status-tls-metadata",
            &workspace_config_json_with_tls(
                "127.0.0.1:0",
                "127.0.0.1:0",
                &upstream_addr.to_string(),
                &cert_path,
                &key_path,
                "tls12",
                &["http11"],
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let response = send_bearer_admin_request(admin_addr, "GET", "/v1/status", &[], b"").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let envelope = parse_http_json_body(&response)?;
        let listeners = envelope
            .get("data")
            .and_then(|value| value.get("listeners"))
            .and_then(serde_json::Value::as_array)
            .ok_or("missing listeners array")?;
        let public_listener = listeners
            .iter()
            .find(|listener| {
                listener.get("class").and_then(serde_json::Value::as_str) == Some("public")
            })
            .ok_or("missing public listener")?;
        let tls = public_listener.get("tls").ok_or("missing tls status")?;

        assert_eq!(tls.get("state").and_then(serde_json::Value::as_str), Some("healthy"));
        assert_eq!(tls.get("minimum_version").and_then(serde_json::Value::as_str), Some("tls12"));
        assert_eq!(
            tls.get("default_certificate")
                .and_then(|value| value.get("cert_path"))
                .and_then(serde_json::Value::as_str),
            Some(cert_path.as_str())
        );
        assert!(tls
            .get("default_certificate")
            .and_then(|value| value.get("fingerprint_sha256"))
            .and_then(serde_json::Value::as_str)
            .is_some());

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bearer_admin_secret_file_rotation_updates_status_and_auth_without_reload(
    ) -> Result<(), DynError> {
        let upstream_addr = spawn_tagged_http1_upstream("admin-secret-rotation").await?;
        let secret_path = write_temp_secret_file("rotating-admin-secret", "initial-secret\n")?;
        let secret_file_path = secret_path.to_string_lossy().into_owned();
        std::env::remove_var("LB_CTL_ROTATING_ADMIN_SECRET");
        std::env::set_var("LB_CTL_ROTATING_ADMIN_SECRET_FILE", &secret_file_path);

        let path = write_temp_config(
            "admin-secret-file-rotation",
            &workspace_config_json_with_admin_policy(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                &bearer_admin_policy_json("LB_CTL_ROTATING_ADMIN_SECRET"),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("legacy-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let initial = send_bearer_admin_request_with_token(
            admin_addr,
            "GET",
            "/v1/status",
            &[],
            b"",
            "initial-secret",
        )
        .await?;
        assert!(initial.starts_with("HTTP/1.1 200 OK"));
        let initial_envelope = parse_http_json_body(&initial)?;
        let secret_sources = initial_envelope
            .get("data")
            .and_then(|value| value.get("admin_auth"))
            .and_then(|value| value.get("secret_sources"))
            .and_then(serde_json::Value::as_array)
            .ok_or("missing secret sources")?;
        assert_eq!(secret_sources.len(), 1);
        assert_eq!(
            secret_sources[0].get("source_kind").and_then(serde_json::Value::as_str),
            Some("file")
        );
        assert_eq!(
            secret_sources[0].get("source_reference").and_then(serde_json::Value::as_str),
            Some(secret_file_path.as_str())
        );
        assert_eq!(
            secret_sources[0]
                .get("supports_rotation_without_reload")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            secret_sources[0].get("healthy").and_then(serde_json::Value::as_bool),
            Some(true)
        );

        fs::write(&secret_path, b"rotated-secret\n")?;

        let stale = send_bearer_admin_request_with_token(
            admin_addr,
            "GET",
            "/v1/status",
            &[],
            b"",
            "initial-secret",
        )
        .await?;
        assert!(stale.starts_with("HTTP/1.1 401 Unauthorized"));

        let rotated = send_bearer_admin_request_with_token(
            admin_addr,
            "GET",
            "/v1/status",
            &[],
            b"",
            "rotated-secret",
        )
        .await?;
        assert!(rotated.starts_with("HTTP/1.1 200 OK"));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unsupported_admin_api_version_returns_machine_readable_error() -> Result<(), DynError>
    {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream_addr = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "unsupported-admin-api-version",
            &workspace_config_json(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let response = send_bearer_admin_request(admin_addr, "GET", "/v2/status", &[], b"").await?;
        assert!(response.starts_with("HTTP/1.1 406 Not Acceptable"));
        let envelope = parse_http_json_body(&response)?;
        assert_eq!(envelope.get("api_version").and_then(serde_json::Value::as_str), Some("v1"));
        assert_eq!(envelope.get("status").and_then(serde_json::Value::as_str), Some("error"));
        assert_eq!(
            envelope
                .get("error")
                .and_then(|value| value.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("unsupported_api_version")
        );

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn versioned_reload_failure_uses_typed_unsupported_mutation_error() -> Result<(), DynError>
    {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let public_bind = reserve_unused_addr().await?;
        let upstream_addr = spawn_tagged_http1_upstream("upstream-a").await?;
        let path = write_temp_config(
            "versioned-reload-unsupported-mutation",
            &workspace_config_json(
                &public_bind.to_string(),
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let admin_addr = supervisor
            .listener_statuses()
            .await
            .into_iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        fs::write(
            &path,
            workspace_config_json(
                &public_bind.to_string(),
                "127.0.0.1:0",
                "http2",
                &upstream_addr.to_string(),
            ),
        )?;

        let reload = send_bearer_admin_request(admin_addr, "POST", "/v1/reload", &[], b"").await?;
        assert!(reload.starts_with("HTTP/1.1 500 Internal Server Error"));
        let reload_envelope = parse_http_json_body(&reload)?;
        assert_eq!(
            reload_envelope
                .get("error")
                .and_then(|value| value.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("unsupported_mutation")
        );

        let status = send_bearer_admin_request(admin_addr, "GET", "/v1/status", &[], b"").await?;
        let status_envelope = parse_http_json_body(&status)?;
        assert_eq!(
            status_envelope
                .get("data")
                .and_then(|value| value.get("last_reload_outcome_code"))
                .and_then(serde_json::Value::as_str),
            Some("reload_failed_blocked_change")
        );

        supervisor.shutdown().await?;
        Ok(())
    }

    fn workspace_config_json(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
    ) -> String {
        workspace_config_json_with_limits(
            public_addr,
            admin_addr,
            public_protocol,
            upstream_addr,
            128,
            128,
        )
    }

    fn workspace_config_json_with_bind_mode(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        public_bind_mode: &str,
        allow_unspecified_bind: bool,
    ) -> String {
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "bind_mode": "{public_bind_mode}",
            "allow_unspecified_bind": {allow_unspecified_bind},
            "protocol": "{public_protocol}",
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
        )
    }

    fn workspace_config_json_with_proxy_protocol(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        proxy_protocol: &str,
    ) -> String {
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "proxy_protocol": "{proxy_protocol}",
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
        )
    }

    fn workspace_config_json_with_proxy_protocol_and_trusted_client_ip(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        proxy_protocol: &str,
        trusted_proxy_cidrs: &[&str],
    ) -> String {
        let trusted_proxy_cidrs = trusted_proxy_cidrs
            .iter()
            .map(|cidr| format!("\"{cidr}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "proxy_protocol": "{proxy_protocol}",
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ],
    "security": {{
        "trusted_client_ip": {{
            "enabled": true,
            "trusted_proxy_cidrs": [{trusted_proxy_cidrs}]
        }}
    }}
}}"#
        )
    }

    fn workspace_config_json_with_drain_timeout(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        drain_timeout_ms: u64,
    ) -> String {
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "max_connections": 128,
            "drain_timeout_ms": {drain_timeout_ms},
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "max_connections": 128,
            "protocol": "http1",
            "drain_timeout_ms": {drain_timeout_ms}
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
        )
    }

    fn workspace_config_json_with_admin_policy(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        admin_policy_json: &str,
    ) -> String {
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"{admin_policy_json}
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
        )
    }

    fn workspace_config_json_with_admin_policy_and_cache(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        admin_policy_json: &str,
    ) -> String {
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"{admin_policy_json}
        }}
    ],
    "routes": [
        {{
            "name": "web",
            "match": {{ "type": "path_prefix", "prefix": "/catalog" }},
            "upstream_cluster": "frontend",
            "policies": {{ "cache_policy": "public-cache" }}
        }}
    ],
    "upstream_clusters": [
        {{
            "name": "frontend",
            "endpoints": [
                {{
                    "id": "frontend-a",
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ],
    "policies": {{
        "http_caches": [
            {{
                "name": "public-cache",
                "spec": {{
                    "methods": ["get", "head"],
                    "default_ttl_secs": 60,
                    "max_ttl_secs": 300,
                    "stale_while_revalidate_secs": 30,
                    "stale_if_error_secs": 60,
                    "cacheable_status_codes": [200],
                    "vary_headers": [],
                    "max_object_bytes": 262144,
                    "honor_cache_control": true,
                    "allow_set_cookie_storage": false,
                    "authorization": "bypass",
                    "revalidation_enabled": true,
                    "purge_enabled": true,
                    "cache_key": {{
                        "include_host": true,
                        "include_method": false,
                        "query": "include_all",
                        "headers": []
                    }},
                    "storage": {{
                        "type": "memory",
                        "max_entries": 256,
                        "max_bytes": 1048576
                    }}
                }}
            }}
        ]
    }}
}}"#
        )
    }

    fn signed_headers_admin_policy_json() -> &'static str {
        r#",
            "admin": {
                "auth": {
                    "mode": "signed_headers",
                    "operators": [
                        {
                            "id": "reader",
                            "secret_env": "LB_CTL_OPERATOR_READ_SECRET",
                            "permissions": ["read"]
                        },
                        {
                            "id": "auditor",
                            "secret_env": "LB_CTL_OPERATOR_AUDIT_SECRET",
                            "permissions": ["audit"]
                        },
                        {
                            "id": "writer",
                            "secret_env": "LB_CTL_OPERATOR_WRITE_SECRET",
                            "permissions": ["read", "audit", "write"]
                        }
                    ],
                    "max_clock_skew_secs": 30,
                    "nonce_ttl_secs": 120
                },
                "audit": {
                    "max_retained_events": 16
                }
            }"#
    }

    fn bearer_admin_policy_json(secret_env: &str) -> String {
        format!(
            r#", 
            "admin": {{
                "auth": {{
                    "mode": "bearer",
                    "secret_env": "{secret_env}",
                    "permissions": ["read", "audit", "write"]
                }},
                "audit": {{
                    "max_retained_events": 16
                }}
            }}"#
        )
    }

    fn workspace_config_json_with_limits(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        public_max_connections: usize,
        admin_max_connections: usize,
    ) -> String {
        format!(
            r#"{{
  "api_version": "v1_alpha1",
  "name": "workspace-runtime",
  "listeners": [
    {{
      "name": "public",
      "class": "public",
      "bind_address": "{public_addr}",
      "protocol": "{public_protocol}",
            "max_connections": {public_max_connections},
      "routes": ["web"]
    }},
    {{
      "name": "admin",
      "class": "admin",
      "bind_address": "{admin_addr}",
            "max_connections": {admin_max_connections},
      "protocol": "http1"
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
          "address": "{upstream_addr}",
          "state": "ready",
          "zone": null,
          "locality": null,
          "weight": 1
        }}
      ]
    }}
  ]
}}"#
        )
    }

    fn workspace_config_json_with_upstream_endpoints(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        endpoints: &[(String, String)],
    ) -> String {
        let endpoints_json = endpoints
            .iter()
            .map(|(id, address)| {
                format!(
                    r#"        {{
                    "id": "{}",
                    "address": "{}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}"#,
                    id.as_str(),
                    address.as_str(),
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "routes": ["web"]
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
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
{endpoints_json}
            ]
        }}
    ]
}}"#
        )
    }

    fn workspace_config_json_with_listener_overload_policy(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        public_max_connections: usize,
        admin_max_connections: usize,
        policy_name: &str,
        brownout_features: &[&str],
    ) -> String {
        let brownout_features_json = brownout_features
            .iter()
            .map(|feature| format!("{{ \"name\": \"{feature}\", \"priority\": \"best_effort\" }}"))
            .collect::<Vec<_>>()
            .join(", ");

        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "max_connections": {public_max_connections},
            "routes": ["web"],
            "policies": {{
                "overload_response": "{policy_name}"
            }}
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "max_connections": {admin_max_connections},
            "protocol": "http1"
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ],
    "policies": {{
        "overload_responses": [
            {{
                "name": "{policy_name}",
                "spec": {{
                    "signal_window_ms": 10000,
                    "constrained_signal_threshold": 1,
                    "shedding_signal_threshold": 1,
                    "brownout_signal_threshold": 1,
                    "brownout_features": [{brownout_features_json}]
                }}
            }}
        ]
    }}
}}"#,
        )
    }

    fn workspace_config_json_with_hostile_edge_policy(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        policy_name: &str,
        max_active_per_source: usize,
        max_tracked_sources: usize,
        max_inflight_handshakes: usize,
    ) -> String {
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "routes": ["web"],
            "policies": {{
                "hostile_edge_protection": "{policy_name}"
            }}
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ],
    "policies": {{
        "hostile_edge_protections": [
            {{
                "name": "{policy_name}",
                "spec": {{
                    "source_quota": {{
                        "aggregation": "exact_ip",
                        "max_active_per_source": {max_active_per_source},
                        "max_tracked_sources": {max_tracked_sources}
                    }},
                    "handshake_guard": {{
                        "max_inflight": {max_inflight_handshakes},
                        "timeout_ms": 5000
                    }}
                }}
            }}
        ]
    }}
}}"#,
        )
    }

    fn workspace_config_json_with_hostile_edge_policy_and_proxy_protocol(
        public_addr: &str,
        admin_addr: &str,
        public_protocol: &str,
        upstream_addr: &str,
        policy_name: &str,
        proxy_protocol: &str,
        max_active_per_source: usize,
        max_tracked_sources: usize,
        max_inflight_handshakes: usize,
    ) -> String {
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "{public_protocol}",
            "proxy_protocol": "{proxy_protocol}",
            "routes": ["web"],
            "policies": {{
                "hostile_edge_protection": "{policy_name}"
            }}
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ],
    "policies": {{
        "hostile_edge_protections": [
            {{
                "name": "{policy_name}",
                "spec": {{
                    "source_quota": {{
                        "aggregation": "exact_ip",
                        "max_active_per_source": {max_active_per_source},
                        "max_tracked_sources": {max_tracked_sources}
                    }},
                    "handshake_guard": {{
                        "max_inflight": {max_inflight_handshakes},
                        "timeout_ms": 5000
                    }}
                }}
            }}
        ]
    }}
}}"#,
        )
    }

    fn workspace_config_json_with_tls(
        public_addr: &str,
        admin_addr: &str,
        upstream_addr: &str,
        cert_path: &str,
        key_path: &str,
        minimum_version: &str,
        alpn_protocols: &[&str],
    ) -> String {
        workspace_config_json_with_tls_and_sni(
            public_addr,
            admin_addr,
            upstream_addr,
            cert_path,
            key_path,
            minimum_version,
            alpn_protocols,
            &[],
        )
    }

    fn workspace_config_json_with_http3_tls(
        public_addr: &str,
        admin_addr: &str,
        upstream_addr: &str,
        cert_path: &str,
        key_path: &str,
    ) -> String {
        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "http3",
            "routes": ["web"],
            "tls_termination": {{
                "minimum_version": "tls13",
                "alpn_protocols": ["http3"],
                "certificate_source": {{
                    "type": "files",
                    "cert_path": "{cert_path}",
                    "key_path": "{key_path}"
                }}
            }}
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#,
        )
    }

    fn workspace_config_json_with_tls_and_sni(
        public_addr: &str,
        admin_addr: &str,
        upstream_addr: &str,
        cert_path: &str,
        key_path: &str,
        minimum_version: &str,
        alpn_protocols: &[&str],
        sni_certificates: &[(Vec<&str>, &str, &str)],
    ) -> String {
        let alpn_json = alpn_protocols
            .iter()
            .map(|protocol| format!("\"{protocol}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let sni_json = if sni_certificates.is_empty() {
            String::from("[]")
        } else {
            format!(
                "[{}]",
                sni_certificates
                    .iter()
                    .map(|(server_names, cert_path, key_path)| {
                        let server_names_json = server_names
                            .iter()
                            .map(|name| format!("\"{name}\""))
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!(
                            "{{\n                    \"server_names\": [{server_names_json}],\n                    \"certificate_source\": {{\n                        \"type\": \"files\",\n                        \"cert_path\": \"{cert_path}\",\n                        \"key_path\": \"{key_path}\"\n                    }}\n                }}"
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        format!(
            r#"{{
    "api_version": "v1_alpha1",
    "name": "workspace-runtime",
    "listeners": [
        {{
            "name": "public",
            "class": "public",
            "bind_address": "{public_addr}",
            "protocol": "https",
            "routes": ["web"],
            "tls_termination": {{
                "minimum_version": "{minimum_version}",
                "alpn_protocols": [{alpn_json}],
                "sni_certificates": {sni_json},
                "certificate_source": {{
                    "type": "files",
                    "cert_path": "{cert_path}",
                    "key_path": "{key_path}"
                }}
            }}
        }},
        {{
            "name": "admin",
            "class": "admin",
            "bind_address": "{admin_addr}",
            "protocol": "http1"
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
                    "address": "{upstream_addr}",
                    "state": "ready",
                    "zone": null,
                    "locality": null,
                    "weight": 1
                }}
            ]
        }}
    ]
}}"#
        )
    }

    fn write_temp_tls_identity() -> Result<(String, String, Vec<u8>), DynError> {
        write_temp_tls_identity_for_host("localhost")
    }

    fn write_temp_tls_identity_for_host(host: &str) -> Result<(String, String, Vec<u8>), DynError> {
        let certified =
            generate_simple_self_signed(vec![host.to_string()]).map_err(to_dyn_error)?;
        let cert_pem = certified.cert.pem();
        let cert_der = certified.cert.der().to_vec();
        let key_pem = certified.key_pair.serialize_pem();
        let unique = unique_test_file_suffix()?;
        let cert_path = std::env::temp_dir().join(format!("way-balancer-cert-{host}-{unique}.pem"));
        let key_path = std::env::temp_dir().join(format!("way-balancer-key-{host}-{unique}.pem"));
        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;
        Ok((
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
            cert_der,
        ))
    }

    async fn spawn_tagged_http1_upstream(body: &'static str) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        spawn_http1_listener(listener, body);
        Ok(address)
    }

    async fn spawn_tagged_http1_upstream_on(
        address: SocketAddr,
        body: &'static str,
    ) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        spawn_http1_listener(listener, body);
        Ok(address)
    }

    fn spawn_http1_listener(listener: TcpListener, body: &'static str) {
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 2048];
                    let _ = stream.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
    }

    async fn spawn_counting_http1_upstream() -> io::Result<(SocketAddr, Arc<AtomicU64>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let counter = Arc::new(AtomicU64::new(0));
        let counter_for_task = Arc::clone(&counter);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = Arc::clone(&counter_for_task);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 2048];
                    let _ = stream.read(&mut buffer).await;
                    let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    let body = format!("count:{count}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok((address, counter))
    }

    async fn spawn_capture_http1_upstream() -> io::Result<(SocketAddr, oneshot::Receiver<String>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (capture_tx, capture_rx) = oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = [0_u8; 4096];
            let bytes_read = stream.read(&mut buffer).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..bytes_read]).into_owned();
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = stream.write_all(response).await;
            let _ = stream.shutdown().await;
            let _ = capture_tx.send(request);
        });
        Ok((address, capture_rx))
    }

    async fn spawn_blocked_http1_upstream(
        body: &'static str,
    ) -> io::Result<(SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        Ok((address, accepted_rx, release_tx))
    }

    async fn spawn_block_first_then_count_http1_upstream(
    ) -> io::Result<(SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>, Arc<AtomicU64>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let counter = Arc::new(AtomicU64::new(0));
        let counter_for_task = Arc::clone(&counter);

        tokio::spawn(async move {
            let Ok((mut first_stream, _)) = listener.accept().await else {
                return;
            };
            let first_counter = Arc::clone(&counter_for_task);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 2048];
                let _ = first_stream.read(&mut buffer).await;
                let count = first_counter.fetch_add(1, Ordering::SeqCst) + 1;
                let _ = accepted_tx.send(());
                let _ = release_rx.await;
                let body = format!("count:{count}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = first_stream.write_all(response.as_bytes()).await;
                let _ = first_stream.shutdown().await;
            });

            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = Arc::clone(&counter_for_task);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 2048];
                    let _ = stream.read(&mut buffer).await;
                    let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    let body = format!("count:{count}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Ok((address, accepted_rx, release_tx, counter))
    }

    async fn spawn_tagged_h2_upstream(body: &'static str) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let mut connection = match server::handshake(stream).await {
                    Ok(connection) => connection,
                    Err(_) => return,
                };

                while let Some(result) = connection.accept().await {
                    let Ok((_request, mut respond)) = result else {
                        break;
                    };
                    let response = Response::builder().status(StatusCode::OK).body(());
                    if let Ok(response) = response {
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from(body.to_string()), true);
                        }
                    }
                }
            }
        });
        Ok(address)
    }

    async fn connect_h2_client(
        address: SocketAddr,
    ) -> Result<h2_client::SendRequest<Bytes>, DynError> {
        let stream = TcpStream::connect(address).await?;
        let (client, connection) = h2_client::handshake(stream).await.map_err(to_dyn_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    async fn send_h2_request(
        client: &mut h2_client::SendRequest<Bytes>,
        path: &str,
    ) -> Result<h2::client::ResponseFuture, h2::Error> {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .body(())
            .map_err(|_| h2::Reason::INTERNAL_ERROR)?;
        let (response, _) = client.send_request(request, true)?;
        Ok(response)
    }

    async fn receive_h2_response(
        response: h2::client::ResponseFuture,
    ) -> Result<(StatusCode, String), DynError> {
        let response = response.await.map_err(to_dyn_error)?;
        let status = response.status();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(to_dyn_error)?;
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, String::from_utf8(bytes).map_err(to_dyn_error)?))
    }

    async fn send_http1_request(address: SocketAddr, target: &str) -> Result<String, DynError> {
        let mut stream = start_http1_request(address, target).await?;
        let mut response = Vec::new();
        match stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => return Err(to_dyn_error(error)),
        }
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn send_prefixed_http1_request(
        address: SocketAddr,
        prefix: &[u8],
        target: &str,
    ) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(prefix).await?;
        stream
            .write_all(
                format!(
                    "GET {target} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        match stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => return Err(to_dyn_error(error)),
        }
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn send_prefixed_http1_request_with_headers(
        address: SocketAddr,
        prefix: &[u8],
        target: &str,
        headers: &[(&str, &str)],
    ) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(prefix).await?;
        let extra_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect::<String>();
        stream
            .write_all(
                format!(
                    "GET {target} HTTP/1.1\r\nHost: example.test\r\n{extra_headers}Connection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        match stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => return Err(to_dyn_error(error)),
        }
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn start_prefixed_http1_request(
        address: SocketAddr,
        prefix: &[u8],
        target: &str,
    ) -> Result<TcpStream, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(prefix).await?;
        stream
            .write_all(
                format!(
                    "GET {target} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        Ok(stream)
    }

    async fn start_http1_request(address: SocketAddr, target: &str) -> Result<TcpStream, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        Ok(stream)
    }

    async fn send_admin_reload(address: SocketAddr) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"POST /reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn send_admin_status(address: SocketAddr) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn send_admin_readyz(address: SocketAddr) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn send_admin_audit(address: SocketAddr) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /audit HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn send_admin_validate(address: SocketAddr) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /validate HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn send_bearer_admin_request(
        address: SocketAddr,
        method: &str,
        target: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<String, DynError> {
        send_bearer_admin_request_with_token(
            address,
            method,
            target,
            extra_headers,
            body,
            "admin-secret",
        )
        .await
    }

    async fn send_bearer_admin_request_with_token(
        address: SocketAddr,
        method: &str,
        target: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
        bearer_token: &str,
    ) -> Result<String, DynError> {
        let mut request = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer_token}\r\nConnection: close\r\n"
        );
        for (name, value) in extra_headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));

        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(body);
        send_admin_request_bytes(address, &bytes).await
    }

    fn parse_http_json_body(response: &str) -> Result<serde_json::Value, DynError> {
        let (_, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| to_dyn_error("http response did not contain a header/body separator"))?;
        serde_json::from_str(body).map_err(to_dyn_error)
    }

    fn json_u64_field(value: &serde_json::Value, key: &str) -> Result<u64, DynError> {
        value
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| to_dyn_error(format!("missing u64 field: {key}")))
    }

    async fn send_signed_admin_request(
        address: SocketAddr,
        secret: &str,
        actor: &str,
        method: &str,
        target: &str,
        nonce: &str,
    ) -> Result<String, DynError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        send_signed_admin_request_with_timestamp(
            address, secret, actor, method, target, timestamp, nonce,
        )
        .await
    }

    async fn send_signed_admin_request_with_timestamp(
        address: SocketAddr,
        secret: &str,
        actor: &str,
        method: &str,
        target: &str,
        timestamp: u64,
        nonce: &str,
    ) -> Result<String, DynError> {
        let signature = sign_admin_request(secret, actor, method, target, timestamp, nonce, b"");
        let request = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\nX-LB-Admin-Actor: {actor}\r\nX-LB-Admin-Timestamp: {timestamp}\r\nX-LB-Admin-Nonce: {nonce}\r\nX-LB-Admin-Signature: {signature}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        send_admin_request_bytes(address, request.as_bytes()).await
    }

    async fn send_admin_json_request(
        address: SocketAddr,
        target: &str,
        body: &str,
    ) -> Result<String, DynError> {
        let request = format!(
            "POST {target} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        send_admin_request_bytes(address, request.as_bytes()).await
    }

    async fn send_signed_admin_json_request(
        address: SocketAddr,
        secret: &str,
        actor: &str,
        target: &str,
        nonce: &str,
        body: &str,
    ) -> Result<String, DynError> {
        send_signed_admin_json_request_with_signed_body(
            address, secret, actor, target, nonce, body, body,
        )
        .await
    }

    async fn send_signed_admin_json_request_with_signed_body(
        address: SocketAddr,
        secret: &str,
        actor: &str,
        target: &str,
        nonce: &str,
        signed_body: &str,
        body: &str,
    ) -> Result<String, DynError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let signature = sign_admin_request(
            secret,
            actor,
            "POST",
            target,
            timestamp,
            nonce,
            signed_body.as_bytes(),
        );
        let request = format!(
            "POST {target} HTTP/1.1\r\nHost: localhost\r\nX-LB-Admin-Actor: {actor}\r\nX-LB-Admin-Timestamp: {timestamp}\r\nX-LB-Admin-Nonce: {nonce}\r\nX-LB-Admin-Signature: {signature}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        send_admin_request_bytes(address, request.as_bytes()).await
    }

    async fn send_admin_request_bytes(
        address: SocketAddr,
        request: &[u8],
    ) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request).await?;
        let mut response = Vec::new();
        match stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => return Err(to_dyn_error(error)),
        }
        String::from_utf8(response).map_err(to_dyn_error)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn signed_cache_invalidation_rejects_body_tampering() -> Result<(), DynError> {
        std::env::set_var("LB_CTL_OPERATOR_READ_SECRET", "reader-secret");
        std::env::set_var("LB_CTL_OPERATOR_AUDIT_SECRET", "auditor-secret");
        std::env::set_var("LB_CTL_OPERATOR_WRITE_SECRET", "writer-secret");
        let (upstream_addr, request_count) = spawn_counting_http1_upstream().await?;
        let path = write_temp_config(
            "cache-invalidate-body-tamper",
            &workspace_config_json_with_admin_policy_and_cache(
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_addr.to_string(),
                signed_headers_admin_policy_json(),
            ),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let statuses = supervisor.listener_statuses().await;
        let public_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = statuses
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let first = send_http1_request(public_addr, "/catalog").await?;
        let second = send_http1_request(public_addr, "/catalog").await?;
        assert!(first.contains("count:1"));
        assert!(second.contains("count:1"));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        let signed_body = r#"{"event_id":"node-a-1","scope":"public","issuer":"node-a","target":{"PathPrefix":"/catalog"},"occurred_at_unix_ms":1700000000000}"#;
        let tampered_body = r#"{"event_id":"node-a-1","scope":"public","issuer":"node-a","target":{"PathPrefix":"/admin"},"occurred_at_unix_ms":1700000000000}"#;
        let response = send_signed_admin_json_request_with_signed_body(
            admin_addr,
            "writer-secret",
            "writer",
            "/cache/invalidate",
            "cache-invalidate-body-tamper",
            signed_body,
            tampered_body,
        )
        .await?;
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(response.contains("signed admin authorization required"));

        let third = send_http1_request(public_addr, "/catalog").await?;
        assert!(third.contains("count:1"));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        supervisor.shutdown().await?;
        Ok(())
    }

    async fn reserve_unused_addr() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        drop(listener);
        Ok(address)
    }

    async fn send_https_http1_request(
        address: SocketAddr,
        cert_der: &[u8],
        server_name: &str,
        target: &str,
    ) -> Result<String, DynError> {
        send_https_http1_request_with_roots(address, &[cert_der.to_vec()], server_name, target)
            .await
    }

    async fn send_https_http1_request_with_roots(
        address: SocketAddr,
        cert_ders: &[Vec<u8>],
        server_name: &str,
        target: &str,
    ) -> Result<String, DynError> {
        send_https_http1_request_with_policy(
            address,
            cert_ders,
            server_name,
            target,
            &[&rustls::version::TLS13, &rustls::version::TLS12],
            &[b"http/1.1"],
        )
        .await
    }

    async fn send_https_http1_request_with_policy(
        address: SocketAddr,
        cert_ders: &[Vec<u8>],
        server_name: &str,
        target: &str,
        protocol_versions: &[&'static rustls::SupportedProtocolVersion],
        alpn_protocols: &[&[u8]],
    ) -> Result<String, DynError> {
        let mut root_store = RootCertStore::empty();
        for cert_der in cert_ders {
            root_store.add(CertificateDer::from(cert_der.clone())).map_err(to_dyn_error)?;
        }
        let mut client_config = RustlsClientConfig::builder_with_protocol_versions(protocol_versions)
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols =
            alpn_protocols.iter().map(|protocol| protocol.to_vec()).collect();
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(address).await?;
        let server_name = ServerName::try_from(server_name.to_string()).map_err(to_dyn_error)?;
        let mut tls_stream = connector.connect(server_name, stream).await.map_err(to_dyn_error)?;
        tls_stream
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        match tls_stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::UnexpectedEof
                    && error.to_string().contains("close_notify") => {}
            Err(error) => return Err(to_dyn_error(error)),
        }
        String::from_utf8(response).map_err(to_dyn_error)
    }

    async fn send_http3_request(
        address: SocketAddr,
        cert_der: &[u8],
        server_name: &str,
        target: &str,
    ) -> Result<(u16, String), DynError> {
        ensure_rustls_crypto_provider();
        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der.to_vec())).map_err(to_dyn_error)?;
        let mut tls_config = RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        let quic_config = QuicClientConfig::try_from(Arc::new(tls_config)).map_err(to_dyn_error)?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_config));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(address, server_name)
            .map_err(|error| to_dyn_error(format!("http3 connect setup failed: {error}")))?
            .await
            .map_err(|error| to_dyn_error(format!("http3 connect failed: {error}")))?;
        let (_driver, mut send_request) = h3_client::new(h3_quinn::Connection::new(connection))
            .await
            .map_err(|error| to_dyn_error(format!("http3 client handshake failed: {error}")))?;

        let request = http1::Request::builder()
            .method("GET")
            .uri(format!("https://{server_name}{target}"))
            .body(())
            .map_err(to_dyn_error)?;
        let mut request_stream = send_request
            .send_request(request)
            .await
            .map_err(|error| to_dyn_error(format!("http3 send request failed: {error}")))?;
        request_stream
            .finish()
            .await
            .map_err(|error| to_dyn_error(format!("http3 request finish failed: {error}")))?;
        let response = request_stream
            .recv_response()
            .await
            .map_err(|error| to_dyn_error(format!("http3 recv response failed: {error}")))?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        while let Some(mut chunk) = request_stream
            .recv_data()
            .await
            .map_err(|error| to_dyn_error(format!("http3 recv body failed: {error}")))?
        {
            let chunk_bytes = chunk.copy_to_bytes(chunk.remaining());
            body.extend_from_slice(&chunk_bytes);
        }

        endpoint.close(0u32.into(), b"done");
        Ok((status, String::from_utf8(body).map_err(to_dyn_error)?))
    }
}
