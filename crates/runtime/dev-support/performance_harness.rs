#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h2::{client, server, Reason};
use h3::server as h3_server;
use http::{Request, Response, StatusCode};
use http1::Response as Http3Response;
use lb_net_core::{
    EndpointMetadata, EndpointState, ListenerClass, ListenerConfig, UpstreamCluster,
    UpstreamClusterName, UpstreamEndpoint, UpstreamEndpointId, UpstreamTarget, UpstreamTransport,
};
use lb_runtime::{
    clear_http3_test_root_certificates, execute_with_hedge,
    set_http3_test_root_certificates,
    proxy_http1_connection, proxy_http1_connection_with_downstream_addr, proxy_http2_connection,
    start_listener, DiscoveryEndpoint,
    DiscoveryMembershipReconciler, DiscoveryProviderKind, DiscoverySnapshot, DiscoverySourceId,
    EndpointHealthPolicy, Http1ConnectionReport, Http1ProxyConfig, Http1ProxyError,
    Http2ConnectionReport, Http2ProxyConfig, Http2ProxyError, ListenerHandle,
    OverloadState, RequestClassificationAdapterContext,
    RequestClassificationAdaptiveMitigationPolicy, RequestClassificationAuthContext,
    RequestClassificationEnforcementPolicy, RequestClassificationPolicyRuntime,
    RequestHedgingPolicy, SheddingAction, SheddingDecision, UpstreamHealthRegistry,
};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

const HTTP1_BENCH_BODY: &str = "bench-http1";
const HTTP2_BENCH_BODY: &str = "bench-http2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeMode {
    Smoke,
    Full,
}

impl EnvelopeMode {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "smoke" => Some(Self::Smoke),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    #[must_use]
    pub fn scenario(self) -> ScenarioConfig {
        match self {
            Self::Smoke => ScenarioConfig {
                http1_requests: 64,
                http2_streams: 64,
                mixed_operations: 64,
                idle_connections: 24,
                active_streams: 24,
                hedging_iterations: 24,
                abuse_decisions: 64,
                discovery_updates: 24,
                http3_bridge_requests: 12,
            },
            Self::Full => ScenarioConfig {
                http1_requests: 256,
                http2_streams: 256,
                mixed_operations: 256,
                idle_connections: 64,
                active_streams: 64,
                hedging_iterations: 96,
                abuse_decisions: 256,
                discovery_updates: 96,
                http3_bridge_requests: 48,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceClaimTier {
    Experimental,
    Supported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentProfile {
    LoopbackRegressionV1,
    LabSmallNonLoopbackV1,
}

impl DeploymentProfile {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "loopback_regression_v1" => Some(Self::LoopbackRegressionV1),
            "lab_small_non_loopback_v1" => Some(Self::LabSmallNonLoopbackV1),
            _ => None,
        }
    }

    #[must_use]
    pub fn spec(self) -> DeploymentProfileSpec {
        match self {
            Self::LoopbackRegressionV1 => DeploymentProfileSpec {
                name: String::from("loopback_regression_v1"),
                claim_tier: PerformanceClaimTier::Experimental,
                summary: String::from(
                    "fast local regression profile for loopback-only throughput, latency, and memory trend detection",
                ),
                host_class: HostClassSpec {
                    label: String::from("developer_loopback_host"),
                    cpu_cores: None,
                    memory_gib: None,
                    nic_gbps: None,
                },
                network_profile: NetworkProfileSpec {
                    label: String::from("loopback_only"),
                    path: String::from("single-host local sockets"),
                    expected_rtt_ms: Some(0.1),
                },
                tls_mode: String::from("rustls_terminated_downstream_optional"),
                connection_mix: String::from("http1_batch + http2_stream_batch + mixed interleaved"),
                request_payload_bytes: 0,
                hostile_edge_posture: String::from("not a supported external capacity claim"),
                supported_envelope: None,
                regression_guardrails: RegressionGuardrails::default(),
                evidence_requirements: vec![
                    String::from("use this profile for relative regressions only"),
                    String::from("do not treat loopback-only numbers as supportable customer capacity claims"),
                ],
            },
            Self::LabSmallNonLoopbackV1 => DeploymentProfileSpec {
                name: String::from("lab_small_non_loopback_v1"),
                claim_tier: PerformanceClaimTier::Supported,
                summary: String::from(
                    "initial supported small-host non-loopback profile for release evidence and conservative capacity claims",
                ),
                host_class: HostClassSpec {
                    label: String::from("small_host_v1"),
                    cpu_cores: Some(4),
                    memory_gib: Some(16),
                    nic_gbps: Some(10),
                },
                network_profile: NetworkProfileSpec {
                    label: String::from("single_az_non_loopback"),
                    path: String::from("client host to dataplane host over dedicated lab network"),
                    expected_rtt_ms: Some(1.5),
                },
                tls_mode: String::from("tls_terminated_downstream_with_hostile_edge_controls_enabled"),
                connection_mix: String::from("http1 + http2 + persistent mixed traffic with reload and failover timing evidence"),
                request_payload_bytes: 1024,
                hostile_edge_posture: String::from(
                    "source quota and handshake guard enabled during supported envelope validation",
                ),
                supported_envelope: Some(SupportedEnvelopeThresholds {
                    min_http1_ops_per_sec: 2_500.0,
                    min_http2_ops_per_sec: 8_000.0,
                    max_mixed_p50_us: 5_000,
                    max_mixed_p95_us: 12_000,
                    max_mixed_p99_us: 20_000,
                    max_idle_connection_rss_kib_per_unit: 16.0,
                    max_http2_stream_rss_kib_per_unit: 24.0,
                    max_reload_success_ms: 5_000,
                    max_reload_degraded_success_ms: 15_000,
                    max_failover_ms: 3_000,
                }),
                regression_guardrails: RegressionGuardrails::default(),
                evidence_requirements: vec![
                    String::from("record the measured reload timing from GET /status reload_last_success_duration_ms"),
                    String::from("record degraded-success timing when reload_applied_overlap_drain_timeout occurs"),
                    String::from("record failover timing from the supported lab procedure before promoting claims to release evidence"),
                ],
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostClassSpec {
    pub label: String,
    pub cpu_cores: Option<usize>,
    pub memory_gib: Option<usize>,
    pub nic_gbps: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkProfileSpec {
    pub label: String,
    pub path: String,
    pub expected_rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeploymentProfileSpec {
    pub name: String,
    pub claim_tier: PerformanceClaimTier,
    pub summary: String,
    pub host_class: HostClassSpec,
    pub network_profile: NetworkProfileSpec,
    pub tls_mode: String,
    pub connection_mix: String,
    pub request_payload_bytes: usize,
    pub hostile_edge_posture: String,
    pub supported_envelope: Option<SupportedEnvelopeThresholds>,
    pub regression_guardrails: RegressionGuardrails,
    pub evidence_requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SupportedEnvelopeThresholds {
    pub min_http1_ops_per_sec: f64,
    pub min_http2_ops_per_sec: f64,
    pub max_mixed_p50_us: u64,
    pub max_mixed_p95_us: u64,
    pub max_mixed_p99_us: u64,
    pub max_idle_connection_rss_kib_per_unit: f64,
    pub max_http2_stream_rss_kib_per_unit: f64,
    pub max_reload_success_ms: u64,
    pub max_reload_degraded_success_ms: u64,
    pub max_failover_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionGuardrails {
    pub max_throughput_drop_pct: f64,
    pub max_latency_increase_pct: f64,
    pub max_memory_growth_pct: f64,
    pub max_timing_regression_pct: f64,
}

impl Default for RegressionGuardrails {
    fn default() -> Self {
        Self {
            max_throughput_drop_pct: 15.0,
            max_latency_increase_pct: 20.0,
            max_memory_growth_pct: 15.0,
            max_timing_regression_pct: 10.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ControlPlaneTimingEvidence {
    pub reload_success_ms: Option<u64>,
    pub reload_degraded_success_ms: Option<u64>,
    pub failover_ms: Option<u64>,
    pub evidence_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Failed,
    NotEvaluated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdCheck {
    pub metric: String,
    pub unit: String,
    pub comparator: String,
    pub expected: f64,
    pub actual: Option<f64>,
    pub status: CheckStatus,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdEvaluation {
    pub claim_tier: PerformanceClaimTier,
    pub supported_claim_ready: bool,
    pub checks: Vec<ThresholdCheck>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineComparisonCheck {
    pub metric: String,
    pub unit: String,
    pub baseline: Option<f64>,
    pub candidate: Option<f64>,
    pub regression_pct: Option<f64>,
    pub allowed_regression_pct: f64,
    pub status: CheckStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub baseline_profile: String,
    pub baseline_mode: EnvelopeMode,
    pub passed: bool,
    pub checks: Vec<BaselineComparisonCheck>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceEnvelopeArtifact {
    pub schema_version: String,
    pub generated_at_unix_ms: u64,
    pub profile: DeploymentProfileSpec,
    pub report: PerformanceEnvelopeReport,
    pub control_plane_timing: ControlPlaneTimingEvidence,
    pub threshold_evaluation: ThresholdEvaluation,
    pub baseline_comparison: Option<BaselineComparison>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScenarioConfig {
    pub http1_requests: usize,
    pub http2_streams: usize,
    pub mixed_operations: usize,
    pub idle_connections: usize,
    pub active_streams: usize,
    pub hedging_iterations: usize,
    pub abuse_decisions: usize,
    pub discovery_updates: usize,
    pub http3_bridge_requests: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThroughputMeasurement {
    pub scenario: String,
    pub operations: usize,
    pub elapsed_ms: u128,
    pub operations_per_sec: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencySummary {
    pub scenario: String,
    pub samples: usize,
    pub mean_us: f64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryMeasurement {
    pub scenario: String,
    pub units: usize,
    pub baseline_rss_kib: Option<u64>,
    pub peak_rss_kib: Option<u64>,
    pub delta_rss_kib: Option<u64>,
    pub per_unit_rss_kib: Option<f64>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsOverheadMeasurement {
    pub plain_ops_per_sec: f64,
    pub tls_ops_per_sec: f64,
    pub throughput_penalty_pct: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceEnvelopeReport {
    pub mode: EnvelopeMode,
    pub scenario: ScenarioConfig,
    pub http1_throughput: ThroughputMeasurement,
    pub http2_throughput: ThroughputMeasurement,
    pub mixed_latency: LatencySummary,
    pub http1_tls_throughput: ThroughputMeasurement,
    pub tls_overhead: TlsOverheadMeasurement,
    pub idle_connection_memory: MemoryMeasurement,
    pub http2_stream_memory: MemoryMeasurement,
    pub advanced_scenarios: Vec<ThroughputMeasurement>,
    pub assumptions: Vec<String>,
}

#[derive(Clone)]
struct TlsIdentity {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
}

struct H2Client {
    send_request: client::SendRequest<Bytes>,
    connection_task: tokio::task::JoinHandle<()>,
}

struct Http3TestRootGuard;

impl Drop for Http3TestRootGuard {
    fn drop(&mut self) {
        clear_http3_test_root_certificates();
    }
}

pub async fn run_performance_envelope(
    mode: EnvelopeMode,
) -> Result<PerformanceEnvelopeReport, DynError> {
    let scenario = mode.scenario();
    let http1_throughput = measure_http1_throughput(scenario.http1_requests)
        .await
        .map_err(|error| io::Error::other(format!("http1_throughput: {error}")))?;
    let http2_throughput = measure_http2_throughput(scenario.http2_streams)
        .await
        .map_err(|error| io::Error::other(format!("http2_throughput: {error}")))?;
    let mixed_latency = measure_mixed_latency(scenario.mixed_operations)
        .await
        .map_err(|error| io::Error::other(format!("mixed_latency: {error}")))?;
    let http1_tls_throughput = measure_http1_tls_throughput(scenario.http1_requests)
        .await
        .map_err(|error| io::Error::other(format!("http1_tls_throughput: {error}")))?;
    let idle_connection_memory = measure_idle_connection_memory(scenario.idle_connections)
        .await
        .map_err(|error| io::Error::other(format!("idle_connection_memory: {error}")))?;
    let http2_stream_memory = measure_http2_stream_memory(scenario.active_streams)
        .await
        .map_err(|error| io::Error::other(format!("http2_stream_memory: {error}")))?;
    let mut advanced_scenarios = vec![
        measure_hedging_execution_throughput(scenario.hedging_iterations)
            .await
            .map_err(|error| io::Error::other(format!("hedging_throughput: {error}")))?,
        measure_abuse_mitigation_decision_throughput(scenario.abuse_decisions)
            .map_err(|error| io::Error::other(format!("abuse_mitigation: {error}")))?,
        measure_discovery_churn_reconcile_throughput(scenario.discovery_updates)
            .map_err(|error| io::Error::other(format!("discovery_churn: {error}")))?,
    ];
    let mut assumptions = vec![
        String::from("loopback-only proxy measurements; these numbers are for relative regression detection and local capacity planning, not internet-facing SLA claims"),
        String::from("resident-set-size sampling is process-level and most comparable across commits on the same host class"),
        String::from("TLS overhead is measured against the same HTTP/1 batch through a local Rustls-terminated downstream connection"),
        String::from("advanced harness scenarios cover hedging execution, abuse-mitigation decision path, discovery membership churn, and HTTP/1 to HTTP/3 bridge path"),
    ];

    match measure_http1_to_http3_bridge_throughput(scenario.http3_bridge_requests).await {
        Ok(measurement) => advanced_scenarios.push(measurement),
        Err(error) => {
            advanced_scenarios.push(ThroughputMeasurement {
                scenario: String::from("http1_to_http3_bridge_batch"),
                operations: scenario.http3_bridge_requests.max(1),
                elapsed_ms: 0,
                operations_per_sec: 0.0,
            });
            assumptions.push(format!(
                "HTTP/1 to HTTP/3 bridge throughput sample unavailable in this run: {error}"
            ));
        }
    }
    let tls_overhead = TlsOverheadMeasurement {
        plain_ops_per_sec: http1_throughput.operations_per_sec,
        tls_ops_per_sec: http1_tls_throughput.operations_per_sec,
        throughput_penalty_pct: percentage_penalty(
            http1_throughput.operations_per_sec,
            http1_tls_throughput.operations_per_sec,
        ),
    };

    Ok(PerformanceEnvelopeReport {
        mode,
        scenario,
        http1_throughput,
        http2_throughput,
        mixed_latency,
        http1_tls_throughput,
        tls_overhead,
        idle_connection_memory,
        http2_stream_memory,
        advanced_scenarios,
        assumptions,
    })
}

pub async fn build_performance_envelope_artifact(
    mode: EnvelopeMode,
    profile: DeploymentProfile,
    control_plane_timing: ControlPlaneTimingEvidence,
    baseline_path: Option<&str>,
) -> Result<PerformanceEnvelopeArtifact, DynError> {
    let report = run_performance_envelope(mode).await?;
    let profile = profile.spec();
    let threshold_evaluation = evaluate_supported_envelope(&profile, &report, &control_plane_timing);
    let baseline_comparison = baseline_path
        .map(load_performance_envelope_artifact)
        .transpose()?
        .map(|baseline| compare_against_baseline(&profile, &report, &control_plane_timing, &baseline));

    Ok(PerformanceEnvelopeArtifact {
        schema_version: String::from("v1"),
        generated_at_unix_ms: unix_time_ms(),
        profile,
        report,
        control_plane_timing,
        threshold_evaluation,
        baseline_comparison,
    })
}

pub async fn capture_control_plane_timing_evidence() -> Result<ControlPlaneTimingEvidence, DynError> {
    let reload_success_ms = Some(measure_reload_success_timing_ms().await?);
    let reload_degraded_success_ms = Some(measure_reload_degraded_success_timing_ms().await?);
    let failover_ms = Some(measure_failover_timing_ms()?);

    Ok(ControlPlaneTimingEvidence {
        reload_success_ms,
        reload_degraded_success_ms,
        failover_ms,
        evidence_source: Some(String::from("performance_harness_local_capture")),
    })
}

pub fn load_performance_envelope_artifact(
    path: &str,
) -> Result<PerformanceEnvelopeArtifact, DynError> {
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(Into::into)
}

fn evaluate_supported_envelope(
    profile: &DeploymentProfileSpec,
    report: &PerformanceEnvelopeReport,
    control_plane_timing: &ControlPlaneTimingEvidence,
) -> ThresholdEvaluation {
    let Some(thresholds) = &profile.supported_envelope else {
        return ThresholdEvaluation {
            claim_tier: profile.claim_tier,
            supported_claim_ready: false,
            checks: Vec::new(),
        };
    };

    let checks = vec![
        at_least_check(
            "http1_ops_per_sec",
            "ops_per_sec",
            thresholds.min_http1_ops_per_sec,
            Some(report.http1_throughput.operations_per_sec),
            "minimum sustained HTTP/1 throughput for supported profile",
        ),
        at_least_check(
            "http2_ops_per_sec",
            "ops_per_sec",
            thresholds.min_http2_ops_per_sec,
            Some(report.http2_throughput.operations_per_sec),
            "minimum sustained HTTP/2 throughput for supported profile",
        ),
        at_most_check(
            "mixed_latency_p50",
            "us",
            thresholds.max_mixed_p50_us as f64,
            Some(report.mixed_latency.p50_us as f64),
            "mixed-traffic p50 latency ceiling",
        ),
        at_most_check(
            "mixed_latency_p95",
            "us",
            thresholds.max_mixed_p95_us as f64,
            Some(report.mixed_latency.p95_us as f64),
            "mixed-traffic p95 latency ceiling",
        ),
        at_most_check(
            "mixed_latency_p99",
            "us",
            thresholds.max_mixed_p99_us as f64,
            Some(report.mixed_latency.p99_us as f64),
            "mixed-traffic p99 latency ceiling",
        ),
        at_most_check(
            "idle_connection_rss_per_unit",
            "kib",
            thresholds.max_idle_connection_rss_kib_per_unit,
            report.idle_connection_memory.per_unit_rss_kib,
            "idle accepted-connection memory growth ceiling",
        ),
        at_most_check(
            "http2_stream_rss_per_unit",
            "kib",
            thresholds.max_http2_stream_rss_kib_per_unit,
            report.http2_stream_memory.per_unit_rss_kib,
            "active HTTP/2 stream memory growth ceiling",
        ),
        at_most_check(
            "reload_success_ms",
            "ms",
            thresholds.max_reload_success_ms as f64,
            control_plane_timing.reload_success_ms.map(|value| value as f64),
            "reload success timing from workspace status evidence",
        ),
        at_most_check(
            "reload_degraded_success_ms",
            "ms",
            thresholds.max_reload_degraded_success_ms as f64,
            control_plane_timing.reload_degraded_success_ms.map(|value| value as f64),
            "degraded-success reload timing from workspace status evidence",
        ),
        at_most_check(
            "failover_ms",
            "ms",
            thresholds.max_failover_ms as f64,
            control_plane_timing.failover_ms.map(|value| value as f64),
            "failover timing from supported lab evidence",
        ),
    ];

    let supported_claim_ready = checks.iter().all(|check| check.status == CheckStatus::Passed);
    ThresholdEvaluation { claim_tier: profile.claim_tier, supported_claim_ready, checks }
}

fn compare_against_baseline(
    profile: &DeploymentProfileSpec,
    report: &PerformanceEnvelopeReport,
    control_plane_timing: &ControlPlaneTimingEvidence,
    baseline: &PerformanceEnvelopeArtifact,
) -> BaselineComparison {
    let guardrails = &profile.regression_guardrails;
    let checks = vec![
        throughput_regression_check(
            "http1_ops_per_sec",
            report.http1_throughput.operations_per_sec,
            baseline.report.http1_throughput.operations_per_sec,
            guardrails.max_throughput_drop_pct,
        ),
        throughput_regression_check(
            "http2_ops_per_sec",
            report.http2_throughput.operations_per_sec,
            baseline.report.http2_throughput.operations_per_sec,
            guardrails.max_throughput_drop_pct,
        ),
        increase_regression_check(
            "mixed_latency_p95",
            "us",
            report.mixed_latency.p95_us as f64,
            baseline.report.mixed_latency.p95_us as f64,
            guardrails.max_latency_increase_pct,
        ),
        increase_regression_check(
            "mixed_latency_p99",
            "us",
            report.mixed_latency.p99_us as f64,
            baseline.report.mixed_latency.p99_us as f64,
            guardrails.max_latency_increase_pct,
        ),
        increase_regression_check_optional(
            "idle_connection_rss_per_unit",
            "kib",
            report.idle_connection_memory.per_unit_rss_kib,
            baseline.report.idle_connection_memory.per_unit_rss_kib,
            guardrails.max_memory_growth_pct,
        ),
        increase_regression_check_optional(
            "http2_stream_rss_per_unit",
            "kib",
            report.http2_stream_memory.per_unit_rss_kib,
            baseline.report.http2_stream_memory.per_unit_rss_kib,
            guardrails.max_memory_growth_pct,
        ),
        increase_regression_check_optional(
            "reload_success_ms",
            "ms",
            control_plane_timing.reload_success_ms.map(|value| value as f64),
            baseline.control_plane_timing.reload_success_ms.map(|value| value as f64),
            guardrails.max_timing_regression_pct,
        ),
        increase_regression_check_optional(
            "failover_ms",
            "ms",
            control_plane_timing.failover_ms.map(|value| value as f64),
            baseline.control_plane_timing.failover_ms.map(|value| value as f64),
            guardrails.max_timing_regression_pct,
        ),
    ];
    let passed = checks.iter().all(|check| check.status != CheckStatus::Failed);

    BaselineComparison {
        baseline_profile: baseline.profile.name.clone(),
        baseline_mode: baseline.report.mode,
        passed,
        checks,
    }
}

fn at_least_check(
    metric: &str,
    unit: &str,
    expected: f64,
    actual: Option<f64>,
    note: &str,
) -> ThresholdCheck {
    let status = match actual {
        Some(actual) if actual >= expected => CheckStatus::Passed,
        Some(_) => CheckStatus::Failed,
        None => CheckStatus::NotEvaluated,
    };

    ThresholdCheck {
        metric: String::from(metric),
        unit: String::from(unit),
        comparator: String::from(">="),
        expected,
        actual,
        status,
        note: String::from(note),
    }
}

fn at_most_check(
    metric: &str,
    unit: &str,
    expected: f64,
    actual: Option<f64>,
    note: &str,
) -> ThresholdCheck {
    let status = match actual {
        Some(actual) if actual <= expected => CheckStatus::Passed,
        Some(_) => CheckStatus::Failed,
        None => CheckStatus::NotEvaluated,
    };

    ThresholdCheck {
        metric: String::from(metric),
        unit: String::from(unit),
        comparator: String::from("<="),
        expected,
        actual,
        status,
        note: String::from(note),
    }
}

fn throughput_regression_check(
    metric: &str,
    candidate: f64,
    baseline: f64,
    allowed_regression_pct: f64,
) -> BaselineComparisonCheck {
    let regression_pct = percentage_drop(baseline, candidate);
    let status = match regression_pct {
        Some(regression_pct) if regression_pct <= allowed_regression_pct => CheckStatus::Passed,
        Some(_) => CheckStatus::Failed,
        None => CheckStatus::NotEvaluated,
    };

    BaselineComparisonCheck {
        metric: String::from(metric),
        unit: String::from("pct"),
        baseline: Some(baseline),
        candidate: Some(candidate),
        regression_pct,
        allowed_regression_pct,
        status,
    }
}

fn increase_regression_check(
    metric: &str,
    unit: &str,
    candidate: f64,
    baseline: f64,
    allowed_regression_pct: f64,
) -> BaselineComparisonCheck {
    let regression_pct = percentage_increase(baseline, candidate);
    let status = match regression_pct {
        Some(regression_pct) if regression_pct <= allowed_regression_pct => CheckStatus::Passed,
        Some(_) => CheckStatus::Failed,
        None => CheckStatus::NotEvaluated,
    };

    BaselineComparisonCheck {
        metric: String::from(metric),
        unit: String::from(unit),
        baseline: Some(baseline),
        candidate: Some(candidate),
        regression_pct,
        allowed_regression_pct,
        status,
    }
}

fn increase_regression_check_optional(
    metric: &str,
    unit: &str,
    candidate: Option<f64>,
    baseline: Option<f64>,
    allowed_regression_pct: f64,
) -> BaselineComparisonCheck {
    let regression_pct = baseline.zip(candidate).and_then(|(baseline, candidate)| percentage_increase(baseline, candidate));
    let status = match regression_pct {
        Some(regression_pct) if regression_pct <= allowed_regression_pct => CheckStatus::Passed,
        Some(_) => CheckStatus::Failed,
        None => CheckStatus::NotEvaluated,
    };

    BaselineComparisonCheck {
        metric: String::from(metric),
        unit: String::from(unit),
        baseline,
        candidate,
        regression_pct,
        allowed_regression_pct,
        status,
    }
}

fn percentage_drop(baseline: f64, candidate: f64) -> Option<f64> {
    if baseline <= f64::EPSILON {
        None
    } else if candidate >= baseline {
        Some(0.0)
    } else {
        Some(((baseline - candidate) / baseline) * 100.0)
    }
}

fn percentage_increase(baseline: f64, candidate: f64) -> Option<f64> {
    if baseline <= f64::EPSILON {
        None
    } else if candidate <= baseline {
        Some(0.0)
    } else {
        Some(((candidate - baseline) / baseline) * 100.0)
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub async fn measure_reload_success_timing_ms() -> Result<u64, DynError> {
    let mut config = ListenerConfig::foundation_local("perf-reload-success", ListenerClass::Public);
    config.idle_timeout = Duration::from_millis(50);
    config.drain_timeout = Duration::from_millis(200);
    let handle = start_listener(config).await?;

    let started_at = Instant::now();
    handle.shutdown().await?;
    Ok(started_at.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
}

pub async fn measure_reload_degraded_success_timing_ms() -> Result<u64, DynError> {
    let mut config = ListenerConfig::foundation_local("perf-reload-degraded", ListenerClass::Public);
    config.idle_timeout = Duration::from_secs(2);
    config.drain_timeout = Duration::from_millis(40);
    let handle = start_listener(config).await?;

    let mut held_connection = TcpStream::connect(handle.local_addr()).await?;
    held_connection.write_all(b"x").await?;

    let started_at = Instant::now();
    handle.shutdown().await?;
    drop(held_connection);
    Ok(started_at.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
}

pub fn measure_failover_timing_ms() -> Result<u64, DynError> {
    let mut policy = EndpointHealthPolicy::default();
    policy.degraded_failure_threshold = 1;
    policy.unhealthy_failure_threshold = 1;
    policy.ejection_failure_threshold = 1;

    let registry = UpstreamHealthRegistry::new(policy);
    let cluster_name = UpstreamClusterName::new("perf-failover")?;
    let primary_id = UpstreamEndpointId::new("primary")?;
    let secondary_id = UpstreamEndpointId::new("secondary")?;
    let primary = UpstreamEndpoint::new(
        primary_id.clone(),
        SocketAddr::from(([127, 0, 0, 1], 9100)),
        EndpointState::Ready,
        EndpointMetadata {
            zone: None,
            locality: None,
            weight: 1,
        },
    )?;
    let secondary = UpstreamEndpoint::new(
        secondary_id.clone(),
        SocketAddr::from(([127, 0, 0, 1], 9101)),
        EndpointState::Ready,
        EndpointMetadata {
            zone: None,
            locality: None,
            weight: 1,
        },
    )?;
    registry.insert_cluster(UpstreamCluster::new(cluster_name.clone(), vec![primary, secondary])?)?;
    registry.advance_time(Duration::from_secs(20));

    let started_at = Instant::now();
    let _ = registry.note_active_failure(&cluster_name, &primary_id)?;
    let candidates = registry.selection_candidates(&cluster_name, true)?;
    if !candidates
        .iter()
        .any(|candidate| candidate.endpoint_id == secondary_id)
    {
        return Err(io::Error::other("failover candidate was not selected").into());
    }

    Ok(started_at.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
}

pub async fn measure_http1_throughput(requests: usize) -> Result<ThroughputMeasurement, DynError> {
    let (upstream_addr, captures_rx) =
        spawn_repeating_http1_upstream(requests, HTTP1_BENCH_BODY).await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(http1_proxy_config(upstream_addr)).await?;
    let mut client = TcpStream::connect(proxy_addr).await?;

    let started_at = Instant::now();
    drive_http1_batch(&mut client, requests).await?;
    let elapsed = started_at.elapsed();
    drop(client);

    let report = receive_http1_proxy_result(report_rx).await?;
    let captures = receive_http1_captures(captures_rx).await?;
    if report.metrics.request_count != requests as u64 || captures.len() != requests {
        return Err(io::Error::other("unexpected HTTP/1 throughput harness counts").into());
    }

    Ok(throughput_measurement("http1_proxy_batch", requests, elapsed))
}

pub async fn measure_http1_tls_throughput(
    requests: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let identity = tls_identity()?;
    let (upstream_addr, captures_rx) =
        spawn_repeating_http1_upstream(requests, HTTP1_BENCH_BODY).await?;
    let (proxy_addr, report_rx) = spawn_one_shot_tls_http1_proxy_listener(
        http1_proxy_config(upstream_addr),
        identity.clone(),
    )
    .await?;

    let stream = TcpStream::connect(proxy_addr).await?;
    let server_name = ServerName::try_from("localhost")?.to_owned();
    let mut client = TlsConnector::from(identity.client).connect(server_name, stream).await?;

    let started_at = Instant::now();
    drive_http1_batch(&mut client, requests).await?;
    let elapsed = started_at.elapsed();
    drop(client);

    let report = receive_http1_proxy_result(report_rx).await?;
    let captures = receive_http1_captures(captures_rx).await?;
    if report.metrics.request_count != requests as u64 || captures.len() != requests {
        return Err(io::Error::other("unexpected HTTP/1 TLS throughput harness counts").into());
    }

    Ok(throughput_measurement("http1_proxy_batch_tls", requests, elapsed))
}

pub async fn measure_http2_throughput(streams: usize) -> Result<ThroughputMeasurement, DynError> {
    let upstream_addr = spawn_basic_h2_upstream(HTTP2_BENCH_BODY).await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(http2_proxy_config(upstream_addr)).await?;
    let mut client = connect_h2_client(proxy_addr).await?;

    let started_at = Instant::now();
    let mut responses = Vec::with_capacity(streams);
    for index in 0..streams {
        responses.push(send_h2_request(&mut client, &format!("/stream-{index}"), None).await?);
    }
    for response in responses {
        let received = receive_h2_response(response).await?;
        if received.0 != StatusCode::OK || received.1 != HTTP2_BENCH_BODY {
            return Err(io::Error::other("unexpected HTTP/2 benchmark response").into());
        }
    }
    let elapsed = started_at.elapsed();
    shutdown_h2_client(client).await;
    time::sleep(Duration::from_millis(50)).await;

    let report = receive_http2_proxy_result(report_rx).await?;
    if report.metrics.request_count != streams as u64 {
        return Err(io::Error::other("unexpected HTTP/2 throughput harness counts").into());
    }

    Ok(throughput_measurement("http2_proxy_stream_batch", streams, elapsed))
}

pub async fn measure_mixed_latency(operations: usize) -> Result<LatencySummary, DynError> {
    let http1_requests = operations / 2;
    let http2_requests = operations - http1_requests;

    let (http1_upstream_addr, http1_captures_rx) =
        spawn_repeating_http1_upstream(http1_requests.max(1), HTTP1_BENCH_BODY).await?;
    let (http1_proxy_addr, http1_report_rx) =
        spawn_one_shot_http1_proxy_listener(http1_proxy_config(http1_upstream_addr)).await?;
    let mut http1_client = TcpStream::connect(http1_proxy_addr).await?;

    let http2_upstream_addr = spawn_basic_h2_upstream(HTTP2_BENCH_BODY).await?;
    let (http2_proxy_addr, http2_report_rx) =
        spawn_one_shot_http2_proxy_listener(http2_proxy_config(http2_upstream_addr)).await?;
    let mut http2_client = connect_h2_client(http2_proxy_addr).await?;

    let mut samples_us = Vec::with_capacity(operations);
    let mut http1_seen = 0usize;
    let mut http2_seen = 0usize;
    for index in 0..operations {
        if index % 2 == 0 && http1_seen < http1_requests {
            let started_at = Instant::now();
            send_one_http1_request(
                &mut http1_client,
                http1_seen + 1 == http1_requests,
                &format!("/mixed-http1-{index}"),
            )
            .await?;
            samples_us.push(duration_to_us(started_at.elapsed()));
            http1_seen += 1;
        }

        if http2_seen < http2_requests {
            let started_at = Instant::now();
            let response =
                send_h2_request(&mut http2_client, &format!("/mixed-http2-{index}"), None).await?;
            let received = receive_h2_response(response).await?;
            if received.0 != StatusCode::OK || received.1 != HTTP2_BENCH_BODY {
                return Err(io::Error::other("unexpected mixed HTTP/2 response").into());
            }
            samples_us.push(duration_to_us(started_at.elapsed()));
            http2_seen += 1;
        }
    }

    drop(http1_client);
    shutdown_h2_client(http2_client).await;
    time::sleep(Duration::from_millis(50)).await;

    let http1_report = receive_http1_proxy_result(http1_report_rx).await?;
    let http2_report = receive_http2_proxy_result(http2_report_rx).await?;
    let http1_captures = receive_http1_captures(http1_captures_rx).await?;
    if http1_report.metrics.request_count != http1_requests as u64
        || http2_report.metrics.request_count != http2_requests as u64
    {
        return Err(io::Error::other("unexpected mixed latency harness counts").into());
    }
    if http1_captures.len() != http1_requests {
        return Err(io::Error::other("unexpected mixed HTTP/1 capture count").into());
    }

    Ok(latency_summary("mixed_http1_http2_interleaved", samples_us))
}

pub async fn measure_idle_connection_memory(
    connections: usize,
) -> Result<MemoryMeasurement, DynError> {
    let baseline_rss_kib = current_rss_kib();

    let mut config = ListenerConfig::foundation_local("perf-envelope", ListenerClass::Public);
    config.max_connections = connections.max(1) + 8;
    config.idle_timeout = Duration::from_secs(2);
    let handle = start_listener(config).await?;
    let local_addr = handle.local_addr();

    let mut clients = Vec::with_capacity(connections);
    for _ in 0..connections {
        let mut stream = TcpStream::connect(local_addr).await?;
        stream.write_all(b"x").await?;
        clients.push(stream);
    }
    time::sleep(Duration::from_millis(75)).await;
    let snapshot = handle.snapshot();
    let peak_rss_kib = current_rss_kib();

    drop(clients);
    handle.shutdown().await?;

    if snapshot.active_connections < connections {
        return Err(io::Error::other(
            "listener memory harness did not retain all idle connections",
        )
        .into());
    }

    Ok(memory_measurement(
        "idle_listener_connections",
        connections,
        baseline_rss_kib,
        peak_rss_kib,
        String::from("resident-set-size delta while the bounded listener keeps loopback idle connections admitted"),
    ))
}

pub async fn measure_http2_stream_memory(streams: usize) -> Result<MemoryMeasurement, DynError> {
    let baseline_rss_kib = current_rss_kib();
    let upstream_addr =
        spawn_delayed_h2_upstream(Duration::from_millis(250), HTTP2_BENCH_BODY).await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http2_proxy_listener(http2_proxy_config(upstream_addr)).await?;
    let mut client = connect_h2_client(proxy_addr).await?;

    let mut responses = Vec::with_capacity(streams);
    for index in 0..streams {
        responses.push(send_h2_request(&mut client, &format!("/hold-{index}"), None).await?);
    }
    time::sleep(Duration::from_millis(75)).await;
    let peak_rss_kib = current_rss_kib();

    for response in responses {
        let received = receive_h2_response(response).await?;
        if received.0 != StatusCode::OK || received.1 != HTTP2_BENCH_BODY {
            return Err(io::Error::other("unexpected HTTP/2 memory response").into());
        }
    }
    shutdown_h2_client(client).await;
    time::sleep(Duration::from_millis(50)).await;

    let report = receive_http2_proxy_result(report_rx).await?;
    if report.metrics.peak_active_streams < streams {
        return Err(io::Error::other(
            "HTTP/2 memory harness did not reach target active stream count",
        )
        .into());
    }

    Ok(memory_measurement(
        "http2_active_streams",
        streams,
        baseline_rss_kib,
        peak_rss_kib,
        String::from("resident-set-size delta while the proxy keeps a single downstream HTTP/2 connection busy with concurrent delayed upstream streams"),
    ))
}

pub async fn measure_hedging_execution_throughput(
    iterations: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let operations = iterations.max(1);
    let started_at = Instant::now();

    for _ in 0..operations {
        let _ = execute_with_hedge(
            RequestHedgingPolicy {
                hedge_delay: Duration::from_millis(2),
                max_attempts: 2,
            },
            || true,
            || async {
                time::sleep(Duration::from_millis(6)).await;
                Ok::<(), io::Error>(())
            },
            || async {
                time::sleep(Duration::from_millis(1)).await;
                Ok::<(), io::Error>(())
            },
        )
        .await
        .map_err(|error| -> DynError { Box::new(error) })?;
    }

    Ok(throughput_measurement(
        "hedging_execution_batch",
        operations,
        started_at.elapsed(),
    ))
}

pub fn measure_abuse_mitigation_decision_throughput(
    decisions: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let operations = decisions.max(1);
    let runtime = RequestClassificationPolicyRuntime::from_config(
        &lb_config_model::RequestClassificationPolicyConfig::default(),
    );
    let enforcement_policy = RequestClassificationEnforcementPolicy::default();
    let adaptive_policy = RequestClassificationAdaptiveMitigationPolicy::default();
    let auth_context = RequestClassificationAuthContext::default();
    let shedding = SheddingDecision {
        action: SheddingAction::Shed,
        state: OverloadState::Brownout,
        reason: None,
    };
    let request_context = RequestClassificationAdapterContext {
        source_ip: Some(String::from("198.51.100.10")),
        method: Some(String::from("POST")),
        path: Some(String::from("/checkout")),
        user_agent: Some(String::from("Mozilla/5.0")),
        content_type: Some(String::from("application/json")),
        headers: vec![
            (String::from("x-request-id"), String::from("perf-run")),
            (String::from("user-agent"), String::from("load-bot/1.0")),
        ],
    };
    let body = b"{\"payload\":\"union select 1\"}";

    let started_at = Instant::now();
    for _ in 0..operations {
        let _ = runtime.classify_enforce_and_adapt_with_overload(
            &request_context,
            body,
            &auth_context,
            &enforcement_policy,
            &adaptive_policy,
            &shedding,
        );
    }

    Ok(throughput_measurement(
        "abuse_mitigation_decision_batch",
        operations,
        started_at.elapsed(),
    ))
}

pub fn measure_discovery_churn_reconcile_throughput(
    updates: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let operations = updates.max(1);
    let registry = UpstreamHealthRegistry::new(EndpointHealthPolicy::default());
    let cluster_name = lb_net_core::UpstreamClusterName::new("perf-discovery")?;
    registry.insert_cluster(lb_net_core::UpstreamCluster::new(cluster_name.clone(), Vec::new())?)?;
    let source = DiscoverySourceId::new(
        DiscoveryProviderKind::DnsAaaa,
        "perf.internal",
        cluster_name.as_str(),
    )?;
    let mut reconciler = DiscoveryMembershipReconciler::new(Duration::from_millis(3));

    let started_at = Instant::now();
    for index in 0..operations {
        let generation = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        let endpoint_count = if index % 2 == 0 { 2 } else { 3 };
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for endpoint_index in 0..endpoint_count {
            let endpoint_id = format!("ep-{endpoint_index}");
            let address = SocketAddr::from((
                [127, 0, 0, 1],
                9300_u16.saturating_add(u16::try_from(endpoint_index).unwrap_or(0)),
            ));
            endpoints.push(DiscoveryEndpoint::new(endpoint_id, address, None, None, 1)?);
        }

        reconciler.reconcile_snapshot(
            &registry,
            DiscoverySnapshot {
                source: source.clone(),
                generation,
                valid_for: Duration::from_secs(20),
                endpoints,
            },
        )?;
        let _ = reconciler.advance_time(&registry, Duration::from_millis(4))?;
    }

    Ok(throughput_measurement(
        "discovery_churn_reconcile_batch",
        operations,
        started_at.elapsed(),
    ))
}

pub async fn measure_http1_to_http3_bridge_throughput(
    requests: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let mut last_error: Option<DynError> = None;
    for _attempt in 0..3 {
        match measure_http1_to_http3_bridge_throughput_once(requests).await {
            Ok(measurement) => return Ok(measurement),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| io::Error::other("http1->http3 bridge harness failed").into()))
}

async fn measure_http1_to_http3_bridge_throughput_once(
    requests: usize,
) -> Result<ThroughputMeasurement, DynError> {
    let operations = requests.max(1);
    let (upstream_addr, cert_der, served_rx) =
        spawn_repeating_h3_upstream(operations, HTTP1_BENCH_BODY).await?;
    set_http3_test_root_certificates(vec![cert_der]);
    let _cert_guard = Http3TestRootGuard;

    let config = Http1ProxyConfig::new(UpstreamTarget::with_transport(
        "http3-upstream",
        upstream_addr,
        UpstreamTransport::Http3,
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;
    let mut client = TcpStream::connect(proxy_addr).await?;

    let started_at = Instant::now();
    drive_http1_batch(&mut client, operations).await?;
    let elapsed = started_at.elapsed();
    drop(client);

    let report = receive_http1_proxy_result(report_rx).await?;
    let served = time::timeout(Duration::from_secs(5), served_rx)
        .await
        .map_err(|_| io::Error::other("HTTP/3 serve wait timed out"))?
        .map_err(|_| io::Error::other("HTTP/3 serve channel closed"))?;
    if report.metrics.request_count != operations as u64 || served != operations {
        return Err(io::Error::other("unexpected HTTP/1->HTTP/3 harness counts").into());
    }

    Ok(throughput_measurement(
        "http1_to_http3_bridge_batch",
        operations,
        elapsed,
    ))
}

fn throughput_measurement(
    scenario: &str,
    operations: usize,
    elapsed: Duration,
) -> ThroughputMeasurement {
    let operations_per_sec = if elapsed.is_zero() {
        operations as f64
    } else {
        operations as f64 / elapsed.as_secs_f64()
    };

    ThroughputMeasurement {
        scenario: scenario.to_string(),
        operations,
        elapsed_ms: elapsed.as_millis(),
        operations_per_sec,
    }
}

fn latency_summary(scenario: &str, mut samples_us: Vec<u64>) -> LatencySummary {
    samples_us.sort_unstable();
    let samples = samples_us.len();
    let sum: u128 = samples_us.iter().map(|sample| u128::from(*sample)).sum();
    let mean_us = if samples == 0 { 0.0 } else { sum as f64 / samples as f64 };

    LatencySummary {
        scenario: scenario.to_string(),
        samples,
        mean_us,
        p50_us: percentile(&samples_us, 0.50),
        p95_us: percentile(&samples_us, 0.95),
        p99_us: percentile(&samples_us, 0.99),
        max_us: samples_us.last().copied().unwrap_or(0),
    }
}

fn memory_measurement(
    scenario: &str,
    units: usize,
    baseline_rss_kib: Option<u64>,
    peak_rss_kib: Option<u64>,
    note: String,
) -> MemoryMeasurement {
    let delta_rss_kib =
        baseline_rss_kib.zip(peak_rss_kib).map(|(baseline, peak)| peak.saturating_sub(baseline));
    let per_unit_rss_kib =
        delta_rss_kib.map(|delta| if units == 0 { 0.0 } else { delta as f64 / units as f64 });

    MemoryMeasurement {
        scenario: scenario.to_string(),
        units,
        baseline_rss_kib,
        peak_rss_kib,
        delta_rss_kib,
        per_unit_rss_kib,
        note,
    }
}

fn percentage_penalty(baseline: f64, candidate: f64) -> f64 {
    if baseline <= f64::EPSILON {
        0.0
    } else {
        ((baseline - candidate) / baseline) * 100.0
    }
}

fn percentile(samples_us: &[u64], percentile: f64) -> u64 {
    if samples_us.is_empty() {
        return 0;
    }
    let index = ((samples_us.len() - 1) as f64 * percentile).round() as usize;
    samples_us[index.min(samples_us.len() - 1)]
}

fn duration_to_us(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

fn ensure_rustls_crypto_provider() {
    static PROVIDER: OnceLock<()> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn tls_identity() -> Result<TlsIdentity, DynError> {
    ensure_rustls_crypto_provider();
    let certified = generate_simple_self_signed(vec![String::from("localhost")])?;
    let cert_der_bytes = certified.cert.der().to_vec();
    let cert_der = CertificateDer::from(cert_der_bytes.clone());
    let key_der = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    let server = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_der))?,
    );

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der_bytes))?;
    let client =
        Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());

    Ok(TlsIdentity { server, client })
}

async fn drive_http1_batch<S>(stream: &mut S, requests: usize) -> Result<(), DynError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for index in 0..requests {
        send_one_http1_request(stream, index + 1 == requests, &format!("/batch-{index}")).await?;
    }
    Ok(())
}

async fn send_one_http1_request<S>(
    stream: &mut S,
    close_connection: bool,
    target: &str,
) -> Result<(), DynError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connection_header = if close_connection { "close" } else { "keep-alive" };
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: example.test\r\nConnection: {connection_header}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let response = read_http_response(stream).await?;
    if !response.starts_with("HTTP/1.1 200 OK\r\n") || !response.ends_with(HTTP1_BENCH_BODY) {
        return Err(io::Error::other("unexpected HTTP/1 benchmark response").into());
    }
    Ok(())
}

async fn spawn_repeating_http1_upstream(
    requests: usize,
    body: &'static str,
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            for _ in 0..requests {
                let capture = match read_http_request_capture(&mut stream).await {
                    Ok(capture) => capture,
                    Err(_) => break,
                };
                captures.push(capture);
                let response =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                if stream.write_all(response.as_bytes()).await.is_err() {
                    break;
                }
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn read_http_request_capture(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::new();
    let head_end = read_until_sequence(stream, &mut buffer, b"\r\n\r\n").await?;
    String::from_utf8(buffer[..head_end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request head utf8"))
}

async fn read_http_response<S>(stream: &mut S) -> io::Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let head_end = read_until_sequence(stream, &mut buffer, b"\r\n\r\n").await?;
    let head = String::from_utf8(buffer[..head_end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response head utf8"))?;
    let content_length = parse_content_length(&head)?;
    let mut body = buffer[head_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0_u8; (content_length - body.len()).min(8192)];
        let bytes_read = stream.read(&mut chunk).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "response body truncated"));
        }
        body.extend_from_slice(&chunk[..bytes_read]);
    }
    body.truncate(content_length);
    let body_text = String::from_utf8(body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response body utf8"))?;
    Ok(format!("{head}{body_text}"))
}

async fn read_until_sequence<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    sequence: &[u8],
) -> io::Result<usize>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(position) = buffer.windows(sequence.len()).position(|window| window == sequence)
        {
            return Ok(position + sequence.len());
        }

        let mut chunk = [0_u8; 1024];
        let bytes_read = stream.read(&mut chunk).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "sequence not found"));
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn parse_content_length(head: &str) -> io::Result<usize> {
    let Some(line) =
        head.lines().find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
    else {
        return Ok(0);
    };

    let Some((_, value)) = line.split_once(':') else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid content-length header"));
    };
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid content-length value"))
}

async fn spawn_one_shot_http1_proxy_listener(
    config: Http1ProxyConfig,
) -> io::Result<(SocketAddr, oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = match listener.accept().await {
            Ok((downstream, _)) => proxy_http1_connection(downstream, &config).await,
            Err(error) => Err(Http1ProxyError::RequestIo(error)),
        };
        let _ = result_tx.send(result);
    });

    Ok((address, result_rx))
}

async fn spawn_one_shot_tls_http1_proxy_listener(
    config: Http1ProxyConfig,
    identity: TlsIdentity,
) -> io::Result<(SocketAddr, oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = match listener.accept().await {
            Ok((downstream, peer_addr)) => {
                let acceptor = TlsAcceptor::from(identity.server);
                match acceptor.accept(downstream).await {
                    Ok(tls_stream) => {
                        proxy_http1_connection_with_downstream_addr(tls_stream, peer_addr, &config)
                            .await
                    }
                    Err(error) => {
                        Err(Http1ProxyError::RequestIo(io::Error::other(error.to_string())))
                    }
                }
            }
            Err(error) => Err(Http1ProxyError::RequestIo(error)),
        };
        let _ = result_tx.send(result);
    });

    Ok((address, result_rx))
}

async fn receive_http1_proxy_result(
    result_rx: oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>,
) -> Result<Http1ConnectionReport, Http1ProxyError> {
    match time::timeout(Duration::from_secs(5), result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(Http1ProxyError::IdleTimeout("proxy result channel closed")),
        Err(_) => Err(Http1ProxyError::IdleTimeout("proxy result wait")),
    }
}

async fn receive_http1_captures(
    capture_rx: oneshot::Receiver<Vec<String>>,
) -> Result<Vec<String>, DynError> {
    match time::timeout(Duration::from_secs(5), capture_rx).await {
        Ok(Ok(captures)) => Ok(captures),
        Ok(Err(_)) => Err(io::Error::other("HTTP/1 capture channel closed").into()),
        Err(_) => Err(io::Error::other("HTTP/1 capture wait timed out").into()),
    }
}

async fn spawn_basic_h2_upstream(body: &'static str) -> io::Result<SocketAddr> {
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
                let Ok(response) = response else {
                    break;
                };
                if let Ok(mut send) = respond.send_response(response, false) {
                    let _ = send.send_data(Bytes::from(body.to_string()), true);
                }
            }
        }
    });

    Ok(address)
}

async fn spawn_repeating_h3_upstream(
    requests: usize,
    body: &'static str,
) -> io::Result<(SocketAddr, Vec<u8>, oneshot::Receiver<usize>)> {
    ensure_rustls_crypto_provider();
    let certified =
        generate_simple_self_signed(vec![String::from("localhost")]).map_err(io::Error::other)?;
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));

    let mut rustls_server = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .map_err(io::Error::other)?;
    rustls_server.alpn_protocols = vec![b"h3".to_vec()];

    let quic_server = QuicServerConfig::try_from(Arc::new(rustls_server)).map_err(io::Error::other)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket.into_std()?,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(io::Error::other)?;

    let (served_tx, served_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut served = 0usize;
        while served < requests {
            let Some(incoming) = endpoint.accept().await else {
                break;
            };
            let Ok(connecting) = incoming.accept() else {
                continue;
            };
            let Ok(connection) = connecting.await else {
                continue;
            };
            let Ok(mut h3_conn) = h3_server::builder().build(h3_quinn::Connection::new(connection)).await else {
                continue;
            };

            while served < requests {
                let Ok(Some(resolver)) = h3_conn.accept().await else {
                    break;
                };
                let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                    break;
                };

                loop {
                    let Ok(chunk) = stream.recv_data().await else {
                        break;
                    };
                    let Some(mut chunk) = chunk else {
                        break;
                    };
                    let _ = chunk.copy_to_bytes(chunk.remaining());
                }

                let response = Http3Response::builder().status(200).body(());
                let Ok(response) = response else {
                    break;
                };
                if stream.send_response(response).await.is_err() {
                    break;
                }
                if stream
                    .send_data(Bytes::from_static(body.as_bytes()))
                    .await
                    .is_err()
                {
                    break;
                }
                if stream.finish().await.is_err() {
                    break;
                }
                served = served.saturating_add(1);
            }
        }

        let _ = served_tx.send(served);
    });

    Ok((address, cert_der.as_ref().to_vec(), served_rx))
}

async fn spawn_delayed_h2_upstream(delay: Duration, body: &'static str) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut connection = match server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let mut tasks = JoinSet::new();
            while let Some(result) = connection.accept().await {
                let Ok((_request, mut respond)) = result else {
                    break;
                };
                tasks.spawn(async move {
                    time::sleep(delay).await;
                    let response = Response::builder().status(StatusCode::OK).body(());
                    if let Ok(response) = response {
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from(body.to_string()), true);
                        }
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
        }
    });

    Ok(address)
}

async fn spawn_one_shot_http2_proxy_listener(
    config: Http2ProxyConfig,
) -> io::Result<(SocketAddr, oneshot::Receiver<Result<Http2ConnectionReport, Http2ProxyError>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (result_tx, result_rx) = oneshot::channel();

    tokio::spawn(async move {
        let result = match listener.accept().await {
            Ok((downstream, _)) => proxy_http2_connection(downstream, &config).await,
            Err(error) => {
                Err(Http2ProxyError::Connect { target: config.upstream.address, source: error })
            }
        };
        let _ = result_tx.send(result);
    });

    Ok((address, result_rx))
}

async fn connect_h2_client(proxy_addr: SocketAddr) -> Result<H2Client, DynError> {
    let stream = TcpStream::connect(proxy_addr).await?;
    let (send_request, connection) = client::handshake(stream).await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(H2Client { send_request, connection_task })
}

async fn send_h2_request(
    client: &mut H2Client,
    path: &str,
    body: Option<Bytes>,
) -> Result<h2::client::ResponseFuture, h2::Error> {
    poll_h2_ready(&mut client.send_request).await?;
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .body(())
        .map_err(|_| h2::Error::from(Reason::INTERNAL_ERROR))?;
    let end_stream = body.is_none();
    let (response, mut send_stream) = client.send_request.send_request(request, end_stream)?;
    if let Some(mut body) = body {
        const MAX_FRAME_CHUNK: usize = 16 * 1024;
        while body.remaining() != 0 {
            let capacity =
                poll_h2_capacity(&mut send_stream, body.remaining().min(MAX_FRAME_CHUNK)).await?;
            let chunk = body.split_to(body.remaining().min(MAX_FRAME_CHUNK).min(capacity));
            let end = body.remaining() == 0;
            send_stream.send_data(chunk, end)?;
        }
    }
    Ok(response)
}

async fn shutdown_h2_client(client: H2Client) {
    let H2Client { send_request, connection_task } = client;
    drop(send_request);
    connection_task.abort();
    let _ = connection_task.await;
}

async fn poll_h2_ready(client: &mut client::SendRequest<Bytes>) -> Result<(), h2::Error> {
    use std::future::poll_fn;
    poll_fn(|cx| client.poll_ready(cx)).await
}

async fn poll_h2_capacity(
    send_stream: &mut h2::SendStream<Bytes>,
    requested: usize,
) -> Result<usize, h2::Error> {
    use std::future::poll_fn;
    use std::task::Poll;

    loop {
        send_stream.reserve_capacity(requested);
        let capacity = poll_fn(|cx| match send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity)),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(h2::Error::from(Reason::INTERNAL_ERROR))),
            Poll::Pending => Poll::Pending,
        })
        .await?;
        if capacity != 0 {
            return Ok(capacity);
        }
        tokio::task::yield_now().await;
    }
}

async fn receive_h2_response(
    response: h2::client::ResponseFuture,
) -> Result<(StatusCode, String), DynError> {
    let response = response.await?;
    let status = response.status();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, String::from_utf8(bytes)?))
}

async fn receive_http2_proxy_result(
    result_rx: oneshot::Receiver<Result<Http2ConnectionReport, Http2ProxyError>>,
) -> Result<Http2ConnectionReport, DynError> {
    match time::timeout(Duration::from_secs(15), result_rx).await {
        Ok(Ok(result)) => result.map_err(Into::into),
        Ok(Err(_)) => Err(io::Error::other("HTTP/2 proxy result channel closed").into()),
        Err(_) => Err(io::Error::other("HTTP/2 proxy result wait timed out").into()),
    }
}

fn http1_proxy_config(upstream_addr: SocketAddr) -> Http1ProxyConfig {
    Http1ProxyConfig::new(UpstreamTarget::new("http1-upstream", upstream_addr))
}

fn http2_proxy_config(upstream_addr: SocketAddr) -> Http2ProxyConfig {
    Http2ProxyConfig::new(UpstreamTarget::new("http2-upstream", upstream_addr))
}

fn current_rss_kib() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps").args(["-o", "rss=", "-p", pid.as_str()]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.trim().parse::<u64>().ok()
}

pub fn run_or_exit<T>(result: Result<T, DynError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("performance harness failed: {error}");
            std::process::exit(1);
        }
    }
}

pub async fn shutdown_listener(handle: ListenerHandle) -> Result<(), DynError> {
    handle.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> PerformanceEnvelopeReport {
        PerformanceEnvelopeReport {
            mode: EnvelopeMode::Smoke,
            scenario: ScenarioConfig {
                http1_requests: 64,
                http2_streams: 64,
                mixed_operations: 64,
                idle_connections: 24,
                active_streams: 24,
                hedging_iterations: 24,
                abuse_decisions: 64,
                discovery_updates: 24,
                http3_bridge_requests: 12,
            },
            http1_throughput: ThroughputMeasurement {
                scenario: String::from("http1"),
                operations: 64,
                elapsed_ms: 20,
                operations_per_sec: 3_200.0,
            },
            http2_throughput: ThroughputMeasurement {
                scenario: String::from("http2"),
                operations: 64,
                elapsed_ms: 5,
                operations_per_sec: 12_800.0,
            },
            mixed_latency: LatencySummary {
                scenario: String::from("mixed"),
                samples: 64,
                mean_us: 2_100.0,
                p50_us: 2_000,
                p95_us: 7_000,
                p99_us: 10_000,
                max_us: 11_000,
            },
            http1_tls_throughput: ThroughputMeasurement {
                scenario: String::from("http1_tls"),
                operations: 64,
                elapsed_ms: 30,
                operations_per_sec: 2_100.0,
            },
            tls_overhead: super::TlsOverheadMeasurement {
                plain_ops_per_sec: 3_200.0,
                tls_ops_per_sec: 2_100.0,
                throughput_penalty_pct: 34.375,
            },
            idle_connection_memory: MemoryMeasurement {
                scenario: String::from("idle"),
                units: 24,
                baseline_rss_kib: Some(1_000),
                peak_rss_kib: Some(1_240),
                delta_rss_kib: Some(240),
                per_unit_rss_kib: Some(10.0),
                note: String::from("sample"),
            },
            http2_stream_memory: MemoryMeasurement {
                scenario: String::from("h2"),
                units: 24,
                baseline_rss_kib: Some(1_000),
                peak_rss_kib: Some(1_336),
                delta_rss_kib: Some(336),
                per_unit_rss_kib: Some(14.0),
                note: String::from("sample"),
            },
            advanced_scenarios: vec![
                ThroughputMeasurement {
                    scenario: String::from("hedging_execution_batch"),
                    operations: 24,
                    elapsed_ms: 100,
                    operations_per_sec: 240.0,
                },
                ThroughputMeasurement {
                    scenario: String::from("abuse_mitigation_decision_batch"),
                    operations: 64,
                    elapsed_ms: 5,
                    operations_per_sec: 12_800.0,
                },
                ThroughputMeasurement {
                    scenario: String::from("discovery_churn_reconcile_batch"),
                    operations: 24,
                    elapsed_ms: 4,
                    operations_per_sec: 6_000.0,
                },
                ThroughputMeasurement {
                    scenario: String::from("http1_to_http3_bridge_batch"),
                    operations: 12,
                    elapsed_ms: 20,
                    operations_per_sec: 600.0,
                },
            ],
            assumptions: vec![String::from("sample")],
        }
    }

    #[test]
    fn deployment_profile_parses_supported_names() {
        assert_eq!(
            DeploymentProfile::parse("loopback_regression_v1"),
            Some(DeploymentProfile::LoopbackRegressionV1)
        );
        assert_eq!(
            DeploymentProfile::parse("lab_small_non_loopback_v1"),
            Some(DeploymentProfile::LabSmallNonLoopbackV1)
        );
        assert_eq!(DeploymentProfile::parse("unknown"), None);
    }

    #[test]
    fn supported_profile_requires_external_timing_evidence_to_be_ready() {
        let profile = DeploymentProfile::LabSmallNonLoopbackV1.spec();
        let evaluation = evaluate_supported_envelope(
            &profile,
            &sample_report(),
            &ControlPlaneTimingEvidence {
                reload_success_ms: Some(2_000),
                reload_degraded_success_ms: None,
                failover_ms: Some(1_500),
                evidence_source: Some(String::from("status")),
            },
        );

        assert_eq!(evaluation.claim_tier, PerformanceClaimTier::Supported);
        assert!(!evaluation.supported_claim_ready);
        assert!(evaluation.checks.iter().any(|check| {
            check.metric == "reload_degraded_success_ms"
                && check.status == super::CheckStatus::NotEvaluated
        }));
    }

    #[test]
    fn baseline_comparison_flags_material_throughput_regression() {
        let profile = DeploymentProfile::LabSmallNonLoopbackV1.spec();
        let baseline = PerformanceEnvelopeArtifact {
            schema_version: String::from("v1"),
            generated_at_unix_ms: 1,
            profile: profile.clone(),
            report: sample_report(),
            control_plane_timing: ControlPlaneTimingEvidence {
                reload_success_ms: Some(2_000),
                reload_degraded_success_ms: Some(8_000),
                failover_ms: Some(1_500),
                evidence_source: Some(String::from("baseline")),
            },
            threshold_evaluation: evaluate_supported_envelope(
                &profile,
                &sample_report(),
                &ControlPlaneTimingEvidence {
                    reload_success_ms: Some(2_000),
                    reload_degraded_success_ms: Some(8_000),
                    failover_ms: Some(1_500),
                    evidence_source: Some(String::from("baseline")),
                },
            ),
            baseline_comparison: None,
        };

        let mut candidate = sample_report();
        candidate.http1_throughput.operations_per_sec = 2_000.0;
        let comparison = compare_against_baseline(
            &profile,
            &candidate,
            &ControlPlaneTimingEvidence {
                reload_success_ms: Some(2_000),
                reload_degraded_success_ms: Some(8_000),
                failover_ms: Some(1_500),
                evidence_source: Some(String::from("candidate")),
            },
            &baseline,
        );

        assert!(!comparison.passed);
        assert!(comparison.checks.iter().any(|check| {
            check.metric == "http1_ops_per_sec" && check.status == super::CheckStatus::Failed
        }));
    }

    #[test]
    fn artifact_round_trip_preserves_profile_contract() -> Result<(), DynError> {
        let artifact = PerformanceEnvelopeArtifact {
            schema_version: String::from("v1"),
            generated_at_unix_ms: 1,
            profile: DeploymentProfileSpec {
                name: String::from("lab_small_non_loopback_v1"),
                claim_tier: PerformanceClaimTier::Supported,
                summary: String::from("sample"),
                host_class: HostClassSpec {
                    label: String::from("small_host_v1"),
                    cpu_cores: Some(4),
                    memory_gib: Some(16),
                    nic_gbps: Some(10),
                },
                network_profile: NetworkProfileSpec {
                    label: String::from("single_az_non_loopback"),
                    path: String::from("lab"),
                    expected_rtt_ms: Some(1.5),
                },
                tls_mode: String::from("tls"),
                connection_mix: String::from("mixed"),
                request_payload_bytes: 1024,
                hostile_edge_posture: String::from("enabled"),
                supported_envelope: Some(SupportedEnvelopeThresholds {
                    min_http1_ops_per_sec: 2_500.0,
                    min_http2_ops_per_sec: 8_000.0,
                    max_mixed_p50_us: 5_000,
                    max_mixed_p95_us: 12_000,
                    max_mixed_p99_us: 20_000,
                    max_idle_connection_rss_kib_per_unit: 16.0,
                    max_http2_stream_rss_kib_per_unit: 24.0,
                    max_reload_success_ms: 5_000,
                    max_reload_degraded_success_ms: 15_000,
                    max_failover_ms: 3_000,
                }),
                regression_guardrails: RegressionGuardrails::default(),
                evidence_requirements: vec![String::from("status")],
            },
            report: sample_report(),
            control_plane_timing: ControlPlaneTimingEvidence {
                reload_success_ms: Some(2_000),
                reload_degraded_success_ms: Some(8_000),
                failover_ms: Some(1_500),
                evidence_source: Some(String::from("status")),
            },
            threshold_evaluation: evaluate_supported_envelope(
                &DeploymentProfile::LabSmallNonLoopbackV1.spec(),
                &sample_report(),
                &ControlPlaneTimingEvidence {
                    reload_success_ms: Some(2_000),
                    reload_degraded_success_ms: Some(8_000),
                    failover_ms: Some(1_500),
                    evidence_source: Some(String::from("status")),
                },
            ),
            baseline_comparison: None,
        };

        let json = serde_json::to_string_pretty(&artifact)?;
        let decoded: PerformanceEnvelopeArtifact = serde_json::from_str(&json)?;
        assert_eq!(decoded.profile.name, "lab_small_non_loopback_v1");
        assert_eq!(decoded.profile.claim_tier, PerformanceClaimTier::Supported);
        assert_eq!(decoded.control_plane_timing.failover_ms, Some(1_500));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn artifact_builder_returns_loopback_profile_without_supported_claim() -> Result<(), DynError> {
        let artifact = build_performance_envelope_artifact(
            EnvelopeMode::Smoke,
            DeploymentProfile::LoopbackRegressionV1,
            ControlPlaneTimingEvidence::default(),
            None,
        )
        .await?;

        assert_eq!(artifact.profile.claim_tier, PerformanceClaimTier::Experimental);
        assert!(!artifact.threshold_evaluation.supported_claim_ready);
        assert!(artifact.threshold_evaluation.checks.is_empty());
        Ok(())
    }
}
