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
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            discovery: None,
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
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            discovery: None,
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
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            discovery: None,
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
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            discovery: None,
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
            transport: lb_config_model::UpstreamTransportConfig::Http1,
            discovery: None,
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
                    "per_try_timeout_ms": 8000,
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
        let failure_manager = canary_runtime
            .failure_manager
            .as_ref()
            .ok_or("missing canary failure manager")?;
        assert_eq!(
            failure_manager.effective_timeout(lb_runtime::TimeoutCategory::Attempt),
            Duration::from_millis(8_000)
        );
        assert!(canary_runtime.enforce_timeout_hierarchy);
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
        assert!(status.contains("\"last_reload_result\":"));
        assert!(status.contains("configuration applied"));
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
    async fn warm_restart_replaces_listener_and_reports_machine_readable_outcome(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let upstream = spawn_tagged_http1_upstream("upstream-restart").await?;
        let path = write_temp_config(
            "warm-restart-success",
            &workspace_config_json("127.0.0.1:0", "127.0.0.1:0", "http1", &upstream.to_string()),
        )?;
        let supervisor = ServeSupervisor::start(
            path.to_str().ok_or("utf8 path")?.to_string(),
            Arc::new(String::from("admin-secret")),
        )
        .await?;

        let before = supervisor.listener_statuses().await;
        let old_public_addr = before
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener")?
            .local_addr;
        let admin_addr = before
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Admin)
            .ok_or("missing admin listener")?
            .local_addr;

        let restart = send_admin_restart(admin_addr).await?;
        assert!(restart.starts_with("HTTP/1.1 200 OK"));

        let after = supervisor.listener_statuses().await;
        let new_public_addr = after
            .iter()
            .find(|status| status.class == lb_config_model::ListenerClassConfig::Public)
            .ok_or("missing public listener after restart")?
            .local_addr;
        assert_ne!(old_public_addr, new_public_addr);

        let response = send_http1_request(new_public_addr, "/").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("upstream-restart"));

        let status = send_admin_status(admin_addr).await?;
        let status_json = parse_http_json_body(&status)?;
        assert_eq!(json_u64_field(&status_json, "restart_requests")?, 1);
        assert_eq!(json_u64_field(&status_json, "restart_success_count")?, 1);
        assert_eq!(json_u64_field(&status_json, "restart_failure_count")?, 0);
        assert!(json_u64_field(&status_json, "restart_last_duration_ms")? >= 1);
        assert!(json_u64_field(&status_json, "restart_last_success_duration_ms")? >= 1);
        assert_eq!(json_u64_field(&status_json, "restart_last_failure_duration_ms")?, 0);
        assert!(status.contains("\"last_restart_outcome_code\": \"restart_applied_overlap_drain\""));

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.contains("\"code\": \"restart_started_overlap_drain\""));
        assert!(audit.contains("\"code\": \"restart_applied_overlap_drain\""));

        supervisor.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn warm_restart_timeout_is_reported_with_machine_readable_outcome(
    ) -> Result<(), DynError> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "admin-secret");
        let (upstream_a, accepted_rx, release_tx) =
            spawn_blocked_http1_upstream("upstream-restart-timeout-a").await?;
        let upstream_b = spawn_tagged_http1_upstream("upstream-restart-timeout-b").await?;
        let path = write_temp_config(
            "warm-restart-timeout",
            &workspace_config_json_with_drain_timeout(
                "127.0.0.1:0",
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
                "127.0.0.1:0",
                "127.0.0.1:0",
                "http1",
                &upstream_b.to_string(),
                50,
            ),
        )?;

        let restart = send_admin_restart(admin_addr).await?;
        assert!(restart.starts_with("HTTP/1.1 200 OK"));

        let status = send_admin_status(admin_addr).await?;
        let status_json = parse_http_json_body(&status)?;
        assert_eq!(json_u64_field(&status_json, "restart_requests")?, 1);
        assert_eq!(json_u64_field(&status_json, "restart_success_count")?, 1);
        assert_eq!(json_u64_field(&status_json, "restart_failure_count")?, 0);
        assert!(status.contains("\"last_restart_outcome_code\": \"restart_applied_overlap_drain_timeout\""));

        let audit = send_admin_audit(admin_addr).await?;
        assert!(audit.contains("\"code\": \"restart_started_overlap_drain\""));
        assert!(audit.contains("\"code\": \"restart_applied_overlap_drain_timeout\""));

        drop(first);
        let _ = release_tx.send(());
        supervisor.shutdown().await?;
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
        let status_json = parse_http_json_body(&status)?;
        assert_eq!(json_u64_field(&status_json, "reload_drained_listener_count")?, 1);
        assert_eq!(json_u64_field(&status_json, "reload_completed_drain_count")?, 0);
        assert_eq!(json_u64_field(&status_json, "reload_drain_timeout_count")?, 1);

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
        assert!(json_u64_field(&final_status_json, "reload_drained_listener_count")? >= 1);
        assert!(json_u64_field(&final_status_json, "reload_completed_drain_count")? >= 1);
        assert_eq!(json_u64_field(&final_status_json, "reload_drain_timeout_count")?, 0);
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

    async fn send_admin_restart(address: SocketAddr) -> Result<String, DynError> {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"POST /restart HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
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
