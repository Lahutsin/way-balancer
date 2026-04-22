use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use lb_net_core::ListenerClass;
use lb_observability::TraceHookPhase;
use lb_observability::{FailureManagementEventKind, OverloadEvent, OverloadEventKind};
use lb_runtime::{
    AbuseRejectionReason, HttpCacheRequestOutcome, HttpCacheRevalidationResult,
    HttpCacheStoreMetrics, HttpUpgradeResult, ListenerAbuseProtectionSnapshot, ListenerEvent,
    ListenerEventKind, ListenerSnapshot, ListenerState, OverloadSnapshot, OverloadState,
    RuntimeTelemetry,
};

#[test]
fn runtime_telemetry_emits_structured_logs_and_metrics() -> Result<(), Box<dyn std::error::Error>> {
    let telemetry = RuntimeTelemetry::new()?;
    telemetry.record_listener_event(
        "Ingress TCP",
        &ListenerEvent {
            kind: ListenerEventKind::Started,
            detail: String::from("listener started"),
        },
    )?;
    telemetry.record_failure_event(
        "payments",
        FailureManagementEventKind::BreakerOpened,
        "breaker opened after retries",
    )?;
    telemetry.record_overload_event(&OverloadEvent {
        kind: OverloadEventKind::RequestShed,
        scope: String::from("dataplane"),
        detail: String::from("shed best-effort traffic"),
    })?;
    telemetry.record_listener_snapshot(&ListenerSnapshot {
        name: String::from("Ingress TCP"),
        class: ListenerClass::Public,
        local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        state: ListenerState::Running,
        active_connections: 3,
        accepted_connections: 5,
        rejected_connections: 1,
        recent_events: Vec::new(),
    })?;
    telemetry.record_listener_abuse_rejection(
        "Ingress TCP",
        AbuseRejectionReason::SourceQuotaExceeded,
        "hostile-edge source quota exhausted",
    )?;
    telemetry.record_listener_abuse_snapshot(
        "Ingress TCP",
        &ListenerAbuseProtectionSnapshot {
            source_quota_rejections: 1,
            tracked_source_limit_rejections: 0,
            handshake_guard_rejections: 0,
            tracked_sources: 2,
            active_handshakes: 1,
        },
    )?;
    telemetry.record_overload_snapshot(
        "dataplane",
        &OverloadSnapshot {
            state: OverloadState::Shedding,
            active_signal_count: 4,
            rate_limited_count: 2,
            concurrency_limited_count: 1,
            breaker_open_count: 1,
            retry_budget_exhausted_count: 0,
            shed_request_count: 7,
            brownout_feature_count: 1,
        },
    )?;
    telemetry.record_http_cache_metrics(
        "public-http",
        &HttpCacheStoreMetrics {
            entry_count: 2,
            total_bytes: 128,
            max_object_bytes: 96,
            ..HttpCacheStoreMetrics::default()
        },
    )?;
    telemetry.record_http_cache_request(
        "public-http",
        HttpCacheRequestOutcome::Hit,
        "fresh",
        "served fresh cache entry",
    )?;
    telemetry.record_http_cache_request(
        "public-http",
        HttpCacheRequestOutcome::StaleHit,
        "stale_if_error",
        "served stale cache entry",
    )?;
    telemetry.record_http_cache_request(
        "public-http",
        HttpCacheRequestOutcome::Bypass,
        "request_cookie",
        "bypassed shared cache due to cookie",
    )?;
    telemetry.record_http_cache_revalidation(
        "public-http",
        HttpCacheRevalidationResult::NotModified,
        "origin confirmed cached object",
    )?;
    telemetry.record_http_cache_purge("public-http", "purged", 3)?;
    telemetry.record_http_cache_invalidation_delivery("public-http", "http_peer", "success", 2)?;
    telemetry.record_http_cache_invalidation_delivery("public-http", "http_peer", "failed", 1)?;
    telemetry.record_http_upgrade(
        "public-http",
        HttpUpgradeResult::Accepted,
        "websocket",
        "websocket tunnel accepted",
    )?;
    telemetry.record_http_upgrade(
        "public-http",
        HttpUpgradeResult::Rejected,
        "policy_denied",
        "route upgrade policy denied websocket",
    )?;
    telemetry.record_http_upgrade(
        "public-http",
        HttpUpgradeResult::Failed,
        "upstream_refused",
        "upstream refused websocket upgrade",
    )?;
    telemetry.record_http3_request("public-http3", "served", "2xx")?;
    telemetry.record_http3_request("public-http3", "failed", "bridge_failed")?;
    telemetry.record_request_latency(
        "http1/request",
        TraceHookPhase::ResponseCompleted,
        Duration::from_millis(7),
    )?;
    telemetry.record_request_latency(
        "http1/request",
        TraceHookPhase::ResponseCompleted,
        Duration::from_millis(180),
    )?;

    let metrics = telemetry.export_metrics();
    assert!(metrics.contains(
        "runtime_listener_active_connections{listener=\"ingress_tcp\",state=\"running\"} 3"
    ));
    assert!(metrics.contains("runtime_listener_accepted_connections{listener=\"ingress_tcp\"} 5"));
    assert!(metrics.contains("runtime_listener_rejected_connections{listener=\"ingress_tcp\"} 1"));
    assert!(metrics.contains(
        "runtime_listener_abuse_rejections_total{listener=\"ingress_tcp\",reason=\"source_quota_exceeded\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_listener_abuse_tracked_sources{listener=\"ingress_tcp\"} 2"
    ));
    assert!(metrics.contains(
        "runtime_listener_abuse_active_handshakes{listener=\"ingress_tcp\"} 1"
    ));
    assert!(metrics.contains("runtime_listener_events_total{listener=\"ingress_tcp\",event_code=\"runtime.listener.started\"} 1"));
    assert!(metrics.contains(
        "runtime_breaker_events_total{scope=\"payments\",event_code=\"failure.breaker.opened\"} 1"
    ));
    assert!(metrics.contains("runtime_overload_state{scope=\"dataplane\"} 2"));
    assert!(metrics.contains("runtime_shed_requests_total{scope=\"dataplane\"} 7"));
    assert!(metrics.contains("runtime_overload_active_signals{scope=\"dataplane\"} 4"));
    assert!(metrics.contains("runtime_overload_rate_limited{scope=\"dataplane\"} 2"));
    assert!(metrics.contains("runtime_overload_concurrency_limited{scope=\"dataplane\"} 1"));
    assert!(metrics.contains("runtime_overload_breaker_open{scope=\"dataplane\"} 1"));
    assert!(metrics.contains("runtime_overload_retry_budget_exhausted{scope=\"dataplane\"} 0"));
    assert!(metrics.contains("runtime_overload_brownout_features{scope=\"dataplane\"} 1"));
    assert!(metrics.contains("runtime_http_cache_entries{scope=\"public-http\"} 2"));
    assert!(metrics.contains("runtime_http_cache_bytes{scope=\"public-http\"} 128"));
    assert!(metrics.contains("runtime_http_cache_max_object_bytes{scope=\"public-http\"} 96"));
    assert!(metrics.contains(
        "runtime_http_cache_requests_total{scope=\"public-http\",result=\"hit\",reason=\"fresh\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http_cache_requests_total{scope=\"public-http\",result=\"stale_hit\",reason=\"stale_if_error\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http_cache_requests_total{scope=\"public-http\",result=\"bypass\",reason=\"request_cookie\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http_cache_revalidations_total{scope=\"public-http\",result=\"not_modified\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http_cache_purge_requests_total{scope=\"public-http\",result=\"purged\"} 1"
    ));
    assert!(metrics.contains("runtime_http_cache_purged_entries_total{scope=\"public-http\"} 3"));
    assert!(metrics.contains(
        "runtime_http_cache_invalidation_peer_deliveries_total{scope=\"public-http\",result=\"success\",reason=\"http_peer\"} 2"
    ));
    assert!(metrics.contains(
        "runtime_http_cache_invalidation_peer_deliveries_total{scope=\"public-http\",result=\"failed\",reason=\"http_peer\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"accepted\",reason=\"websocket\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"rejected\",reason=\"policy_denied\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http_upgrades_total{scope=\"public-http\",result=\"failed\",reason=\"upstream_refused\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http3_requests_total{scope=\"public-http3\",result=\"served\",reason=\"2xx\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_http3_requests_total{scope=\"public-http3\",result=\"failed\",reason=\"bridge_failed\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_request_latency_samples_total{scope=\"http1_request\",bucket=\"le_10ms\",phase=\"response_completed\"} 1"
    ));
    assert!(metrics.contains(
        "runtime_request_latency_samples_total{scope=\"http1_request\",bucket=\"le_250ms\",phase=\"response_completed\"} 1"
    ));

    let snapshot = telemetry.snapshot();
    assert_eq!(snapshot.events.len(), 12);
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "runtime.listener.started"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "runtime.listener.rejected"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "failure.breaker.opened"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "overload.request.shed"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "cache.hit"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "cache.revalidated"));
    assert!(snapshot.events.iter().any(|event| event.code.as_str() == "runtime.http_upgrade.accepted"));
    assert!(snapshot.events.iter().any(|event| event.code.as_str() == "runtime.http_upgrade.rejected"));
    assert!(snapshot.events.iter().any(|event| event.code.as_str() == "runtime.http_upgrade.failed"));
    Ok(())
}
