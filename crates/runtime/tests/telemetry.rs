use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use lb_net_core::ListenerClass;
use lb_observability::{FailureManagementEventKind, OverloadEvent, OverloadEventKind};
use lb_runtime::{
    HttpCacheRequestOutcome, HttpCacheRevalidationResult, HttpCacheStoreMetrics,
    ListenerEvent, ListenerEventKind, ListenerSnapshot, ListenerState, OverloadSnapshot,
    OverloadState, RuntimeTelemetry,
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

    let metrics = telemetry.export_metrics();
    assert!(metrics.contains(
        "runtime_listener_active_connections{listener=\"ingress_tcp\",state=\"running\"} 3"
    ));
    assert!(metrics.contains("runtime_listener_events_total{listener=\"ingress_tcp\",event_code=\"runtime.listener.started\"} 1"));
    assert!(metrics.contains(
        "runtime_breaker_events_total{scope=\"payments\",event_code=\"failure.breaker.opened\"} 1"
    ));
    assert!(metrics.contains("runtime_overload_state{scope=\"dataplane\"} 2"));
    assert!(metrics.contains("runtime_shed_requests_total{scope=\"dataplane\"} 7"));
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

    let snapshot = telemetry.snapshot();
    assert_eq!(snapshot.events.len(), 8);
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "runtime.listener.started"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "failure.breaker.opened"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "overload.request.shed"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "cache.hit"));
    assert!(snapshot.logs.iter().any(|record| record.code.as_str() == "cache.revalidated"));
    Ok(())
}
