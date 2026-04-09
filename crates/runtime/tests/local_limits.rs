use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use lb_runtime::{
    LimitContext, LocalConcurrencyLimitConfig, LocalConcurrencyLimiter, LocalLimitError,
    LocalLimitKeyKind, LocalLimitScope, LocalRateLimitConfig, LocalRateLimiter,
};

#[test]
fn rejects_rate_limited_traffic_predictably() -> Result<(), Box<dyn std::error::Error>> {
    let limiter = LocalRateLimiter::new(LocalRateLimitConfig {
        scope: LocalLimitScope::Listener { name: String::from("public") },
        key_kind: LocalLimitKeyKind::SourceIp,
        requests_per_window: 2,
        window: Duration::from_secs(1),
        max_tracked_keys: 4,
    })?;
    let context = LimitContext {
        source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ..LimitContext::default()
    };

    assert!(limiter.check(Duration::ZERO, &context)?.allowed);
    assert!(limiter.check(Duration::ZERO, &context)?.allowed);
    let rejected = limiter.check(Duration::ZERO, &context)?;
    assert!(!rejected.allowed);
    assert_eq!(rejected.remaining, 0);
    assert_eq!(limiter.metrics().rate_limited_count, 1);

    Ok(())
}

#[test]
fn concurrency_guard_rejects_when_capacity_is_exhausted() -> Result<(), Box<dyn std::error::Error>>
{
    let limiter = LocalConcurrencyLimiter::new(LocalConcurrencyLimitConfig {
        scope: LocalLimitScope::UpstreamCluster { name: String::from("payments") },
        key_kind: LocalLimitKeyKind::Global,
        max_concurrent: 1,
        max_tracked_keys: 2,
    })?;

    let lease = limiter.try_acquire(&LimitContext::default())?;
    let rejected = limiter.try_acquire(&LimitContext::default());
    assert!(matches!(rejected, Err(LocalLimitError::ConcurrencyLimitExceeded)));
    assert_eq!(limiter.metrics().active_concurrency, 1);
    assert_eq!(limiter.metrics().concurrency_rejection_count, 1);

    drop(lease);
    assert_eq!(limiter.metrics().active_concurrency, 0);
    Ok(())
}

#[test]
fn malformed_route_keys_cannot_bypass_normalization() -> Result<(), Box<dyn std::error::Error>> {
    let limiter = LocalRateLimiter::new(LocalRateLimitConfig {
        scope: LocalLimitScope::Route { name: String::from("checkout") },
        key_kind: LocalLimitKeyKind::RouteName,
        requests_per_window: 1,
        window: Duration::from_secs(60),
        max_tracked_keys: 4,
    })?;

    let first =
        LimitContext { route_name: Some(String::from(" Checkout ")), ..LimitContext::default() };
    let second =
        LimitContext { route_name: Some(String::from("CHECKOUT")), ..LimitContext::default() };

    assert!(limiter.check(Duration::ZERO, &first)?.allowed);
    let rejected = limiter.check(Duration::ZERO, &second)?;
    assert!(!rejected.allowed);

    Ok(())
}

#[test]
fn limiter_state_remains_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let limiter = LocalRateLimiter::new(LocalRateLimitConfig {
        scope: LocalLimitScope::Listener { name: String::from("public") },
        key_kind: LocalLimitKeyKind::SourceIp,
        requests_per_window: 10,
        window: Duration::from_secs(1),
        max_tracked_keys: 2,
    })?;

    let _ = limiter.check(
        Duration::ZERO,
        &LimitContext {
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            ..LimitContext::default()
        },
    )?;
    let _ = limiter.check(
        Duration::from_millis(10),
        &LimitContext {
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ..LimitContext::default()
        },
    )?;
    let _ = limiter.check(
        Duration::from_millis(20),
        &LimitContext {
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))),
            ..LimitContext::default()
        },
    )?;

    assert_eq!(limiter.metrics().tracked_keys, 2);
    Ok(())
}
