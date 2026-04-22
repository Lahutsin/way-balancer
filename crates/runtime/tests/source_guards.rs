use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use lb_net_core::{ListenerBindMode, ListenerClass, ListenerConfig};
use lb_runtime::{
    start_listener_with_protection, HandshakeGuardPolicy, ListenerAbuseProtectionPolicy,
    ListenerAbuseProtectionSnapshot, ListenerRuntimeError, ListenerState, SourceAggregation,
    SourceQuotaPolicy,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_rejects_clients_after_per_source_quota() -> io::Result<()> {
    let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    config.max_connections = 8;
    config.idle_timeout = Duration::from_secs(30);
    let handle = start_listener_with_protection(
        config,
        ListenerAbuseProtectionPolicy {
            source_quota: Some(SourceQuotaPolicy::new(SourceAggregation::ExactIp, 1, 8)),
            handshake_guard: None,
        },
    )
    .await
    .map_err(runtime_error_to_io)?;

    wait_for_state(&handle, ListenerState::Running).await?;

    let first = TcpStream::connect(handle.local_addr()).await?;
    wait_for_rejection_metric(&handle, |snapshot| snapshot.tracked_sources == 1).await?;

    let second = TcpStream::connect(handle.local_addr()).await?;
    wait_for_rejected_connections(&handle, 1).await?;

    drop(second);
    drop(first);
    handle.shutdown().await.map_err(runtime_error_to_io)?;

    let snapshot = handle.abuse_protection_snapshot();
    assert_eq!(snapshot.source_quota_rejections, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_rejects_connections_when_handshake_cap_is_exhausted() -> io::Result<()> {
    let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    config.max_connections = 8;
    config.idle_timeout = Duration::from_secs(30);
    let handle = start_listener_with_protection(
        config,
        ListenerAbuseProtectionPolicy {
            source_quota: None,
            handshake_guard: Some(HandshakeGuardPolicy::new(1, Duration::from_secs(5))),
        },
    )
    .await
    .map_err(runtime_error_to_io)?;

    wait_for_state(&handle, ListenerState::Running).await?;

    let first = TcpStream::connect(handle.local_addr()).await?;
    wait_for_rejection_metric(&handle, |snapshot| snapshot.active_handshakes == 1).await?;

    let second = TcpStream::connect(handle.local_addr()).await?;
    wait_for_rejected_connections(&handle, 1).await?;

    drop(second);
    drop(first);
    handle.shutdown().await.map_err(runtime_error_to_io)?;

    let snapshot = handle.abuse_protection_snapshot();
    assert_eq!(snapshot.handshake_guard_rejections, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legitimate_traffic_passes_when_limits_allow_it() -> io::Result<()> {
    let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    config.max_connections = 8;
    config.idle_timeout = Duration::from_secs(30);
    let handle = start_listener_with_protection(
        config,
        ListenerAbuseProtectionPolicy {
            source_quota: Some(SourceQuotaPolicy::new(SourceAggregation::ExactIp, 2, 8)),
            handshake_guard: Some(HandshakeGuardPolicy::new(2, Duration::from_secs(5))),
        },
    )
    .await
    .map_err(runtime_error_to_io)?;

    wait_for_state(&handle, ListenerState::Running).await?;

    let mut first = TcpStream::connect(handle.local_addr()).await?;
    let mut second = TcpStream::connect(handle.local_addr()).await?;
    first.write_all(b"a").await?;
    second.write_all(b"b").await?;

    wait_for_rejection_metric(&handle, |snapshot| snapshot.active_handshakes == 0).await?;
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.rejected_connections, 0);
    assert!(snapshot.accepted_connections >= 2);

    drop(first);
    drop(second);
    handle.shutdown().await.map_err(runtime_error_to_io)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dual_stack_listener_groups_ipv4_clients_by_ipv4_subnet() -> io::Result<()> {
    let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    config.bind_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    config.bind_mode = ListenerBindMode::DualStack;
    config.allow_unspecified_bind = true;
    config.max_connections = 8;
    config.idle_timeout = Duration::from_secs(30);
    let handle = start_listener_with_protection(
        config,
        ListenerAbuseProtectionPolicy {
            source_quota: Some(SourceQuotaPolicy::new(SourceAggregation::Ipv4Subnet24, 1, 8)),
            handshake_guard: None,
        },
    )
    .await
    .map_err(runtime_error_to_io)?;

    wait_for_state(&handle, ListenerState::Running).await?;

    let port = handle.local_addr().port();
    let first = TcpStream::connect(("127.0.0.1", port)).await?;
    wait_for_rejection_metric(&handle, |snapshot| snapshot.tracked_sources == 1).await?;

    let second = TcpStream::connect(("127.0.0.1", port)).await?;
    wait_for_rejected_connections(&handle, 1).await?;

    drop(second);
    drop(first);
    handle.shutdown().await.map_err(runtime_error_to_io)?;

    let snapshot = handle.abuse_protection_snapshot();
    assert_eq!(snapshot.source_quota_rejections, 1);
    assert_eq!(snapshot.tracked_sources, 0);
    Ok(())
}

async fn wait_for_state(
    handle: &lb_runtime::ListenerHandle,
    target: ListenerState,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if handle.snapshot().state == target {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("timed out waiting for listener state"));
        }
        time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_rejected_connections(
    handle: &lb_runtime::ListenerHandle,
    target: usize,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if handle.snapshot().rejected_connections >= target {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("timed out waiting for rejected connections"));
        }
        time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_rejection_metric(
    handle: &lb_runtime::ListenerHandle,
    predicate: impl Fn(ListenerAbuseProtectionSnapshot) -> bool,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let snapshot = handle.abuse_protection_snapshot();
        if predicate(snapshot) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("timed out waiting for abuse protection snapshot"));
        }
        time::sleep(Duration::from_millis(10)).await;
    }
}

fn runtime_error_to_io(error: ListenerRuntimeError) -> io::Error {
    io::Error::other(error.to_string())
}
