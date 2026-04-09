use std::io;
use std::net::TcpListener as StdTcpListener;
use std::time::{Duration, Instant};

use lb_net_core::{ListenerClass, ListenerConfig};
use lb_runtime::{start_listener, ListenerRuntimeError, ListenerState};
use tokio::net::TcpStream;
use tokio::time;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_starts_and_stops_gracefully() -> io::Result<()> {
    let config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    let handle = start_listener(config).await.map_err(runtime_error_to_io)?;

    wait_for_state(&handle, ListenerState::Running).await?;
    handle.shutdown().await.map_err(runtime_error_to_io)?;

    let snapshot = handle.snapshot();
    assert_eq!(snapshot.state, ListenerState::Stopped);
    assert!(snapshot.local_addr.port() != 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_rejects_connections_after_admission_limit() -> io::Result<()> {
    let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    config.max_connections = 1;
    config.idle_timeout = Duration::from_secs(30);
    let handle = start_listener(config).await.map_err(runtime_error_to_io)?;

    wait_for_state(&handle, ListenerState::Running).await?;

    let first = TcpStream::connect(handle.local_addr()).await?;
    wait_for_active_connections(&handle, 1).await?;

    let second = TcpStream::connect(handle.local_addr()).await?;
    wait_for_rejected_connections(&handle, 1).await?;
    drop(second);
    drop(first);

    handle.shutdown().await.map_err(runtime_error_to_io)?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_reports_bind_failure() -> io::Result<()> {
    let reserved = StdTcpListener::bind("127.0.0.1:0")?;
    let address = reserved.local_addr()?;
    let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    config.bind_address = address;

    let result = start_listener(config).await;

    assert!(matches!(result, Err(ListenerRuntimeError::Bind(_))));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_shutdown_is_idempotent() -> io::Result<()> {
    let config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    let handle = start_listener(config).await.map_err(runtime_error_to_io)?;

    wait_for_state(&handle, ListenerState::Running).await?;
    handle.shutdown().await.map_err(runtime_error_to_io)?;
    handle.shutdown().await.map_err(runtime_error_to_io)?;

    assert_eq!(handle.snapshot().state, ListenerState::Stopped);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn burst_connections_do_not_break_listener() -> io::Result<()> {
    let mut config = ListenerConfig::foundation_local("public", ListenerClass::Public);
    config.max_connections = 2;
    config.idle_timeout = Duration::from_secs(30);
    let handle = start_listener(config).await.map_err(runtime_error_to_io)?;

    wait_for_state(&handle, ListenerState::Running).await?;

    let mut streams = Vec::new();
    for _ in 0..8 {
        streams.push(TcpStream::connect(handle.local_addr()).await?);
    }

    wait_for_rejected_connections_at_least(&handle, 1).await?;
    drop(streams);
    handle.shutdown().await.map_err(runtime_error_to_io)?;

    let snapshot = handle.snapshot();
    assert!(snapshot.accepted_connections >= 1);
    assert!(snapshot.rejected_connections >= 1);

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

async fn wait_for_active_connections(
    handle: &lb_runtime::ListenerHandle,
    target: usize,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if handle.snapshot().active_connections == target {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(io::Error::other("timed out waiting for active connections"));
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
        if handle.snapshot().rejected_connections == target {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(io::Error::other("timed out waiting for rejected connections"));
        }

        time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_rejected_connections_at_least(
    handle: &lb_runtime::ListenerHandle,
    minimum: usize,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if handle.snapshot().rejected_connections >= minimum {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(io::Error::other("timed out waiting for rejected connection burst"));
        }

        time::sleep(Duration::from_millis(10)).await;
    }
}

fn runtime_error_to_io(error: ListenerRuntimeError) -> io::Error {
    io::Error::other(error.to_string())
}
