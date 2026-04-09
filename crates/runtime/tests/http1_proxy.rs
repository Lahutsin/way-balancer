use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lb_config_model::{
    AuthorizationCacheBehaviorConfig, CacheKeyPolicyConfig, HttpCachePolicyConfig,
};
use lb_net_core::UpstreamTarget;
use lb_runtime::{
    build_http_cache_key_material, proxy_http1_connection, Http1ConnectionReport,
    Http1ProxyConfig, Http1ProxyError, Http1ResponseCacheConfig, HttpCacheRequest,
    HttpCacheStore, HttpCacheStoreConfig, HttpCacheStoreError, ProtocolAnomalyCategory,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time;

#[derive(Debug)]
struct RequestCapture {
    head: String,
    body: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_keep_alive_requests_and_normalizes_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, captures_rx) = spawn_keep_alive_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET /api/one HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n",
        )
        .await?;
    let first_response = read_http_response(&mut client).await?;
    assert!(first_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_response.ends_with("hello"));

    client
        .write_all(b"GET /api/two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut client).await?;
    assert!(second_response.starts_with("HTTP/1.1 201 Created\r\n"));
    assert!(second_response.ends_with("world"));
    drop(client);

    let captures = receive_capture_list(captures_rx).await?;
    assert_eq!(captures.len(), 2);
    assert!(captures[0].head.contains("GET /api/one HTTP/1.1\r\n"));
    assert!(captures[0].head.contains("x-forwarded-for: 127.0.0.1\r\n"));
    assert!(!captures[0].head.contains("connection: keep-alive\r\n"));

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 2);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));
    assert_eq!(report.metrics.response_status_counts.get(&201), Some(&1));

    Ok(())
}

async fn spawn_not_modified_revalidation_upstream() -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\nCache-Control: max-age=5\r\n\r\n",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_short_ttl_not_modified_revalidation_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\nCache-Control: max-age=1\r\n\r\n",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_revalidation_replacement_upstream() -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\nCache-Control: max-age=5\r\nETag: \"v2\"\r\n\r\nrenewed",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streams_large_request_body() -> Result<(), Box<dyn std::error::Error>> {
    let (upstream_addr, capture_rx) = spawn_body_echo_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_body_bytes = 256 * 1024;
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let body = vec![b'a'; 64 * 1024];
    let mut request = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(&request).await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.contains("received=65536"));
    drop(client);

    let capture = receive_capture(capture_rx).await?;
    assert_eq!(capture.body.len(), body.len());

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.request_count, 1);
    assert_eq!(report.metrics.response_status_counts.get(&200), Some(&1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_malformed_http_requests() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_upstream().await?;
    let (proxy_addr, report_rx) =
        spawn_one_shot_http1_proxy_listener(proxy_config(upstream_addr)).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(b"GET / HTTP/1.1\r\nHost example.test\r\nConnection: close\r\n\r\n").await?;
    drop(client);

    let result = receive_proxy_result(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::ParseRequest(_))));
    if let Err(error) = result {
        assert_eq!(error.anomaly_category(), Some(ProtocolAnomalyCategory::MalformedMessage));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforces_header_count_limit() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_header_count = 2;
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: test\r\nX-Test: 1\r\nConnection: close\r\n\r\n",
        )
        .await?;
    drop(client);

    let result = receive_proxy_result(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::ParseRequest(_))));
    if let Err(error) = result {
        assert_eq!(
            error.anomaly_category(),
            Some(ProtocolAnomalyCategory::HeaderCountLimitExceeded)
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforces_body_size_limit() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = spawn_idle_upstream().await?;
    let mut config = proxy_config(upstream_addr);
    config.limits.max_body_bytes = 16;
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 32\r\nConnection: close\r\n\r\n12345678901234567890123456789012",
        )
        .await?;
    drop(client);

    let result = receive_proxy_result(report_rx).await;
    assert!(matches!(result, Err(Http1ProxyError::BodyLimitExceeded("request body"))));
    if let Err(error) = result {
        assert_eq!(error.anomaly_category(), Some(ProtocolAnomalyCategory::BodySizeLimitExceeded));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_cache_hits_avoid_upstream_requests() -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (upstream_addr, capture_rx) = spawn_single_cacheable_upstream().await?;
    let first_config = proxy_config(upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)));
    let (first_proxy_addr, first_report_rx) = spawn_one_shot_http1_proxy_listener(first_config).await?;

    let mut first_client = TcpStream::connect(first_proxy_addr).await?;
    first_client
        .write_all(b"GET /cacheable HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let first_response = read_http_response(&mut first_client).await?;
    assert!(first_response.ends_with("cached"));
    drop(first_client);

    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.cache_miss_count, 1);
    assert_eq!(first_report.metrics.cache_fill_count, 1);

    let captures = receive_capture_list(capture_rx).await?;
    assert_eq!(captures.len(), 1);

    let unused_upstream = reserve_unused_addr().await?;
    let second_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (second_proxy_addr, second_report_rx) = spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /cacheable HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("cached"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_hit_count, 1);
    assert_eq!(second_report.metrics.cache_miss_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_cacheable_responses_bypass_storage_without_breaking_proxying(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (upstream_addr, capture_rx) = spawn_no_store_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /private HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.contains("Cache-Control: no-store") || response.contains("cache-control: no-store"));
    assert!(response.ends_with("private"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_miss_count, 1);
    assert_eq!(report.metrics.cache_fill_count, 0);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookie_bearing_requests_bypass_shared_cache_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (first_upstream_addr, first_capture_rx) = spawn_single_cacheable_upstream().await?;
    let first_config = proxy_config(first_upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (first_proxy_addr, first_report_rx) = spawn_one_shot_http1_proxy_listener(first_config).await?;

    let mut first_client = TcpStream::connect(first_proxy_addr).await?;
    first_client
        .write_all(b"GET /cookie-session HTTP/1.1\r\nHost: example.test\r\nCookie: session=alpha\r\nConnection: close\r\n\r\n")
        .await?;
    let first_response = read_http_response(&mut first_client).await?;
    assert!(first_response.ends_with("cached"));
    drop(first_client);

    let first_report = receive_proxy_result(first_report_rx).await?;
    assert_eq!(first_report.metrics.cache_bypass_count, 1);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(first_capture_rx).await?.len(), 1);

    let (second_upstream_addr, second_capture_rx) = spawn_single_cacheable_upstream().await?;
    let second_config = proxy_config(second_upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (second_proxy_addr, second_report_rx) = spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /cookie-session HTTP/1.1\r\nHost: example.test\r\nCookie: session=beta\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("cached"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_bypass_count, 1);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(second_capture_rx).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsafe_vary_headers_fail_closed_without_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (upstream_addr, capture_rx) = spawn_vary_cookie_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /vary-cookie HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("unsafe"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 0);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_cache_control_responses_fail_closed_without_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (upstream_addr, capture_rx) = spawn_private_cache_control_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /private-cache-control HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("private"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 0);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_while_revalidate_window_can_serve_stale_entries(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 2,
        stale_if_error_secs: 0,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };
    let (upstream_addr, capture_rx) = spawn_swr_upstream().await?;
    let config = proxy_config(upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /swr HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("stale"));
    drop(client);
    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);

    time::sleep(Duration::from_millis(1_100)).await;

    let unused_upstream = reserve_unused_addr().await?;
    let second_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (second_proxy_addr, second_report_rx) = spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /swr HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("stale"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_hit_count, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_if_error_window_can_fallback_on_upstream_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 0,
        stale_if_error_secs: 3,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };
    let (upstream_addr, capture_rx) = spawn_stale_if_error_upstream().await?;
    let config = proxy_config(upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /sie HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("backup"));
    drop(client);
    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);

    time::sleep(Duration::from_millis(1_100)).await;

    let unused_upstream = reserve_unused_addr().await?;
    let second_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (second_proxy_addr, second_report_rx) = spawn_one_shot_http1_proxy_listener(second_config).await?;

    let mut second_client = TcpStream::connect(second_proxy_addr).await?;
    second_client
        .write_all(b"GET /sie HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let second_response = read_http_response(&mut second_client).await?;
    assert!(second_response.ends_with("backup"));
    drop(second_client);

    let second_report = receive_proxy_result(second_report_rx).await?;
    assert_eq!(second_report.metrics.cache_hit_count, 1);
    assert_eq!(second_report.metrics.cache_miss_count, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditional_revalidation_uses_validators_and_304_refreshes_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 2,
        stale_if_error_secs: 0,
        revalidation_enabled: true,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (seed_upstream_addr, seed_capture_rx) = spawn_revalidation_seed_upstream().await?;
    let seed_config = proxy_config(seed_upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)));
    let (seed_proxy_addr, seed_report_rx) = spawn_one_shot_http1_proxy_listener(seed_config).await?;

    let mut seed_client = TcpStream::connect(seed_proxy_addr).await?;
    seed_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let seed_response = read_http_response(&mut seed_client).await?;
    assert!(seed_response.ends_with("cached"));
    drop(seed_client);

    let seed_report = receive_proxy_result(seed_report_rx).await?;
    assert_eq!(seed_report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(seed_capture_rx).await?.len(), 1);

    time::sleep(Duration::from_millis(1_100)).await;

    let (revalidate_upstream_addr, revalidate_capture_rx) =
        spawn_not_modified_revalidation_upstream().await?;
    let revalidate_config = proxy_config(revalidate_upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)));
    let (revalidate_proxy_addr, revalidate_report_rx) =
        spawn_one_shot_http1_proxy_listener(revalidate_config).await?;

    let mut revalidate_client = TcpStream::connect(revalidate_proxy_addr).await?;
    revalidate_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let revalidate_response = read_http_response(&mut revalidate_client).await?;
    assert!(revalidate_response.ends_with("cached"));
    drop(revalidate_client);

    let revalidate_report = receive_proxy_result(revalidate_report_rx).await?;
    assert_eq!(revalidate_report.metrics.cache_miss_count, 1);
    assert_eq!(revalidate_report.metrics.cache_fill_count, 1);

    let revalidate_captures = receive_capture_list(revalidate_capture_rx).await?;
    assert_eq!(revalidate_captures.len(), 1);
    assert!(revalidate_captures[0].head.contains("if-none-match: \"v1\"\r\n"));
    assert!(revalidate_captures[0]
        .head
        .contains("if-modified-since: Wed, 21 Oct 2015 07:28:00 GMT\r\n"));

    let unused_upstream = reserve_unused_addr().await?;
    let post_refresh_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (post_refresh_proxy_addr, post_refresh_report_rx) =
        spawn_one_shot_http1_proxy_listener(post_refresh_config).await?;

    let mut post_refresh_client = TcpStream::connect(post_refresh_proxy_addr).await?;
    post_refresh_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let post_refresh_response = read_http_response(&mut post_refresh_client).await?;
    assert!(post_refresh_response.ends_with("cached"));
    drop(post_refresh_client);

    let post_refresh_report = receive_proxy_result(post_refresh_report_rx).await?;
    assert_eq!(post_refresh_report.metrics.cache_hit_count, 1);
    assert_eq!(post_refresh_report.metrics.cache_miss_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditional_revalidation_200_replaces_cached_object(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 2,
        stale_if_error_secs: 0,
        revalidation_enabled: true,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (seed_upstream_addr, seed_capture_rx) = spawn_revalidation_seed_upstream().await?;
    let seed_config = proxy_config(seed_upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)));
    let (seed_proxy_addr, seed_report_rx) = spawn_one_shot_http1_proxy_listener(seed_config).await?;

    let mut seed_client = TcpStream::connect(seed_proxy_addr).await?;
    seed_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let seed_response = read_http_response(&mut seed_client).await?;
    assert!(seed_response.ends_with("cached"));
    drop(seed_client);

    let seed_report = receive_proxy_result(seed_report_rx).await?;
    assert_eq!(seed_report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(seed_capture_rx).await?.len(), 1);

    time::sleep(Duration::from_millis(1_100)).await;

    let (replacement_upstream_addr, replacement_capture_rx) =
        spawn_revalidation_replacement_upstream().await?;
    let replacement_config = proxy_config(replacement_upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)));
    let (replacement_proxy_addr, replacement_report_rx) =
        spawn_one_shot_http1_proxy_listener(replacement_config).await?;

    let mut replacement_client = TcpStream::connect(replacement_proxy_addr).await?;
    replacement_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let replacement_response = read_http_response(&mut replacement_client).await?;
    assert!(replacement_response.ends_with("renewed"));
    drop(replacement_client);

    let replacement_report = receive_proxy_result(replacement_report_rx).await?;
    assert_eq!(replacement_report.metrics.cache_miss_count, 1);
    assert_eq!(replacement_report.metrics.cache_fill_count, 1);

    let replacement_captures = receive_capture_list(replacement_capture_rx).await?;
    assert_eq!(replacement_captures.len(), 1);
    assert!(replacement_captures[0].head.contains("if-none-match: \"v1\"\r\n"));
    assert!(replacement_captures[0]
        .head
        .contains("if-modified-since: Wed, 21 Oct 2015 07:28:00 GMT\r\n"));

    let unused_upstream = reserve_unused_addr().await?;
    let post_replace_config = proxy_config(unused_upstream)
        .with_response_cache(Http1ResponseCacheConfig::new(policy, Arc::clone(&shared_store)));
    let (post_replace_proxy_addr, post_replace_report_rx) =
        spawn_one_shot_http1_proxy_listener(post_replace_config).await?;

    let mut post_replace_client = TcpStream::connect(post_replace_proxy_addr).await?;
    post_replace_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let post_replace_response = read_http_response(&mut post_replace_client).await?;
    assert!(post_replace_response.ends_with("renewed"));
    drop(post_replace_client);

    let post_replace_report = receive_proxy_result(post_replace_report_rx).await?;
    assert_eq!(post_replace_report.metrics.cache_hit_count, 1);
    assert_eq!(post_replace_report.metrics.cache_miss_count, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_revalidation_cycles_stay_bounded_under_soak(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let policy = HttpCachePolicyConfig {
        default_ttl_secs: 30,
        stale_while_revalidate_secs: 2,
        stale_if_error_secs: 0,
        revalidation_enabled: true,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };

    let (seed_upstream_addr, seed_capture_rx) = spawn_revalidation_seed_upstream().await?;
    let seed_config = proxy_config(seed_upstream_addr)
        .with_response_cache(Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)));
    let (seed_proxy_addr, seed_report_rx) = spawn_one_shot_http1_proxy_listener(seed_config).await?;

    let mut seed_client = TcpStream::connect(seed_proxy_addr).await?;
    seed_client
        .write_all(b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let seed_response = read_http_response(&mut seed_client).await?;
    assert!(seed_response.ends_with("cached"));
    drop(seed_client);

    let seed_report = receive_proxy_result(seed_report_rx).await?;
    assert_eq!(seed_report.metrics.cache_fill_count, 1);
    assert_eq!(receive_capture_list(seed_capture_rx).await?.len(), 1);

    for cycle in 0..3 {
        time::sleep(Duration::from_millis(1_100)).await;

        let (revalidate_upstream_addr, revalidate_capture_rx) =
            spawn_short_ttl_not_modified_revalidation_upstream().await?;
        let revalidate_config = proxy_config(revalidate_upstream_addr).with_response_cache(
            Http1ResponseCacheConfig::new(policy.clone(), Arc::clone(&shared_store)),
        );
        let (revalidate_proxy_addr, revalidate_report_rx) =
            spawn_one_shot_http1_proxy_listener(revalidate_config).await?;

        let mut revalidate_client = TcpStream::connect(revalidate_proxy_addr).await?;
        revalidate_client
            .write_all(
                b"GET /revalidate HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let revalidate_response = read_http_response(&mut revalidate_client).await?;
        assert!(revalidate_response.ends_with("cached"));
        drop(revalidate_client);

        let revalidate_report = receive_proxy_result(revalidate_report_rx).await?;
        assert_eq!(revalidate_report.metrics.cache_fill_count, 1);
        assert_eq!(revalidate_report.metrics.cache_miss_count, 1);
        assert_eq!(receive_capture_list(revalidate_capture_rx).await?.len(), 1);

        let metrics = shared_store.metrics();
        assert_eq!(metrics.entry_count, 1, "cycle {cycle} should keep one cached object");
        assert!(
            metrics.total_bytes <= 64 * 1024,
            "cycle {cycle} exceeded cache byte budget"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_cache_directives_fail_closed_without_storing(
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_store = Arc::new(HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 16,
        max_bytes: 64 * 1024,
        max_object_bytes: 16 * 1024,
    })?);
    let (upstream_addr, capture_rx) = spawn_invalid_cache_control_upstream().await?;
    let config = proxy_config(upstream_addr).with_response_cache(Http1ResponseCacheConfig::new(
        HttpCachePolicyConfig::default(),
        Arc::clone(&shared_store),
    ));
    let (proxy_addr, report_rx) = spawn_one_shot_http1_proxy_listener(config).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client
        .write_all(b"GET /invalid-cache-control HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response = read_http_response(&mut client).await?;
    assert!(response.ends_with("broken"));
    drop(client);

    let report = receive_proxy_result(report_rx).await?;
    assert_eq!(report.metrics.cache_fill_count, 0);
    assert_eq!(shared_store.metrics().entry_count, 0);
    assert_eq!(receive_capture_list(capture_rx).await?.len(), 1);
    Ok(())
}

#[test]
fn equivalent_requests_produce_identical_cache_keys(
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = HttpCachePolicyConfig {
        authorization: AuthorizationCacheBehaviorConfig::Partition,
        cache_key: CacheKeyPolicyConfig {
            include_host: true,
            include_method: true,
            headers: vec![String::from("accept-language")],
            ..CacheKeyPolicyConfig::default()
        },
        ..HttpCachePolicyConfig::default()
    };
    let first = HttpCacheRequest {
        method: "get",
        target: "/items?b=%2f&a=2&a=1",
        headers: &[
            lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: String::from("Example.TEST"),
            },
            lb_proto_http::HttpHeader {
                name: String::from("accept-language"),
                value: String::from(" en-US , en "),
            },
        ],
    };
    let second = HttpCacheRequest {
        method: "GET",
        target: "http://example.test/items?a=1&a=2&b=%2F",
        headers: &[
            lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: String::from("example.test"),
            },
            lb_proto_http::HttpHeader {
                name: String::from("accept-language"),
                value: String::from("en,en-us"),
            },
        ],
    };

    let first_key = build_http_cache_key_material(&policy, &first, &[])?
        .expect("key")
        .primary;
    let second_key = build_http_cache_key_material(&policy, &second, &[])?
        .expect("key")
        .primary;
    assert_eq!(first_key, second_key);
    Ok(())
}

#[test]
fn authorization_bypass_skips_cache_key_construction_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = HttpCachePolicyConfig::default();
    let request = HttpCacheRequest {
        method: "GET",
        target: "/profile",
        headers: &[
            lb_proto_http::HttpHeader {
                name: String::from("host"),
                value: String::from("example.test"),
            },
            lb_proto_http::HttpHeader {
                name: String::from("authorization"),
                value: String::from("Bearer top-secret"),
            },
        ],
    };

    assert!(build_http_cache_key_material(&policy, &request, &[])?.is_none());
    Ok(())
}

#[test]
fn malformed_request_shapes_do_not_produce_ambiguous_cache_keys() {
    let policy = HttpCachePolicyConfig::default();
    let request = HttpCacheRequest {
        method: "GET",
        target: "http://other.test/items?x=%zz",
        headers: &[lb_proto_http::HttpHeader {
            name: String::from("host"),
            value: String::from("example.test"),
        }],
    };

    let error = build_http_cache_key_material(&policy, &request, &[])
        .expect_err("must fail");
    assert!(matches!(
        error,
        HttpCacheStoreError::InvalidRequestTarget(_) | HttpCacheStoreError::HostAuthorityMismatch { .. }
    ));
}

async fn spawn_keep_alive_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut captures = Vec::new();
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ =
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
            }
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld",
                    )
                    .await;
            }
            let _ = captures_tx.send(captures);
        }
    });

    Ok((address, captures_rx))
}

async fn spawn_body_echo_upstream() -> io::Result<(SocketAddr, oneshot::Receiver<RequestCapture>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nreceived={}",
                    capture.body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = capture_tx.send(capture);
            }
        }
    });

    Ok((address, capture_rx))
}

async fn spawn_single_cacheable_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nETag: \"v1\"\r\n\r\ncached",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_revalidation_seed_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=1, stale-while-revalidate=2\r\nETag: \"v1\"\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\ncached",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_no_store_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nprivate",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_swr_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\nCache-Control: max-age=1, stale-while-revalidate=2\r\n\r\nstale",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_stale_if_error_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=1, stale-if-error=2\r\n\r\nbackup",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_invalid_cache_control_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=bogus\r\n\r\nbroken",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_vary_cookie_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nCache-Control: max-age=30\r\nVary: Cookie\r\n\r\nunsafe",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_private_cache_control_upstream(
) -> io::Result<(SocketAddr, oneshot::Receiver<Vec<RequestCapture>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (captures_tx, captures_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captures = Vec::new();
        if let Ok((mut stream, _)) = listener.accept().await {
            if let Ok(capture) = read_http_request_capture(&mut stream).await {
                captures.push(capture);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\nCache-Control: private, max-age=30\r\n\r\nprivate",
                    )
                    .await;
            }
        }
        let _ = captures_tx.send(captures);
    });

    Ok((address, captures_rx))
}

async fn spawn_idle_upstream() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        if let Ok((_stream, _)) = listener.accept().await {
            time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(address)
}

async fn reserve_unused_addr() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    listener.local_addr()
}

async fn read_http_request_capture(stream: &mut TcpStream) -> io::Result<RequestCapture> {
    let mut buffer = Vec::new();
    let head_end = read_until_sequence(stream, &mut buffer, b"\r\n\r\n").await?;
    let head = String::from_utf8(buffer[..head_end].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request head utf8"))?;
    let content_length = parse_content_length(&head)?;
    let mut body = buffer[head_end..].to_vec();

    while body.len() < content_length {
        let mut chunk = vec![0_u8; (content_length - body.len()).min(8192)];
        let bytes_read = stream.read(&mut chunk).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body truncated"));
        }
        body.extend_from_slice(&chunk[..bytes_read]);
    }
    body.truncate(content_length);

    Ok(RequestCapture { head, body })
}

async fn read_http_response(stream: &mut TcpStream) -> io::Result<String> {
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

async fn read_until_sequence(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    sequence: &[u8],
) -> io::Result<usize> {
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
    let line = head.lines().find(|line| line.to_ascii_lowercase().starts_with("content-length:"));
    let Some(line) = line else {
        return Ok(0);
    };

    let (_, value) = line.split_once(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid content-length header")
    })?;
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

async fn receive_proxy_result(
    result_rx: oneshot::Receiver<Result<Http1ConnectionReport, Http1ProxyError>>,
) -> Result<Http1ConnectionReport, Http1ProxyError> {
    match time::timeout(Duration::from_secs(2), result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(Http1ProxyError::IdleTimeout("proxy result channel closed")),
        Err(_) => Err(Http1ProxyError::IdleTimeout("proxy result wait")),
    }
}

async fn receive_capture(
    capture_rx: oneshot::Receiver<RequestCapture>,
) -> Result<RequestCapture, Box<dyn std::error::Error>> {
    let capture = time::timeout(Duration::from_secs(2), capture_rx).await??;
    Ok(capture)
}

async fn receive_capture_list(
    capture_rx: oneshot::Receiver<Vec<RequestCapture>>,
) -> Result<Vec<RequestCapture>, Box<dyn std::error::Error>> {
    let captures = time::timeout(Duration::from_secs(2), capture_rx).await??;
    Ok(captures)
}

fn proxy_config(upstream_addr: SocketAddr) -> Http1ProxyConfig {
    Http1ProxyConfig::new(UpstreamTarget::new("http-upstream", upstream_addr))
}
