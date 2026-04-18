#![allow(clippy::expect_used)]

use std::time::Duration;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use http::StatusCode;
use lb_runtime::{
    HttpCacheEntry, HttpCacheKey, HttpCacheMetadata, HttpCacheStore, HttpCacheStoreConfig,
};

fn benchmark_entry(now: Duration, body_len: usize) -> HttpCacheEntry {
    HttpCacheEntry {
        metadata: HttpCacheMetadata {
            status: StatusCode::OK,
            stored_at: now,
            fresh_until: now + Duration::from_secs(30),
            stale_while_revalidate_until: Some(now + Duration::from_secs(60)),
            stale_if_error_until: Some(now + Duration::from_secs(90)),
            etag: None,
            last_modified: None,
        },
        headers: Vec::new(),
        body: Bytes::from(vec![b'x'; body_len]),
    }
}

fn benchmark_store() -> HttpCacheStore {
    HttpCacheStore::new(HttpCacheStoreConfig {
        max_entries: 128,
        max_bytes: 256 * 1024,
        max_object_bytes: 8 * 1024,
    })
    .expect("valid benchmark cache store")
}

fn benchmark_key(path: &str) -> HttpCacheKey {
    HttpCacheKey::new(format!("path={path}\nhost=example.test")).expect("valid benchmark key")
}

fn bench_cache_hit_path(criterion: &mut Criterion) {
    let store = benchmark_store();
    let key = benchmark_key("/bench-hit");
    store
        .insert(Duration::from_secs(1), key.clone(), benchmark_entry(Duration::from_secs(1), 128))
        .expect("cache insert succeeds");

    criterion.bench_function("http_cache_lookup_hit", |bench| {
        bench.iter(|| {
            let lookup = store.lookup(Duration::from_secs(2), black_box(&key));
            black_box(lookup.expect("cached entry exists"));
        });
    });
}

fn bench_cache_miss_path(criterion: &mut Criterion) {
    let store = benchmark_store();
    let key = benchmark_key("/bench-miss");

    criterion.bench_function("http_cache_lookup_miss", |bench| {
        bench.iter(|| {
            let lookup = store.lookup(Duration::from_secs(2), black_box(&key));
            black_box(lookup);
        });
    });
}

fn bench_cache_stale_lookup_path(criterion: &mut Criterion) {
    let store = benchmark_store();
    let key = benchmark_key("/bench-stale");
    store
        .insert(Duration::from_secs(1), key.clone(), benchmark_entry(Duration::from_secs(1), 128))
        .expect("cache insert succeeds");

    criterion.bench_function("http_cache_lookup_stale_revalidation_candidate", |bench| {
        bench.iter(|| {
            let lookup = store.lookup(Duration::from_secs(45), black_box(&key));
            black_box(lookup.expect("stale entry remains available"));
        });
    });
}

criterion_group!(
    benches,
    bench_cache_hit_path,
    bench_cache_miss_path,
    bench_cache_stale_lookup_path
);
criterion_main!(benches);
