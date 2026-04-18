#[path = "../dev-support/performance_harness.rs"]
mod performance_harness;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use performance_harness::{
    measure_http1_throughput, measure_http1_tls_throughput, measure_http2_throughput,
    measure_mixed_latency, run_or_exit,
};

fn bench_http1_proxy_batch(criterion: &mut Criterion) {
    let operations = 64usize;
    let mut group = criterion.benchmark_group("dataplane_envelope_http1");
    group.throughput(Throughput::Elements(operations as u64));
    group.bench_function("http1_proxy_batch", |bench| {
        bench.iter(|| {
            let measurement = run_or_exit(
                tokio::runtime::Runtime::new()
                    .map_err(Into::into)
                    .and_then(|runtime| runtime.block_on(measure_http1_throughput(operations))),
            );
            criterion::black_box(measurement);
        });
    });
    group.finish();
}

fn bench_http1_tls_proxy_batch(criterion: &mut Criterion) {
    let operations = 64usize;
    let mut group = criterion.benchmark_group("dataplane_envelope_http1_tls");
    group.throughput(Throughput::Elements(operations as u64));
    group.bench_function("http1_proxy_batch_tls", |bench| {
        bench.iter(|| {
            let measurement =
                run_or_exit(tokio::runtime::Runtime::new().map_err(Into::into).and_then(
                    |runtime| runtime.block_on(measure_http1_tls_throughput(operations)),
                ));
            criterion::black_box(measurement);
        });
    });
    group.finish();
}

fn bench_http2_proxy_batch(criterion: &mut Criterion) {
    let operations = 64usize;
    let mut group = criterion.benchmark_group("dataplane_envelope_http2");
    group.throughput(Throughput::Elements(operations as u64));
    group.bench_function("http2_proxy_stream_batch", |bench| {
        bench.iter(|| {
            let measurement = run_or_exit(
                tokio::runtime::Runtime::new()
                    .map_err(Into::into)
                    .and_then(|runtime| runtime.block_on(measure_http2_throughput(operations))),
            );
            criterion::black_box(measurement);
        });
    });
    group.finish();
}

fn bench_mixed_latency_batch(criterion: &mut Criterion) {
    let operations = 64usize;
    criterion.bench_function("mixed_http1_http2_interleaved_batch", |bench| {
        bench.iter(|| {
            let summary = run_or_exit(
                tokio::runtime::Runtime::new()
                    .map_err(Into::into)
                    .and_then(|runtime| runtime.block_on(measure_mixed_latency(operations))),
            );
            criterion::black_box(summary);
        });
    });
}

criterion_group!(
    benches,
    bench_http1_proxy_batch,
    bench_http1_tls_proxy_batch,
    bench_http2_proxy_batch,
    bench_mixed_latency_batch
);
criterion_main!(benches);
