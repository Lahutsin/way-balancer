#[path = "../dev-support/performance_harness.rs"]
mod performance_harness;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use performance_harness::{
    measure_abuse_mitigation_decision_throughput, measure_discovery_churn_reconcile_throughput,
    measure_hedging_execution_throughput, measure_http1_to_http3_bridge_throughput, run_or_exit,
};

fn bench_hedging_scenario(criterion: &mut Criterion) {
    let operations = 24usize;
    let mut group = criterion.benchmark_group("performance_scenario_hedging");
    group.throughput(Throughput::Elements(operations as u64));
    group.bench_function("hedging_execution_batch", |bench| {
        bench.iter(|| {
            let measurement = run_or_exit(
                tokio::runtime::Runtime::new().map_err(Into::into).and_then(|runtime| {
                    runtime.block_on(measure_hedging_execution_throughput(operations))
                }),
            );
            criterion::black_box(measurement);
        });
    });
    group.finish();
}

fn bench_abuse_mitigation_scenario(criterion: &mut Criterion) {
    let operations = 128usize;
    let mut group = criterion.benchmark_group("performance_scenario_abuse_mitigation");
    group.throughput(Throughput::Elements(operations as u64));
    group.bench_function("abuse_mitigation_decision_batch", |bench| {
        bench.iter(|| {
            let measurement =
                run_or_exit(measure_abuse_mitigation_decision_throughput(operations));
            criterion::black_box(measurement);
        });
    });
    group.finish();
}

fn bench_discovery_churn_scenario(criterion: &mut Criterion) {
    let operations = 128usize;
    let mut group = criterion.benchmark_group("performance_scenario_discovery_churn");
    group.throughput(Throughput::Elements(operations as u64));
    group.bench_function("discovery_churn_reconcile_batch", |bench| {
        bench.iter(|| {
            let measurement = run_or_exit(measure_discovery_churn_reconcile_throughput(operations));
            criterion::black_box(measurement);
        });
    });
    group.finish();
}

fn bench_http3_bridge_scenario(criterion: &mut Criterion) {
    let operations = 12usize;
    let mut group = criterion.benchmark_group("performance_scenario_http3_bridge");
    group.throughput(Throughput::Elements(operations as u64));
    group.bench_function("http1_to_http3_bridge_batch", |bench| {
        bench.iter(|| {
            let measurement = run_or_exit(
                tokio::runtime::Runtime::new().map_err(Into::into).and_then(|runtime| {
                    runtime.block_on(measure_http1_to_http3_bridge_throughput(operations))
                }),
            );
            criterion::black_box(measurement);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hedging_scenario,
    bench_abuse_mitigation_scenario,
    bench_discovery_churn_scenario,
    bench_http3_bridge_scenario
);
criterion_main!(benches);
