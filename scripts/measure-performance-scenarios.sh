#!/usr/bin/env sh
set -eu

sample_size="${BENCH_SAMPLE_SIZE:-10}"
output_dir="${PERF_OUTPUT_DIR:-target/performance-envelope}"

mkdir -p "$output_dir"

scenario_example_output="$output_dir/scenarios-smoke.json"
scenario_bench_output="$output_dir/criterion-scenarios.txt"

cargo run --release -p lb-runtime --example performance_envelope -- --mode smoke \
  | tee "$scenario_example_output"

cargo bench -p lb-runtime --bench performance_scenarios -- --sample-size "$sample_size" \
  | tee "$scenario_bench_output"

printf 'advanced performance scenario artifacts written to %s\n' "$output_dir"
