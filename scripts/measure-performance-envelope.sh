#!/usr/bin/env sh
set -eu

mode="${1:-smoke}"
sample_size="${BENCH_SAMPLE_SIZE:-10}"
output_dir="${PERF_OUTPUT_DIR:-target/performance-envelope}"

mkdir -p "$output_dir"

example_output="$output_dir/envelope-${mode}.json"
bench_output="$output_dir/criterion-${mode}.txt"

cargo run --release -p lb-runtime --example performance_envelope -- --mode "$mode" | tee "$example_output"
cargo bench -p lb-runtime --bench dataplane_envelope -- --sample-size "$sample_size" | tee "$bench_output"

printf 'performance envelope artifacts written to %s\n' "$output_dir"