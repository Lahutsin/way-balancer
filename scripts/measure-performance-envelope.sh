#!/usr/bin/env sh
set -eu

mode="${1:-smoke}"
sample_size="${BENCH_SAMPLE_SIZE:-10}"
output_dir="${PERF_OUTPUT_DIR:-target/performance-envelope}"
profile="${PERF_PROFILE:-loopback_regression_v1}"
baseline="${PERF_BASELINE:-}"
reload_success_ms="${PERF_RELOAD_SUCCESS_MS:-}"
reload_degraded_success_ms="${PERF_RELOAD_DEGRADED_SUCCESS_MS:-}"
failover_ms="${PERF_FAILOVER_MS:-}"
timing_evidence_source="${PERF_TIMING_EVIDENCE_SOURCE:-}"
capture_control_plane_timing="${PERF_CAPTURE_CONTROL_PLANE_TIMING:-}"

mkdir -p "$output_dir"

./scripts/check-performance-profiles.sh --assert-profile "$profile"

example_output="$output_dir/envelope-${profile}-${mode}.json"
bench_output="$output_dir/criterion-${profile}-${mode}.txt"

set -- cargo run --release -p lb-runtime --example performance_envelope -- --mode "$mode" --profile "$profile"

if [ -n "$baseline" ]; then
	set -- "$@" --baseline "$baseline"
fi

if [ -n "$reload_success_ms" ]; then
	set -- "$@" --observed-reload-success-ms "$reload_success_ms"
fi

if [ -n "$reload_degraded_success_ms" ]; then
	set -- "$@" --observed-reload-degraded-success-ms "$reload_degraded_success_ms"
fi

if [ -n "$failover_ms" ]; then
	set -- "$@" --observed-failover-ms "$failover_ms"
fi

if [ -n "$timing_evidence_source" ]; then
	set -- "$@" --timing-evidence-source "$timing_evidence_source"
fi

if [ -n "$capture_control_plane_timing" ] && [ "$capture_control_plane_timing" != "0" ]; then
	set -- "$@" --capture-control-plane-timing
fi

"$@" | tee "$example_output"
cargo bench -p lb-runtime --bench dataplane_envelope -- --sample-size "$sample_size" | tee "$bench_output"

printf 'performance envelope artifacts written to %s\n' "$output_dir"