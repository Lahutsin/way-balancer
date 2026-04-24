#!/usr/bin/env sh
set -eu

output_dir="${PERF_OUTPUT_DIR:-target/performance-envelope}"
profile="${PERF_PROFILE:-loopback_regression_v1}"
soak_rounds="${PERF_SOAK_ROUNDS:-3}"
capacity_modes="${PERF_CAPACITY_MODES:-smoke full}"
scenario_runs="${PERF_SCENARIO_RUNS:-1}"
bench_sample_size="${BENCH_SAMPLE_SIZE:-10}"
capture_control_plane_timing="${PERF_CAPTURE_CONTROL_PLANE_TIMING:-}"

mkdir -p "$output_dir"

run_id="$(date +%s)"
manifest_file="$output_dir/soak-capacity-${profile}-${run_id}.json"
manifest_tmp="$output_dir/.soak-capacity-${run_id}.tmp"

: > "$manifest_tmp"

printf 'running soak chaos rounds: %s\n' "$soak_rounds"
round=1
while [ "$round" -le "$soak_rounds" ]; do
  soak_log="$output_dir/soak-chaos-round-${round}.txt"
  ./scripts/check-soak-chaos.sh >"$soak_log" 2>&1
  printf '{"round": %s, "log": "%s"}\n' "$round" "$soak_log" >> "$manifest_tmp"
  round=$((round + 1))
done

for mode in $capacity_modes; do
  capacity_log="$output_dir/capacity-envelope-${profile}-${mode}.txt"
  PERF_PROFILE="$profile" \
  PERF_OUTPUT_DIR="$output_dir" \
  PERF_CAPTURE_CONTROL_PLANE_TIMING="$capture_control_plane_timing" \
  BENCH_SAMPLE_SIZE="$bench_sample_size" \
  ./scripts/measure-performance-envelope.sh "$mode" >"$capacity_log" 2>&1
done

scenario=1
while [ "$scenario" -le "$scenario_runs" ]; do
  scenario_log="$output_dir/capacity-scenarios-run-${scenario}.txt"
  PERF_OUTPUT_DIR="$output_dir" \
  BENCH_SAMPLE_SIZE="$bench_sample_size" \
  ./scripts/measure-performance-scenarios.sh >"$scenario_log" 2>&1
  scenario=$((scenario + 1))
done

{
  printf '{\n'
  printf '  "schema_version": "v1",\n'
  printf '  "generated_at_unix_ms": %s,\n' "$(($(date +%s) * 1000))"
  printf '  "profile": "%s",\n' "$profile"
  printf '  "soak_rounds": %s,\n' "$soak_rounds"
  printf '  "capacity_modes": ['

  mode_index=0
  mode_count=0
  for mode in $capacity_modes; do
    mode_count=$((mode_count + 1))
  done
  for mode in $capacity_modes; do
    mode_index=$((mode_index + 1))
    if [ "$mode_index" -gt 1 ]; then
      printf ', '
    fi
    printf '"%s"' "$mode"
  done
  printf '],\n'

  printf '  "scenario_runs": %s,\n' "$scenario_runs"
  printf '  "bench_sample_size": %s,\n' "$bench_sample_size"
  printf '  "capture_control_plane_timing": "%s",\n' "$capture_control_plane_timing"
  printf '  "soak_logs": [\n'

  line_index=0
  total_lines="$(wc -l < "$manifest_tmp" | tr -d ' ')"
  while IFS= read -r line; do
    line_index=$((line_index + 1))
    if [ "$line_index" -lt "$total_lines" ]; then
      printf '    %s,\n' "$line"
    else
      printf '    %s\n' "$line"
    fi
  done < "$manifest_tmp"

  printf '  ],\n'
  printf '  "artifacts": {\n'
  printf '    "envelope_prefix": "%s/envelope-%s-<mode>.json",\n' "$output_dir" "$profile"
  printf '    "criterion_prefix": "%s/criterion-%s-<mode>.txt",\n' "$output_dir" "$profile"
  printf '    "scenario_json": "%s/scenarios-smoke.json",\n' "$output_dir"
  printf '    "scenario_criterion": "%s/criterion-scenarios.txt"\n' "$output_dir"
  printf '  }\n'
  printf '}\n'
} > "$manifest_file"

rm -f "$manifest_tmp"

printf 'soak and capacity automation artifacts written to %s\n' "$output_dir"
printf 'manifest: %s\n' "$manifest_file"
