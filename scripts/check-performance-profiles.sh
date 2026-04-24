#!/usr/bin/env sh
set -eu

profiles_file="artifacts/performance-envelope/supported-profiles.v1.json"

assert_profile_name=""
if [ "${1:-}" = "--assert-profile" ]; then
  assert_profile_name="${2:-}"
  if [ -z "$assert_profile_name" ]; then
    echo "missing value for --assert-profile" >&2
    exit 2
  fi
fi

test -f "$profiles_file"

grep -q '"schema_version"[[:space:]]*:[[:space:]]*"v1"' "$profiles_file"
grep -q '"profiles"[[:space:]]*:[[:space:]]*\[' "$profiles_file"

grep -q '"name"[[:space:]]*:[[:space:]]*"loopback_regression_v1"' "$profiles_file"
grep -q '"name"[[:space:]]*:[[:space:]]*"lab_small_non_loopback_v1"' "$profiles_file"
grep -q '"claim_tier"[[:space:]]*:[[:space:]]*"experimental"' "$profiles_file"
grep -q '"claim_tier"[[:space:]]*:[[:space:]]*"supported"' "$profiles_file"

grep -q '"host_assumptions"[[:space:]]*:' "$profiles_file"
grep -q '"network_assumptions"[[:space:]]*:' "$profiles_file"
grep -q '"tls_mode"[[:space:]]*:' "$profiles_file"
grep -q '"connection_mix"[[:space:]]*:' "$profiles_file"
grep -q '"request_payload_bytes"[[:space:]]*:' "$profiles_file"
grep -q '"hostile_edge_posture"[[:space:]]*:' "$profiles_file"
grep -q '"evidence_requirements"[[:space:]]*:[[:space:]]*\[' "$profiles_file"

grep -q '"supported_thresholds"[[:space:]]*:' "$profiles_file"
grep -q '"min_http1_ops_per_sec"[[:space:]]*:' "$profiles_file"
grep -q '"min_http2_ops_per_sec"[[:space:]]*:' "$profiles_file"
grep -q '"max_mixed_p95_us"[[:space:]]*:' "$profiles_file"
grep -q '"max_reload_success_ms"[[:space:]]*:' "$profiles_file"
grep -q '"max_failover_ms"[[:space:]]*:' "$profiles_file"

name_lines="$(grep -o '"name"[[:space:]]*:[[:space:]]*"[a-z0-9_]*"' "$profiles_file" | sed -E 's/.*"([a-z0-9_]+)"$/\1/')"
unique_count="$(printf '%s\n' "$name_lines" | grep -v '^$' | sort | uniq | wc -l | tr -d ' ')"
total_count="$(printf '%s\n' "$name_lines" | grep -v '^$' | wc -l | tr -d ' ')"
if [ "$unique_count" != "$total_count" ]; then
  echo "duplicate profile name detected in $profiles_file" >&2
  exit 1
fi

if [ -n "$assert_profile_name" ]; then
  if ! printf '%s\n' "$name_lines" | grep -q "^$assert_profile_name$"; then
    echo "unsupported PERF_PROFILE: $assert_profile_name" >&2
    echo "supported profile names:" >&2
    printf '%s\n' "$name_lines" | grep -v '^$' | sort -u >&2
    exit 2
  fi
fi

echo "performance profile definitions validated"