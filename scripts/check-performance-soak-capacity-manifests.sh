#!/usr/bin/env sh
set -eu

dir="${1:-artifacts/performance-envelope}"

if [ ! -d "$dir" ]; then
  echo "manifest directory does not exist: $dir" >&2
  exit 2
fi

found=0
for manifest in "$dir"/soak-capacity-*.json; do
  if [ ! -f "$manifest" ]; then
    continue
  fi
  found=1

  grep -q '"schema_version"[[:space:]]*:[[:space:]]*"v1"' "$manifest"
  grep -q '"generated_at_unix_ms"[[:space:]]*:' "$manifest"
  grep -q '"profile"[[:space:]]*:' "$manifest"
  grep -q '"soak_rounds"[[:space:]]*:' "$manifest"
  grep -q '"capacity_modes"[[:space:]]*:' "$manifest"
  grep -q '"scenario_runs"[[:space:]]*:' "$manifest"
  grep -q '"soak_logs"[[:space:]]*:' "$manifest"
  grep -q '"artifacts"[[:space:]]*:' "$manifest"
  grep -q '"envelope_prefix"[[:space:]]*:' "$manifest"
  grep -q '"criterion_prefix"[[:space:]]*:' "$manifest"
  grep -q '"scenario_json"[[:space:]]*:' "$manifest"
  grep -q '"scenario_criterion"[[:space:]]*:' "$manifest"

done

if [ "$found" -eq 0 ]; then
  echo "no published soak-capacity manifests found in $dir; skipping structural validation"
  exit 0
fi

echo "published soak-capacity manifests validated"
