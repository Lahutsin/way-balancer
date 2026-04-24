#!/usr/bin/env sh
set -eu

source_dir="${1:-target/performance-envelope}"
dest_dir="${2:-artifacts/performance-envelope}"

if [ ! -d "$source_dir" ]; then
  echo "source directory does not exist: $source_dir" >&2
  exit 2
fi

mkdir -p "$dest_dir"

copied=0
for pattern in \
  'envelope-*.json' \
  'criterion-*.txt' \
  'scenarios-smoke.json' \
  'soak-chaos-round-*.txt' \
  'capacity-envelope-*.txt' \
  'capacity-scenarios-run-*.txt' \
  'soak-capacity-*.json'
do
  for file in "$source_dir"/$pattern; do
    if [ -f "$file" ]; then
      cp "$file" "$dest_dir"/
      copied=$((copied + 1))
    fi
  done
done

if [ "$copied" -eq 0 ]; then
  echo "no performance evidence artifacts found in $source_dir" >&2
  exit 1
fi

echo "published $copied performance evidence artifact(s) to $dest_dir"
