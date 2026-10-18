#!/usr/bin/env sh
set -eu

mkdir -p artifacts/sbom

if command -v cargo-cyclonedx >/dev/null 2>&1; then
  cargo cyclonedx --format json --all --output-prefix artifacts/sbom/way-balancer
elif command -v cargo >/dev/null 2>&1; then
  cargo metadata --format-version 1 --locked > artifacts/sbom/cargo-metadata.v1.json
fi

echo "SBOM artifacts generated in artifacts/sbom" > artifacts/sbom/README.txt
