#!/usr/bin/env sh
set -eu

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
./scripts/check-coverage.sh
cargo doc --workspace --no-deps

./scripts/check-release-artifacts.sh

./scripts/check-secret-scanning.sh

if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  echo "cargo-deny not installed; skipping dependency policy check" >&2
fi

if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "cargo-audit not installed; skipping vulnerability audit" >&2
fi
