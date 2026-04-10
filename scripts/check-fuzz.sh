#!/usr/bin/env sh
set -eu

cargo test -p lb-proto-http --test property_tests
cargo test -p lb-runtime --test property_tests

if command -v cargo-fuzz >/dev/null 2>&1; then
  cargo fuzz build --manifest-path fuzz/Cargo.toml http1_head_parse
  cargo fuzz build --manifest-path fuzz/Cargo.toml request_target_canonicalization
  cargo fuzz build --manifest-path fuzz/Cargo.toml cache_key_material
else
  echo "cargo-fuzz not installed; skipping fuzz target build" >&2
fi