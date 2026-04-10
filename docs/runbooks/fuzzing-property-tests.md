# Fuzzing And Property Tests

## Purpose

This runbook describes the current parser and invariant-testing surface used to catch malformed-input crashes, hangs, and canonicalization regressions.

## Property Test Coverage

Continuous property tests currently cover:

- request-target canonicalization query ordering
- route matching longest-prefix specificity
- cache-key host canonicalization invariants

These suites run through:

- `cargo test -p lb-proto-http --test property_tests`
- `cargo test -p lb-runtime --test property_tests`

## Fuzz Targets

The repository now carries `cargo-fuzz` targets in `fuzz/` for:

- `http1_head_parse`
- `request_target_canonicalization`
- `cache_key_material`

These targets exercise parser and canonicalization surfaces that are both security-sensitive and prone to malformed-input bugs.

## CI And Scheduled Usage

Use:

- `./scripts/check-fuzz.sh`

This script always runs the property-test suites. When `cargo-fuzz` is installed, it also builds all registered fuzz targets so drift in the fuzz harnesses is caught during automation.

## Operator Notes

- Property tests are the continuous low-cost invariant layer.
- Fuzz targets are the parser-abuse and malformed-input exploration layer.
- New parsing or canonicalization surfaces should add either a property test, a fuzz target, or both before rollout.