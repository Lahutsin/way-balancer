# Performance Envelope Evidence

This directory stores release-grade performance-envelope artifacts for named supported deployment profiles.

## Expected Artifact Shape

- one JSON artifact per measured profile and mode, for example `lab-small-non-loopback-v1-smoke.json`
- optional prior baseline artifact used for candidate comparison
- optional accompanying Criterion text output copied from `target/performance-envelope/criterion-*.txt`
- canonical profile-definition catalog: `supported-profiles.v1.json`

## Supported Profile Definitions

`supported-profiles.v1.json` is the machine-readable contract for named performance profiles.

It defines:

- allowed profile names used by `PERF_PROFILE`
- required host and network assumptions for each named profile
- claim tier (`experimental` or `supported`)
- supported-threshold expectations for supported profiles

Validation hook:

```sh
./scripts/check-performance-profiles.sh
```

## Required Fields For Supported Claims

A release-grade artifact must include all of these:

- profile name, claim tier, host-class assumptions, network assumptions, TLS mode, request mix, and hostile-edge posture
- loopback harness measurements for throughput, mixed latency, TLS overhead, and memory growth
- control-plane timing evidence for reload success and failover
- threshold evaluation showing `supported_claim_ready = true`

## Canonical Generation Flow

Generate an artifact with a supported profile:

```sh
PERF_PROFILE=lab_small_non_loopback_v1 \
PERF_RELOAD_SUCCESS_MS=<observed_reload_ms> \
PERF_RELOAD_DEGRADED_SUCCESS_MS=<observed_degraded_reload_ms> \
PERF_FAILOVER_MS=<observed_failover_ms> \
PERF_TIMING_EVIDENCE_SOURCE="GET /status and lab failover trace" \
PERF_OUTPUT_DIR=artifacts/performance-envelope \
./scripts/measure-performance-envelope.sh smoke
```

Compare a candidate with a stored baseline:

```sh
PERF_PROFILE=lab_small_non_loopback_v1 \
PERF_BASELINE=artifacts/performance-envelope/lab-small-non-loopback-baseline.json \
PERF_OUTPUT_DIR=artifacts/performance-envelope \
./scripts/measure-performance-envelope.sh smoke
```

The measurement script rejects unknown `PERF_PROFILE` values before running the benchmark harness.

Long-run soak and capacity automation flow:

```sh
PERF_SOAK_ROUNDS=3 \
PERF_CAPACITY_MODES="smoke full" \
PERF_SCENARIO_RUNS=1 \
PERF_OUTPUT_DIR=artifacts/performance-envelope \
./scripts/measure-performance-soak-capacity.sh
```

This automation stores a machine-readable manifest under:

- `soak-capacity-<profile>-<timestamp>.json`

and includes references to per-round soak logs plus generated envelope and Criterion artifacts.

Publish generated performance evidence into release-artifact structure:

```sh
./scripts/publish-performance-evidence.sh target/performance-envelope artifacts/performance-envelope
```

Validate published soak-capacity manifests:

```sh
./scripts/check-performance-soak-capacity-manifests.sh artifacts/performance-envelope
```

## Release Review Notes

- Loopback-only artifacts remain useful for regressions, but they do not satisfy `EVID-010` by themselves.
- Supported profile artifacts must document the non-loopback lab assumptions that produced the claim.
- If reload or failover timing evidence is missing, keep the artifact as advisory only and do not use it as GA support evidence.