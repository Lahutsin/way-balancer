# Performance Envelope Evidence

This directory stores release-grade performance-envelope artifacts for named supported deployment profiles.

## Expected Artifact Shape

- one JSON artifact per measured profile and mode, for example `lab-small-non-loopback-v1-smoke.json`
- optional prior baseline artifact used for candidate comparison
- optional accompanying Criterion text output copied from `target/performance-envelope/criterion-*.txt`

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

## Release Review Notes

- Loopback-only artifacts remain useful for regressions, but they do not satisfy `EVID-010` by themselves.
- Supported profile artifacts must document the non-loopback lab assumptions that produced the claim.
- If reload or failover timing evidence is missing, keep the artifact as advisory only and do not use it as GA support evidence.