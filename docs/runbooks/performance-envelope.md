# Performance Envelope

## Purpose

This runbook defines the repeatable performance program used to track dataplane throughput, mixed-traffic latency, memory growth, TLS overhead, and control-plane timing boundaries over time.

## What Is Covered

- HTTP/1 loopback proxy throughput through the runtime proxy path
- HTTP/2 loopback stream throughput through the runtime proxy path
- mixed HTTP/1 plus HTTP/2 latency with persistent loopback clients
- TLS termination overhead for the HTTP/1 proxy path using `tokio-rustls`
- resident-memory growth per idle accepted connection and per active HTTP/2 stream
- named deployment profile artifacts that separate regression-only loopback runs from supported non-loopback release evidence
- optional reload and failover timing evidence captured from stable operator surfaces and stored in the same artifact schema

## Reproducible Commands

Run the smoke-sized envelope locally with:

```sh
./scripts/measure-performance-envelope.sh smoke
```

Run the larger local envelope with:

```sh
./scripts/measure-performance-envelope.sh full
```

Generate a supported-profile artifact with non-loopback timing evidence attached:

```sh
PERF_PROFILE=lab_small_non_loopback_v1 \
PERF_RELOAD_SUCCESS_MS=1800 \
PERF_RELOAD_DEGRADED_SUCCESS_MS=6200 \
PERF_FAILOVER_MS=1400 \
PERF_TIMING_EVIDENCE_SOURCE="GET /status and lab failover trace" \
./scripts/measure-performance-envelope.sh smoke
```

Compare a candidate artifact against a prior baseline:

```sh
PERF_PROFILE=lab_small_non_loopback_v1 \
PERF_BASELINE=artifacts/performance-envelope/lab-small-non-loopback-baseline.json \
./scripts/measure-performance-envelope.sh smoke
```

This produces two artifacts under `target/performance-envelope/`:

- JSON artifact from `cargo run --release -p lb-runtime --example performance_envelope`
- Criterion report text from `cargo bench -p lb-runtime --bench dataplane_envelope`

## Scenario Assumptions

- Measurements are loopback-only and are meant for regression detection plus capacity planning baselines, not internet-facing latency claims.
- The memory probe uses resident-set-size sampling from the local process and is most useful as a relative trend line across commits on the same host class.
- The HTTP/1 memory probe measures accepted idle listener connections through `lb_runtime::start_listener`.
- The HTTP/2 stream memory probe measures concurrent active proxy streams while the upstream intentionally delays completion.
- TLS overhead is measured as the delta between the same HTTP/1 request batch over plain TCP and over a local Rustls-terminated downstream connection.

## Named Profiles

The artifact schema supports two profile tiers:

- `loopback_regression_v1`: experimental regression-only profile for fast local checks. It remains useful for trend detection but is not a supported customer capacity claim.
- `lab_small_non_loopback_v1`: initial supported small-host profile for release evidence when measurements are collected on a non-loopback lab path and include reload and failover timing evidence.

### Supported Profile: `lab_small_non_loopback_v1`

This profile is the initial supportable envelope for `0.1.x` when operators and release engineers collect evidence on a host class with all of these assumptions:

- `4` vCPU
- `16 GiB` RAM
- `10 GbE` NIC or equivalent dedicated lab network capacity
- single-AZ non-loopback client-to-dataplane path with expected RTT around `1.5 ms`
- downstream TLS enabled
- hostile-edge controls enabled, including source quota and handshake guard
- mixed HTTP/1 and HTTP/2 traffic with approximately `1 KiB` requests

Initial support thresholds for that profile are:

- HTTP/1 throughput: at least `2500 ops/s`
- HTTP/2 throughput: at least `8000 ops/s`
- mixed latency: p50 at most `5 ms`, p95 at most `12 ms`, p99 at most `20 ms`
- idle connection RSS growth: at most `16 KiB` per connection
- active HTTP/2 stream RSS growth: at most `24 KiB` per stream
- reload success timing: at most `5000 ms`
- degraded-success reload timing: at most `15000 ms`
- failover timing: at most `3000 ms`

These thresholds are the supported boundary, not a promise that every environment will match the same numbers without the documented host, network, and hostile-edge assumptions.

## Tested Operating Envelope

Current in-repo coverage defines these regression scenarios:

- smoke mode: 64 HTTP/1 requests, 64 HTTP/2 streams, 64 mixed operations, 24 idle connections, 24 active streams
- full mode: 256 HTTP/1 requests, 256 HTTP/2 streams, 256 mixed operations, 64 idle connections, 64 active streams

Treat these scenarios as the minimum repeatable local envelope for release candidates and major runtime changes.

## Latest Smoke Run

The current canonical smoke run via `./scripts/measure-performance-envelope.sh smoke` completed successfully in this workspace and produced these representative results:

- HTTP/1 batch throughput: about `4.1k` to `4.9k` requests per second in the example harness, with Criterion reporting roughly `14.0k` operations per second for the tighter benchmark loop
- HTTP/2 stream throughput: about `20.1k` streams per second in the example harness, with Criterion reporting roughly `1.11k` stream-batch operations per second for the repeated benchmark scenario
- mixed interleaved latency: about `246 us` p50, `392 us` p95, and `446 us` p99 in smoke mode
- idle accepted-connection RSS delta: about `2.0 KiB` per connection in smoke mode
- active HTTP/2 stream RSS delta: about `6.0 KiB` per stream in smoke mode

The TLS comparison in the smoke example currently shows visible noise on a single short loopback run. Treat the Criterion comparison plus repeated local runs as the stronger signal for TLS regressions than any single smoke-mode percentage.

## Control-Plane Timing Evidence

For supported non-loopback profiles, reload and failover timings are recorded from stable operator-facing sources instead of inferred from loopback proxy throughput runs:

- reload success timing comes from `GET /status` fields such as `reload_last_success_duration_ms`
- degraded-success timing comes from `GET /status` when the outcome code is `reload_applied_overlap_drain_timeout`
- failover timing comes from the documented lab failover procedure and must be attached to the artifact with `PERF_FAILOVER_MS` and `PERF_TIMING_EVIDENCE_SOURCE`

If these timing fields are missing, the generated artifact remains useful, but it is not ready to support a release-grade non-loopback capacity claim.

## Regression Interpretation

- sustained HTTP/1 or HTTP/2 throughput drops beyond normal host variance should be treated as dataplane regressions
- mixed-traffic p95 or p99 growth indicates parser, routing, or upstream-client work is becoming more expensive under interleaved load
- rising per-connection or per-stream RSS deltas indicate memory growth that will compress safe concurrency ceilings
- widening TLS overhead indicates certificate handling, handshake work, or encrypted I/O has regressed

Artifact-to-artifact comparison also applies explicit guardrails:

- throughput should not regress by more than `15%`
- mixed latency should not grow by more than `20%`
- per-unit memory growth should not regress by more than `15%`
- reload and failover timings should not regress by more than `10%`

## Hostile-Edge Interpretation

- When measuring an internet-facing profile, treat hostile-edge controls as part of the supported envelope rather than a separate emergency mode.
- Source quotas and handshake guards should be enabled during adversarial smoke or soak runs so capacity numbers reflect the real fairness posture operators will ship.
- Sustained growth in `runtime_listener_abuse_tracked_sources` without corresponding healthy throughput growth usually indicates scan or flood pressure rather than organic demand.
- Frequent `runtime_listener_abuse_rejections_total` increments are acceptable under abusive tests, but they should not coincide with `GET /readyz` degradation unless `tracked_source_capacity_saturated` or `handshake_guard_saturated` is active.
- If hostile-edge saturation appears before upstream pools, tune per-source quotas or handshake budgets first; only then revisit global listener connection ceilings.

## Supported Versus Experimental Claims

- Loopback artifacts stay experimental and should be used for regression detection only.
- A non-loopback artifact becomes supportable only when it uses a named supported profile, includes the required reload and failover timing evidence, and passes every threshold check in the artifact.
- Release evidence should store the supported artifact under `artifacts/performance-envelope/` so GA review can inspect the exact profile assumptions and measured thresholds.

## Validation Hooks

- `crates/runtime/benches/dataplane_envelope.rs` provides repeatable Criterion throughput measurements
- `crates/runtime/examples/performance_envelope.rs` produces the mixed-latency and memory envelope summary
- `scripts/measure-performance-envelope.sh` is the canonical local entrypoint for operators and reviewers
- `artifacts/performance-envelope/README.md` defines the release-evidence storage location for supported profile artifacts