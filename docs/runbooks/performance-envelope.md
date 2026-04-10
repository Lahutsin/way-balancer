# Performance Envelope

## Purpose

This runbook defines the repeatable in-repo performance envelope used to track dataplane throughput, mixed-traffic latency, memory growth, and TLS overhead over time.

## What Is Covered

- HTTP/1 loopback proxy throughput through the runtime proxy path
- HTTP/2 loopback stream throughput through the runtime proxy path
- mixed HTTP/1 plus HTTP/2 latency with persistent loopback clients
- TLS termination overhead for the HTTP/1 proxy path using `tokio-rustls`
- resident-memory growth per idle accepted connection and per active HTTP/2 stream

## Reproducible Commands

Run the smoke-sized envelope locally with:

```sh
./scripts/measure-performance-envelope.sh smoke
```

Run the larger local envelope with:

```sh
./scripts/measure-performance-envelope.sh full
```

This produces two artifacts under `target/performance-envelope/`:

- JSON summary from `cargo run --release -p lb-runtime --example performance_envelope`
- Criterion report text from `cargo bench -p lb-runtime --bench dataplane_envelope`

## Scenario Assumptions

- Measurements are loopback-only and are meant for regression detection plus capacity planning baselines, not internet-facing latency claims.
- The memory probe uses resident-set-size sampling from the local process and is most useful as a relative trend line across commits on the same host class.
- The HTTP/1 memory probe measures accepted idle listener connections through `lb_runtime::start_listener`.
- The HTTP/2 stream memory probe measures concurrent active proxy streams while the upstream intentionally delays completion.
- TLS overhead is measured as the delta between the same HTTP/1 request batch over plain TCP and over a local Rustls-terminated downstream connection.

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

## Regression Interpretation

- sustained HTTP/1 or HTTP/2 throughput drops beyond normal host variance should be treated as dataplane regressions
- mixed-traffic p95 or p99 growth indicates parser, routing, or upstream-client work is becoming more expensive under interleaved load
- rising per-connection or per-stream RSS deltas indicate memory growth that will compress safe concurrency ceilings
- widening TLS overhead indicates certificate handling, handshake work, or encrypted I/O has regressed

## Validation Hooks

- `crates/runtime/benches/dataplane_envelope.rs` provides repeatable Criterion throughput measurements
- `crates/runtime/examples/performance_envelope.rs` produces the mixed-latency and memory envelope summary
- `scripts/measure-performance-envelope.sh` is the canonical local entrypoint for operators and reviewers