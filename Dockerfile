FROM rust:1.85-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --release -p lb-dataplane

FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/target/release/lb-dataplane /usr/local/bin/lb-dataplane

ENTRYPOINT ["/usr/local/bin/lb-dataplane"]