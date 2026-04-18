ARG APP_BIN=lb-dataplane

FROM rust:1.85-bookworm AS builder

ARG APP_BIN

WORKDIR /app
COPY . .
RUN cargo build --release -p ${APP_BIN}
RUN install -D /app/target/release/${APP_BIN} /out/lb-entrypoint

FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /out/lb-entrypoint /usr/local/bin/lb-entrypoint

ENTRYPOINT ["/usr/local/bin/lb-entrypoint"]