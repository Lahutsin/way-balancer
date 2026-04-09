FROM rust:1.85-bookworm AS builder

ARG LB_CONTROL_PLANE_SIGNING_KEY_ED25519
ARG LB_CTL_ADMIN_SECRET
ARG LB_CTL_OPERATOR_SECRET

WORKDIR /app
COPY . .
RUN cargo build --release -p lb-dataplane

FROM debian:bookworm-slim

ARG LB_CONTROL_PLANE_SIGNING_KEY_ED25519
ARG LB_CTL_ADMIN_SECRET
ARG LB_CTL_OPERATOR_SECRET

WORKDIR /app
COPY --from=builder /app/target/release/lb-dataplane /usr/local/bin/lb-dataplane

ENTRYPOINT ["/usr/local/bin/lb-dataplane"]