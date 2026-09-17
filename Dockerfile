# ==============================================================================
# Phylax (φύλαξ) — Production Multi-Stage Dockerfile
# Builds an ultra-lean (<20MB) standalone WAF reverse proxy container
# ==============================================================================

FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /usr/src/phylax
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples

RUN cargo build --release --features cli

# Runtime Stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S phylax && adduser -S phylax -G phylax

COPY --from=builder /usr/src/phylax/target/release/phylax /usr/local/bin/phylax

USER phylax
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:3000/_phylax/healthz || exit 1

ENTRYPOINT ["phylax"]
CMD ["serve", "--upstream", "http://127.0.0.1:8080", "--listen", "0.0.0.0:3000"]
