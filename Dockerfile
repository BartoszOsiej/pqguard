# ── Stage 1: Build ──
FROM rust:1.80-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

# ── Stage 2: Runtime ──
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/pqguard /usr/local/bin/pqguard
RUN useradd -m pqguard
USER pqguard
WORKDIR /home/pqguard
ENTRYPOINT ["pqguard"]
