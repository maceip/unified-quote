# ===========================================================================
# bountynet-genesis: TEE-attested GitHub Actions runner
# ===========================================================================
# Multi-stage build:
#   Stage 1: Build bountynet-shim from Rust source
#   Stage 2: Download GitHub Actions runner
#   Stage 3: Assemble minimal runtime image
# ===========================================================================

# --- Stage 1: Build the Rust shim ---
FROM rust:1.94-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY v2/ v2/

# Build in release mode
RUN cargo build --release --bin bountynet-shim && \
    strip target/release/bountynet-shim

# --- Stage 2: Download GitHub Actions runner ---
FROM debian:bookworm-slim AS runner-dl

RUN apt-get update && apt-get install -y curl jq && rm -rf /var/lib/apt/lists/*

ARG RUNNER_VERSION=2.323.0
ARG RUNNER_ARCH=x64

RUN curl -fsSL \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz" \
    -o /tmp/runner.tar.gz && \
    mkdir -p /opt/actions-runner && \
    tar xzf /tmp/runner.tar.gz -C /opt/actions-runner && \
    rm /tmp/runner.tar.gz

# --- Stage 3: Runtime image ---
FROM debian:bookworm-slim

# Runtime deps for both shim and GitHub runner
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    libicu72 \
    libssl3 \
    libkrb5-3 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Create runner user (GitHub runner refuses to run as root)
RUN useradd -m -d /home/runner -s /bin/bash runner

# Copy bountynet-shim
COPY --from=builder /build/target/release/bountynet-shim /usr/local/bin/bountynet-shim

# Copy GitHub Actions runner
COPY --from=runner-dl /opt/actions-runner /opt/actions-runner
RUN chown -R runner:runner /opt/actions-runner

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Attestation endpoint port
EXPOSE 9384

# Environment defaults
ENV RUNNER_DIR=/opt/actions-runner
ENV ATTEST_PORT=9384

USER runner
WORKDIR /opt/actions-runner

ENTRYPOINT ["/entrypoint.sh"]
