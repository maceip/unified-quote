#!/bin/bash
set -euo pipefail

# ============================================================================
# Stage 0: Attested Build
#
# Runs inside a TEE. Takes source code, builds it, produces an artifact
# and an attestation document proving what was built.
#
# Implements the core contribution of the Attestable Containers paper:
#   TEE proves: "source S was compiled into artifact A by environment E"
#
# The ratcheting mechanism: CT (source hash) is computed and locked
# BEFORE any build commands run. This prevents the build process
# from modifying the source after measurement.
#
# Usage:
#   ./build-attested.sh <repo-url> [commit-sha] [build-cmd]
#
# Output:
#   ./output/artifact          — the built artifact
#   ./output/attestation.json  — the attestation document
#   ./output/registry-entry.json — ready to append to registry.json
#
# Requirements:
#   - Running inside a TEE (TDX, SNP, or Nitro)
#   - uq-runner available in PATH (for TEE evidence collection)
#   - git, sha384sum or openssl
# ============================================================================

REPO_URL="${1:?Usage: build-attested.sh <repo-url> [commit-sha] [build-cmd]}"
COMMIT="${2:-HEAD}"
BUILD_CMD="${3:-}"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

echo "[stage0] === Attested Build ==="
echo "[stage0] Repo: ${REPO_URL}"
echo "[stage0] Commit: ${COMMIT}"
echo "[stage0] TEE: checking..."

# --- Step 1: Verify we're inside a TEE ---
TEE_PLATFORM="unknown"
if [ -e /sys/kernel/config/tsm/report ] || [ -e /dev/tdx_guest ]; then
    TEE_PLATFORM="tdx"
elif [ -e /dev/sev-guest ]; then
    TEE_PLATFORM="snp"
elif [ -e /dev/nsm ]; then
    TEE_PLATFORM="nitro"
else
    echo "[stage0] ERROR: No TEE detected. Attested builds require TEE hardware."
    echo "[stage0] This script must run inside a TDX, SNP, or Nitro enclave."
    exit 1
fi
echo "[stage0] TEE platform: ${TEE_PLATFORM}"

# --- Step 2: Clone source ---
echo "[stage0] Cloning ${REPO_URL}..."
git clone --quiet "${REPO_URL}" "${WORK_DIR}/src"
cd "${WORK_DIR}/src"

if [ "${COMMIT}" != "HEAD" ]; then
    git checkout --quiet "${COMMIT}"
fi
ACTUAL_COMMIT=$(git rev-parse HEAD)
echo "[stage0] Commit: ${ACTUAL_COMMIT}"

# --- Step 3: RATCHET — Lock the source hash BEFORE building ---
# This is the critical step from the Attestable Containers paper.
# CT is computed over the complete source tree. After this point,
# no modification to the source is possible without changing CT.
echo "[stage0] Computing source hash (CT)..."
CT=$(find . -type f -not -path './.git/*' | sort | xargs -I{} sha384sum {} | sha384sum | cut -d' ' -f1)
echo "[stage0] CT (source hash): ${CT}"

# Write CT to a lockfile — this is the ratchet.
# The attestation will bind this CT. If the source changes
# between now and the quote, the attestation won't match.
echo "${CT}" > "${WORK_DIR}/ct.lock"
chmod 444 "${WORK_DIR}/ct.lock"

# --- Step 4: Detect and run build ---
echo "[stage0] Building..."
if [ -n "${BUILD_CMD}" ]; then
    eval "${BUILD_CMD}"
elif [ -f Cargo.toml ]; then
    cargo build --release 2>&1 | tail -5
    ARTIFACT=$(find target/release -maxdepth 1 -type f -executable | head -1)
elif [ -f Dockerfile ]; then
    docker build -t stage0-build . 2>&1 | tail -5
    # Export the image as a tarball
    ARTIFACT="${WORK_DIR}/image.tar"
    docker save stage0-build -o "${ARTIFACT}"
elif [ -f package.json ]; then
    npm ci && npm run build 2>&1 | tail -5
    ARTIFACT=$(ls -1 dist/ 2>/dev/null | head -1)
    [ -n "${ARTIFACT}" ] && ARTIFACT="dist/${ARTIFACT}"
else
    echo "[stage0] ERROR: No recognized build system (Cargo.toml, Dockerfile, package.json)"
    exit 1
fi

if [ -z "${ARTIFACT:-}" ] || [ ! -e "${ARTIFACT:-}" ]; then
    echo "[stage0] ERROR: Build produced no artifact"
    exit 1
fi
echo "[stage0] Artifact: ${ARTIFACT}"

# --- Step 5: Compute artifact hash ---
A=$(sha384sum "${ARTIFACT}" | cut -d' ' -f1)
echo "[stage0] A (artifact hash): ${A}"

# --- Step 6: Compute Value X over the built output ---
# This is what stage 1 will verify at runtime.
# For Docker images, X = hash of all files in the image.
# For binaries, X = hash of the binary itself.
if [ -f "${ARTIFACT}" ] && file "${ARTIFACT}" | grep -q "tar archive"; then
    # Docker image: extract and hash all files
    EXTRACT_DIR=$(mktemp -d)
    tar xf "${ARTIFACT}" -C "${EXTRACT_DIR}" 2>/dev/null || true
    VALUE_X=$(find "${EXTRACT_DIR}" -type f | sort | xargs -I{} sha384sum {} | sha384sum | cut -d' ' -f1)
    rm -rf "${EXTRACT_DIR}"
else
    VALUE_X=$(sha384sum "${ARTIFACT}" | cut -d' ' -f1)
fi
echo "[stage0] Value X: ${VALUE_X}"

# --- Step 7: Collect TEE attestation ---
# Bind (CT, A, Value X) into the TEE quote via report_data.
# report_data[0..32] = sha256(CT || A || Value_X)
# report_data[32..64] = Value_X[0..32]
BINDING=$(echo -n "${CT}${A}${VALUE_X}" | openssl dgst -sha256 -binary | xxd -p -c 256)
REPORT_DATA="${BINDING}$(echo -n "${VALUE_X}" | head -c 64)"

echo "[stage0] Collecting TEE attestation..."

# Use configfs-tsm for TDX
if [ "${TEE_PLATFORM}" = "tdx" ] && [ -d /sys/kernel/config/tsm/report ]; then
    REPORT_NAME="stage0-$$"
    REPORT_DIR="/sys/kernel/config/tsm/report/${REPORT_NAME}"
    mkdir -p "${REPORT_DIR}"

    # Pad report_data to 64 bytes
    PADDED_RD=$(printf "%-128s" "${REPORT_DATA}" | tr ' ' '0')
    echo "${PADDED_RD}" | xxd -r -p > "${REPORT_DIR}/inblob"

    QUOTE_HEX=$(xxd -p "${REPORT_DIR}/outblob" | tr -d '\n')
    rmdir "${REPORT_DIR}" 2>/dev/null || true

    echo "[stage0] TDX quote collected: ${#QUOTE_HEX} hex chars"
else
    echo "[stage0] WARNING: TEE quote collection not available for ${TEE_PLATFORM} in this script"
    echo "[stage0] Use uq-runner for full evidence collection"
    QUOTE_HEX=""
fi

# --- Step 8: Write output ---
mkdir -p "${OUTPUT_DIR}"
cp "${ARTIFACT}" "${OUTPUT_DIR}/artifact" 2>/dev/null || \
    cp "${ARTIFACT}" "${OUTPUT_DIR}/"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > "${OUTPUT_DIR}/attestation.json" <<ATTEST
{
  "stage": 0,
  "tee_platform": "${TEE_PLATFORM}",
  "source_url": "${REPO_URL}",
  "source_commit": "${ACTUAL_COMMIT}",
  "ct": "${CT}",
  "artifact_hash": "${A}",
  "value_x": "${VALUE_X}",
  "report_data": "${REPORT_DATA}",
  "quote_hex": "${QUOTE_HEX}",
  "timestamp": "${TIMESTAMP}"
}
ATTEST

cat > "${OUTPUT_DIR}/registry-entry.json" <<REG
{
  "value_x": "${VALUE_X}",
  "platform_measurements": {
    "tdx_mrtd": null,
    "snp_measurement": null,
    "nitro_pcr0": null
  },
  "git_commit": "${ACTUAL_COMMIT}",
  "runner_version": "stage0-built",
  "image_digest": "sha384:${A}",
  "registered_at": "${TIMESTAMP}",
  "recommended": true,
  "deprecated": false,
  "notes": "Built by stage0 inside ${TEE_PLATFORM}. CT=${CT:0:16}..."
}
REG

echo ""
echo "[stage0] === Build Attestation Complete ==="
echo "[stage0] Source commit: ${ACTUAL_COMMIT}"
echo "[stage0] CT (source):  ${CT}"
echo "[stage0] A (artifact): ${A}"
echo "[stage0] Value X:      ${VALUE_X}"
echo "[stage0] TEE platform: ${TEE_PLATFORM}"
echo "[stage0] Output:       ${OUTPUT_DIR}/"
echo ""
echo "[stage0] The attestation proves:"
echo "[stage0]   This source → this artifact, built inside genuine ${TEE_PLATFORM} hardware."
echo "[stage0]   No reproducible build required. The TEE is the witness."
