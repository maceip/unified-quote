#!/bin/bash
set -euo pipefail

# ===========================================================================
# unified-quote entrypoint
#
# Configures the GitHub Actions runner, then launches uq-runner
# (which starts the attestation endpoint and then exec's the runner).
# ===========================================================================

echo "[uq] Starting unified-quote runner..."
echo "[uq] TEE attestation endpoint will be on :${ATTEST_PORT:-9384}"

# --- Configure runner if not already configured ---
if [ ! -f /opt/actions-runner/.runner ]; then
    if [ -z "${GITHUB_TOKEN:-}" ]; then
        echo "[uq] ERROR: GITHUB_TOKEN is required for runner registration"
        exit 1
    fi

    if [ -z "${GITHUB_REPO:-}" ]; then
        echo "[uq] ERROR: GITHUB_REPO is required (e.g., maceip/unified-quote)"
        exit 1
    fi

    echo "[uq] Obtaining runner registration token..."
    REG_TOKEN=$(curl -s -X POST \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${GITHUB_REPO}/actions/runners/registration-token" \
        | jq -r .token)

    if [ "${REG_TOKEN}" = "null" ] || [ -z "${REG_TOKEN}" ]; then
        echo "[uq] ERROR: Failed to get registration token. Check GITHUB_TOKEN permissions."
        exit 1
    fi

    RUNNER_NAME="${RUNNER_NAME:-unified-quote-$(hostname | cut -c1-8)}"
    RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,unified-quote,tee}"

    echo "[uq] Registering runner '${RUNNER_NAME}' for ${GITHUB_REPO}..."
    /opt/actions-runner/config.sh \
        --url "https://github.com/${GITHUB_REPO}" \
        --token "${REG_TOKEN}" \
        --name "${RUNNER_NAME}" \
        --labels "${RUNNER_LABELS}" \
        --unattended \
        --replace \
        --ephemeral
fi

# --- Launch uq-runner ---
# The shim:
#   1. Computes Value X over the runner directory
#   2. Collects TEE attestation (if available)
#   3. Starts the /attest HTTP endpoint
#   4. Exec's the runner
exec uq-runner
