#!/usr/bin/env bash
# Build and execute csr-attestation-tpm-example in Docker using the TCG TPM 2.0 simulator.
#
# Usage:
#   ./docker/run.sh                    # run full workflow end-to-end
#   ./docker/run.sh bash               # open a shell in the client container
#   ./docker/run.sh ./3_createkey.sh   # run one step manually
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose -f "${COMPOSE_FILE}" --project-directory "${SCRIPT_DIR}")
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose -f "${COMPOSE_FILE}")
else
    echo "ERROR: docker compose (v2) or docker-compose (v1) is required." >&2
    exit 1
fi

cleanup() {
    echo "==> Stopping simulator ..."
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Building images ..."
"${COMPOSE[@]}" build

echo "==> Resetting old containers ..."
"${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true

echo "==> Starting simulator ..."
"${COMPOSE[@]}" up -d simulator

echo "==> Waiting for simulator to become reachable ..."
"${COMPOSE[@]}" run --rm client bash -euo pipefail -c '
until bash -c "</dev/tcp/simulator/2321" 2>/dev/null; do
    echo "  waiting for simulator on port 2321 ..."
    sleep 1
done
echo "  simulator is ready."
'

if [[ $# -eq 0 ]]; then
    echo "==> Running full workflow ..."
    "${COMPOSE[@]}" run --rm client bash -euo pipefail -c '
./0_clean.sh all
tpm2_startup -c
./1_makeCA.sh
./2_initial_provision.sh
./3_createkey.sh
./4_createcsr.sh
./5_verifykey.sh
'
else
    echo "==> Running: $*"
    "${COMPOSE[@]}" run --rm client "$@"
fi

echo "==> Workflow complete."
