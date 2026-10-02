#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-sigstore-test}"
REG_NAME="${CLUSTER_NAME}-registry"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PF_PID_FILE="${SCRIPT_DIR}/.port-forward.pids"

echo ">>> tearing down sigstore test environment"

echo ">>> killing port-forwards"
if [ -f "${PF_PID_FILE}" ]; then
  cmd=""
  while IFS= read -r pid; do
    if [ -z "${pid}" ]; then
      continue
    fi
    cmd="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
    if [[ "${cmd}" == *kubectl*"port-forward"* ]]; then
      kill "${pid}" 2>/dev/null || true
    fi
  done < "${PF_PID_FILE}"
  rm -f "${PF_PID_FILE}"
fi

echo ">>> uninstalling scaffold Helm release"
helm uninstall scaffold -n sigstore 2>/dev/null || true

echo ">>> deleting kind cluster ${CLUSTER_NAME}"
kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true

echo ">>> removing registries"
docker rm -f "${REG_NAME}" 2>/dev/null || true
docker rm -f "${CLUSTER_NAME}-registry2" 2>/dev/null || true

echo ">>> clearing cluster-bound PKI material"
rm -rf "${SCRIPT_DIR}/pki" "${SCRIPT_DIR}/keys"

echo ">>> done"
