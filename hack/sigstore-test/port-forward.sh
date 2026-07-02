#!/usr/bin/env bash
# Set up port-forwarding to sigstore services and export env vars.
# Source this file: source hack/sigstore-test/port-forward.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PF_PID_FILE="${SCRIPT_DIR}/.port-forward.pids"

stop_port_forwards() {
  if [ ! -f "${PF_PID_FILE}" ]; then
    return
  fi

  local cmd
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
}

start_port_forward() {
  kubectl "$@" &>/dev/null &
  echo "$!" >> "${PF_PID_FILE}"
}

echo ">>> setting up port-forwarding to sigstore services"

stop_port_forwards
: > "${PF_PID_FILE}"
sleep 1

# Rekor
start_port_forward -n rekor-system port-forward svc/rekor-server 3000:80
# Fulcio
start_port_forward -n fulcio-system port-forward svc/fulcio-server 5555:80
# TUF
start_port_forward -n tuf-system port-forward svc/tuf 8081:80

sleep 2

export REKOR_URL="http://localhost:3000"
export FULCIO_URL="http://localhost:5555"
export TUF_MIRROR="http://localhost:8081"

echo "  REKOR_URL=${REKOR_URL}"
echo "  FULCIO_URL=${FULCIO_URL}"
echo "  TUF_MIRROR=${TUF_MIRROR}"
echo ""
echo "Port-forwarding active. PIDs recorded in ${PF_PID_FILE}."
