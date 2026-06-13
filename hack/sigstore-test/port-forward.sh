#!/usr/bin/env bash
# Set up port-forwarding to sigstore services and export env vars.
# Source this file: source hack/sigstore-test/port-forward.sh
set -euo pipefail

echo ">>> setting up port-forwarding to sigstore services"

# Kill any existing port-forwards
pkill -f "kubectl.*port-forward.*sigstore" 2>/dev/null || true
sleep 1

# Rekor
kubectl -n rekor-system port-forward svc/rekor-server 3000:80 &>/dev/null &
# Fulcio
kubectl -n fulcio-system port-forward svc/fulcio-server 5555:80 &>/dev/null &
# TUF
kubectl -n tuf-system port-forward svc/tuf 8081:80 &>/dev/null &

sleep 2

export REKOR_URL="http://localhost:3000"
export FULCIO_URL="http://localhost:5555"
export TUF_MIRROR="http://localhost:8081"

echo "  REKOR_URL=${REKOR_URL}"
echo "  FULCIO_URL=${FULCIO_URL}"
echo "  TUF_MIRROR=${TUF_MIRROR}"
echo ""
echo "Port-forwarding active. Use 'kill %1 %2 %3' to stop."
