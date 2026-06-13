#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-sigstore-test}"
REG_NAME="${CLUSTER_NAME}-registry"

echo ">>> tearing down sigstore test environment"

echo ">>> killing port-forwards"
pkill -f "kubectl.*port-forward.*sigstore" 2>/dev/null || true

echo ">>> uninstalling scaffold Helm release"
helm uninstall scaffold -n sigstore 2>/dev/null || true

echo ">>> deleting kind cluster ${CLUSTER_NAME}"
kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true

echo ">>> removing registries"
docker rm -f "${REG_NAME}" 2>/dev/null || true
docker rm -f "${CLUSTER_NAME}-registry2" 2>/dev/null || true

echo ">>> done"
