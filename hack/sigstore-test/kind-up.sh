#!/usr/bin/env bash
# Create the kind cluster for the sigstore harness.
#
# Reads the rendered kind cluster config from $KIND_CONFIG_PATH (defaults to
# ./kind-cluster.yaml). Run `make kind-config` first, or invoke `make up`
# which depends on the kind-config target.
#
# Registries are spun up by registries-up.sh; the sigstore stack is installed
# by setup-sigstore.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-sigstore-test}"
NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.32.2}"
KIND_CONFIG_PATH="${KIND_CONFIG_PATH:-${SCRIPT_DIR}/kind-cluster.yaml}"

if [ ! -s "${KIND_CONFIG_PATH}" ]; then
  echo "kind cluster config not found at ${KIND_CONFIG_PATH}" >&2
  echo "run 'make kind-config' first" >&2
  exit 1
fi

if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo ">>> creating kind cluster ${CLUSTER_NAME} from ${KIND_CONFIG_PATH}"
  kind create cluster --name "${CLUSTER_NAME}" --image "${NODE_IMAGE}" --config "${KIND_CONFIG_PATH}"
else
  echo ">>> cluster ${CLUSTER_NAME} already exists"
fi

echo ">>> waiting for cluster readiness"
kubectl wait node "${CLUSTER_NAME}-control-plane" --for=condition=ready --timeout=2m
kubectl wait --for=condition=ready -n kube-system -l k8s-app=kube-dns pod --timeout=2m

echo ""
echo "=== Cluster Ready ==="
echo "  cluster: ${CLUSTER_NAME}"
echo ""
echo "Next: registries-up.sh, setup-sigstore.sh"
