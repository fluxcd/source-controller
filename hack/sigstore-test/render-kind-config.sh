#!/usr/bin/env bash
# Render hack/sigstore-test/kind-cluster.yaml from kind-cluster.yaml.tpl,
# substituting CLUSTER_NAME and registry host ports. The rendered file is
# .gitignored; regenerate it via `make kind-config` whenever cluster name
# or ports change. CI workflows can override the output path via
# KIND_CONFIG_PATH so the rendered config survives a subsequent
# actions/checkout step run by setup-kubernetes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-sigstore-test}"
REG_LOCALHOST_PORT="${REG_LOCALHOST_PORT:-5555}"
REG2_LOCALHOST_PORT="${REG2_LOCALHOST_PORT:-5557}"
KIND_CONFIG_PATH="${KIND_CONFIG_PATH:-${SCRIPT_DIR}/kind-cluster.yaml}"

mkdir -p "$(dirname "${KIND_CONFIG_PATH}")"
sed \
  -e "s|\${CLUSTER_NAME}|${CLUSTER_NAME}|g" \
  -e "s|\${REG_LOCALHOST_PORT}|${REG_LOCALHOST_PORT}|g" \
  -e "s|\${REG2_LOCALHOST_PORT}|${REG2_LOCALHOST_PORT}|g" \
  "${SCRIPT_DIR}/kind-cluster.yaml.tpl" > "${KIND_CONFIG_PATH}"

echo "rendered kind cluster config to ${KIND_CONFIG_PATH}"
echo "  CLUSTER_NAME=${CLUSTER_NAME}"
echo "  REG_LOCALHOST_PORT=${REG_LOCALHOST_PORT}"
echo "  REG2_LOCALHOST_PORT=${REG2_LOCALHOST_PORT}"
