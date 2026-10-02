#!/usr/bin/env bash
# Spin up the two local OCI registries the sigstore harness consumes,
# coupled to CLUSTER_NAME so each kind cluster has its own pair.
#
#   ${CLUSTER_NAME}-registry   zot, OCI 1.1 referrers API
#   ${CLUSTER_NAME}-registry2  registry:2, tag-based referrers fallback
#
# Both containers attach to the kind Docker network so kubelet can pull
# images by their in-cluster DNS name (which matches the container name).
# Run kind-up.sh first so the kind network exists.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-sigstore-test}"
REG_NAME="${CLUSTER_NAME}-registry"
REG2_NAME="${CLUSTER_NAME}-registry2"
REG_LOCALHOST_PORT="${REG_LOCALHOST_PORT:-5555}"
REG2_LOCALHOST_PORT="${REG2_LOCALHOST_PORT:-5557}"
REG_CLUSTER_PORT=5000
ZOT_VERSION="${ZOT_VERSION:-v2.1.7}"
REGISTRY_VERSION="${REGISTRY_VERSION:-2.8.3}"

ARCH=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/')
ZOT_IMAGE="ghcr.io/project-zot/zot-linux-${ARCH}:${ZOT_VERSION}"
REGISTRY_IMAGE="registry:${REGISTRY_VERSION}"

# Primary registry: zot (supports OCI 1.1 referrers API natively)
if [ "$(docker inspect -f '{{.State.Running}}' "${REG_NAME}" 2>/dev/null || true)" != 'true' ]; then
  echo ">>> starting ${ZOT_IMAGE} as ${REG_NAME} on localhost:${REG_LOCALHOST_PORT}"
  docker run -d --restart=always \
    -p "127.0.0.1:${REG_LOCALHOST_PORT}:${REG_CLUSTER_PORT}" \
    --name "${REG_NAME}" \
    "${ZOT_IMAGE}"
else
  echo ">>> registry ${REG_NAME} already running"
fi

# Fallback registry: registry:2 (tag-based referrers only)
if [ "$(docker inspect -f '{{.State.Running}}' "${REG2_NAME}" 2>/dev/null || true)" != 'true' ]; then
  echo ">>> starting ${REGISTRY_IMAGE} as ${REG2_NAME} on localhost:${REG2_LOCALHOST_PORT}"
  docker run -d --restart=always \
    -p "127.0.0.1:${REG2_LOCALHOST_PORT}:${REG_CLUSTER_PORT}" \
    --name "${REG2_NAME}" \
    "${REGISTRY_IMAGE}"
else
  echo ">>> registry:2 ${REG2_NAME} already running"
fi

# Connect both registries to the kind Docker network so the cluster
# resolves them via their container names.
for name in "${REG_NAME}" "${REG2_NAME}"; do
  if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${name}" 2>/dev/null)" = 'null' ]; then
    echo ">>> connecting ${name} to kind network"
    docker network connect "kind" "${name}"
  fi
done

echo ""
echo "=== Registries Ready ==="
echo "  primary:  localhost:${REG_LOCALHOST_PORT} (in-cluster: ${REG_NAME}:${REG_CLUSTER_PORT})"
echo "  fallback: localhost:${REG2_LOCALHOST_PORT} (in-cluster: ${REG2_NAME}:${REG_CLUSTER_PORT})"
