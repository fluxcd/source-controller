#!/usr/bin/env bash
# Spin up a kind cluster with a local OCI registry on the same Docker network.
# Sigstore stack installation is a separate step (see setup-sigstore.sh).
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-sigstore-test}"
REG_NAME="${CLUSTER_NAME}-registry"
REG_LOCALHOST_PORT="${REG_LOCALHOST_PORT:-5555}"
REG_CLUSTER_PORT=5000
NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.32.2}"

echo "=== Phase 1: Local OCI Registries ==="
# Primary registry: zot (supports OCI 1.1 referrers API natively)
if [ "$(docker inspect -f '{{.State.Running}}' "${REG_NAME}" 2>/dev/null || true)" != 'true' ]; then
  echo ">>> starting zot ${REG_NAME} on localhost:${REG_LOCALHOST_PORT}"
  docker run -d --restart=always \
    -p "127.0.0.1:${REG_LOCALHOST_PORT}:5000" \
    --name "${REG_NAME}" \
    ghcr.io/project-zot/zot-linux-$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/'):latest
else
  echo ">>> registry ${REG_NAME} already running"
fi

# Fallback registry: registry:2 (tag-based referrers only, no referrers API)
REG2_NAME="${CLUSTER_NAME}-registry2"
REG2_LOCALHOST_PORT="${REG2_LOCALHOST_PORT:-5557}"
if [ "$(docker inspect -f '{{.State.Running}}' "${REG2_NAME}" 2>/dev/null || true)" != 'true' ]; then
  echo ">>> starting registry:2 ${REG2_NAME} on localhost:${REG2_LOCALHOST_PORT}"
  docker run -d --restart=always \
    -p "127.0.0.1:${REG2_LOCALHOST_PORT}:${REG_CLUSTER_PORT}" \
    --name "${REG2_NAME}" \
    registry:2
else
  echo ">>> registry:2 ${REG2_NAME} already running"
fi

echo "=== Phase 2: Kind Cluster ==="
if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo ">>> creating kind cluster ${CLUSTER_NAME}"
  cat <<EOF | kind create cluster --name "${CLUSTER_NAME}" --image "${NODE_IMAGE}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        service-account-jwks-uri: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${REG_LOCALHOST_PORT}"]
    endpoint = ["http://${REG_NAME}:${REG_CLUSTER_PORT}"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."${REG_NAME}:${REG_CLUSTER_PORT}"]
    endpoint = ["http://${REG_NAME}:${REG_CLUSTER_PORT}"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${REG2_LOCALHOST_PORT}"]
    endpoint = ["http://${REG2_NAME}:${REG_CLUSTER_PORT}"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."${REG2_NAME}:${REG_CLUSTER_PORT}"]
    endpoint = ["http://${REG2_NAME}:${REG_CLUSTER_PORT}"]
EOF
else
  echo ">>> cluster ${CLUSTER_NAME} already exists"
fi

# Connect registries to kind network
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${REG_NAME}" 2>/dev/null)" = 'null' ]; then
  echo ">>> connecting registry:3 to kind network"
  docker network connect "kind" "${REG_NAME}"
fi
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${REG2_NAME}" 2>/dev/null)" = 'null' ]; then
  echo ">>> connecting registry:2 to kind network"
  docker network connect "kind" "${REG2_NAME}"
fi

echo ">>> waiting for cluster readiness"
kubectl wait node "${CLUSTER_NAME}-control-plane" --for=condition=ready --timeout=2m
kubectl wait --for=condition=ready -n kube-system -l k8s-app=kube-dns pod --timeout=2m

# Allow unauthenticated OIDC discovery (needed for Fulcio to validate SA tokens)
kubectl create clusterrolebinding oidc-reviewer \
  --clusterrole=system:service-account-issuer-discovery \
  --group=system:unauthenticated 2>/dev/null || true

echo ""
echo "=== Cluster Ready ==="
echo "  cluster:   ${CLUSTER_NAME}"
echo "  registry3: localhost:${REG_LOCALHOST_PORT} (in-cluster: ${REG_NAME}:${REG_CLUSTER_PORT})"
echo "  registry2: localhost:${REG2_LOCALHOST_PORT} (in-cluster: ${REG2_NAME}:${REG_CLUSTER_PORT})"
echo ""
echo "Next: run setup-sigstore.sh to install the sigstore stack"
