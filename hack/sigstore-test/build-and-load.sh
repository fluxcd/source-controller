#!/usr/bin/env bash
# Build source-controller and load it into the kind cluster.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-sigstore-test}"
IMG="${IMG:-test/source-controller}"
TAG="${TAG:-latest}"
BUILD_PLATFORM="${BUILD_PLATFORM:-linux/arm64}"

REPO_ROOT="$(git rev-parse --show-toplevel)"

echo ">>> building source-controller image"
cd "${REPO_ROOT}"
make docker-build IMG="${IMG}" TAG="${TAG}" BUILD_PLATFORMS="${BUILD_PLATFORM}" BUILD_ARGS=--load

echo ">>> loading image into kind cluster ${CLUSTER_NAME}"
kind load docker-image --name "${CLUSTER_NAME}" "${IMG}:${TAG}"

echo ">>> deploying source-controller"
make dev-deploy IMG="${IMG}" TAG="${TAG}"

# dev-deploy reapplies the same :latest tag, so the Deployment spec is
# unchanged and an already-running pod will keep the old image. Force a
# rollout so re-runs of this script pick up the freshly loaded binary.
kubectl -n source-system rollout restart deploy/source-controller

echo ">>> waiting for source-controller rollout"
kubectl -n source-system rollout status deploy/source-controller --timeout=2m

echo ">>> source-controller deployed"
kubectl -n source-system get pods
