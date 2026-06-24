#!/usr/bin/env bash

set -eoux pipefail

CREATE_CLUSTER="${CREATE_CLUSTER:-true}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
LOAD_IMG_INTO_KIND="${LOAD_IMG_INTO_KIND:-true}"
BUILD_PLATFORM="${BUILD_PLATFORM:-linux/amd64}"

IMG=test/source-controller
TAG=latest

ROOT_DIR="$(git rev-parse --show-toplevel)"
BUILD_DIR="${ROOT_DIR}/build"

if "${CREATE_CLUSTER}"; then
    KIND_CLUSTER_NAME="flux-${RANDOM}"
    export KUBECONFIG="${ROOT_DIR}/build/kindconfig"

    echo "Spinning up flux kind cluster"
    kind create cluster --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}"
fi

function cleanup(){
    EXIT_CODE="$?"

    # only dump all logs if an error has occurred
    if [ ${EXIT_CODE} -ne 0 ]; then
        kubectl -n kube-system describe pods
        kubectl -n source-system describe pods
        kubectl -n source-system get gitrepositories -oyaml
        kubectl -n source-system get ocirepositories -oyaml
        kubectl -n source-system get helmrepositories -oyaml
        kubectl -n source-system get helmcharts -oyaml
        kubectl -n source-system get all
        kubectl -n source-system logs deploy/source-controller
    else
        echo "All E2E tests passed!"
    fi

    if "${CREATE_CLUSTER}"; then
        echo "Delete cluster"
        kind delete cluster --name "${KIND_CLUSTER_NAME}"
    fi
    exit ${EXIT_CODE}
}
trap cleanup EXIT

# Wait for nodes to be ready and pods to be running
kubectl wait node "${KIND_CLUSTER_NAME}-control-plane" --for=condition=ready --timeout=2m
kubectl wait --for=condition=ready -n kube-system -l k8s-app=kube-dns pod
kubectl wait --for=condition=ready -n local-path-storage -l app=local-path-provisioner pod

echo "Build, load image into kind and deploy controller"
make docker-build IMG="${IMG}" TAG="${TAG}" BUILD_PLATFORMS="${BUILD_PLATFORM}" BUILD_ARGS=--load

if "${LOAD_IMG_INTO_KIND}"; then
    kind load docker-image --name "${KIND_CLUSTER_NAME}" "${IMG}":"${TAG}"
fi

make dev-deploy IMG="${IMG}" TAG="${TAG}"

echo "Run smoke tests"
kubectl -n source-system apply -f "${ROOT_DIR}/config/samples"
kubectl -n source-system rollout status deploy/source-controller --timeout=1m
kubectl -n source-system wait gitrepository/gitrepository-sample --for=condition=ready --timeout=1m
kubectl -n source-system wait ocirepository/ocirepository-sample --for=condition=ready --timeout=1m
kubectl -n source-system wait helmrepository/helmrepository-sample --for=condition=ready --timeout=1m
kubectl -n source-system wait helmchart/helmchart-sample --for=condition=ready --timeout=1m
kubectl -n source-system wait helmchart/helmchart-sample-oci --for=condition=ready --timeout=1m
kubectl -n source-system delete -f "${ROOT_DIR}/config/samples"

echo "Run HelmChart values file tests"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/helmchart-valuesfile"
kubectl -n source-system wait helmchart/podinfo --for=condition=ready --timeout=5m
kubectl -n source-system wait helmchart/podinfo-git --for=condition=ready --timeout=5m
kubectl -n source-system delete -f "${ROOT_DIR}/config/testdata/helmchart-valuesfile"

echo "Run large Git repo tests"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/git/large-repo.yaml"
kubectl -n source-system wait gitrepository/large-repo --for=condition=ready --timeout=3m15s

echo "Run HelmChart from OCI registry tests"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/helmchart-from-oci/source.yaml"
kubectl -n source-system wait helmchart/podinfo --for=condition=ready --timeout=1m
kubectl -n source-system wait helmchart/podinfo-keyless --for=condition=ready --timeout=1m

kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/helmchart-from-oci/cosign-v3.yaml"
kubectl -n source-system wait helmchart/podinfo-cosign-v3-keyless --for=condition=ready --timeout=1m

kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/helmchart-from-oci/notation.yaml"
curl -sSLo notation.crt https://raw.githubusercontent.com/stefanprodan/podinfo/master/.notation/notation.crt
curl -sSLo trustpolicy.json https://raw.githubusercontent.com/stefanprodan/podinfo/master/.notation/trustpolicy.json
kubectl -n source-system create secret generic notation-config --from-file=notation.crt --from-file=trustpolicy.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n source-system wait helmchart/podinfo-notation --for=condition=ready --timeout=1m

echo "Run OCIRepository verify tests"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/ocirepository/signed-with-cosign-v2-key.yaml"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/ocirepository/signed-with-cosign-v2-keyless.yaml"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/ocirepository/signed-with-cosign-v3-key.yaml"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/ocirepository/signed-with-cosign-v3-keyless.yaml"
curl -sSLo cosign.pub https://raw.githubusercontent.com/stefanprodan/podinfo/master/.cosign/cosign.pub
kubectl -n source-system create secret generic cosign-key --from-file=cosign.pub --dry-run=client -o yaml | kubectl apply -f -
curl -sSLo cosign-testing.pub https://raw.githubusercontent.com/fluxcd-testing/cosign-testing/main/cosign.pub
kubectl -n source-system create secret generic cosign-testing-key --from-file=cosign-testing.pub --dry-run=client -o yaml | kubectl apply -f -

kubectl -n source-system wait ocirepository/podinfo-deploy-signed-with-v2-key --for=condition=ready --timeout=1m
kubectl -n source-system wait ocirepository/podinfo-deploy-signed-with-v2-keyless --for=condition=ready --timeout=1m
kubectl -n source-system wait ocirepository/podinfo-deploy-signed-with-v3-key --for=condition=ready --timeout=1m
kubectl -n source-system wait ocirepository/podinfo-deploy-signed-with-v3-keyless --for=condition=ready --timeout=1m

kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/ocirepository/signed-with-notation.yaml"
kubectl -n source-system wait ocirepository/podinfo-deploy-signed-with-notation --for=condition=ready --timeout=1m
