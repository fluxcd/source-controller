#!/usr/bin/env bash

set -eoux pipefail

CREATE_CLUSTER="${CREATE_CLUSTER:-true}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
LOAD_IMG_INTO_KIND="${LOAD_IMG_INTO_KIND:-true}"
BUILD_PLATFORM="${BUILD_PLATFORM:-linux/amd64}"
MINIO_HELM_VER="${MINIO_HELM_VER:-v6.3.1}"
# Older tags do not bundle multiple architectures. Newer tags are 5-6 times larger.
MINIO_TAG="${MINIO_TAG:-RELEASE.2020-09-17T04-49-20Z}"

IMG=test/source-controller
TAG=latest

MC_RELEASE=mc.RELEASE.2021-12-16T23-38-39Z
MC_AMD64_SHA256=d14302bbdaa180a073c1627ff9fbf55243221e33d47e32df61a950f635810978
MC_ARM64_SHA256=00791995bf8d102e3159e23b3af2f5e6f4c784fafd88c60161dcf3f0169aa217

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
        kubectl -n minio get all
        kubectl -n minio describe pods
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
kubectl -n source-system wait helmrepository/helmrepository-sample-oci --for=condition=ready --timeout=1m
kubectl -n source-system wait helmchart/helmchart-sample --for=condition=ready --timeout=1m
kubectl -n source-system wait helmchart/helmchart-sample-oci --for=condition=ready --timeout=1m
kubectl -n source-system delete -f "${ROOT_DIR}/config/samples"

echo "Run HelmChart values file tests"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/helmchart-valuesfile"
kubectl -n source-system wait helmchart/podinfo --for=condition=ready --timeout=5m
kubectl -n source-system wait helmchart/podinfo-git --for=condition=ready --timeout=5m
kubectl -n source-system delete -f "${ROOT_DIR}/config/testdata/helmchart-valuesfile"

echo "Setup Minio"
kubectl create ns minio
helm repo add minio https://helm.min.io/ --force-update
helm upgrade minio minio/minio --wait -i \
    --version "${MINIO_HELM_VER}" \
    --namespace minio \
    --set accessKey=myaccesskey \
    --set secretKey=mysecretkey \
    --set resources.requests.memory=128Mi \
    --set persistence.enable=false \
    --set image.tag="${MINIO_TAG}"
kubectl -n minio port-forward svc/minio 9000:9000 &>/dev/null &

sleep 2

if [ ! -f "${BUILD_DIR}/mc" ]; then
    MC_SHA256="${MC_AMD64_SHA256}"
    ARCH="amd64"
    if [ "${BUILD_PLATFORM}" = "linux/arm64" ]; then
        MC_SHA256="${MC_ARM64_SHA256}"
        ARCH="arm64"
    fi

    mkdir -p "${BUILD_DIR}"
    curl -o "${BUILD_DIR}/mc" -LO "https://dl.min.io/client/mc/release/linux-${ARCH}/archive/${MC_RELEASE}"
    if ! echo "${MC_SHA256}  ${BUILD_DIR}/mc" | sha256sum --check; then
        echo "Checksum failed for mc."
        rm "${BUILD_DIR}/mc"
        exit 1
    fi

    chmod +x "${BUILD_DIR}/mc"
fi

"${BUILD_DIR}/mc" alias set minio http://localhost:9000 myaccesskey mysecretkey --api S3v4
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/minio/secret.yaml"

echo "Run Bucket tests"
"${BUILD_DIR}/mc" mb minio/podinfo
"${BUILD_DIR}/mc" mirror "${ROOT_DIR}/config/testdata/minio/manifests/" minio/podinfo

kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/bucket/source.yaml"
kubectl -n source-system wait bucket/podinfo --for=condition=ready --timeout=1m


echo "Run HelmChart from Bucket tests"
"${BUILD_DIR}/mc" mb minio/charts
"${BUILD_DIR}/mc" mirror "${ROOT_DIR}/controllers/testdata/charts/helmchart/" minio/charts/helmchart

kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/helmchart-from-bucket/source.yaml"
kubectl -n source-system wait bucket/charts --for=condition=ready --timeout=1m
kubectl -n source-system wait helmchart/helmchart-bucket --for=condition=ready --timeout=1m

echo "Run large Git repo tests"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/git/large-repo.yaml"
kubectl -n source-system wait gitrepository/large-repo-go-git --for=condition=ready --timeout=2m15s
kubectl -n source-system wait gitrepository/large-repo-libgit2 --for=condition=ready --timeout=2m15s


# Test experimental libgit2 transport. Any tests against the default transport must
# either run before this, or patch the deployment again to disable this, as once enabled
# only the managed transport will be used.
kubectl -n source-system patch deployment source-controller \
    --patch '{"spec": {"template": {"spec": {"containers": [{"name": "manager","env": [{"name": "EXPERIMENTAL_GIT_TRANSPORT", "value": "true"}]}]}}}}'

# wait until the patch took effect and the new source-controller is running
sleep 20s

kubectl -n source-system wait --for=condition=ready --timeout=1m -l app=source-controller pod

echo "Re-run large libgit2 repo test with managed transport"
kubectl -n source-system wait gitrepository/large-repo-libgit2 --for=condition=ready --timeout=2m15s
kubectl -n source-system exec deploy/source-controller -- printenv | grep EXPERIMENTAL_GIT_TRANSPORT=true


echo "Run HelmChart from OCI registry tests"
kubectl -n source-system apply -f "${ROOT_DIR}/config/testdata/helmchart-from-oci/source.yaml"
kubectl -n source-system wait helmrepository/podinfo --for=condition=ready --timeout=1m
kubectl -n source-system wait helmchart/podinfo --for=condition=ready --timeout=1m
