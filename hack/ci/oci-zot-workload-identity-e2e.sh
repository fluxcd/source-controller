#!/usr/bin/env bash
# End-to-end test for OCI registry authentication with Kubernetes ServiceAccount
# tokens, using Zot's OIDC bearer authentication.
#
# It creates a dedicated kind cluster with a ServiceAccount issuer reachable
# from a Zot container on the kind network, deploys source-controller, and
# verifies that an OCIRepository using the generic provider authenticates to
# Zot with a projected ServiceAccount token.
set -euo pipefail

IMG="${IMG:-test/source-controller:latest}"
ZOT_IMAGE="${ZOT_IMAGE:-ghcr.io/project-zot/zot-linux-amd64:v2.1.22}"
CLUSTER="${CLUSTER:-zot-oidc}"
ZOT_CONTAINER="${ZOT_CONTAINER:-zot-oidc}"
ZOT_PORT="${ZOT_PORT:-5000}"
ZOT_HOST_PORT="${ZOT_HOST_PORT:-5050}"
AUDIENCE="zot-registry"
NS="source-system"
APP_NS="zot-e2e"
SA_NAME="zot-puller"
SA_NAME_B="zot-puller-b"
WRONG_AUD_SA_NAME="zot-puller-wrong-aud"
REPO_A="zot-e2e-a"
REPO_B="zot-e2e-b"
OCIREPO_A="zot-oidc-a"
OCIREPO_B="zot-oidc-b"
REV="test"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
CREATED_CLUSTER=false

log()  { echo -e "\n\033[1;34m==> $*\033[0m"; }
info() { echo "    $*"; }
fail() { echo -e "\033[1;31mFAIL: $*\033[0m" >&2; exit 1; }

cleanup() {
    local code=$?
    if [ "$code" -ne 0 ]; then
        log "FAILURE (exit ${code}) — dumping diagnostics"
        kubectl -n "${NS}" logs deploy/source-controller --tail=120 2>/dev/null || true
        kubectl -n "${APP_NS}" get ocirepositories -o yaml 2>/dev/null || true
        docker logs --tail=80 "${ZOT_CONTAINER}" 2>/dev/null || true
    fi
    if [ -n "${KEEP:-}" ]; then
        log "KEEP set — leaving cluster, container and ${WORKDIR} for inspection"
        exit "${code}"
    fi
    log "Cleaning up"
    docker rm -f "${ZOT_CONTAINER}" >/dev/null 2>&1 || true
    if [ "${CREATED_CLUSTER}" = "true" ]; then
        kind delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
    fi
    rm -rf "${WORKDIR}" 2>/dev/null || sudo rm -rf "${WORKDIR}" 2>/dev/null || true
    exit "${code}"
}
trap cleanup EXIT

require() { command -v "$1" >/dev/null 2>&1 || fail "required tool '$1' not found in PATH"; }
for bin in docker kind kubectl kustomize flux; do require "$bin"; done

start_zot() {
    local config="$1"
    docker rm -f "${ZOT_CONTAINER}" >/dev/null 2>&1 || true
    docker run -d --name "${ZOT_CONTAINER}" --network kind \
        -p "127.0.0.1:${ZOT_HOST_PORT}:${ZOT_PORT}" \
        -v "${config}:/etc/zot/config.json:ro" \
        -v "${WORKDIR}/zot-data:/var/lib/zot" \
        "${ZOT_IMAGE}" serve /etc/zot/config.json >/dev/null

    local code
    for _ in $(seq 1 60); do
        code="$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${ZOT_HOST_PORT}/v2/" 2>/dev/null || echo 000)"
        case "${code}" in
            200|401) return 0 ;;
        esac
        sleep 1
    done
    docker logs --tail=80 "${ZOT_CONTAINER}" 2>/dev/null || true
    fail "Zot did not become ready (last HTTP status: ${code})"
}

##############################################################################
log "Creating kind cluster '${CLUSTER}' with an externally reachable issuer"
##############################################################################
if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    info "Deleting pre-existing cluster"
    kind delete cluster --name "${CLUSTER}"
fi
cat <<EOF | kind create cluster --name "${CLUSTER}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      certSANs:
        - "${CLUSTER}-control-plane"
      extraArgs:
        service-account-issuer: "https://${CLUSTER}-control-plane:6443"
        anonymous-auth: "true"
EOF
CREATED_CLUSTER=true
kubectl config use-context "kind-${CLUSTER}" >/dev/null
kubectl wait --for=condition=Ready nodes --all --timeout=180s

OIDC_ISSUER="https://${CLUSTER}-control-plane:6443"
info "OIDC issuer: ${OIDC_ISSUER}"

log "Allowing unauthenticated OIDC discovery"
kubectl create clusterrolebinding oidc-reviewer \
    --clusterrole=system:service-account-issuer-discovery \
    --group=system:unauthenticated >/dev/null 2>&1 || true

log "Exporting the kind CA certificate"
docker cp "${CLUSTER}-control-plane:/etc/kubernetes/pki/ca.crt" "${WORKDIR}/kind-ca.pem"
mkdir -p "${WORKDIR}/zot-data"
chmod 0777 "${WORKDIR}/zot-data"

##############################################################################
log "Seeding Zot with an artifact while authentication is disabled"
##############################################################################
cat > "${WORKDIR}/zot-open.json" <<EOF
{
  "distSpecVersion": "1.1.1",
  "storage": {
    "rootDirectory": "/var/lib/zot"
  },
  "http": {
    "address": "0.0.0.0",
    "port": ${ZOT_PORT},
    "compat": ["docker2s2"]
  },
  "log": {
    "level": "debug"
  }
}
EOF
start_zot "${WORKDIR}/zot-open.json"

mkdir -p "${WORKDIR}/artifact-a" "${WORKDIR}/artifact-b"
echo "artifact for ${SA_NAME}" > "${WORKDIR}/artifact-a/index.txt"
echo "artifact for ${SA_NAME_B}" > "${WORKDIR}/artifact-b/index.txt"
flux push artifact "oci://localhost:${ZOT_HOST_PORT}/${REPO_A}:${REV}" \
    --path="${WORKDIR}/artifact-a" \
    --source=zot-oidc-e2e-a \
    --revision="${REV}"
flux push artifact "oci://localhost:${ZOT_HOST_PORT}/${REPO_B}:${REV}" \
    --path="${WORKDIR}/artifact-b" \
    --source=zot-oidc-e2e-b \
    --revision="${REV}"
docker rm -f "${ZOT_CONTAINER}" >/dev/null

##############################################################################
log "Starting Zot with OIDC bearer authentication"
##############################################################################
cat > "${WORKDIR}/zot-auth.json" <<EOF
{
  "distSpecVersion": "1.1.1",
  "storage": {
    "rootDirectory": "/var/lib/zot"
  },
  "http": {
    "address": "0.0.0.0",
    "port": ${ZOT_PORT},
    "compat": ["docker2s2"],
    "auth": {
      "bearer": {
        "realm": "http://${ZOT_CONTAINER}:${ZOT_PORT}/zot/auth/token",
        "service": "${ZOT_CONTAINER}:${ZOT_PORT}",
        "oidc": [
          {
            "issuer": "${OIDC_ISSUER}",
            "audiences": ["${AUDIENCE}"],
            "certificateAuthorityFile": "/etc/zot/kind-ca.pem"
          }
        ]
      }
    },
    "accessControl": {
      "repositories": {
        "${REPO_A}": {
          "policies": [
            {
              "users": ["${OIDC_ISSUER}/system:serviceaccount:${APP_NS}:${SA_NAME}"],
              "actions": ["read"]
            }
          ],
          "defaultPolicy": []
        },
        "${REPO_B}": {
          "policies": [
            {
              "users": ["${OIDC_ISSUER}/system:serviceaccount:${APP_NS}:${SA_NAME_B}"],
              "actions": ["read"]
            }
          ],
          "defaultPolicy": []
        }
      }
    }
  },
  "log": {
    "level": "debug"
  }
}
EOF
docker run -d --name "${ZOT_CONTAINER}" --network kind \
    -p "127.0.0.1:${ZOT_HOST_PORT}:${ZOT_PORT}" \
    -v "${WORKDIR}/zot-auth.json:/etc/zot/config.json:ro" \
    -v "${WORKDIR}/kind-ca.pem:/etc/zot/kind-ca.pem:ro" \
    -v "${WORKDIR}/zot-data:/var/lib/zot" \
    "${ZOT_IMAGE}" serve /etc/zot/config.json >/dev/null

for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${ZOT_HOST_PORT}/v2/" 2>/dev/null || echo 000)"
    [ "${code}" = "401" ] && break
    sleep 1
done
[ "${code}" = "401" ] || fail "Zot did not start with bearer auth (last HTTP status: ${code})"

##############################################################################
log "Deploying source-controller"
##############################################################################
kind load docker-image "${IMG}" --name "${CLUSTER}"
make -C "${ROOT_DIR}" install >/dev/null
make -C "${ROOT_DIR}" dev-deploy IMG="${IMG%:*}" TAG="${IMG##*:}" >/dev/null
kubectl -n "${NS}" patch deploy/source-controller --type=json \
    -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--feature-gates=ObjectLevelWorkloadIdentity=true"}]' >/dev/null
kubectl -n "${NS}" rollout status deploy/source-controller --timeout=2m

##############################################################################
log "Creating ServiceAccounts and OCIRepositories"
##############################################################################
kubectl create namespace "${APP_NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "${APP_NS}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${SA_NAME}
  annotations:
    credential.auth.fluxcd.io/provider: kubernetes
    credential.auth.fluxcd.io/type: jwt
    credential.auth.fluxcd.io/audiences: ${AUDIENCE}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${SA_NAME_B}
  annotations:
    credential.auth.fluxcd.io/provider: kubernetes
    credential.auth.fluxcd.io/type: jwt
    credential.auth.fluxcd.io/audiences: ${AUDIENCE}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${WRONG_AUD_SA_NAME}
  annotations:
    credential.auth.fluxcd.io/provider: kubernetes
    credential.auth.fluxcd.io/type: jwt
    credential.auth.fluxcd.io/audiences: wrong-audience
EOF

kubectl -n "${APP_NS}" apply -f - >/dev/null <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: ${OCIREPO_A}
  namespace: ${APP_NS}
spec:
  interval: 1m
  timeout: 30s
  insecure: true
  provider: generic
  serviceAccountName: ${SA_NAME}
  url: oci://${ZOT_CONTAINER}:${ZOT_PORT}/${REPO_A}
  ref:
    tag: ${REV}
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: ${OCIREPO_B}
  namespace: ${APP_NS}
spec:
  interval: 1m
  timeout: 30s
  insecure: true
  provider: generic
  serviceAccountName: ${SA_NAME_B}
  url: oci://${ZOT_CONTAINER}:${ZOT_PORT}/${REPO_B}
  ref:
    tag: ${REV}
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: ${OCIREPO_A}-cross
  namespace: ${APP_NS}
spec:
  interval: 1m
  timeout: 30s
  insecure: true
  provider: generic
  serviceAccountName: ${SA_NAME}
  url: oci://${ZOT_CONTAINER}:${ZOT_PORT}/${REPO_B}
  ref:
    tag: ${REV}
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: ${OCIREPO_B}-cross
  namespace: ${APP_NS}
spec:
  interval: 1m
  timeout: 30s
  insecure: true
  provider: generic
  serviceAccountName: ${SA_NAME_B}
  url: oci://${ZOT_CONTAINER}:${ZOT_PORT}/${REPO_A}
  ref:
    tag: ${REV}
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: ${OCIREPO_A}-wrong-audience
  namespace: ${APP_NS}
spec:
  interval: 1m
  timeout: 30s
  insecure: true
  provider: generic
  serviceAccountName: ${WRONG_AUD_SA_NAME}
  url: oci://${ZOT_CONTAINER}:${ZOT_PORT}/${REPO_A}
  ref:
    tag: ${REV}
EOF

log "Waiting for the owned-repository OCIRepositories to become Ready"
kubectl -n "${APP_NS}" wait "ocirepository/${OCIREPO_A}" \
    --for=condition=Ready --timeout=3m
kubectl -n "${APP_NS}" wait "ocirepository/${OCIREPO_B}" \
    --for=condition=Ready --timeout=3m
info "Each ServiceAccount authenticated to its own repository"

expect_denied() {
    local name="$1" status msg
    for _ in $(seq 1 60); do
        status="$(kubectl -n "${APP_NS}" get "ocirepository/${name}" \
            -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
        msg="$(kubectl -n "${APP_NS}" get "ocirepository/${name}" \
            -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || true)"
        if [ "${status}" = "True" ]; then
            fail "OCIRepository ${name} unexpectedly succeeded"
        fi
        if [ "${status}" = "False" ] && printf '%s' "${msg}" | grep -qiE '401|403|unauthorized|forbidden|denied|authentication'; then
            info "OCIRepository ${name} correctly denied"
            return 0
        fi
        sleep 2
    done
    fail "OCIRepository ${name} did not fail in time (status=${status:-unknown}; message=${msg:-})"
}

log "Verifying cross-ServiceAccount access is denied"
expect_denied "${OCIREPO_A}-cross"
expect_denied "${OCIREPO_B}-cross"
expect_denied "${OCIREPO_A}-wrong-audience"

log "SUCCESS: each ServiceAccount accessed only its own repository"
