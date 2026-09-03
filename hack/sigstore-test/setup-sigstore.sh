#!/usr/bin/env bash
# Install sigstore stack into the kind cluster using the scaffold Helm chart.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGSTORE_SCAFFOLD_VERSION="${SIGSTORE_SCAFFOLD_VERSION:-0.6.109}"

echo "=== Installing Sigstore Stack ==="
echo ">>> cluster node / Kubernetes version:"
kubectl get nodes -o wide || true
kubectl version -o yaml 2>/dev/null | grep -iE 'gitVersion|major|minor' || true

helm repo add sigstore https://sigstore.github.io/helm-charts 2>/dev/null || true
helm repo update sigstore

# Allow unauthenticated OIDC discovery so Fulcio can fetch the cluster's
# JWKS to validate service-account tokens. Without this the scaffold's
# Fulcio/CTLog jobs never reach Complete and the helm install blocks until
# timeout. Paired with the apiserver service-account-jwks-uri set on the
# kind cluster config.
kubectl create clusterrolebinding oidc-reviewer \
  --clusterrole=system:service-account-issuer-discovery \
  --group=system:unauthenticated 2>/dev/null || true

# DEBUG: dump cluster state across all sigstore namespaces. Called on a
# failed/timed-out helm install so the Actions log shows which pods or jobs
# are unhealthy instead of a silent hang. Remove once CI is green.
dump_sigstore_state() {
  echo "::group::sigstore cluster state (debug)"

  echo "--- nodes ---"
  kubectl get nodes -o wide 2>/dev/null || true
  echo "--- node conditions / capacity / allocatable ---"
  kubectl describe nodes 2>/dev/null \
    | grep -iE 'Name:|MemoryPressure|DiskPressure|PIDPressure|Ready|cpu:|memory:|ephemeral-storage:|Allocated resources|Non-terminated' || true
  echo "--- node-level kernel/OOM hints (kind node is a container) ---"
  for node in $(kubectl get nodes -o name 2>/dev/null | sed 's|node/||'); do
    docker exec "${node}" sh -c 'dmesg 2>/dev/null | grep -iE "oom|killed process|out of memory" | tail -15' 2>/dev/null || true
  done

  for ns in sigstore trillian-system rekor-system fulcio-system ctlog-system tuf-system; do
    kubectl get ns "${ns}" &>/dev/null || continue
    echo "--- namespace ${ns}: pods (with restart counts) ---"
    kubectl -n "${ns}" get pods -o wide 2>/dev/null || true
    echo "--- namespace ${ns}: jobs ---"
    kubectl -n "${ns}" get jobs 2>/dev/null || true
    # Dump every pod that is not both Running and Ready. A pod can be phase
    # Running yet crash-looping (e.g. trillian-mysql), so filter on the Ready
    # condition rather than phase, and prefer --previous logs to catch the
    # output from the container instance that just died.
    for pod in $(kubectl -n "${ns}" get pods -o name 2>/dev/null); do
      ready=$(kubectl -n "${ns}" get "${pod}" \
        -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
      [ "${ready}" = "True" ] && continue
      echo "--- ${ns}/${pod} (Ready=${ready:-<none>}) describe ---"
      kubectl -n "${ns}" describe "${pod}" 2>/dev/null \
        | grep -iE 'State:|Reason:|Exit Code:|Restart Count:|Message:|Last State:|Started:|Finished:|Events:|Warning|Liveness|Readiness' || true
      echo "--- ${ns}/${pod} previous-instance logs ---"
      kubectl -n "${ns}" logs "${pod}" --all-containers --previous --tail=80 2>/dev/null \
        || echo "    (no previous logs)"
      echo "--- ${ns}/${pod} current logs ---"
      kubectl -n "${ns}" logs "${pod}" --all-containers --tail=80 2>/dev/null \
        || echo "    (no current logs)"
    done
  done

  echo "--- recent warning events (all namespaces) ---"
  kubectl get events -A --field-selector type=Warning \
    --sort-by=.lastTimestamp 2>/dev/null | tail -60 || true
  echo "::endgroup::"
}

# Override the Trillian database image and probes for MySQL 8.x via a
# checked-in values file (see trillian.mysql.values.yaml for the rationale).
echo ">>> installing sigstore/scaffold ${SIGSTORE_SCAFFOLD_VERSION} (this takes a few minutes)..."

# DEBUG: while `helm --wait` blocks (up to 10m), snapshot trillian-mysql a few
# times in the background. By the time the wait fails the pod is deep in
# CrashLoopBackOff and --previous only shows the latest crash, so capture the
# early instances too. Remove once CI is green.
watch_mysql() {
  local ns=trillian-system
  for delay in 45 90 150 240; do
    sleep "${delay}"
    echo "::group::trillian-mysql snapshot @ ${delay}s"
    kubectl -n "${ns}" get pods -l app.kubernetes.io/name=mysql -o wide 2>/dev/null || true
    for pod in $(kubectl -n "${ns}" get pods -l app.kubernetes.io/name=mysql -o name 2>/dev/null); do
      kubectl -n "${ns}" describe "${pod}" 2>/dev/null \
        | grep -iE 'State:|Reason:|Exit Code:|Restart Count:|Last State:|Message:' || true
      echo "  -- current logs --"
      kubectl -n "${ns}" logs "${pod}" --tail=60 2>/dev/null || true
      echo "  -- previous logs --"
      kubectl -n "${ns}" logs "${pod}" --previous --tail=60 2>/dev/null || true
    done
    echo "::endgroup::"
  done
}
watch_mysql &
WATCH_PID=$!

if ! helm upgrade --install scaffold sigstore/scaffold \
  --version "${SIGSTORE_SCAFFOLD_VERSION}" \
  --namespace sigstore --create-namespace \
  --values "${SCRIPT_DIR}/trillian.mysql.values.yaml" \
  --timeout 10m \
  --wait;
then
  echo "ERROR: sigstore scaffold install failed or timed out; dumping state" >&2
  kill "${WATCH_PID}" 2>/dev/null || true
  dump_sigstore_state
  exit 1
fi
kill "${WATCH_PID}" 2>/dev/null || true

echo ">>> waiting for sigstore namespaces"
for ns in trillian-system rekor-system fulcio-system ctlog-system tuf-system; do
  if kubectl get ns "${ns}" &>/dev/null; then
    echo "  ${ns}: waiting for deployments..."
    for deploy in $(kubectl get deploy -n "${ns}" -o name 2>/dev/null); do
      echo "    >>> rollout status ${ns}/${deploy} (timeout 5m)"
      kubectl rollout status --timeout=5m -n "${ns}" "${deploy}" 2>/dev/null || true
    done
    echo "  ${ns}: waiting for jobs to complete (timeout 5m)"
    kubectl wait --timeout=5m -n "${ns}" --for=condition=Complete jobs --all 2>/dev/null || true
  fi
done

echo "=== Extracting PKI Material ==="
mkdir -p "${SCRIPT_DIR}/pki"

kubectl -n fulcio-system get secrets fulcio-pub-key -ojsonpath='{.data.cert}' 2>/dev/null \
  | base64 -d > "${SCRIPT_DIR}/pki/fulcio.crt.pem" && echo "  extracted fulcio.crt.pem" || echo "  WARN: fulcio cert not found"

kubectl -n ctlog-system get secret ctlog-public-key -ojsonpath='{.data.public}' 2>/dev/null \
  | base64 -d > "${SCRIPT_DIR}/pki/ctfe.pub" && echo "  extracted ctfe.pub" || echo "  WARN: ctlog pub key not found"

# Rekor public key is fetched via API since the scaffold chart uses an in-memory signer
echo "  fetching rekor public key via API..."
kubectl -n rekor-system port-forward svc/rekor-server 3000:80 &>/dev/null &
PF_PID=$!
sleep 2
if curl -sf http://localhost:3000/api/v1/log/publicKey > "${SCRIPT_DIR}/pki/rekor.pub" 2>/dev/null; then
  echo "  extracted rekor.pub"
else
  echo "  WARN: could not fetch rekor public key"
fi
kill $PF_PID 2>/dev/null || true

echo ""
echo "=== Patching Fulcio config for cluster.local issuer ==="
# kind clusters use https://kubernetes.default.svc.cluster.local as the OIDC
# issuer for ServiceAccount tokens; the scaffold chart's default Fulcio
# config only accepts https://kubernetes.default.svc, so we replace the
# configmap with one that accepts both and restart the server.
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: fulcio-server-config
  namespace: fulcio-system
data:
  config.json: |
    {
      "OIDCIssuers": {
        "https://kubernetes.default.svc": {
          "IssuerURL": "https://kubernetes.default.svc",
          "ClientID": "sigstore",
          "Type": "kubernetes"
        },
        "https://kubernetes.default.svc.cluster.local": {
          "IssuerURL": "https://kubernetes.default.svc.cluster.local",
          "ClientID": "sigstore",
          "Type": "kubernetes"
        }
      },
      "MetaIssuers": {
        "https://kubernetes.*.svc": {
          "ClientID": "sigstore",
          "Type": "kubernetes"
        }
      }
    }
EOF
kubectl -n fulcio-system rollout restart deploy/fulcio-server
echo ">>> waiting for fulcio-server rollout (timeout 2m)"
kubectl -n fulcio-system rollout status deploy/fulcio-server --timeout=2m

echo ""
echo "=== Exposing rekor and fulcio via NodePort ==="
# The cosign CLI runs outside the cluster during test-signing.sh; expose
# rekor-server and fulcio-server as NodePorts so the host can reach them
# via the kind control-plane node IP.
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: rekor-np
  namespace: rekor-system
spec:
  type: NodePort
  selector:
    app.kubernetes.io/component: server
    app.kubernetes.io/instance: scaffold
    app.kubernetes.io/name: rekor
  ports:
  - name: http
    port: 80
    targetPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: fulcio-np
  namespace: fulcio-system
spec:
  type: NodePort
  selector:
    app.kubernetes.io/instance: scaffold
    app.kubernetes.io/name: fulcio
  ports:
  - name: http
    port: 80
    targetPort: 5555
EOF

echo ""
echo "=== Sigstore Stack Ready ==="
echo "  pki: ${SCRIPT_DIR}/pki/"
ls -la "${SCRIPT_DIR}/pki/" 2>/dev/null
