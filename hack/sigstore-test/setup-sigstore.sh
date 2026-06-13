#!/usr/bin/env bash
# Install sigstore stack into the kind cluster using the scaffold Helm chart.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Installing Sigstore Stack ==="
helm repo add sigstore https://sigstore.github.io/helm-charts 2>/dev/null || true
helm repo update sigstore

echo ">>> installing sigstore/scaffold (this takes a few minutes)..."
helm upgrade --install scaffold sigstore/scaffold \
  --namespace sigstore --create-namespace \
  --timeout 10m \
  --wait

echo ">>> waiting for sigstore namespaces"
for ns in trillian-system rekor-system fulcio-system ctlog-system tuf-system; do
  if kubectl get ns "${ns}" &>/dev/null; then
    echo "  ${ns}: waiting for deployments..."
    for deploy in $(kubectl get deploy -n "${ns}" -o name 2>/dev/null); do
      kubectl rollout status --timeout=5m -n "${ns}" "${deploy}" 2>/dev/null || true
    done
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
echo "=== Sigstore Stack Ready ==="
echo "  pki: ${SCRIPT_DIR}/pki/"
ls -la "${SCRIPT_DIR}/pki/" 2>/dev/null
