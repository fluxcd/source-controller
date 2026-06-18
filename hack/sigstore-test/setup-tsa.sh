#!/usr/bin/env bash
# Generate a TSA cert chain + encrypted private key and reconfigure the
# scaffold helm release to deploy timestamp-server with the `file` signer.
# This is the simplest path to a running TSA inside kind because the chart's
# default tink signer requires keysets the scaffold chart does not ship.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSA_DIR="${SCRIPT_DIR}/pki/tsa"
SIGSTORE_SCAFFOLD_VERSION="${SIGSTORE_SCAFFOLD_VERSION:-0.6.109}"
mkdir -p "${TSA_DIR}"

PASSWORD="${TSA_PASSWORD:-flux-tsa-test}"

if [ ! -s "${TSA_DIR}/leaf.key" ]; then
  echo ">>> generating TSA cert chain (root + leaf)"
  # Root CA
  openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout "${TSA_DIR}/root.key" \
    -out "${TSA_DIR}/root.crt" \
    -subj '/CN=Flux Test TSA Root/O=Flux/C=US' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign' \
    >/dev/null 2>&1

  # Leaf with timestamping EKU. timestamp-server v2 requires ECDSA keys.
  # We skip the intermediate so timestamp-authority's enforce-intermediate-eku
  # check (default true) does not apply.
  openssl ecparam -name prime256v1 -genkey -noout -out "${TSA_DIR}/leaf.key.unencrypted"
  openssl req -new -key "${TSA_DIR}/leaf.key.unencrypted" \
    -out "${TSA_DIR}/leaf.csr" \
    -subj '/CN=Flux Test TSA/O=Flux/C=US' \
    >/dev/null 2>&1
  cat > "${TSA_DIR}/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
EOF
  openssl x509 -req -in "${TSA_DIR}/leaf.csr" \
    -CA "${TSA_DIR}/root.crt" -CAkey "${TSA_DIR}/root.key" \
    -CAcreateserial -out "${TSA_DIR}/leaf.crt" \
    -days 3650 -extfile "${TSA_DIR}/leaf.ext" \
    >/dev/null 2>&1

  # Encrypt the leaf key with the password (PKCS#8 PEM, AES-256).
  openssl pkcs8 -topk8 -v2 aes-256-cbc \
    -in "${TSA_DIR}/leaf.key.unencrypted" \
    -out "${TSA_DIR}/leaf.key" \
    -passout "pass:${PASSWORD}"
  rm -f "${TSA_DIR}/leaf.key.unencrypted"

  # Chain order expected by timestamp-server v2: leaf, ..., root.
  cat "${TSA_DIR}/leaf.crt" "${TSA_DIR}/root.crt" > "${TSA_DIR}/chain.pem"
fi

CHAIN_CONTENT="$(cat "${TSA_DIR}/chain.pem")"

echo ">>> creating tsa-server-secret"
# Pre-create the namespace and stamp Helm ownership metadata so the next
# `helm upgrade scaffold` can adopt it (the scaffold chart's TSA subchart
# templates a Namespace resource for tsa-system, which would otherwise
# collide with the namespace we need now to hold tsa-server-secret).
kubectl create namespace tsa-system --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace tsa-system \
  app.kubernetes.io/managed-by=Helm --overwrite
kubectl annotate namespace tsa-system \
  meta.helm.sh/release-name=scaffold \
  meta.helm.sh/release-namespace=sigstore --overwrite
kubectl -n tsa-system create secret generic tsa-server-secret \
  --from-file=private="${TSA_DIR}/leaf.key" \
  --from-literal=password="${PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo ">>> upgrading scaffold ${SIGSTORE_SCAFFOLD_VERSION} helm release with file-signer TSA"
helm upgrade scaffold sigstore/scaffold \
  --version "${SIGSTORE_SCAFFOLD_VERSION}" \
  --namespace sigstore \
  --reuse-values \
  --set tsa.enabled=true \
  --set tsa.server.args.signer=file \
  --set-string tsa.server.args.cert_chain="${CHAIN_CONTENT}" \
  --timeout 5m --wait

echo ">>> waiting for tsa-server rollout"
kubectl -n tsa-system rollout status deploy/tsa-server --timeout=2m

echo ">>> creating tsa-np NodePort service"
kubectl apply -f - <<'EOF'
---
apiVersion: v1
kind: Service
metadata:
  name: tsa-np
  namespace: tsa-system
spec:
  type: NodePort
  selector:
    app.kubernetes.io/instance: scaffold
    app.kubernetes.io/name: tsa
  ports:
  - name: http
    port: 80
    targetPort: 5555
EOF

echo "=== TSA Ready ==="
echo "  chain: ${TSA_DIR}/chain.pem"
echo "  leaf cert: ${TSA_DIR}/leaf.crt"
kubectl -n tsa-system get pods,svc
