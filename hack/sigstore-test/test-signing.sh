#!/usr/bin/env bash
# test-signing.sh: Validate cosign v2/v3 x key-pair/keyless verification flows.
#
# Prerequisites:
#   - kind cluster running (hack/sigstore-test/kind-up.sh)
#   - sigstore stack installed (hack/sigstore-test/setup-sigstore.sh)
#   - source-controller deployed (hack/sigstore-test/build-and-load.sh)
#   - fulcio config patched for cluster.local issuer
#   - rekor-np and fulcio-np NodePort services created
set -eoux pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
KEYS_DIR="${SCRIPT_DIR}/keys"
TESTDATA="${SCRIPT_DIR}/testdata"

REG="localhost:5555"
REG2="localhost:5557"
NS="source-system"

NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
REKOR_NP=$(kubectl -n rekor-system get svc rekor-np -o jsonpath='{.spec.ports[0].nodePort}')
FULCIO_NP=$(kubectl -n fulcio-system get svc fulcio-np -o jsonpath='{.spec.ports[0].nodePort}')
REKOR_URL="http://${NODE_IP}:${REKOR_NP}"
FULCIO_URL="http://${NODE_IP}:${FULCIO_NP}"

# --- Setup keys and secrets ---

mkdir -p "$KEYS_DIR" "$PKI_DIR"

if [ ! -f "$KEYS_DIR/test.key" ]; then
  COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix="$KEYS_DIR/test"
fi
if [ ! -f "$KEYS_DIR/wrong.key" ]; then
  COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix="$KEYS_DIR/wrong"
fi
if [ ! -f "$KEYS_DIR/signing-config-notlog.json" ]; then
  cosign signing-config create --out "$KEYS_DIR/signing-config-notlog.json"
fi

if [ ! -s "$PKI_DIR/trusted_root.json" ]; then
  cosign trusted-root create \
    --fulcio="url=http://fulcio-server.fulcio-system.svc,certificate-chain=$PKI_DIR/fulcio.crt.pem" \
    --rekor="url=http://rekor-server.rekor-system.svc,public-key=$PKI_DIR/rekor.pub,start-time=2024-01-01T00:00:00Z" \
    --ctfe="url=http://ctlog.ctlog-system.svc,public-key=$PKI_DIR/ctfe.pub,start-time=2024-01-01T00:00:00Z" \
    --out "$PKI_DIR/trusted_root.json"
fi

# Wrong trusted root (uses wrong.pub as rekor key)
cosign trusted-root create \
  --fulcio="url=http://fulcio-server.fulcio-system.svc,certificate-chain=$PKI_DIR/fulcio.crt.pem" \
  --rekor="url=http://rekor-server.rekor-system.svc,public-key=$KEYS_DIR/wrong.pub,start-time=2024-01-01T00:00:00Z" \
  --ctfe="url=http://ctlog.ctlog-system.svc,public-key=$PKI_DIR/ctfe.pub,start-time=2024-01-01T00:00:00Z" \
  --out "$PKI_DIR/wrong_trusted_root.json"

kubectl -n "$NS" create secret generic cosign-test-key \
  --from-file=cosign.pub="$KEYS_DIR/test.pub" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic cosign-wrong-key \
  --from-file=cosign.pub="$KEYS_DIR/wrong.pub" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic sigstore-trusted-root \
  --from-file=trusted_root.json="$PKI_DIR/trusted_root.json" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic sigstore-wrong-root \
  --from-file=trusted_root.json="$PKI_DIR/wrong_trusted_root.json" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret docker-registry registry-creds \
  --docker-server="sigstore-test-registry:5000" \
  --docker-username=user --docker-password=pass \
  --dry-run=client -o yaml | kubectl apply -f -

# --- Helper ---

push_artifact() {
  local ref="$1"
  local tmp
  tmp=$(mktemp -d)
  echo "{\"test\":\"$(basename "$ref")\"}" > "$tmp/data.yaml"
  flux push artifact "oci://$ref" --path="$tmp" --source=test --revision=v1
  rm -rf "$tmp"
}

# --- Sign artifacts ---

echo "Run cosign v2-style key-pair tests"
push_artifact "$REG/test/v2-key:v1"
COSIGN_PASSWORD="" cosign sign --key="$KEYS_DIR/test.key" \
  --tlog-upload=false --use-signing-config=false --new-bundle-format=false \
  --allow-insecure-registry "$REG/test/v2-key:v1"

echo "Run cosign v3 bundle key-pair tests"
push_artifact "$REG/test/v3-key:v1"
COSIGN_PASSWORD="" cosign sign --key="$KEYS_DIR/test.key" \
  --signing-config="$KEYS_DIR/signing-config-notlog.json" \
  --allow-insecure-registry "$REG/test/v3-key:v1"

echo "Run cosign v2-style keyless tests"
push_artifact "$REG/test/v2-keyless:v1"
cosign sign \
  --trusted-root="$PKI_DIR/trusted_root.json" \
  --fulcio-url="$FULCIO_URL" --rekor-url="$REKOR_URL" \
  --allow-insecure-registry --use-signing-config=false --new-bundle-format=false \
  --identity-token="$(kubectl create token default -n default --audience=sigstore)" \
  --yes "$REG/test/v2-keyless:v1"

echo "Run cosign v3 bundle keyless tests"
push_artifact "$REG/test/v3-keyless:v1"
cosign sign \
  --trusted-root="$PKI_DIR/trusted_root.json" \
  --fulcio-url="$FULCIO_URL" --rekor-url="$REKOR_URL" \
  --allow-insecure-registry --use-signing-config=false \
  --identity-token="$(kubectl create token default -n default --audience=sigstore)" \
  --yes "$REG/test/v3-keyless:v1"

echo "Run cosign v3 key-pair with tlog tests"
push_artifact "$REG/test/v3-key-tlog:v1"
COSIGN_PASSWORD="" cosign sign --key="$KEYS_DIR/test.key" \
  --trusted-root="$PKI_DIR/trusted_root.json" \
  --rekor-url="$REKOR_URL" \
  --allow-insecure-registry --use-signing-config=false \
  --yes "$REG/test/v3-key-tlog:v1"

echo "Run registry auth test"
push_artifact "$REG/test/authed:v1"
COSIGN_PASSWORD="" cosign sign --key="$KEYS_DIR/test.key" \
  --tlog-upload=false --use-signing-config=false --new-bundle-format=false \
  --allow-insecure-registry "$REG/test/authed:v1"

echo "Run registry:2 fallback tests"
push_artifact "$REG2/test/v3-key-fallback:v1"
COSIGN_PASSWORD="" cosign sign --key="$KEYS_DIR/test.key" \
  --signing-config="$KEYS_DIR/signing-config-notlog.json" \
  --allow-insecure-registry "$REG2/test/v3-key-fallback:v1"

push_artifact "$REG2/test/v3-keyless-fallback:v1"
cosign sign \
  --trusted-root="$PKI_DIR/trusted_root.json" \
  --fulcio-url="$FULCIO_URL" --rekor-url="$REKOR_URL" \
  --allow-insecure-registry --use-signing-config=false \
  --identity-token="$(kubectl create token default -n default --audience=sigstore)" \
  --yes "$REG2/test/v3-keyless-fallback:v1"

push_artifact "$REG2/test/v3-key-tlog-fallback:v1"
COSIGN_PASSWORD="" cosign sign --key="$KEYS_DIR/test.key" \
  --trusted-root="$PKI_DIR/trusted_root.json" \
  --rekor-url="$REKOR_URL" \
  --allow-insecure-registry --use-signing-config=false \
  --yes "$REG2/test/v3-key-tlog-fallback:v1"

# --- Apply and verify ---

echo "Run OCIRepository verify tests"
kubectl -n "$NS" apply -f "${TESTDATA}/v2-key.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/v3-key.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/v2-keyless-trustedroot.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/v3-keyless-trustedroot.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/v3-key-tlog.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/combined-secretref-trustedroot.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/registry-auth.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/registry2-fallback.yaml"

kubectl -n "$NS" wait ocirepository/test-v2-key --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-v3-key --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-v2-keyless --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-v3-keyless --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-v3-key-tlog --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-combined --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-authed --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-v3-key-fallback --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-v3-keyless-fallback --for=condition=ready --timeout=1m
kubectl -n "$NS" wait ocirepository/test-v3-key-tlog-fallback --for=condition=ready --timeout=1m

echo "Run negative verification tests"
kubectl -n "$NS" apply -f "${TESTDATA}/wrong-key.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/wrong-identity.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/wrong-rekor-key.yaml"

# Negative tests: wait for VerificationError condition
sleep 30
kubectl -n "$NS" get ocirepository test-wrong-key -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' | grep -q "VerificationError"
kubectl -n "$NS" get ocirepository test-wrong-identity -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' | grep -q "VerificationError"
kubectl -n "$NS" get ocirepository test-wrong-rekor -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' | grep -q "VerificationError"

echo "All sigstore verification tests passed!"
