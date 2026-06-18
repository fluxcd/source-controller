#!/usr/bin/env bash
# test-signing.sh: Validate cosign v2/v3 x key-pair/keyless verification flows
# against a custom Sigstore trusted root.
#
# Prerequisites (driven by hack/sigstore-test/Makefile):
#   - kind cluster + registries: make up registries
#   - sigstore stack + fulcio config + rekor/fulcio NodePorts: make sigstore
#   - source-controller deployed: make build
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
KEYS_DIR="${SCRIPT_DIR}/keys"
TESTDATA="${SCRIPT_DIR}/testdata"

REG_LOCALHOST_PORT="${REG_LOCALHOST_PORT:-5555}"
REG2_LOCALHOST_PORT="${REG2_LOCALHOST_PORT:-5557}"
REG="localhost:${REG_LOCALHOST_PORT}"
REG2="localhost:${REG2_LOCALHOST_PORT}"
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

# Full trusted root: Fulcio + Rekor + ctfe. Regenerated every run because
# the underlying ctfe / rekor / fulcio keys are cluster-scoped and a stale
# cache against a fresh cluster would mis-verify SCTs and inclusion proofs.
cosign trusted-root create \
  --fulcio="url=http://fulcio-server.fulcio-system.svc,certificate-chain=$PKI_DIR/fulcio.crt.pem" \
  --rekor="url=http://rekor-server.rekor-system.svc,public-key=$PKI_DIR/rekor.pub,start-time=2024-01-01T00:00:00Z" \
  --ctfe="url=http://ctlog.ctlog-system.svc,public-key=$PKI_DIR/ctfe.pub,start-time=2024-01-01T00:00:00Z" \
  --out "$PKI_DIR/trusted_root.json"

# Wrong trusted root: replace the Rekor public key with a key that did not
# sign the entries. Used for negative tests.
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

# cosign_sign_keyless runs `cosign sign` with a freshly minted Kubernetes
# service-account token appended as --identity-token. cosign sends that token
# to Fulcio to obtain a signing certificate, so it is a bearer credential and
# must never reach the logs. If xtrace is active (detected via $-, which
# contains 'x' when `set -x` is on), the helper disables it while the token is
# in scope and restores it afterward, so the JWT is never traced. All
# arguments are forwarded verbatim to `cosign sign`.
cosign_sign_keyless() {
  local was_x=0
  case "$-" in *x*) was_x=1 ;; esac
  set +x
  local token rc=0
  token="$(kubectl create token default -n default --audience=sigstore)"
  cosign sign "$@" --identity-token="${token}" || rc=$?
  unset token
  [ "${was_x}" = 1 ] && set -x
  return "${rc}"
}

# --- Sign artifacts ---
#
# The "v2-style" cases below produce cosign v2-format signatures by passing
# --tlog-upload=false, --use-signing-config=false, and --new-bundle-format=false
# to a v3 cosign binary. These flags are deprecated in cosign v3 (the v3 CLI
# already prints a "Flag --tlog-upload has been deprecated" warning) and may
# be removed in a future cosign release. If that happens, rewrite the affected
# cases to drop the flags and use a transparency-log-less --signing-config
# instead, or replace them with v3-bundle equivalents.

echo "Run cosign v2-style key-pair tests"
push_artifact "$REG/test/v2-key:v1"
# DEPRECATED-FLAGS: --tlog-upload=false / --new-bundle-format=false
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
# DEPRECATED-FLAGS: --new-bundle-format=false
cosign_sign_keyless \
  --trusted-root="$PKI_DIR/trusted_root.json" \
  --fulcio-url="$FULCIO_URL" --rekor-url="$REKOR_URL" \
  --allow-insecure-registry --use-signing-config=false --new-bundle-format=false \
  --yes "$REG/test/v2-keyless:v1"

echo "Run cosign v3 bundle keyless tests"
push_artifact "$REG/test/v3-keyless:v1"
cosign_sign_keyless \
  --trusted-root="$PKI_DIR/trusted_root.json" \
  --fulcio-url="$FULCIO_URL" --rekor-url="$REKOR_URL" \
  --allow-insecure-registry --use-signing-config=false \
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
# DEPRECATED-FLAGS: --tlog-upload=false / --new-bundle-format=false
COSIGN_PASSWORD="" cosign sign --key="$KEYS_DIR/test.key" \
  --tlog-upload=false --use-signing-config=false --new-bundle-format=false \
  --allow-insecure-registry "$REG/test/authed:v1"

echo "Run registry:2 fallback tests"
push_artifact "$REG2/test/v3-key-fallback:v1"
COSIGN_PASSWORD="" cosign sign --key="$KEYS_DIR/test.key" \
  --signing-config="$KEYS_DIR/signing-config-notlog.json" \
  --allow-insecure-registry "$REG2/test/v3-key-fallback:v1"

push_artifact "$REG2/test/v3-keyless-fallback:v1"
cosign_sign_keyless \
  --trusted-root="$PKI_DIR/trusted_root.json" \
  --fulcio-url="$FULCIO_URL" --rekor-url="$REKOR_URL" \
  --allow-insecure-registry --use-signing-config=false \
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

# wait_ready logs before blocking on each OCIRepository so a hang names the
# object it is stuck on instead of stalling silently.
wait_ready() {
  local name="$1"
  echo ">>> waiting for ocirepository/${name} Ready (timeout 1m)"
  kubectl -n "$NS" wait "ocirepository/${name}" --for=condition=ready --timeout=1m
}

wait_ready test-v2-key
wait_ready test-v3-key
wait_ready test-v2-keyless
wait_ready test-v3-keyless
wait_ready test-v3-key-tlog
wait_ready test-combined
wait_ready test-authed
wait_ready test-v3-key-fallback
wait_ready test-v3-keyless-fallback
wait_ready test-v3-key-tlog-fallback

echo "Run negative verification tests"
kubectl -n "$NS" apply -f "${TESTDATA}/wrong-key.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/wrong-identity.yaml"
kubectl -n "$NS" apply -f "${TESTDATA}/wrong-rekor-key.yaml"

NEGATIVE_CASES=(
  test-wrong-key
  test-wrong-identity
  test-wrong-rekor
)

# Assert each negative case reaches Ready=False with reason VerificationError
# and never flips to Ready=True. A plain one-shot grep races reconciliation:
# an object that has not reconciled yet shows an empty reason (false pass) and
# an object that wrongly verifies later would be missed. Poll until each case
# reports the failure reason, treating Ready=True as an immediate hard failure.
assert_verification_error() {
  local name="$1"
  local deadline=$((SECONDS + 90))
  local ready reason
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    ready=$(kubectl -n "$NS" get ocirepository "${name}" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
    reason=$(kubectl -n "$NS" get ocirepository "${name}" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)
    if [ "${ready}" = "True" ]; then
      echo "FAIL: ${name} unexpectedly verified (Ready=True)" >&2
      return 1
    fi
    if [ "${ready}" = "False" ] && [ "${reason}" = "VerificationError" ]; then
      echo "  ok: ${name} rejected with VerificationError"
      return 0
    fi
    sleep 3
  done
  echo "FAIL: ${name} did not report VerificationError within 90s (ready=${ready:-<none>} reason=${reason:-<none>})" >&2
  return 1
}

for case in "${NEGATIVE_CASES[@]}"; do
  assert_verification_error "${case}"
done

echo "All sigstore verification tests passed!"
