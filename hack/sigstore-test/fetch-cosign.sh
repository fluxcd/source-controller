#!/usr/bin/env bash
# Fetch cosign v2 and v3 binaries for testing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"
mkdir -p "${BIN_DIR}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "unsupported arch: ${ARCH}"; exit 1 ;;
esac

# cosign v3 (latest)
COSIGN_V3_VERSION="${COSIGN_V3_VERSION:-v3.0.6}"
COSIGN_V3_URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_V3_VERSION}/cosign-${OS}-${ARCH}"

# cosign v2 (last v2 release)
COSIGN_V2_VERSION="${COSIGN_V2_VERSION:-v2.4.3}"
COSIGN_V2_URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_V2_VERSION}/cosign-${OS}-${ARCH}"

fetch_binary() {
  local name="$1" url="$2" dest="$3"
  if [ -f "${dest}" ]; then
    echo ">>> ${name} already exists at ${dest}"
  else
    echo ">>> downloading ${name} from ${url}"
    curl -fSL -o "${dest}" "${url}"
    chmod +x "${dest}"
  fi
  "${dest}" version 2>&1 | head -3
  echo ""
}

fetch_binary "cosign-v3" "${COSIGN_V3_URL}" "${BIN_DIR}/cosign-v3"
fetch_binary "cosign-v2" "${COSIGN_V2_URL}" "${BIN_DIR}/cosign-v2"

echo "=== Cosign binaries ready ==="
echo "  v2: ${BIN_DIR}/cosign-v2"
echo "  v3: ${BIN_DIR}/cosign-v3"
