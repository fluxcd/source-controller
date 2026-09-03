#!/usr/bin/env bash
# Fetch a cosign v3 binary for the local sigstore test harness.
#
# CI guidance: when running this harness from a GitHub Actions workflow, do
# NOT run this script. Install cosign with the official action instead, which
# puts `cosign` on PATH where test-signing.sh expects it:
#
#     - uses: sigstore/cosign-installer@v3
#
# sigstore/cosign-installer only accepts `cosign-release`, `install-dir`, and
# `use-sudo` inputs. Each released version of the action hardcodes a default
# `cosign-release` (v3.0.6 at time of writing), so letting dependabot's
# github-actions ecosystem bump the action ref is what advances cosign. Avoid
# pinning `cosign-release:` unless you need a specific version, because
# dependabot does not edit `with:` input values.
#
# This script is a local-dev fallback that downloads cosign directly from
# GitHub releases. If a `cosign` (or `cosign-v3`) is already on PATH the
# download is skipped and the on-PATH binary is symlinked into ./bin.
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

# cosign v3 (latest). Update via dependabot when invoked from CI through
# sigstore/cosign-installer.
COSIGN_V3_VERSION="${COSIGN_V3_VERSION:-v3.0.6}"
COSIGN_V3_URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_V3_VERSION}/cosign-${OS}-${ARCH}"

# fetch_binary stages a binary at ${dest} unless one of the following is true:
#  - a binary named like ${dest} (or one of the extra PATH aliases in $4..) is
#    already on PATH (e.g. `cosign` installed by sigstore/cosign-installer)
#  - the file already exists (cached local copy)
# In the on-PATH cases the binary is symlinked into ./bin rather than fetched.
fetch_binary() {
  local name="$1" url="$2" dest="$3"
  shift 3
  local candidates=("$(basename "${dest}")" "$@")
  local on_path=""
  local c
  for c in "${candidates[@]}"; do
    on_path="$(command -v "${c}" || true)"
    if [ -n "${on_path}" ] && [ "${on_path}" != "${dest}" ]; then
      echo ">>> ${name} satisfied by '${c}' on PATH at ${on_path}; skipping download"
      ln -sf "${on_path}" "${dest}"
      break
    fi
    on_path=""
  done
  if [ -z "${on_path}" ]; then
    if [ -f "${dest}" ]; then
      echo ">>> ${name} already exists at ${dest}"
    else
      echo ">>> downloading ${name} from ${url}"
      curl -fSL -o "${dest}" "${url}"
      chmod +x "${dest}"
    fi
  fi
  "${dest}" version 2>&1 | head -3
  echo ""
}

# v3 is also satisfied by a plain `cosign` on PATH, which is what
# sigstore/cosign-installer provides.
fetch_binary "cosign-v3" "${COSIGN_V3_URL}" "${BIN_DIR}/cosign-v3" cosign

echo "=== Cosign binary ready ==="
echo "  v3: ${BIN_DIR}/cosign-v3"
