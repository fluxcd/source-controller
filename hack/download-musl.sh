#!/usr/bin/env bash

set -eoux pipefail

MUSL_X86_64_FILENAME=x86_64-linux-musl-native.tgz
MUSL_X86_64_SHA512=44d441ad9aa11a06feddf3daa4c9f53ad7d9ca37af1f5a61379aca07793703d179410cea723c1b7fca94c4de19a321228bdb3656bc5cbdb5e3bea8e2d6dac6c7
MUSL_AARCH64_FILENAME=aarch64-linux-musl-native.tgz
MUSL_AARCH64_SHA512=16d544e09845c9dbba50f29e0cb04dd661e17eb63c56acad6a67fd2a78aa7596b792477c7177d3cd56d408a27dc291a90507df882f2b099c0f25511ce08fd3b5

MUSL_FILENAME="${MUSL_X86_64_FILENAME}"
MUSL_SHA512="${MUSL_X86_64_SHA512}"
if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
    MUSL_FILENAME="${MUSL_AARCH64_FILENAME}"
    MUSL_SHA512="${MUSL_AARCH64_SHA512}"
fi

MUSL_AARCH64_URL="https://more.musl.cc/11.2.1/x86_64-linux-musl/${MUSL_FILENAME}"

ROOT_DIR="$(git rev-parse --show-toplevel)"
MUSL_DIR="${ROOT_DIR}/build/musl"

if [ ! -f "${MUSL_DIR}/bin" ]; then
    TARGET_FILE="${MUSL_DIR}/${MUSL_FILENAME}"
    mkdir -p "${MUSL_DIR}"

    echo "${MUSL_SHA512}  ${TARGET_FILE}"
    curl -o "${TARGET_FILE}" -LO "${MUSL_AARCH64_URL}"
    if ! echo "${MUSL_SHA512}  ${TARGET_FILE}" | sha512sum --check; then
        echo "Checksum failed for ${MUSL_FILENAME}."
        rm -rf "${MUSL_DIR}"
        exit 1
    fi

    tar xzf "${TARGET_FILE}" -C "${MUSL_DIR}"
    rm "${TARGET_FILE}"
fi
