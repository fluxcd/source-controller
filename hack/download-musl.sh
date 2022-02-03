#!/usr/bin/env bash

set -eoux pipefail

MUSL_X86_64_FILENAME=x86_64-linux-musl-native.tgz
MUSL_X86_64_SHA512=44d441ad9aa11a06feddf3daa4c9f53ad7d9ca37af1f5a61379aca07793703d179410cea723c1b7fca94c4de19a321228bdb3656bc5cbdb5e3bea8e2d6dac6c7
MUSL_AARCH64_FILENAME=aarch64-linux-musl-native.tgz
MUSL_AARCH64_SHA512=16d544e09845c9dbba50f29e0cb04dd661e17eb63c56acad6a67fd2a78aa7596b792477c7177d3cd56d408a27dc291a90507df882f2b099c0f25511ce08fd3b5
MUSL_XX86_64_FILENAME=x86_64-linux-musl-cross.tgz
MUSL_XX86_64_SHA512=52abd1a56e670952116e35d1a62e048a9b6160471d988e16fa0e1611923dd108a581d2e00874af5eb04e4968b1ba32e0eb449a1f15c3e4d5240ebe09caf5a9f3
MUSL_XAARCH64_FILENAME=aarch64-linux-musl-cross.tgz
MUSL_XAARCH64_SHA512=8695ff86979cdf30fbbcd33061711f5b1ebc3c48a87822b9ca56cde6d3a22abd4dab30fdcd1789ac27c6febbaeb9e5bde59d79d66552fae53d54cc1377a19272
MUSL_XARMV7_FILENAME=armv7l-linux-musleabihf-cross.tgz
MUSL_XARMV7_SHA512=1bb399a61da425faac521df9b8d303e60ad101f6c7827469e0b4bc685ce1f3dedc606ac7b1e8e34d79f762a3bfe3e8ab479a97e97d9f36fbd9fc5dc9d7ed6fd1

TARGET_ARCH="${TARGET_ARCH:-$(uname -m)}"
ENV_FILE="${ENV_FILE:-false}"

MUSL_FILENAME=""
MUSL_SHA512=""

ROOT_DIR="${ROOT_DIR:-$(git rev-parse --show-toplevel)}"
MUSL_DIR="${ROOT_DIR}/build/musl"


if [ "${TARGET_ARCH}" = "$(uname -m)" ]; then
    MUSL_FILENAME="${MUSL_X86_64_FILENAME}"
    MUSL_SHA512="${MUSL_X86_64_SHA512}"
    MUSL_PREFIX="${TARGET_ARCH}-linux-musl-native/bin/${TARGET_ARCH}-linux-musl"
    if [ "${TARGET_ARCH}" = "arm64" ] || [ "${TARGET_ARCH}" = "aarch64" ]; then
        MUSL_FILENAME="${MUSL_AARCH64_FILENAME}"
        MUSL_SHA512="${MUSL_AARCH64_SHA512}"
    fi
else
    MUSL_FILENAME="${MUSL_XX86_64_FILENAME}"
    MUSL_SHA512="${MUSL_XX86_64_SHA512}"
    MUSL_PREFIX="${TARGET_ARCH}-linux-musl-cross/bin/${TARGET_ARCH}-linux-musl"
    if [ "${TARGET_ARCH}" = "arm64" ] || [ "${TARGET_ARCH}" = "aarch64" ]; then
        MUSL_FILENAME="${MUSL_XAARCH64_FILENAME}"
        MUSL_SHA512="${MUSL_XAARCH64_SHA512}"
    elif [ "${TARGET_ARCH}" = "arm" ] || [ "${TARGET_ARCH}" = "armv7" ]; then
        MUSL_FILENAME="${MUSL_XARMV7_FILENAME}"
        MUSL_SHA512="${MUSL_XARMV7_SHA512}"
        MUSL_PREFIX=armv7l-linux-musleabihf-cross/bin/armv7l-linux-musleabihf
    fi
fi

mkdir -p "${MUSL_DIR}"

if "${ENV_FILE}"; then
    cat<<EOF > "${MUSL_DIR}/${TARGET_ARCH}.env"
CC="$(pwd)/build/musl/${MUSL_PREFIX}-gcc"
CXX="$(pwd)/build/musl/${MUSL_PREFIX}-g++"
AR="$(pwd)/build/musl/${MUSL_PREFIX}-ar"
EOF
fi

MUSL_AARCH64_URL="https://more.musl.cc/11.2.1/x86_64-linux-musl/${MUSL_FILENAME}"

if [ ! -f "${MUSL_DIR}/bin" ]; then
    TARGET_FILE="${MUSL_DIR}/${MUSL_FILENAME}"
    curl -o "${TARGET_FILE}" -LO "${MUSL_AARCH64_URL}"
    if ! echo "${MUSL_SHA512}  ${TARGET_FILE}" | sha512sum; then
        echo "Checksum failed for ${MUSL_FILENAME}."
        rm -rf "${MUSL_DIR}"
        exit 1
    fi

    tar xzf "${TARGET_FILE}" -C "${MUSL_DIR}"
    rm "${TARGET_FILE}"
fi
