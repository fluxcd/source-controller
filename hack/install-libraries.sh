#!/usr/bin/env bash

set -euxo pipefail

IMG="${IMG:-}"
TAG="${TAG:-}"
IMG_TAG="${IMG}:${TAG}"
DOWNLOAD_URL="https://github.com/fluxcd/golang-with-libgit2/releases/download/${TAG}"

TMP_DIR=$(mktemp -d)

function cleanup(){
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

fatal() {
    echo '[ERROR] ' "$@" >&2
    exit 1
}

download() {
    [[ $# -eq 2 ]] || fatal 'download needs exactly 2 arguments'

    curl -o "$1" -sfL "$2"

    [[ $? -eq 0 ]] || fatal 'Download failed'
}

download_files() {
    [[ $# -eq 1 ]] || fatal 'download_files needs exactly 1 arguments'

    FILE_NAMES="checksums.txt checksums.txt.sig checksums.txt.pem $1"

    for FILE_NAME in ${FILE_NAMES}; do
        download "${TMP_DIR}/${FILE_NAME}" "${DOWNLOAD_URL}/${FILE_NAME}"
    done    
}

cosign_verify(){
    [[ $# -eq 3 ]] || fatal 'cosign_verify needs exactly 3 arguments'

    cosign verify-blob --cert "$1" --signature "$2" "$3"
    
    [[ $? -eq 0 ]] || fatal 'signature verification failed'
}

assure_provenance() {
    [[ $# -eq 1 ]] || fatal 'assure_provenance needs exactly 1 arguments'

    cosign_verify "${TMP_DIR}/checksums.txt.pem" \
                  "${TMP_DIR}/checksums.txt.sig" \
                  "${TMP_DIR}/checksums.txt"

    pushd "${TMP_DIR}" || exit
    if command -v sha256sum; then
        grep "$1" "checksums.txt" | sha256sum --check
    else
        grep "$1" "checksums.txt" | shasum -a 256 --check
    fi
    popd || exit
        
    [[ $? -eq 0 ]] || fatal 'integrity verification failed'
}

extract_libraries(){
    [[ $# -eq 2 ]] || fatal 'extract_libraries needs exactly 2 arguments'

    tar -xf "${TMP_DIR}/$1"

    rm "${TMP_DIR}/$1"
    mv "${2}" "${TAG}"
    mv "${TAG}/" "./build/libgit2"
}

fix_pkgconfigs(){
    NEW_DIR="$(/bin/pwd)/build/libgit2/${TAG}"

    # Update the prefix paths included in the .pc files.
    if [[ $OSTYPE == 'darwin'* ]]; then
        # https://github.com/fluxcd/golang-with-libgit2/blob/v0.1.4/.github/workflows/release.yaml#L158
        INSTALLED_DIR="/Users/runner/work/golang-with-libgit2/golang-with-libgit2/build/darwin-libgit2-only"

        # This will make it easier to update to the location in which they will be used.
        # sed has a sight different behaviour in MacOS
        # NB: Some macOS users may override their sed with gsed. If gsed is the PATH, use that instead.
        if command -v gsed &> /dev/null; then 
            find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} gsed -i "s;${INSTALLED_DIR};${NEW_DIR};g" {}
        else
            find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} sed -i "" "s;${INSTALLED_DIR};${NEW_DIR};g" {}
        fi
    else
        # https://github.com/fluxcd/golang-with-libgit2/blob/v0.1.4/.github/workflows/release.yaml#L52
        INSTALLED_DIR="/home/runner/work/golang-with-libgit2/golang-with-libgit2/build/build_libgit2_only"
    
        find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} sed -i "s;${INSTALLED_DIR};${NEW_DIR};g" {}
    fi
}

extract_from_image(){
    PLATFORM=$1
    DIR=$2

    id=$(docker create --platform="${PLATFORM}" "${IMG_TAG}" sh)
    docker cp "${id}":/usr/local - > output.tar.gz
    docker rm -v "${id}"

    tar -xf output.tar.gz "local/${DIR}"
    rm output.tar.gz

    NEW_DIR="$(/bin/pwd)/build/libgit2/${TAG}"
    INSTALLED_DIR="/usr/local/${DIR}"

    mv "local/${DIR}" "${TAG}"
    rm -rf "local"
    mv "${TAG}/" "./build/libgit2"

    # Update the prefix paths included in the .pc files.
    # This will make it easier to update to the location in which they will be used.
    find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} sed -i "s;${INSTALLED_DIR};${NEW_DIR};g" {}
}

install_libraries(){
    if [ -d "./build/libgit2/${TAG}" ]; then
        echo "Skipping: libgit2 ${TAG} already installed"
        exit 0
    fi

    mkdir -p "./build/libgit2"

    # Linux ARM support is still based on the container image libraries.
    if [[ $OSTYPE == 'linux'* ]]; then
        if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
            extract_from_image "linux/arm64" "aarch64-alpine-linux-musl"
            fix_pkgconfigs "aarch64-alpine-linux-musl"
            exit 0
        fi
    fi

    FILE_NAME="linux-$(uname -m)-libgit2-only.tar.gz"
    DIR="linux-libgit2-only"
    if [[ $OSTYPE == 'darwin'* ]]; then
        FILE_NAME="darwin-libgit2-only.tar.gz"
        DIR="darwin-libgit2-only"
    fi

    download_files "${FILE_NAME}"
    assure_provenance "${FILE_NAME}"
    extract_libraries "${FILE_NAME}" "${DIR}"
    fix_pkgconfigs
}

install_libraries
