#!/usr/bin/env bash

set -euxo pipefail

IMG="${IMG:-}"
TAG="${TAG:-}"
IMG_TAG="${IMG}:${TAG}"

function extract(){
    PLATFORM=$1
    DIR=$2

    id=$(docker create --platform="${PLATFORM}" "${IMG_TAG}" sh)
    docker cp "${id}":/usr/local - > output.tar.gz
    docker rm -v "${id}"

    tar -xf output.tar.gz "local/${DIR}"
    rm output.tar.gz
}

function setup() {
    PLATFORM=$1
    DIR=$2

    extract "${PLATFORM}" "${DIR}"
   
    NEW_DIR="$(/bin/pwd)/build/libgit2/${TAG}"
    INSTALLED_DIR="/usr/local/${DIR}"

    mv "local/${DIR}" "${TAG}"
    rm -rf "local"
    mv "${TAG}/" "./build/libgit2"

    # Update the prefix paths included in the .pc files.
    # This will make it easier to update to the location in which they will be used.
    find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} sed -i "s;${INSTALLED_DIR};${NEW_DIR};g" {}
}

function setup_current() {
    if [ -d "./build/libgit2/${TAG}" ]; then
        echo "Skipping libgit2 setup as it already exists"
        exit 0
    fi

    mkdir -p "./build/libgit2"
    if [[ $OSTYPE == 'darwin'* ]]; then
        # For MacOS development environments, download the amd64 static libraries released from from golang-with-libgit2.
        curl -o output.tar.gz -LO "https://github.com/fluxcd/golang-with-libgit2/releases/download/${TAG}/darwin-libs.tar.gz"
       
        DIR=libgit2-darwin
        NEW_DIR="$(/bin/pwd)/build/libgit2/${TAG}"
        INSTALLED_DIR="/Users/runner/work/golang-with-libgit2/golang-with-libgit2/build/${DIR}-amd64"

        tar -xf output.tar.gz
        rm output.tar.gz
        mv "${DIR}" "${TAG}"
        mv "${TAG}/" "./build/libgit2"

        LIBGIT2_SED="s;-L/Applications/Xcode_.* ;;g"
        LIBGIT2PC="$(/bin/pwd)/build/libgit2/${TAG}/lib/pkgconfig/libgit2.pc"
        # Some macOS users may override their sed with gsed. If gsed is the PATH, use that instead.
        if command -v gsed &> /dev/null; then 
            # Removes abs path from build machine, and let iconv be resolved automatically by default search paths.
            gsed -i "${LIBGIT2_SED}" "${LIBGIT2PC}"

            # Update the prefix paths included in the .pc files.
            # This will make it easier to update to the location in which they will be used.
            # sed has a sight different behaviour in MacOS
            find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} gsed -i "s;${INSTALLED_DIR};${NEW_DIR};g" {}
        else
            # Removes abs path from build machine, and let iconv be resolved automatically by default search paths.
            sed -i "" "${LIBGIT2_SED}" "${LIBGIT2PC}"

            # Update the prefix paths included in the .pc files.
            # This will make it easier to update to the location in which they will be used.
            # sed has a sight different behaviour in MacOS
            find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} sed -i "" "s;${INSTALLED_DIR};${NEW_DIR};g" {}
        fi
    else
        # for linux development environments, use the static libraries from the official container images.
        DIR="x86_64-alpine-linux-musl"
        PLATFORM="linux/amd64"

        if [[ "$(uname -m)" == armv7* ]]; then 
            DIR="armv7-alpine-linux-musleabihf"
            PLATFORM="linux/arm/v7"
        elif [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
            DIR="aarch64-alpine-linux-musl"
            PLATFORM="linux/arm64"
        fi
        
        setup "${PLATFORM}" "${DIR}"
    fi
}

setup_current
