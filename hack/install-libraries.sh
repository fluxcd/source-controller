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

    mkdir -p "./build/libgit2"

    mv "local/${DIR}" "${TAG}"
    rm -rf "local"
    mv "${TAG}/" "./build/libgit2"

    # Update the prefix paths included in the .pc files.
    # This will make it easier to update to the location in which they will be used.
    if [[ $OSTYPE == 'darwin'* ]]; then    
        # sed has a sight different behaviour in MacOS
        find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} sed -i "" "s;${INSTALLED_DIR};${NEW_DIR};g" {}
    else
        find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} sed -i "s;${INSTALLED_DIR};${NEW_DIR};g" {}
    fi
}

function setup_current() {
    if [ -d "./build/libgit2/${TAG}" ]; then
        echo "Skipping libgit2 setup as it already exists"
        exit 0
    fi

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
}

setup_current
