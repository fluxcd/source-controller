#!/usr/bin/env bash

# Copyright 2022 The Flux authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euxo pipefail

LIBGIT2_TAG="${LIBGIT2_TAG:-libgit2-1.1.1-7}"
GOPATH="${GOPATH:-/root/go}"
GO_SRC="${GOPATH}/src"
PROJECT_PATH="github.com/fluxcd/source-controller"

cd "${GO_SRC}"

pushd "${PROJECT_PATH}"

export TARGET_DIR="$(/bin/pwd)/build/libgit2/${LIBGIT2_TAG}"

# For most cases, libgit2 will already be present. 
# The exception being at the oss-fuzz integration.
if [ ! -d "${TARGET_DIR}" ]; then
    curl -o output.tar.gz -LO "https://github.com/fluxcd/golang-with-libgit2/releases/download/${LIBGIT2_TAG}/linux-$(uname -m)-libs.tar.gz"
    
    DIR=libgit2-linux
    NEW_DIR="$(/bin/pwd)/build/libgit2/${LIBGIT2_TAG}"
    INSTALLED_DIR="/home/runner/work/golang-with-libgit2/golang-with-libgit2/build/${DIR}"

    mkdir -p ./build/libgit2

    tar -xf output.tar.gz
    rm output.tar.gz
    mv "${DIR}" "${LIBGIT2_TAG}"
    mv "${LIBGIT2_TAG}/" "./build/libgit2"

    # Update the prefix paths included in the .pc files.
    # This will make it easier to update to the location in which they will be used.
    find "${NEW_DIR}" -type f -name "*.pc" | xargs -I {} sed -i "s;${INSTALLED_DIR};${NEW_DIR};g" {}
fi

apt-get update && apt-get install -y pkg-config

export CGO_ENABLED=1
export LIBRARY_PATH="${TARGET_DIR}/lib:${TARGET_DIR}/lib64"
export PKG_CONFIG_PATH="${TARGET_DIR}/lib/pkgconfig:${TARGET_DIR}/lib64/pkgconfig"
export CGO_CFLAGS="-I${TARGET_DIR}/include -I${TARGET_DIR}/include/openssl"
export CGO_LDFLAGS="$(pkg-config --libs --static --cflags libssh2 openssl libgit2)"

go mod tidy -compat=1.17

popd

pushd "${PROJECT_PATH}/tests/fuzz"

# Setup files to be embedded into controllers_fuzzer.go's testFiles variable.
mkdir -p testdata/crd
cp ../../config/crd/bases/*.yaml testdata/crd/
cp -r ../../controllers/testdata/certs testdata/

go mod tidy -compat=1.17

# ref: https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_go_fuzzer
go-fuzz -tags gofuzz -func=FuzzRandomGitFiles -o gitrepository_fuzzer.a .
clang -o /out/fuzz_random_git_files \
    gitrepository_fuzzer.a \
    "${TARGET_DIR}/lib/libgit2.a" \
    "${TARGET_DIR}/lib/libssh2.a" \
    "${TARGET_DIR}/lib/libz.a" \
    "${TARGET_DIR}/lib64/libssl.a" \
    "${TARGET_DIR}/lib64/libcrypto.a" \
    -fsanitize=fuzzer

go-fuzz -tags gofuzz -func=FuzzGitResourceObject -o fuzz_git_resource_object.a .
clang -o /out/fuzz_git_resource_object \
    fuzz_git_resource_object.a \
    "${TARGET_DIR}/lib/libgit2.a" \
    "${TARGET_DIR}/lib/libssh2.a" \
    "${TARGET_DIR}/lib/libz.a" \
    "${TARGET_DIR}/lib64/libssl.a" \
    "${TARGET_DIR}/lib64/libcrypto.a" \
    -fsanitize=fuzzer

# By now testdata is embedded in the binaries and no longer needed.
rm -rf testdata/

popd
