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

LIBGIT2_TAG="${LIBGIT2_TAG:-v0.2.0}"
GOPATH="${GOPATH:-/root/go}"
GO_SRC="${GOPATH}/src"
PROJECT_PATH="github.com/fluxcd/source-controller"

pushd "${GO_SRC}/${PROJECT_PATH}"

export TARGET_DIR="$(/bin/pwd)/build/libgit2/${LIBGIT2_TAG}"

# For most cases, libgit2 will already be present.
# The exception being at the oss-fuzz integration.
if [ ! -d "${TARGET_DIR}" ]; then
    curl -o output.tar.gz -LO "https://github.com/fluxcd/golang-with-libgit2/releases/download/${LIBGIT2_TAG}/linux-x86_64-libgit2-only.tar.gz"

    DIR=linux-libgit2-only
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
export PKG_CONFIG_PATH="${TARGET_DIR}/lib/pkgconfig"
export CGO_LDFLAGS="$(pkg-config --libs --static --cflags libgit2)"
export LIBRARY_PATH="${TARGET_DIR}/lib"
export CGO_CFLAGS="-I${TARGET_DIR}/include"

go get -d github.com/AdaLogics/go-fuzz-headers

# The implementation of libgit2 is sensitive to the versions of git2go.
# Leaving it to its own devices, the minimum version of git2go used may not
# be compatible with the currently implemented version. Hence the modifications
# of the existing go.mod.
sed "s;\./api;$(/bin/pwd)/api;g" go.mod > tests/fuzz/go.mod
sed -i 's;module github.com/fluxcd/source-controller;module github.com/fluxcd/source-controller/tests/fuzz;g' tests/fuzz/go.mod
echo "replace github.com/fluxcd/source-controller => $(/bin/pwd)/" >> tests/fuzz/go.mod

cp go.sum tests/fuzz/go.sum

pushd "tests/fuzz"

go mod download

go get -d github.com/AdaLogics/go-fuzz-headers
go get -d github.com/fluxcd/source-controller

# Setup files to be embedded into controllers_fuzzer.go's testFiles variable.
mkdir -p testdata/crd
cp ../../config/crd/bases/*.yaml testdata/crd/
cp -r ../../controllers/testdata/certs testdata/

go get -d github.com/AdaLogics/go-fuzz-headers

# Using compile_go_fuzzer to compile fails when statically linking libgit2 dependencies
# via CFLAGS/CXXFLAGS.
function go_compile(){
    function=$1
    fuzzer=$2

    if [[ $SANITIZER = *coverage* ]]; then
        # ref: https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_go_fuzzer
        compile_go_fuzzer "${PROJECT_PATH}/tests/fuzz" "${function}" "${fuzzer}"
    else
        go-fuzz -tags gofuzz -func="${function}" -o "${fuzzer}.a" .
        ${CXX} ${CXXFLAGS} ${LIB_FUZZING_ENGINE} -o "${OUT}/${fuzzer}" \
            "${fuzzer}.a" "${TARGET_DIR}/lib/libgit2.a" \
            -fsanitize="${SANITIZER}"
    fi
}

go_compile FuzzRandomGitFiles fuzz_gitrepository_fuzzer
go_compile FuzzGitResourceObject fuzz_git_resource_object

# By now testdata is embedded in the binaries and no longer needed.
# Remove the dir given that it will be owned by root otherwise.
rm -rf testdata/

popd
popd
