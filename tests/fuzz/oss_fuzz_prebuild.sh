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

# This file is executed by upstream oss-fuzz for any requirements that
# are specific for building this project.

# Some tests requires embedded resources. Embedding does not allow
# for traversing into ascending dirs, therefore we copy those contents here:
mkdir -p controllers/testdata/crd
cp config/crd/bases/*.yaml controllers/testdata/crd/

# libgit2, cmake and pkg-config are requirements to support libgit2.
LIBGIT2_TAG="${LIBGIT2_TAG:-v0.4.0}"

# Avoid updating apt get and installing dependencies, if they are already in place.
if (! command -v cmake &> /dev/null) || (! command -v pkg-config &> /dev/null) then
    apt-get update && apt-get install -y cmake pkg-config
fi

export TARGET_DIR="$(/bin/pwd)/build/libgit2/${LIBGIT2_TAG}"

# For most cases, libgit2 will already be present.
# The exception being at the oss-fuzz integration.
if [ ! -d "${TARGET_DIR}" ]; then
    curl --connect-timeout 2 --retry 3 --retry-delay 1 --retry-max-time 30 \
        -o output.tar.gz -LO "https://github.com/fluxcd/golang-with-libgit2/releases/download/${LIBGIT2_TAG}/linux-$(uname -m)-libgit2-only.tar.gz"

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

export CGO_ENABLED=1
export LIBRARY_PATH="${TARGET_DIR}/lib"
export PKG_CONFIG_PATH="${TARGET_DIR}/lib/pkgconfig"
export CGO_CFLAGS="-I${TARGET_DIR}/include"
export CGO_LDFLAGS="$(pkg-config --libs --static --cflags libgit2)"

# Temporary hack whilst libgit2 is still in use.
# Enables the fuzzing compilation to link libgit2.
#
# After building the fuzzers, the value of
# LIB_FUZZING_ENGINE is reset to what it was before
# it to avoid side effects onto other repositories.
#
# For context refer to:
# https://github.com/google/oss-fuzz/pull/9063
export PRE_LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE}"

export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE} -Wl,--start-group ${TARGET_DIR}/lib/libgit2.a"
