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

# This file is executed by upstream oss-fuzz after its building process.
# Use it for unsetting any environment variables that may impact other building
# processes.

if [[ -n "${PRE_LIB_FUZZING_ENGINE}" ]]; then
	export LIB_FUZZING_ENGINE="${PRE_LIB_FUZZING_ENGINE}"
fi

unset TARGET_DIR
unset CGO_ENABLED
unset LIBRARY_PATH
unset PKG_CONFIG_PATH
unset CGO_CFLAGS
unset CGO_LDFLAGS
unset PRE_LIB_FUZZING_ENGINE
