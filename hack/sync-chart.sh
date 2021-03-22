#! /usr/bin/env sh

# Copyright 2020, 2021 The Flux authors. All rights reserved.
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

set -e

__print_header() {
    printf 'apiVersion: {{ include "source-controller.rbac.apiVersion" . }}\n'
    printf 'kind: %s\n' "$1"
    printf 'metadata:\n'
    printf '  name: {{ include "source-controller.rbac.fullname" . }}:%s\n' "$2"
    printf '  labels:\n'
    printf '    {{- include "source-controller.labels" . | nindent 4 }}\n'
}

__sync_crds() {
    # remove existing crds
    rm -rf chart/crds

    # copy crds from config
    cp -R config/crd/bases chart/crds
}

__sync_clusterroles() {
    # remove existing roles
    rm -f chart/templates/*_clusterrole.yaml chart/templates/clusterrole.yaml
    role="./config/rbac/role.yaml"

    find config/rbac -type f -name '*_role.yaml' -or -name 'role.yaml' | while IFS= read -r role; do
        kind=$(yq e '.kind' "$role" | tr '[:upper:]' '[:lower:]')

        if test "${kind:-'role'}" = "role"; then
            continue
        fi

        basename=$(basename "$role")
        filename=${basename##*.yaml}
        filename=${basename%role*}
        filename=${filename}clusterrole.yaml

        name=$(yq e '.metadata.name' "$role")
        name=${name%-role*}

        {
            printf '{{- if and .Values.rbac.create .Values.watchAllNamespaces -}}\n'
            __print_header "ClusterRole" "$name"
            yq e '.rules | { "rules": . }' "$role"
            printf '{{- end }}\n'
        } > "chart/templates/${filename}"
    done
}

__sync_roles() {
    # remove existing roles
    rm -f chart/templates/*_role.yaml chart/templates/role.yaml

    find config/rbac -type f -name '*_role.yaml' -or -name 'role.yaml' | while IFS= read -r role; do
        basename=$(basename "$role")
        filename=${basename##*.yaml}
        filename=${basename%role*}
        filename=${filename}role.yaml

        name=$(yq e '.metadata.name' "$role")
        name=${name%-role*}

        {
            if test "$name" = "leader-election"; then
                printf '{{- if and .Values.rbac.create -}}\n'
            else
                printf '{{- if and .Values.rbac.create (not .Values.watchAllNamespaces) -}}\n'
            fi
            __print_header "Role" "$name"
            yq e '.rules | { "rules": . }' "$role"
            printf '{{- end }}\n'
        } > "chart/templates/${filename}"
    done
}

__sync_crds
__sync_clusterroles
__sync_roles
