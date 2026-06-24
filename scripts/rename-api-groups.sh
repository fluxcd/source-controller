#!/usr/bin/env bash

set -e

# Portable in-place sed flag: GNU sed (Linux) uses `-i`, while BSD/macOS sed
# requires an explicit (empty) backup suffix `-i ''`. Detect which one we have
# and build the flag as an array so it can be passed through xargs.
if sed --version >/dev/null 2>&1; then
    SEDI=(-i)
else
    SEDI=(-i '')
fi

declare -A replacements

replacements=(
    ["source.toolkit.fluxcd.io"]="cd.qdrant.io"
    ["domain: toolkit.fluxcd.io"]="domain: qdrant.io"
    ["finalizers.fluxcd.io"]="finalizers.qdrant.io"
    ["group: source"]="group: cd"
    ["shortName=gitrepo"]="shortName=qdrantgitrepo"
    ["shortName=hc"]="shortName=qdranthc"
    ["shortName=helmrepo"]="shortName=qdranthelmrepo"
    ["shortName=ocirepo"]="shortName=qdrantocirepo"
    ["group: cd.toolkit.fluxcd.io"]="group: cd.qdrant.io"
)

replace_files_content() {
    for pattern in "${!replacements[@]}"; do
        echo "Renaming '$pattern' to '${replacements[$pattern]}'"
        find . -type f \( -name '*.go' -o -name '*.yml' -o -name '*.yaml' -o -path './docs/*.md' -o -name 'PROJECT' \) | xargs sed "${SEDI[@]}" "s/$pattern/${replacements[$pattern]}/g"
    done

    # special ones (multiline)
    find . -type f \( -name '*.go' -o -name '*.yml' -o -name '*.yaml' -o -path './docs/*.md' -o -name 'PROJECT' \) | xargs sed "${SEDI[@]}" '/shortNames:/,/^ *-/s/- gitrepo/- qdrantgitrepo/'
    find . -type f \( -name '*.go' -o -name '*.yml' -o -name '*.yaml' -o -path './docs/*.md' -o -name 'PROJECT' \) | xargs sed "${SEDI[@]}" '/shortNames:/,/^ *-/s/- hc/- qdranthc/'
    find . -type f \( -name '*.go' -o -name '*.yml' -o -name '*.yaml' -o -path './docs/*.md' -o -name 'PROJECT' \) | xargs sed "${SEDI[@]}" '/shortNames:/,/^ *-/s/- helmrepo/- qdranthelmrepo/'
    find . -type f \( -name '*.go' -o -name '*.yml' -o -name '*.yaml' -o -path './docs/*.md' -o -name 'PROJECT' \) | xargs sed "${SEDI[@]}" '/shortNames:/,/^ *-/s/- ocirepo/- qdrantocirepo/'
}

copy_crd_base_files() {
    old_pattern="source.toolkit.fluxcd.io"
    new_pattern="cd.qdrant.io"
    for file in config/crd/bases/*.yaml; do
        new_filename=`echo $file | sed s/$old_pattern/$new_pattern/g`
        echo "Copying '$file' to '$new_filename'"
        cp $file $new_filename || true
    done
}

# For some reason in the original patch we were keeping the original files. We
# do the same here. We use git restore to undo the changes made by the call to
# `replace_files_content`.
restore_original_crd_base_files() {
    git restore config/crd/bases/source*
}

replace_files_content
copy_crd_base_files
restore_original_crd_base_files
