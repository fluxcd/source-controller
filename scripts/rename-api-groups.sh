#!/usr/bin/env bash
#
# Renames the upstream Flux API groups to the Qdrant ones.
#
# Portable: works with bash 3.2+ (macOS) and bash 4+/5 (Linux), and with both
# BSD and GNU sed, so it can run on a developer laptop and on a CI runner.

set -euo pipefail

# Pairs of (pattern, replacement). The two arrays are index-aligned and applied
# in this order. Patterns are sed basic regular expressions.
patterns=(
    "source.toolkit.fluxcd.io"
    "domain: toolkit.fluxcd.io"
    "finalizers.fluxcd.io"
    "group: source"
    "shortName=gitrepo"
    "shortName=hc"
    "shortName=helmrepo"
    "shortName=ocirepo"
    "group: cd.toolkit.fluxcd.io"
)
replacements=(
    "cd.qdrant.io"
    "domain: qdrant.io"
    "finalizers.qdrant.io"
    "group: cd"
    "shortName=qdrantgitrepo"
    "shortName=qdranthc"
    "shortName=qdranthelmrepo"
    "shortName=qdrantocirepo"
    "group: cd.qdrant.io"
)

# Multiline fixes for the shortNames lists in CRDs: "from" and "to" are the list
# entries, the range limits the substitution to the shortNames block.
short_names_from=("gitrepo" "hc" "helmrepo" "ocirepo")
short_names_to=("qdrantgitrepo" "qdranthc" "qdranthelmrepo" "qdrantocirepo")

# A suffix that cannot collide with files tracked in the repository.
backup_suffix=".rename-api-groups.bak"

# sed_in_place EXPRESSION runs sed -i on every file the script rewrites.
# "-i<suffix>" (no space) is the one form accepted by both BSD and GNU sed. The
# backups are removed right after.
sed_in_place() {
    local expression=$1
    find . -type f \( -name '*.go' -o -name '*.yml' -o -name '*.yaml' -o -path './docs/*.md' -o -name 'PROJECT' \) \
        -not -path './.git/*' \
        -exec sed -i"${backup_suffix}" -e "${expression}" {} +
    find . -type f -name "*${backup_suffix}" -not -path './.git/*' -delete
}

replace_files_content() {
    local i
    for i in "${!patterns[@]}"; do
        echo "Renaming '${patterns[$i]}' to '${replacements[$i]}'"
        sed_in_place "s/${patterns[$i]}/${replacements[$i]}/g"
    done

    # special ones (multiline)
    for i in "${!short_names_from[@]}"; do
        sed_in_place "/shortNames:/,/^ *-/s/- ${short_names_from[$i]}/- ${short_names_to[$i]}/"
    done
}

copy_crd_base_files() {
    local old_pattern="source.toolkit.fluxcd.io"
    local new_pattern="cd.qdrant.io"
    local file new_filename
    for file in config/crd/bases/*.yaml; do
        new_filename="${file//${old_pattern}/${new_pattern}}"
        echo "Copying '$file' to '$new_filename'"
        cp "$file" "$new_filename" || true
    done
}

# For some reason in the original patch we were keeping the original files. We
# do the same here. We use git restore to undo the changes made by the call to
# `replace_files_content`.
restore_original_crd_base_files() {
    local files
    files=$(git ls-files -- 'config/crd/bases/source*')
    # The fork may have dropped the original files, then there is nothing to restore.
    if [ -n "$files" ]; then
        # shellcheck disable=SC2086 # file names in this directory have no spaces
        git restore -- $files
    fi
}

replace_files_content
copy_crd_base_files
restore_original_crd_base_files
