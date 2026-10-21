#!/usr/bin/env bash
#
# Brings the latest upstream release of this fork into a local branch.
#
# It only touches the local repository: pushing the branch and opening the pull
# request is done by .github/workflows/sync-upstream.yaml.
#
# Usage:
#   scripts/sync-upstream.sh target [TAG]   Print the upstream tag to sync, or
#                                           "up-to-date" if there is nothing new.
#   scripts/sync-upstream.sh merge TAG      Create sync/upstream-TAG from the
#                                           current HEAD, merge TAG into it and
#                                           apply the Qdrant adaptations.
#
# Environment:
#   UPSTREAM_URL   Upstream repository (default: the fluxcd source-controller).
#   SKIP_TIDY      Set to a non-empty value to skip `make tidy`.
#   GITHUB_OUTPUT  When set (GitHub Actions), results are appended to it.
#
# "merge" always leaves a branch behind and reports one of these statuses:
#   merged    The merge was clean. Rename script and make tidy were applied.
#   conflict  The merge had conflicts. They are committed as-is (conflict
#             markers included) so that CI fails loudly on the pull request,
#             and the conflicting files are listed in $CONFLICTS_FILE.

set -euo pipefail

UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/fluxcd/source-controller.git}"
UPSTREAM_REFS="refs/upstream-tags"
CONFLICTS_FILE="${CONFLICTS_FILE:-.sync-upstream-conflicts}"

# Upstream stable releases only: vX.Y.Z. This skips pre-releases and the
# "api/vX.Y.Z" tags of the API module.
STABLE_TAG_REGEX='^v[0-9]+\.[0-9]+\.[0-9]+$'

output() {
    echo "$1=$2"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        echo "$1=$2" >> "$GITHUB_OUTPUT"
    fi
}

fetch_upstream_tags() {
    # Upstream tags go into their own namespace so they cannot clash with the
    # fork's own tags (vX.Y.Z-qdrant.N).
    git fetch --quiet --no-tags "$UPSTREAM_URL" "+refs/tags/*:${UPSTREAM_REFS}/*"
}

latest_stable_tag() {
    git for-each-ref --format='%(refname:strip=2)' "${UPSTREAM_REFS}/" \
        | grep -E "$STABLE_TAG_REGEX" \
        | sort -V \
        | tail -n 1
}

validate_tag() {
    if ! [[ $1 =~ $STABLE_TAG_REGEX ]]; then
        echo "error: '$1' is not a stable upstream release tag (expected vX.Y.Z)" >&2
        exit 2
    fi
    if ! git rev-parse --verify --quiet "${UPSTREAM_REFS}/$1" > /dev/null; then
        echo "error: upstream tag '$1' not found" >&2
        exit 2
    fi
}

cmd_target() {
    fetch_upstream_tags
    local tag=${1:-$(latest_stable_tag)}
    if [ -z "$tag" ]; then
        echo "error: no stable upstream release tags found at $UPSTREAM_URL" >&2
        exit 1
    fi
    validate_tag "$tag"

    if git merge-base --is-ancestor "${UPSTREAM_REFS}/${tag}" HEAD; then
        output status up-to-date
        output tag "$tag"
        return 0
    fi
    output status needs-sync
    output tag "$tag"
    output branch "sync/upstream-${tag}"
}

cmd_merge() {
    local tag=${1:?usage: sync-upstream.sh merge TAG}
    fetch_upstream_tags
    validate_tag "$tag"

    local branch="sync/upstream-${tag}"
    git checkout --quiet -b "$branch"

    output tag "$tag"
    output branch "$branch"

    if ! git merge --no-ff -m "Merge upstream tag ${tag}" "${UPSTREAM_REFS}/${tag}"; then
        git diff --name-only --diff-filter=U > "$CONFLICTS_FILE"
        # Commit the conflict markers on purpose: the pull request shows exactly
        # what needs resolving and CI cannot go green until someone does.
        git add --all -- . ":(exclude)${CONFLICTS_FILE}"
        git commit --quiet --no-verify -m "Merge upstream tag ${tag} (UNRESOLVED CONFLICTS)"
        output status conflict
        output conflicts_file "$CONFLICTS_FILE"
        return 0
    fi

    ./scripts/rename-api-groups.sh > /dev/null
    if [ -n "$(git status --porcelain)" ]; then
        git add --all
        git commit --quiet -m "chore: apply rename-api-groups.sh after merging ${tag}"
    fi

    if [ -z "${SKIP_TIDY:-}" ]; then
        # The project's own target: tidies the root and the api/ module.
        make tidy
        if [ -n "$(git status --porcelain)" ]; then
            git add --all
            git commit --quiet -m "chore: make tidy after merging ${tag}"
        fi
    fi

    output status merged
}

case "${1:-}" in
    target) shift; cmd_target "$@" ;;
    merge)  shift; cmd_merge "$@" ;;
    *)
        sed -n '3,25p' "$0" >&2
        exit 2
        ;;
esac
