#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Whether the checked-out change touches any of the given paths: files changed
# between the merge base of <base-sha> and HEAD, and HEAD. A path ending in /
# matches everything under it; any other path matches that file only. CI's
# arm64 job uses it to decide whether to do its work: the job itself always
# runs, so its required check always reports.
#
# <base-sha> is the pull request's base, or the commit before a push. When it
# is empty, all zeros (a new branch) or not in the clone, the change cannot
# be compared and is treated as touching the paths, so the work is done.
#
# Usage: scripts/ci-touches.sh <base-sha> <path>...
# Exit status: 0 if touched (or not comparable), 1 if not, 2 on bad usage,
# and git's own status if git fails. Only 1 may skip the checks.
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 <base-sha> <path>..." >&2
    exit 2
fi
base="$1"
shift

if [[ -z "${base}" || "${base}" =~ ^0+$ ]] \
        || ! fork="$(git merge-base "${base}" HEAD 2>/dev/null)"; then
    echo "cannot compare with base '${base}' (new branch, or not in this clone): treating the change as relevant"
    exit 0
fi

# A plain assignment, so a failing git diff stops the script (set -e) with
# its own status, never the "not touched" exit 1.
changed="$(git diff --name-only "${fork}" HEAD)"
touched=()
while IFS= read -r file; do
    [[ -n "${file}" ]] || continue
    for path in "$@"; do
        if [[ "${path}" == */ && "${file}" == "${path}"* ]] || [[ "${file}" == "${path}" ]]; then
            touched+=("${file}")
            break
        fi
    done
done <<< "${changed}"

if [[ ${#touched[@]} -eq 0 ]]; then
    echo "none of $* changed since ${fork:0:12}"
    exit 1
fi
echo "changed since ${fork:0:12}: ${touched[*]}"
