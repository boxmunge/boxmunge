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
# With --outside, the question turns around: whether the change touches any
# file NOT under the given paths. The heavy Docker jobs use it to skip a
# change made only of files they cannot read (the client, the version-check
# service, contributor docs), so a path nobody listed is always tested.
#
# Usage: scripts/ci-touches.sh [--outside] <base-sha> <path>...
# Exit status: 0 if touched (or not comparable), 1 if not, 2 on bad usage,
# and git's own status if git fails. Only 1 may skip the checks.
set -euo pipefail

outside=false
if [ "${1:-}" = --outside ]; then
    outside=true
    shift
fi
if [ $# -lt 2 ]; then
    echo "usage: $0 [--outside] <base-sha> <path>..." >&2
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
    listed=false
    for path in "$@"; do
        if [[ "${path}" == */ && "${file}" == "${path}"* ]] || [[ "${file}" == "${path}" ]]; then
            listed=true
            break
        fi
    done
    [[ "${listed}" == "${outside}" ]] || touched+=("${file}")
done <<< "${changed}"

if [[ ${#touched[@]} -eq 0 ]]; then
    if "${outside}"; then
        echo "nothing outside $* changed since ${fork:0:12}"
    else
        echo "none of $* changed since ${fork:0:12}"
    fi
    exit 1
fi
echo "changed since ${fork:0:12}: ${touched[*]}"
