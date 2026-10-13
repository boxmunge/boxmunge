#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Verify that every non-merge commit in BASE..HEAD carries a Developer
# Certificate of Origin sign-off (`Signed-off-by:` trailer, added by
# `git commit -s`) whose email matches the commit author's email.
#
# Commits authored by GitHub bots (e.g. Dependabot) are exempt: a bot cannot
# certify origin, and its changes are reviewed by a maintainer before merge.
#
# Usage: scripts/check-dco.sh <base-sha> <head-sha>
# Exit status: 0 if every commit is signed off, 1 otherwise, 2 on bad usage.
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <base-sha> <head-sha>" >&2
    exit 2
fi
base="$1"
head="$2"

failures=0
checked=0
while IFS=$'\t' read -r sha author_email; do
    [ -n "$sha" ] || continue
    checked=$((checked + 1))
    case "$author_email" in
        *"[bot]@users.noreply.github.com")
            echo "skip  ${sha:0:12} (bot author ${author_email})"
            continue
            ;;
    esac
    signoffs=$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha")
    author_lc=$(printf '%s' "$author_email" | tr '[:upper:]' '[:lower:]')
    if printf '%s\n' "$signoffs" | tr '[:upper:]' '[:lower:]' | grep -qF "<${author_lc}>"; then
        echo "ok    ${sha:0:12}"
    else
        echo "FAIL  ${sha:0:12} has no 'Signed-off-by:' trailer for <${author_email}>" >&2
        failures=$((failures + 1))
    fi
done < <(git log --no-merges --format='%H%x09%ae' "${base}..${head}")

if [ "$checked" -eq 0 ]; then
    echo "ERROR: no commits found in ${base}..${head}" >&2
    exit 1
fi
if [ "$failures" -gt 0 ]; then
    cat >&2 <<MSG

${failures} commit(s) are missing a DCO sign-off.
boxmunge requires every commit to be signed off (see CONTRIBUTING.md).
To fix the commits on your branch:

    git rebase --signoff ${base:0:12}
    git push --force-with-lease
MSG
    exit 1
fi
echo "All ${checked} commit(s) signed off."
