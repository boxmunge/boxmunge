#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# CI's lock-install guard: install every server lock file, hash-checked, into
# a fresh venv of each given Python, and run nothing. The locks are compiled
# on 3.13 (where the unit job installs them), so a dependency that a marker
# keeps below 3.13 is silently missing from them, and they then fail on the
# server's 3.11 floor; CI runs this on 3.11 and 3.12.
#
# The box set goes in one pip call, as the upgrade shim installs a slot
# (requirements.txt is the base of -tui and -mcp), so conflicting pins fail
# here too; requirements-dev.txt goes on top, as CI and contributors install
# it. A second pip call replaces a pin from the first without a word, so
# `pip check` runs last: a dev pin below a box package's floor fails here,
# not in a test that imports the downgraded package.
#
# Usage: scripts/ci-lock-install.sh <python>...
set -euo pipefail

BOX=(requirements.txt requirements-build.txt requirements-tui.txt requirements-mcp.txt)
DEV=(requirements-dev.txt)

if [[ $# -eq 0 ]]; then
    echo "usage: $0 <python>..." >&2
    exit 2
fi
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

box=() dev=()
for req in "${BOX[@]}"; do box+=(-r "$req"); done
for req in "${DEV[@]}"; do dev+=(-r "$req"); done
for python in "$@"; do
    venv="$work/$(basename "$python")"
    "$python" -m venv "$venv"
    pip=("$venv/bin/pip" install --quiet --disable-pip-version-check --no-cache-dir
         --require-hashes)
    "${pip[@]}" "${box[@]}"
    "${pip[@]}" "${dev[@]}"
    "$venv/bin/pip" check
    echo "$python: ${BOX[*]} ${DEV[*]} install and pip check"
done
