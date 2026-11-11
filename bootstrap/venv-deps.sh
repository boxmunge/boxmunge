#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/venv-deps.sh — install this bundle's Python dependencies into
# env-active, only from its hash-pinned requirements files (covered by the
# release's signed SHA256SUMS). Run by install.sh on a fresh install or a
# re-run by hand; an upgrade's venv is built by the shim (install_pinned_deps
# in scripts/boxmunge-upgrade.d/release.sh), from the same files.
#
# Every file goes in, in one pip run; MCP always: it is how agents operate the
# box.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
BUNDLE="$(cd "$(dirname "$0")/.." && pwd)"
REQUIREMENTS=(requirements-build.txt requirements-tui.txt requirements-mcp.txt)

die() { echo "ERROR: venv-deps.sh: $*" >&2; exit 1; }

venv="$BOXMUNGE_ROOT/env-active"
args=()
for req in "${REQUIREMENTS[@]}"; do
    [[ -f "$BUNDLE/$req" ]] || die "the bundle has no hash-pinned $req; refusing an unpinned install"
    args+=(-r "$BUNDLE/$req")
done
echo "  Installing the hash-pinned dependencies into $venv"
"$venv/bin/pip" install --quiet --no-cache-dir --require-hashes "${args[@]}" \
    || die "pip could not install the hash-pinned dependencies into $venv"
