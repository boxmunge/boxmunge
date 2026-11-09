#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/venv-deps.sh <active|standby> — install this bundle's Python
# dependencies into a venv slot, only from its hash-pinned requirements files
# (covered by the release's signed SHA256SUMS). Run by install.sh.
#
#   active    env-active: a fresh install, or the installer re-run by hand
#   standby   the slot the upgrade shim running install.sh has just
#             installed this release into, and swaps to next (install.sh
#             --upgrade-shim, or a shim run-by-old-shim.sh recognises)
#
# Every file goes in, in one pip run; MCP always: it is how agents operate the
# box. The standby case exists because an upgrade is run by the box's current
# shim, not by this release's, and that shim installs only the requirements
# files it knows: up to 0.10.1, not requirements-mcp.txt, so the box came up
# without MCP. install.sh is this release's one step between that shim's venv
# build and its swap. For a later shim, which installs every file itself, pip
# finds nothing to do.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
BUNDLE="$(cd "$(dirname "$0")/.." && pwd)"
REQUIREMENTS=(requirements-build.txt requirements-tui.txt requirements-mcp.txt)

die() { echo "ERROR: venv-deps.sh: $*" >&2; exit 1; }

# standby_venv: the slot env-active does not point at, once it is shown to run
# this bundle's release. Anything else means the shim is not where this script
# assumes (between its venv build and its swap), and that slot may be the
# proven release a rollback needs, so it is not touched.
standby_venv() {
    local live venv want have
    live="$(readlink "$BOXMUNGE_ROOT/env-active")" || die "$BOXMUNGE_ROOT/env-active is not a symlink"
    case "$live" in
        "$BOXMUNGE_ROOT/env-a") venv="$BOXMUNGE_ROOT/env-b" ;;
        "$BOXMUNGE_ROOT/env-b") venv="$BOXMUNGE_ROOT/env-a" ;;
        *) die "$BOXMUNGE_ROOT/env-active points at '$live', not env-a or env-b" ;;
    esac
    want="$(sed -n 's/^version = "\([0-9]*\.[0-9]*\.[0-9]*\)"$/\1/p' "$BUNDLE/pyproject.toml")"
    [[ -n "$want" ]] || die "$BUNDLE/pyproject.toml has no X.Y.Z version"
    have="$("$venv/bin/boxmunge-server" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    [[ "$have" == "$want" ]] \
        || die "the standby slot $venv runs boxmunge '${have:-nothing}', not this bundle's $want; the upgrade shim runs install.sh --upgrade-shim after installing $want there and before swapping to it, so this slot is left alone"
    echo "$venv"
}

case "${1:-}" in
    active) venv="$BOXMUNGE_ROOT/env-active" ;;
    standby) venv="$(standby_venv)" ;;
    *) die "usage: venv-deps.sh <active|standby>" ;;
esac
args=()
for req in "${REQUIREMENTS[@]}"; do
    [[ -f "$BUNDLE/$req" ]] || die "the bundle has no hash-pinned $req; refusing an unpinned install"
    args+=(-r "$BUNDLE/$req")
done
echo "  Installing the hash-pinned dependencies into $venv"
# A pip failure (a network blip, a full disk) exits 75, so install.sh does
# too: a shim that blocklists a failed install.sh names the cause in the
# reason, system_upgrade_failed: install_sh_exit_75 (OPERATIONS.md).
"$venv/bin/pip" install --quiet --no-cache-dir --require-hashes "${args[@]}" || {
    echo "ERROR: venv-deps.sh: pip could not install the hash-pinned dependencies into $venv" >&2
    exit 75
}
