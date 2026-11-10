#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/install-shim.sh — install this bundle's upgrade shim as
# BOXMUNGE_ROOT/bin/boxmunge-upgrade. Run by install.sh.
#
# Refused, as the shim's own self-update refuses it (self_update_shim), when
# it fails `bash -n` or is the unbuilt source shim, which needs
# scripts/boxmunge-upgrade.d/ beside it and would refuse every command once in
# bin/. Written to a temporary file renamed into place: when the upgrade shim
# runs install.sh after its own self-update refused the bundle's shim,
# bin/boxmunge-upgrade is the running shim, and bash reads a script from its
# file as it goes, so copying over that inode would hand the running upgrade
# the new bytes part-way through. A temp left by a run killed before its
# rename is removed by the next run.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
src="$(cd "$(dirname "$0")/.." && pwd)/scripts/boxmunge-upgrade"
dest="${BOXMUNGE_ROOT}/bin/boxmunge-upgrade"
refuse() {
    echo "ERROR: ${src} $1, so this release cannot be installed; ${dest} is left as it was." \
         "Install another release." >&2
    exit 1
}
bash -n "${src}" || refuse "has syntax errors (see above)"
! grep -q '^# >>> boxmunge-upgrade.d:' "${src}" || refuse "is the unbuilt source shim"

rm -f "${BOXMUNGE_ROOT}/bin/.boxmunge-upgrade."*
tmp="$(mktemp "${BOXMUNGE_ROOT}/bin/.boxmunge-upgrade.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT
trap 'exit 1' INT TERM HUP
cp "${src}" "${tmp}"
chmod 755 "${tmp}"
mv -f "${tmp}" "${dest}"
