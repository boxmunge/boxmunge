#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/install-shim.sh — install this bundle's upgrade shim as
# BOXMUNGE_ROOT/bin/boxmunge-upgrade. Run by install.sh.
#
# Gated on `bash -n`, and written to a temporary file renamed into place: when
# the upgrade shim runs install.sh after its own self-update refused the
# bundle's shim, bin/boxmunge-upgrade is the running shim, and bash reads a
# script from its file as it goes, so copying over that inode would hand the
# running upgrade the new bytes part-way through.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
src="$(cd "$(dirname "$0")/.." && pwd)/scripts/boxmunge-upgrade"
dest="${BOXMUNGE_ROOT}/bin/boxmunge-upgrade"
if ! bash -n "${src}"; then
    echo "ERROR: ${src} has syntax errors (see above), so this release cannot be installed;" \
         "${dest} is left as it was. Install another release." >&2
    exit 1
fi
tmp="$(mktemp "${BOXMUNGE_ROOT}/bin/.boxmunge-upgrade.XXXXXX")"
cp "${src}" "${tmp}"
chmod 755 "${tmp}"
mv -f "${tmp}" "${dest}"
