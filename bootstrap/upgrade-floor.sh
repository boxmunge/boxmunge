#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/upgrade-floor.sh: refuse to install this release over a boxmunge
# older than the upgrade floor. Run by install.sh before it changes anything.
#
# The floor is what let this release drop the code that carried older installs
# forward, so it must not run over one. An upgrade shim is refused earlier, in
# its pre-flight, by src/boxmunge/upgrade_floor.py, which states the same floor
# and bridge release (tests/test_upgrade_floor.py holds the two together). This
# is that check for install.sh run by hand on an existing box.
#
# A box with no config/version is let through: every release records it as the
# last step of an install, so without one no install ever completed there, and
# a re-run of this installer is how an interrupted first install is finished.
set -euo pipefail

UPGRADE_FLOOR="0.11.0"
BRIDGE_RELEASE="0.11.6"
BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
RECORD="${BOXMUNGE_ROOT}/config/version"

[[ -e "${RECORD}" ]] || exit 0
recorded="$(head -n 1 "${RECORD}")"
installed="${recorded%%+*}"
if [[ ! "${installed}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: ${RECORD} does not record the release this box runs (it holds" \
         "'${recorded}'), and an upgrade must start from ${UPGRADE_FLOOR} or later." \
         "Write the release that \`${BOXMUNGE_ROOT}/env-active/bin/boxmunge-server --version\`" \
         "prints into that file, then run this again. Nothing was changed." >&2
    exit 1
fi
if ! printf '%s\n' "${UPGRADE_FLOOR}" "${installed}" | sort -V -C; then
    echo "ERROR: this release cannot be installed over boxmunge ${installed}: an upgrade" \
         "must start from ${UPGRADE_FLOOR} or later. Upgrade to ${BRIDGE_RELEASE} first:" \
         "sudo ${BOXMUNGE_ROOT}/bin/boxmunge-upgrade target ${BRIDGE_RELEASE}" >&2
    echo "       Nothing was changed: this box stays on ${installed}." >&2
    exit 1
fi
