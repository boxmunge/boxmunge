#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/installer-fingerprint.sh — record or forget the installer
# fingerprint. Run by install.sh as root.
#
#   installer-fingerprint.sh record <bundle_dir>   at the very end of a run
#   installer-fingerprint.sh forget                when the run is incomplete
#
# The fingerprint covers install.sh and the files it installs from, as
# applied: the upgrade shim computes the same over a new bundle
# (system_upgrade in scripts/boxmunge-upgrade.d/system.sh,
# tests/test_installer_fingerprint.py) and re-runs install.sh before the slot
# swap when they differ, so new system pieces (apt packages, systemd units,
# install.sh-only migrations) need no manual re-run. A release that changes
# only bootstrap/sshd-hardening.sh, system/Dockerfile, a systemd unit, Caddy's
# compose file or the maintenance page re-runs it too.
#
# It is kept in root-only upgrade-root/: releases up to 0.11.3 kept it in
# deploy-writable state/, where deploy could plant a link, a FIFO or the
# bundle's own hash. That old copy is never read, and is not touched here
# either: deploy can put anything at that name (a directory, say), and a
# failed install.sh blocklists the release.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
DIR="${BOXMUNGE_ROOT}/upgrade-root"
FILE="${DIR}/installer.sha256"

if [[ -L "${DIR}" ]]; then
    echo "ERROR: ${DIR} is a symlink; remove it and run install.sh again" >&2
    exit 1
fi
mkdir -p "${DIR}"
if [[ "$(id -u)" -eq 0 ]]; then chown root:root "${DIR}"; fi
chmod 0700 "${DIR}"

case "${1:-}" in
    record)
        bundle="${2:?Usage: installer-fingerprint.sh record <bundle_dir>}"
        (cd "${bundle}" && find . \( -path ./install.sh -o -path './bootstrap/*' -o -path './src/boxmunge/sshd/*' -o -path './system/*' -o -path './systemd/*' -o -path ./caddy/compose.yml -o -path './caddy/maintenance/*' \) -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | awk '{print $1}' > "${FILE}.tmp"
        chmod 0600 "${FILE}.tmp"
        mv -f "${FILE}.tmp" "${FILE}"
        ;;
    forget)
        rm -f "${FILE}"
        ;;
    *)
        echo "Usage: installer-fingerprint.sh {record <bundle_dir>|forget}" >&2
        exit 64
        ;;
esac
