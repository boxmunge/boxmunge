#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/systemd-units.sh — install boxmunge's systemd units and start its
# timers. Run by install.sh as root.
#
#   systemd-units.sh <bundle_dir>
#
# BOXMUNGE_SLOT_UNITS names the live venv slot's record of its release's
# units (env-<slot>/boxmunge-systemd), which a platform rollback to that slot
# installs again (scripts/boxmunge-upgrade.d/units.sh). Run by the upgrade
# shim before its swap (FROM_UPGRADE_SHIM=1), the live slot still holds the
# previous release: the units it ran are recorded before they are replaced,
# unless it has its record already. Run by hand, this bundle is installed
# into the live slot, so its units are the slot's record.
#
# `systemctl enable --now` starts a timer that is not running, but leaves a
# running one on the schedule it loaded: a release that changes a timer's
# OnCalendar would take effect only at the next reboot. So each timer whose
# unit file this run changes is restarted once the units are reloaded.
set -euo pipefail

SRC="${1:?Usage: systemd-units.sh <bundle_dir>}/systemd"
DEST="${BOXMUNGE_SYSTEMD_DIR:-/etc/systemd/system}"
SLOT_UNITS="${BOXMUNGE_SLOT_UNITS:-}"

# record_units <dir>: its boxmunge units, as the slot's record. The record is
# a link to a versioned directory beside it, written in full first and swapped
# in by rename, so a copy cut short leaves the previous record whole (as the
# shim's copy_units does).
record_units() {
    local unit stage previous
    mkdir -p "$(dirname "${SLOT_UNITS}")"
    stage="$(mktemp -d "$(dirname "${SLOT_UNITS}")/.boxmunge-systemd.XXXXXX")"
    for unit in "$1"/boxmunge-*.service "$1"/boxmunge-*.timer; do
        if [[ -f "${unit}" ]] && ! cp "${unit}" "${stage}/"; then
            rm -rf "${stage}"
            echo "ERROR: could not copy ${unit} into ${SLOT_UNITS}; the record is left as it was" >&2
            exit 1
        fi
    done
    previous="$(readlink "${SLOT_UNITS}" 2>/dev/null || true)"
    ln -s "$(basename "${stage}")" "${stage}.link"
    python3 -I -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "${stage}.link" "${SLOT_UNITS}"
    if [[ "${previous}" =~ ^\.boxmunge-systemd\.[A-Za-z0-9]+$ ]]; then
        rm -rf "$(dirname "${SLOT_UNITS}")/${previous}"
    fi
}
if [[ -n "${SLOT_UNITS}" ]]; then
    if [[ "${FROM_UPGRADE_SHIM:-0}" == 1 ]]; then
        if [[ ! -d "${SLOT_UNITS}" ]] && compgen -G "${DEST}/boxmunge-*.timer" >/dev/null; then
            record_units "${DEST}"
        fi
    else
        record_units "${SRC}"
    fi
fi

changed=()
for timer in "${SRC}/"*.timer; do
    cmp -s "${timer}" "${DEST}/${timer##*/}" || changed+=("${timer##*/}")
done
cp "${SRC}/"*.service "${SRC}/"*.timer "${DEST}/"
systemctl daemon-reload
systemctl enable --now \
    boxmunge-auto-update.timer \
    boxmunge-backup-sync.timer \
    boxmunge-backup.timer \
    boxmunge-container-update.timer \
    boxmunge-cve-scan.timer \
    boxmunge-health.timer
if [[ "${#changed[@]}" -gt 0 ]]; then
    systemctl restart "${changed[@]}"
fi
