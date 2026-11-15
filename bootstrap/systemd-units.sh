#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/systemd-units.sh — install boxmunge's systemd units and start its
# timers. Run by install.sh as root.
#
#   systemd-units.sh <bundle_dir>
#
# `systemctl enable --now` starts a timer that is not running, but leaves a
# running one on the schedule it loaded: a release that changes a timer's
# OnCalendar would take effect only at the next reboot. So each timer whose
# unit file this run changes is restarted once the units are reloaded.
set -euo pipefail

SRC="${1:?Usage: systemd-units.sh <bundle_dir>}/systemd"
DEST="${BOXMUNGE_SYSTEMD_DIR:-/etc/systemd/system}"

# The scan and container-update timers were replaced by boxmunge-maintenance
# (scan, then update, in one unit). Retire them; a no-op once they are gone.
for old in boxmunge-cve-scan.timer boxmunge-container-update.timer; do
    if [[ -e "${DEST}/${old}" ]]; then
        systemctl disable --now "${old}"
        rm -f "${DEST}/${old}"
    fi
done

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
    boxmunge-health.timer \
    boxmunge-kev-watch.timer \
    boxmunge-maintenance.timer
if [[ "${#changed[@]}" -gt 0 ]]; then
    systemctl restart "${changed[@]}"
fi
