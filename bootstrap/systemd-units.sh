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
