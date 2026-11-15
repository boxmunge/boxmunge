#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/systemd-units.sh — install boxmunge's systemd units and start its
# timers and the job runner's path unit. Run by install.sh as root.
#
#   systemd-units.sh <bundle_dir>
#
# BOXMUNGE_SLOT_UNITS names the live venv slot's record of its release's
# units (env-<slot>/boxmunge-systemd), which a platform rollback to that slot
# installs again (scripts/boxmunge-upgrade.d/units.sh). Run by the upgrade
# shim before its swap (FROM_UPGRADE_SHIM=1), the live slot still holds the
# previous release: the units it ran are recorded before they are replaced,
# unless it has its record already. This release is then in the standby
# slot, the one BOXMUNGE_ROOT/env-active does not name (as
# bootstrap/audit-seal.sh picks it), and this bundle's units are written as
# that slot's record. The shim wrote one already, but 0.11.11's shim copies
# only .service and .timer units: without boxmunge-jobs.path in the record,
# the 0.12 shim's heal would remove the job runner's trigger from the box it
# just upgraded. Run by hand, this bundle is installed into the live slot, so
# its units are the slot's record.
#
# `systemctl enable --now` starts a timer that is not running, but leaves a
# running one on the schedule it loaded: a release that changes a timer's
# OnCalendar would take effect only at the next reboot. So each timer whose
# unit file this run changes is restarted once the units are reloaded, and so
# is a changed path unit, which keeps the watch it loaded the same way.
set -euo pipefail

SRC="${1:?Usage: systemd-units.sh <bundle_dir>}/systemd"
DEST="${BOXMUNGE_SYSTEMD_DIR:-/etc/systemd/system}"
SLOT_UNITS="${BOXMUNGE_SLOT_UNITS:-}"

# record_units <dir> <record>: <dir>'s boxmunge units, as a slot's record.
# The record is a link to a versioned directory beside it, written in full
# first and swapped in by rename, so a copy cut short leaves the previous
# record whole (as the shim's copy_units does).
record_units() {
    local unit stage previous record="$2"
    mkdir -p "$(dirname "${record}")"
    stage="$(mktemp -d "$(dirname "${record}")/.boxmunge-systemd.XXXXXX")"
    for unit in "$1"/boxmunge-*.service "$1"/boxmunge-*.timer "$1"/boxmunge-*.path; do
        if [[ -f "${unit}" ]] && ! cp "${unit}" "${stage}/"; then
            rm -rf "${stage}"
            echo "ERROR: could not copy ${unit} into ${record}; the record is left as it was" >&2
            exit 1
        fi
    done
    previous="$(readlink "${record}" 2>/dev/null || true)"
    ln -s "$(basename "${stage}")" "${stage}.link"
    python3 -I -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "${stage}.link" "${record}"
    if [[ "${previous}" =~ ^\.boxmunge-systemd\.[A-Za-z0-9]+$ ]]; then
        rm -rf "$(dirname "${record}")/${previous}"
    fi
}

# standby_slot_dir: the slot env-active does not name, which holds this
# release while the shim installs it.
standby_slot_dir() {
    local root="${BOXMUNGE_ROOT:?BOXMUNGE_ROOT must be set when run by the upgrade shim}" live
    live="$(readlink "${root}/env-active")" || live=""
    case "${live##*/}" in
        env-a) echo "${root}/env-b" ;;
        env-b) echo "${root}/env-a" ;;
        *) echo "ERROR: ${root}/env-active points at '${live}', not env-a or env-b, so the slot" \
                "holding this release is unknown and its systemd units were not recorded." \
                "Point it back at the live slot, then run the upgrade again." >&2
           exit 1 ;;
    esac
}

if [[ -n "${SLOT_UNITS}" ]]; then
    if [[ "${FROM_UPGRADE_SHIM:-0}" == 1 ]]; then
        if [[ ! -d "${SLOT_UNITS}" ]] && compgen -G "${DEST}/boxmunge-*.timer" >/dev/null; then
            record_units "${DEST}" "${SLOT_UNITS}"
        fi
        standby="$(standby_slot_dir)"
        if [[ ! -d "${standby}" ]]; then
            echo "ERROR: ${standby}, the slot this release is installed into, is missing," \
                 "so its systemd units were not recorded" >&2
            exit 1
        fi
        record_units "${SRC}" "${standby}/boxmunge-systemd"
    else
        record_units "${SRC}" "${SLOT_UNITS}"
    fi
fi

# The scan and container-update timers were replaced by boxmunge-maintenance
# (scan, then update, in one unit). Retire them; a no-op once they are gone.
for old in boxmunge-cve-scan.timer boxmunge-container-update.timer; do
    if [[ -e "${DEST}/${old}" ]]; then
        systemctl disable --now "${old}"
        rm -f "${DEST}/${old}"
    fi
done

changed=()
for watcher in "${SRC}/"*.timer "${SRC}/"*.path; do
    cmp -s "${watcher}" "${DEST}/${watcher##*/}" || changed+=("${watcher##*/}")
done
# Every service is copied, and none is enabled itself: the timers start most;
# the scans start boxmunge-autofix.service when they queue a patch; and
# boxmunge-jobs.path starts boxmunge-jobs.service, at boot and whenever a job
# is queued.
cp "${SRC}/"*.service "${SRC}/"*.timer "${SRC}/"*.path "${DEST}/"
systemctl daemon-reload
systemctl enable --now \
    boxmunge-audit-rotate.timer \
    boxmunge-auto-update.timer \
    boxmunge-backup-sync.timer \
    boxmunge-backup.timer \
    boxmunge-health.timer \
    boxmunge-jobs.path \
    boxmunge-kev-watch.timer \
    boxmunge-maintenance.timer
if [[ "${#changed[@]}" -gt 0 ]]; then
    systemctl restart "${changed[@]}"
fi
