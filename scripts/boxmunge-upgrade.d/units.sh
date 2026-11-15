# shellcheck shell=bash
# units.sh — the systemd units of the release each venv slot holds, so a
# rollback puts the previous release's units back.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.
#
# Releases add and retire units: 0.12 replaces the scan and container-update
# timers with boxmunge-maintenance.timer and adds boxmunge-kev-watch.timer and
# boxmunge-autofix.service. The new release's install.sh installs its units
# before the swap, and the older release a rollback returns to knows nothing of
# them: left as they are, its timers would run commands that release lacks.
# So each slot keeps its release's units in env-<slot>/boxmunge-systemd: the
# upgrade copies the bundle's there for the standby; the release's own
# bootstrap/systemd-units.sh records the units the live slot ran before it
# replaces them; a slot with no copy yet records the live units as its own
# (seed_slot_units). A rollback installs the slot's units, disables and removes
# every boxmunge unit the slot does not ship, and enables its timers
# (restore_slot_units). A shim from before 0.11.11 does not, so 0.12 installs
# only over 0.11.11 or later: the upgrade that adds 0.12's units is run by a
# shim that can take them away again. Every check-probation and upgrade,
# holding the upgrade lock with nothing in flight, also puts the live slot's
# units back where they differ (heal_slot_units).

SYSTEMD_UNIT_DIR="${BOXMUNGE_SYSTEMD_DIR:-/etc/systemd/system}"

slot_units() { echo "$BOXMUNGE_ROOT/env-$1/boxmunge-systemd"; }

# copy_units <from_dir> <record>: <record> anew, with the boxmunge-*.service
# and boxmunge-*.timer files of <from_dir>. The record is a link to a
# versioned directory beside it, written in full first and swapped in by
# rename, so a copy cut short leaves the previous record whole (the same
# scheme as bootstrap/systemd-units.sh's record_units).
copy_units() {
    local from="$1" to="$2" unit stage previous
    mkdir -p "$(dirname "$to")"
    stage="$(mktemp -d "$(dirname "$to")/.boxmunge-systemd.XXXXXX")"
    for unit in "$from"/boxmunge-*.service "$from"/boxmunge-*.timer; do
        if [[ -f "$unit" ]] && ! cp "$unit" "$stage/"; then
            rm -rf "$stage"
            log "ERROR: could not copy $unit into a units record; $to is left as it was"
            return 1
        fi
    done
    previous="$(readlink "$to" 2>/dev/null || true)"
    ln -s "$(basename "$stage")" "$stage.link"
    python3 -I -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$stage.link" "$to"
    if [[ "$previous" =~ ^\.boxmunge-systemd\.[A-Za-z0-9]+$ ]]; then
        rm -rf "${to%/*}/$previous"
    fi
}

# Units every release ships: a record without one of them that is live is
# damaged (cut short, emptied), and is never installed.
ALWAYS_SHIPPED_UNITS=(boxmunge-health.timer boxmunge-health.service boxmunge-backup.timer
                      boxmunge-backup-sync.timer boxmunge-auto-update.timer)

# record_damaged <dir>: why <dir> cannot be a release's units, or nothing.
record_damaged() {
    local name
    [[ -f "$1/boxmunge-health.timer" ]] || { echo "it has no boxmunge-health.timer"; return 0; }
    for name in "${ALWAYS_SHIPPED_UNITS[@]}"; do
        if [[ -e "$SYSTEMD_UNIT_DIR/$name" && ! -f "$1/$name" ]]; then
            echo "it lacks $name, which every release ships"
            return 0
        fi
    done
}

# seed_slot_units <slot>: a slot without its own copy (installed by install.sh
# or by an older shim) records the live units as its own.
seed_slot_units() {
    local dest
    dest="$(slot_units "$1")"
    if [[ ! -d "$dest" ]] && compgen -G "$SYSTEMD_UNIT_DIR/boxmunge-*.timer" >/dev/null; then
        copy_units "$SYSTEMD_UNIT_DIR" "$dest"
    fi
}

# units_match <dir>: the live boxmunge units are exactly <dir>'s, by name
# and content.
units_match() {
    local unit name
    for unit in "$1"/boxmunge-*.service "$1"/boxmunge-*.timer; do
        [[ -f "$unit" ]] || continue
        cmp -s "$unit" "$SYSTEMD_UNIT_DIR/${unit##*/}" || return 1
    done
    for unit in "$SYSTEMD_UNIT_DIR"/boxmunge-*.service "$SYSTEMD_UNIT_DIR"/boxmunge-*.timer; do
        [[ -e "$unit" || -L "$unit" ]] || continue
        name="${unit##*/}"
        [[ -e "$1/$name" ]] || return 1
    done
    return 0
}

# heal_slot_units: the live slot has a record of its units and the live
# units are not those, so a rollback left the newer release's: put them back.
# The caller holds the upgrade lock and nothing is in flight.
heal_slot_units() {
    local src
    src="$(slot_units "$ACTIVE_SLOT")"
    compgen -G "$src/boxmunge-*.timer" >/dev/null || return 0
    units_match "$src" && return 0
    log "The live systemd units are not those of the release on slot $ACTIVE_SLOT (a rollback left them); restoring them"
    bm_log warn upgrade "systemd units differ from the live slot's; restoring" "{\"slot\": \"$ACTIVE_SLOT\"}"
    restore_slot_units "$ACTIVE_SLOT" || true   # a refusal is logged; the check goes on
}

# restore_slot_units <slot>: best effort, since a units failure must not undo
# the rollback; each failure is logged loudly. The installer fingerprint
# named the newer release's units, so it is dropped: the next upgrade runs
# its install.sh again.
restore_slot_units() {
    local src unit name ok=1 timers=() changed=()
    src="$(slot_units "$1")"
    if ! compgen -G "$src/boxmunge-*.timer" >/dev/null; then
        log "ERROR: slot $1 has no record of its systemd units ($src), so the units of the release rolled back from stay installed; put the running release's own back by reinstalling it (sudo bash boxmunge-install.sh)"
        bm_log error upgrade "systemd units not restored" "{\"slot\": \"$1\"}"
        return 0
    fi
    local damaged
    damaged="$(record_damaged "$src")"
    if [[ -n "$damaged" ]]; then
        log "ERROR: refusing slot $1's record of its systemd units ($src): $damaged. The live units are left as they are; reinstall the running release to put its own back (sudo bash boxmunge-install.sh)"
        bm_log error upgrade "systemd units record refused" "{\"slot\": \"$1\"}"
        return 1
    fi
    for unit in "$SYSTEMD_UNIT_DIR"/boxmunge-*.service "$SYSTEMD_UNIT_DIR"/boxmunge-*.timer; do
        [[ -e "$unit" || -L "$unit" ]] || continue
        name="${unit##*/}"
        [[ ! -e "$src/$name" ]] || continue
        if [[ "$name" == *.timer ]]; then
            systemctl disable --now "$name" || { ok=0; log "ERROR: could not disable $name"; }
        fi
        rm -f "$unit"
        log "Removed $name: the release on slot $1 does not ship it"
    done
    for unit in "$src"/boxmunge-*.timer; do
        name="${unit##*/}"
        timers+=("$name")
        cmp -s "$unit" "$SYSTEMD_UNIT_DIR/$name" || changed+=("$name")
    done
    for unit in "$src"/boxmunge-*.service "$src"/boxmunge-*.timer; do
        if [[ -f "$unit" ]]; then cp "$unit" "$SYSTEMD_UNIT_DIR/" || ok=0; fi
    done
    systemctl daemon-reload || ok=0
    systemctl enable --now "${timers[@]}" || ok=0
    if [[ "${#changed[@]}" -gt 0 ]]; then systemctl restart "${changed[@]}" || ok=0; fi
    rm -f "$INSTALLER_HASH_FILE"
    if [[ "$ok" -eq 1 ]]; then
        log "Restored the systemd units of the release on slot $1"
    else
        log "ERROR: restoring the systemd units of slot $1 did not finish (see above); as supervisor, check: systemctl list-timers 'boxmunge-*'"
        bm_log error upgrade "systemd units restore incomplete" "{\"slot\": \"$1\"}"
    fi
}
