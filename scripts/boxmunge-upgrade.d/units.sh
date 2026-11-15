# shellcheck shell=bash
# units.sh — the systemd units of the release each venv slot holds, so a
# rollback puts the previous release's units back.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.
#
# Releases add and retire units: 0.12 replaced the scan and container-update
# timers with boxmunge-maintenance.timer and added boxmunge-kev-watch.timer and
# boxmunge-autofix.service. The new release's install.sh installs its units
# before the swap, and the older release a rollback returns to knows nothing of
# them: left as they are, its timers would run commands that release lacks.
# So each slot keeps its release's units in env-<slot>/boxmunge-systemd: the
# upgrade copies the bundle's there for the standby; the release's own
# bootstrap/systemd-units.sh records the units the live slot ran before it
# replaces them; a slot with no copy yet records the live units as its own
# (seed_slot_units). A rollback installs the slot's units, disables and removes
# every boxmunge unit the slot does not ship, and enables its timers
# (restore_slot_units).

SYSTEMD_UNIT_DIR="${BOXMUNGE_SYSTEMD_DIR:-/etc/systemd/system}"

slot_units() { echo "$BOXMUNGE_ROOT/env-$1/boxmunge-systemd"; }

# copy_units <from_dir> <to_dir>: <to_dir> anew, with the boxmunge-*.service
# and boxmunge-*.timer files of <from_dir>.
copy_units() {
    local from="$1" to="$2" unit
    rm -rf "$to"
    mkdir -p "$to"
    for unit in "$from"/boxmunge-*.service "$from"/boxmunge-*.timer; do
        if [[ -f "$unit" ]]; then cp "$unit" "$to/"; fi
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
