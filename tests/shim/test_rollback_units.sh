#!/usr/bin/env bash
# tests/shim/test_rollback_units.sh — a rollback puts the previous release's
# systemd units back: the units it does not ship are disabled and removed,
# its own (timers it retired included) installed and enabled, and the
# installer fingerprint dropped so the next upgrade runs install.sh again.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# Path units (boxmunge-jobs.path) are units like the timers: recorded,
# disabled and removed when the slot lacks them, enabled when it has them.
# shellcheck disable=SC2015
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

unit() { printf '[Unit]\nDescription=%s\n' "$2" > "$1"; }

# Active a = the newer release on probation, with its units live; b = the
# previous release, whose units its slot recorded.
new_root a
live="$BOXMUNGE_SYSTEMD_DIR"
for u in boxmunge-maintenance.timer boxmunge-maintenance.service boxmunge-kev-watch.timer \
         boxmunge-kev-watch.service boxmunge-autofix.service boxmunge-health.timer \
         boxmunge-health.service boxmunge-cve-scan.service boxmunge-jobs.path \
         boxmunge-jobs.service; do unit "$live/$u" "new $u"; done
old="$BOXMUNGE_ROOT/env-b/boxmunge-systemd"
mkdir -p "$old"
for u in boxmunge-cve-scan.timer boxmunge-cve-scan.service boxmunge-container-update.timer \
         boxmunge-container-update.service boxmunge-health.timer boxmunge-health.service; do
    unit "$old/$u" "old $u"
done
mkdir -p "$BOXMUNGE_ROOT/upgrade-root"
echo "newhash" > "$BOXMUNGE_ROOT/upgrade-root/installer.sha256"
mock_server a 'if [[ "$1" == "health" ]]; then exec health-report 2; fi; exit 0'
rm "$BOXMUNGE_ROOT/env-b/bin/python"
printf '#!/usr/bin/env bash\nexit 0\n' > "$BOXMUNGE_ROOT/env-b/bin/python"
chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
write_probation "1.2.3" "b" "$SOON"
run_shim check-probation
expect 1 "Rollback complete" "a critical probation health check rolls back"
installed="$(cd "$live" && ls | sort | tr '\n' ' ')"
want="boxmunge-container-update.service boxmunge-container-update.timer boxmunge-cve-scan.service boxmunge-cve-scan.timer boxmunge-health.service boxmunge-health.timer "
[[ "$installed" == "$want" ]] && pass "exactly the previous release's units are installed" \
    || fail "installed: $installed"
[[ "$(cat "$live/boxmunge-health.timer")" == *"old boxmunge-health.timer"* ]] \
    && pass "a unit both ship is the previous release's" || fail "health.timer not restored"
calls="$(cat "$BOXMUNGE_ROOT/calls")"
for t in boxmunge-maintenance.timer boxmunge-kev-watch.timer boxmunge-jobs.path; do
    [[ "$calls" == *"systemctl disable --now $t"* ]] && pass "$t disabled" || fail "$t not disabled: $calls"
done
[[ "$calls" == *"systemctl enable --now boxmunge-container-update.timer boxmunge-cve-scan.timer boxmunge-health.timer"* ]] \
    && pass "the previous release's timers are enabled" || fail "timers not enabled: $calls"
[[ "$calls" == *"systemctl restart"*"boxmunge-health.timer"* ]] \
    && pass "a timer whose file changed is restarted" || fail "health.timer not restarted: $calls"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/installer.sha256" ]] \
    && pass "the installer fingerprint is dropped" || fail "installer fingerprint kept"
drop_root

# A previous slot with no record of its units: the rollback still completes,
# and says loudly that the units were left.
new_root a
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-kev-watch.timer" "new"
mock_server a 'if [[ "$1" == "health" ]]; then exec health-report 2; fi; exit 0'
rm "$BOXMUNGE_ROOT/env-b/bin/python"
printf '#!/usr/bin/env bash\nexit 0\n' > "$BOXMUNGE_ROOT/env-b/bin/python"
chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
write_probation "1.2.3" "b" "$SOON"
run_shim check-probation
expect 1 "Rollback complete" "the rollback completes without a units record"
[[ "$OUT" == *"slot b has no record of its systemd units"* ]] && pass "the missing record is reported" \
    || fail "no report: $OUT"
[[ -e "$BOXMUNGE_SYSTEMD_DIR/boxmunge-kev-watch.timer" ]] && pass "nothing removed without a record" \
    || fail "a unit was removed without a record"
drop_root

# seed_slot_units and copy_units, as an upgrade runs them.
new_root a
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-health.timer" "live"
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-health.service" "live"
unit "$BOXMUNGE_SYSTEMD_DIR/other.service" "not ours"
with_shim_functions seed_slot_units a
[[ "$(cd "$BOXMUNGE_ROOT/env-a/boxmunge-systemd" && ls | tr '\n' ' ')" == "boxmunge-health.service boxmunge-health.timer " ]] \
    && pass "a slot without a record records the live boxmunge units" || fail "seed wrong"
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-health.timer" "changed"
with_shim_functions seed_slot_units a
[[ "$(cat "$BOXMUNGE_ROOT/env-a/boxmunge-systemd/boxmunge-health.timer")" == *live* ]] \
    && pass "a slot's own record is kept" || fail "seed overwrote the slot's record"
drop_root

# Self-heal: the live units are not the live slot's (edited by hand, or left
# by a rollback that could not restore them). The next check-probation (no
# probation, nothing in flight) puts the live slot's own back; units that
# already match are left alone.
new_root a
mkdir -p "$BOXMUNGE_ROOT/env-a/boxmunge-systemd"
for u in boxmunge-cve-scan.timer boxmunge-cve-scan.service boxmunge-health.timer; do
    unit "$BOXMUNGE_ROOT/env-a/boxmunge-systemd/$u" "old $u"
done
for u in boxmunge-kev-watch.timer boxmunge-maintenance.timer boxmunge-health.timer; do
    unit "$BOXMUNGE_SYSTEMD_DIR/$u" "new $u"
done
run_shim check-probation
expect 0 "restoring them" "check-probation heals units a rollback left"
installed="$(cd "$BOXMUNGE_SYSTEMD_DIR" && ls | sort | tr '\n' ' ')"
[[ "$installed" == "boxmunge-cve-scan.service boxmunge-cve-scan.timer boxmunge-health.timer " ]] \
    && pass "the live slot's units are back" || fail "installed after heal: $installed"
: > "$BOXMUNGE_ROOT/calls"
run_shim check-probation
expect 0 "" "a second check-probation runs"
[[ "$OUT" != *"restoring them"* && "$(cat "$BOXMUNGE_ROOT/calls")" != *"enable"* ]] \
    && pass "units that match are left alone" || fail "healed again: $OUT"
drop_root

# A rollback run by an older shim, whose restore knows only timers and
# services, removes boxmunge-jobs.service but leaves boxmunge-jobs.path
# behind; this shim's heal sees the stray path unit and removes it.
new_root a
mkdir -p "$BOXMUNGE_ROOT/env-a/boxmunge-systemd"
for u in boxmunge-health.timer boxmunge-health.service; do
    unit "$BOXMUNGE_ROOT/env-a/boxmunge-systemd/$u" "old $u"
    unit "$BOXMUNGE_SYSTEMD_DIR/$u" "old $u"
done
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-jobs.path" "new boxmunge-jobs.path"
run_shim check-probation
expect 0 "restoring them" "check-probation heals a stray path unit"
installed="$(cd "$BOXMUNGE_SYSTEMD_DIR" && ls | sort | tr '\n' ' ')"
[[ "$installed" == "boxmunge-health.service boxmunge-health.timer " ]] \
    && pass "the stray path unit is removed" || fail "installed after heal: $installed"
[[ "$(cat "$BOXMUNGE_ROOT/calls")" == *"systemctl disable --now boxmunge-jobs.path"* ]] \
    && pass "the stray path unit is disabled" || fail "not disabled: $(cat "$BOXMUNGE_ROOT/calls")"
drop_root

# A slot whose release ships a path unit: it is recorded, and a restore
# installs and enables it with the timers.
new_root a
for u in boxmunge-health.timer boxmunge-jobs.path boxmunge-jobs.service; do
    unit "$BOXMUNGE_SYSTEMD_DIR/$u" "live $u"
done
with_shim_functions seed_slot_units a
[[ "$(cd "$BOXMUNGE_ROOT/env-a/boxmunge-systemd" && ls | tr '\n' ' ')" == "boxmunge-health.timer boxmunge-jobs.path boxmunge-jobs.service " ]] \
    && pass "a slot's record holds its path units" || fail "path unit not recorded"
rm "$BOXMUNGE_SYSTEMD_DIR/boxmunge-jobs.path"
run_shim check-probation
expect 0 "restoring them" "check-probation heals a missing path unit"
[[ "$(cat "$BOXMUNGE_SYSTEMD_DIR/boxmunge-jobs.path" 2>/dev/null)" == *"live boxmunge-jobs.path"* ]] \
    && pass "the path unit is put back" || fail "path unit not restored"
[[ "$(cat "$BOXMUNGE_ROOT/calls")" == *"systemctl enable --now boxmunge-health.timer boxmunge-jobs.path"* ]] \
    && pass "the path unit is enabled with the timers" || fail "not enabled: $(cat "$BOXMUNGE_ROOT/calls")"
drop_root

# A live slot with no record (installed from a bundle without units) is left
# alone.
new_root a
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-kev-watch.timer" "new"
run_shim check-probation
expect 0 "" "check-probation without a units record"
[[ -e "$BOXMUNGE_SYSTEMD_DIR/boxmunge-kev-watch.timer" && "$OUT" != *"restoring them"* ]] \
    && pass "no record: no heal" || fail "healed without a record: $OUT"
drop_root

# A damaged record (no health timer) is refused: the live units stay as they
# are, the rollback still completes.
new_root a
for u in boxmunge-kev-watch.timer boxmunge-health.timer; do unit "$BOXMUNGE_SYSTEMD_DIR/$u" "new $u"; done
mkdir -p "$BOXMUNGE_ROOT/env-b/boxmunge-systemd"
unit "$BOXMUNGE_ROOT/env-b/boxmunge-systemd/boxmunge-cve-scan.timer" "old"
mock_server a 'if [[ "$1" == "health" ]]; then exec health-report 2; fi; exit 0'
rm "$BOXMUNGE_ROOT/env-b/bin/python"
printf '#!/usr/bin/env bash\nexit 0\n' > "$BOXMUNGE_ROOT/env-b/bin/python"
chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
write_probation "1.2.3" "b" "$SOON"
run_shim check-probation
expect 1 "Rollback complete" "the rollback completes past a damaged record"
[[ "$OUT" == *"refusing slot b's record of its systemd units"*"no boxmunge-health.timer"* ]] \
    && pass "the damaged record is refused, loudly" || fail "not refused: $OUT"
installed="$(cd "$BOXMUNGE_SYSTEMD_DIR" && ls | sort | tr '\n' ' ')"
[[ "$installed" == "boxmunge-health.timer boxmunge-kev-watch.timer " \
   && "$(cat "$BOXMUNGE_SYSTEMD_DIR/boxmunge-health.timer")" == *"new boxmunge-health.timer"* ]] \
    && pass "the live units are untouched" || fail "live units changed: $installed"
[[ "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" != *"systemctl disable"* ]] \
    && pass "nothing disabled" || fail "a unit was disabled"
drop_root

# copy_units cut short (cp fails part-way): the previous record stays whole.
new_root a
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-health.timer" "first"
with_shim_functions copy_units "$BOXMUNGE_SYSTEMD_DIR" "$BOXMUNGE_ROOT/env-a/boxmunge-systemd"
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-health.timer" "second"
unit "$BOXMUNGE_SYSTEMD_DIR/boxmunge-health.service" "second"
broken="$(mktemp -d)"
printf '#!/usr/bin/env bash\nexit 1\n' > "$broken/cp"
chmod +x "$broken/cp"
rc=0
( PATH="$broken:$PATH"; set -e; with_shim_functions copy_units "$BOXMUNGE_SYSTEMD_DIR" \
    "$BOXMUNGE_ROOT/env-a/boxmunge-systemd" ) >/dev/null 2>&1 || rc=$?
record="$BOXMUNGE_ROOT/env-a/boxmunge-systemd"
[[ "$rc" -ne 0 && "$(ls "$record" | tr '\n' ' ')" == "boxmunge-health.timer " \
   && "$(cat "$record/boxmunge-health.timer")" == *first* ]] \
    && pass "an interrupted record write leaves the old record" || fail "record changed (rc=$rc): $(ls "$record")"
with_shim_functions copy_units "$BOXMUNGE_SYSTEMD_DIR" "$record"
[[ -L "$record" && "$(cat "$record/boxmunge-health.timer")" == *second* ]] \
    && pass "a whole write swaps the record in" || fail "record not replaced"
[[ "$(compgen -G "$BOXMUNGE_ROOT/env-a/.boxmunge-systemd.*" | grep -cv '\.link$')" -le 2 ]] \
    && pass "the replaced record is removed" || fail "records pile up"
rm -rf "$broken"
drop_root

grep -q 'restore_slot_units "$prev_slot"' "$REPO_DIR/scripts/boxmunge-upgrade.d/slots.sh" \
    && pass "complete_rollback restores the units" || fail "complete_rollback does not restore units"
grep -q 'copy_units "$bundle/systemd" "$(slot_units "$standby")" \\' "$REPO_DIR/scripts/boxmunge-upgrade" \
    && pass "an upgrade records the bundle's units for the standby" || fail "standby units not recorded"

finish
