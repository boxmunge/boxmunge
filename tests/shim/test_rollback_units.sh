#!/usr/bin/env bash
# tests/shim/test_rollback_units.sh — a rollback puts the previous release's
# systemd units back: the units it does not ship are disabled and removed,
# its own (timers it retired included) installed and enabled, and the
# installer fingerprint dropped so the next upgrade runs install.sh again.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
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
         boxmunge-health.service boxmunge-cve-scan.service; do unit "$live/$u" "new $u"; done
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
for t in boxmunge-maintenance.timer boxmunge-kev-watch.timer; do
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

grep -q 'restore_slot_units "$prev_slot"' "$REPO_DIR/scripts/boxmunge-upgrade.d/slots.sh" \
    && pass "complete_rollback restores the units" || fail "complete_rollback does not restore units"
grep -q 'copy_units "$bundle/systemd" "$(slot_units "$standby")"' "$REPO_DIR/scripts/boxmunge-upgrade" \
    && pass "an upgrade records the bundle's units for the standby" || fail "standby units not recorded"

finish
