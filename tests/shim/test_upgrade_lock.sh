#!/usr/bin/env bash
# tests/shim/test_upgrade_lock.sh — one upgrade at a time, whatever deploy does.
#
# upgrade.lock is in root-only upgrade-root/, so deploy cannot replace it to
# let a second upgrade run beside one in progress. The lock older shims take,
# upgrade-state/upgrade.lock, is still taken too: the 0.10.1 shim that
# installs this one keeps running, holding only that lock, until its upgrade
# ends (tests/integration/test_shim_hop.py runs that hop for real).
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

ROOT_LOCK="upgrade-root/upgrade.lock"
LEGACY_LOCK="upgrade-state/upgrade.lock"

mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# hold <file>: take the lock on <file> through fd 7 of this test shell, as a
# running upgrade would; release it with `exec 7>&-`.
hold() {
    mkdir -p "$(dirname "$1")"
    exec 7<>"$1"
    flock -n 7 || { echo "could not take $1 for the test" >&2; exit 1; }
}

# A run creates the root-only lock, 0600 in a 0700 directory, and the legacy one.
new_root a
run_shim check-probation
expect 0 "" "check-probation runs with no lock files yet"
[[ -f "$BOXMUNGE_ROOT/$ROOT_LOCK" && "$(mode_of "$BOXMUNGE_ROOT/upgrade-root")" == 700 \
    && "$(mode_of "$BOXMUNGE_ROOT/$ROOT_LOCK")" == 600 ]] \
    && pass "upgrade.lock is created 0600 in a 0700 upgrade-root/" \
    || fail "upgrade-root/ is $(mode_of "$BOXMUNGE_ROOT/upgrade-root"): $(ls -l "$BOXMUNGE_ROOT/$ROOT_LOCK" 2>&1)"
[[ -f "$BOXMUNGE_ROOT/$LEGACY_LOCK" ]] && pass "the legacy lock is taken too" \
    || fail "the legacy lock was not created"
drop_root

# Either lock held: another upgrade is running.
for held in "$ROOT_LOCK" "$LEGACY_LOCK"; do
    new_root a
    hold "$BOXMUNGE_ROOT/$held"
    PATH="$FAILVISUDO:$PATH" run_shim run 1.2.3 ignored-url
    expect 1 "Another upgrade is in progress" "run refuses while $held is held"
    run_shim check-probation
    expect 0 "Another upgrade is in progress; skipping" "check-probation skips while $held is held"
    exec 7>&-
    PATH="$FAILVISUDO:$PATH" run_shim run 1.2.3 ignored-url
    expect 1 "failed visudo" "run proceeds once $held is released"
    drop_root
done

# Deploy renames the legacy lock away and leaves a fresh file while an upgrade
# holds both: the root-only lock still stops a second upgrade.
new_root a
hold "$BOXMUNGE_ROOT/$ROOT_LOCK"
exec 6<>"$BOXMUNGE_ROOT/$LEGACY_LOCK"
flock -n 6
mv "$BOXMUNGE_ROOT/$LEGACY_LOCK" "$BOXMUNGE_ROOT/upgrade-state/moved-away"
: > "$BOXMUNGE_ROOT/$LEGACY_LOCK"
PATH="$FAILVISUDO:$PATH" run_shim run 1.2.3 ignored-url
expect 1 "Another upgrade is in progress" "a replaced legacy lock does not let a second upgrade run"
exec 7>&- 6>&-
drop_root

# upgrade-root/ is root's; a link there is refused, not followed.
new_root a
elsewhere="$(mktemp -d)"
ln -s "$elsewhere" "$BOXMUNGE_ROOT/upgrade-root"
run_shim check-probation
expect 1 "upgrade-root is a symlink" "a linked upgrade-root/ is refused"
[[ ! -e "$elsewhere/upgrade.lock" ]] && pass "no lock was created through the link" \
    || fail "root created a lock through a linked upgrade-root/"
rm -rf "$elsewhere"
drop_root

# A descriptor handed in for the legacy lock must be that file.
new_root a
run_shim check-probation
other="$(mktemp)"
RC=0
OUT="$(BM_UPGRADE_LOCK_FD=9 bash "$SHIM" check-probation 9<>"$BOXMUNGE_ROOT/$ROOT_LOCK" 8<>"$other" 2>&1)" || RC=$?
expect 1 "fd 8 is not $BOXMUNGE_ROOT/$LEGACY_LOCK" "a legacy lock descriptor for another file is refused"
rm -f "$other"
drop_root

finish
