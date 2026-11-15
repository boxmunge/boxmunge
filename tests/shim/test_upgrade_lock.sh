#!/usr/bin/env bash
# tests/shim/test_upgrade_lock.sh — one upgrade at a time, whatever deploy does.
#
# upgrade.lock is in root-only upgrade-root/, so deploy cannot replace it to
# let a second upgrade run beside one in progress. The shim that installs this
# one holds it until its upgrade ends (tests/integration/test_shim_hop.py runs
# that hop for real).
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

ROOT_LOCK="upgrade-root/upgrade.lock"

mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# hold <file>: take the lock on <file> through fd 7 of this test shell, as a
# running upgrade would; release it with `exec 7>&-`.
hold() {
    mkdir -p "$(dirname "$1")"
    exec 7<>"$1"
    flock -n 7 || { echo "could not take $1 for the test" >&2; exit 1; }
}

# A run creates the root-only lock, 0600 in a 0700 directory, and no other.
new_root a
run_shim check-probation
expect 0 "" "check-probation runs with no lock files yet"
[[ -f "$BOXMUNGE_ROOT/$ROOT_LOCK" && "$(mode_of "$BOXMUNGE_ROOT/upgrade-root")" == 700 \
    && "$(mode_of "$BOXMUNGE_ROOT/$ROOT_LOCK")" == 600 ]] \
    && pass "upgrade.lock is created 0600 in a 0700 upgrade-root/" \
    || fail "upgrade-root/ is $(mode_of "$BOXMUNGE_ROOT/upgrade-root"): $(ls -l "$BOXMUNGE_ROOT/$ROOT_LOCK" 2>&1)"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-state/upgrade.lock" ]] && pass "no lock is made in deploy-writable upgrade-state/" \
    || fail "a lock was made in upgrade-state/"
drop_root

# The lock held: another upgrade is running.
for held in "$ROOT_LOCK"; do
    new_root a
    hold "$BOXMUNGE_ROOT/$held"
    PATH="$FAILVISUDO:$PATH" run_shim target 1.2.3
    expect 1 "Another upgrade is in progress" "target refuses while $held is held"
    run_shim check-probation
    expect 0 "Another upgrade is in progress; skipping" "check-probation skips while $held is held"
    exec 7>&-
    PATH="$FAILVISUDO:$PATH" run_shim target 1.2.3
    expect 1 "failed visudo" "target proceeds once $held is released"
    drop_root
done

# The auto-update timer's run waits for the lock, as its discovery does: a
# readiness check holds it for up to ten minutes, and must not hold off an
# update. One released meanwhile lets it go ahead; one held past the wait is
# an error in the operational log, naming how to find the holder.
for held in "$ROOT_LOCK"; do
    new_root a
    hold "$BOXMUNGE_ROOT/$held"
    PATH="$FAILVISUDO:$PATH" bash "$SHIM" run 1.2.3 ignored-url > "$BOXMUNGE_ROOT/run.out" 2>&1 7>&- &
    waiter=$!
    sleep 1
    exec 7>&-
    RC=0; wait "$waiter" || RC=$?
    OUT="$(cat "$BOXMUNGE_ROOT/run.out")"
    expect 1 "failed visudo" "run waits for $held and goes ahead once it is released"
    drop_root
done
new_root a
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; fi' \
    > "$BOXMUNGE_ROOT/env-a/bin/python"
WAITLOCK="$(mktemp -d)"
printf '#!/usr/bin/env bash\necho "flock $*" >> "$BOXMUNGE_ROOT/calls"\nexit 1\n' > "$WAITLOCK/flock"
chmod +x "$WAITLOCK/flock"
PATH="$WAITLOCK:$PATH" run_shim run 1.2.3 ignored-url
expect 1 "upgrade.lock was held for the whole 15 minutes the auto-update timer waited" "run gives up after its wait, saying so"
grep -q "^flock -w 900 9$" "$BOXMUNGE_ROOT/calls" && grep -q "bm_log error .*sudo lslocks | grep upgrade.lock" "$BOXMUNGE_ROOT/calls" \
    && pass "run waits 900 s, and a lock held past it is an error naming the holder's search" \
    || fail "wait: $(cat "$BOXMUNGE_ROOT/calls")"
rm -rf "$WAITLOCK"
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

# record_bm_log: the live slot's python records what bm_log writes.
record_bm_log() {
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; fi' \
        > "$BOXMUNGE_ROOT/env-a/bin/python"
}

# A held lock makes check-probation skip, and each skip is counted: a skip is
# routine, but a whole hour of them means something is holding the lock (no
# upgrade takes that long), and no probation moves meanwhile. That is an error
# in the operational log, not a silent exit 0.
new_root a
record_bm_log
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
echo 10 > "$BOXMUNGE_ROOT/upgrade-root/lock-skips"
PATH="$BUSYLOCK:$PATH" run_shim check-probation
expect 0 "skipping (11 in a row: upgrade.lock is held)" "a skip is counted"
[[ "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" != *"bm_log error"* ]] && pass "eleven skips are not an error yet" \
    || fail "logged too early: $(cat "$BOXMUNGE_ROOT/calls")"
PATH="$BUSYLOCK:$PATH" run_shim check-probation
expect 0 "skipping (12 in a row" "the twelfth skip is counted"
[[ "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" == *"bm_log error check-probation could not take upgrade.lock 12 times in a row"*"lslocks"* ]] \
    && pass "an hour of skips is an error naming how to find the holder" || fail "not logged: $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
run_shim check-probation
expect 0 "" "check-probation runs once the lock is free"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/lock-skips" ]] && pass "taking the lock resets the count" \
    || fail "count left: $(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips")"
drop_root

# A lock file that is not root's is refused, never locked: only root runs
# upgrades. Needs root (to make a file another user owns).
if [[ "$(id -u)" -eq 0 ]]; then
    new_root a
    mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
    : > "$BOXMUNGE_ROOT/$ROOT_LOCK"
    chown nobody "$BOXMUNGE_ROOT/$ROOT_LOCK"
    run_shim check-probation
    expect 1 "$ROOT_LOCK is not root's" "a lock file that is not root's is refused"
    drop_root
fi

finish
