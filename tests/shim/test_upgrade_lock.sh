#!/usr/bin/env bash
# tests/shim/test_upgrade_lock.sh — one upgrade at a time, whatever deploy does.
#
# upgrade.lock is in root-only upgrade-root/, so deploy cannot replace it to
# let a second upgrade run beside one in progress. The lock older shims take,
# upgrade-state/upgrade.lock, is still taken too: the 0.10.1 shim that
# installs this one keeps running, holding only that lock, until its upgrade
# ends (tests/integration/test_shim_hop.py runs that hop for real).
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
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
for held in "$ROOT_LOCK" "$LEGACY_LOCK"; do
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

# Deploy renames the legacy lock away and leaves a fresh file while an upgrade
# holds both: the root-only lock still stops a second upgrade.
new_root a
hold "$BOXMUNGE_ROOT/$ROOT_LOCK"
exec 6<>"$BOXMUNGE_ROOT/$LEGACY_LOCK"
flock -n 6
mv "$BOXMUNGE_ROOT/$LEGACY_LOCK" "$BOXMUNGE_ROOT/upgrade-state/moved-away"
: > "$BOXMUNGE_ROOT/$LEGACY_LOCK"
PATH="$FAILVISUDO:$PATH" run_shim target 1.2.3
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

# Deploy can unlink root's legacy lock and hold a flock on its own file at the
# name. Only root runs upgrades, so a lock file that is not root's is no real
# lock: it is replaced with root's, loudly, and the run goes on. Needs root
# (to make a file another user owns).
if [[ "$(id -u)" -eq 0 ]]; then
    new_root a
    record_bm_log
    write_probation 1.2.3 b "2000-01-01T00:00:00+00:00"
    : > "$BOXMUNGE_ROOT/$LEGACY_LOCK"
    chown nobody "$BOXMUNGE_ROOT/$LEGACY_LOCK"
    exec 6<>"$BOXMUNGE_ROOT/$LEGACY_LOCK"
    flock -n 6
    run_shim check-probation
    expect 0 "promoted" "a lock file deploy planted and holds does not stall the probation"
    [[ "$OUT" == *"is not root's"* && "$(stat -c %u "$BOXMUNGE_ROOT/$LEGACY_LOCK")" == 0 ]] \
        && pass "it is replaced with root's, with a warning" || fail "out: $OUT; $(ls -l "$BOXMUNGE_ROOT/$LEGACY_LOCK")"
    [[ "$(cat "$BOXMUNGE_ROOT/calls")" == *"bm_log warn legacy upgrade lock not root's: replaced"* ]] \
        && pass "the replacement is in the operational log" || fail "not logged: $(cat "$BOXMUNGE_ROOT/calls")"
    exec 6>&-
    drop_root

    # Root's own 0644 legacy lock (as a 0.10.1 shim left it) is made 0600, so
    # deploy can no longer open it to lock it.
    new_root a
    : > "$BOXMUNGE_ROOT/$LEGACY_LOCK"
    chmod 0644 "$BOXMUNGE_ROOT/$LEGACY_LOCK"
    chmod 0711 "$BOXMUNGE_ROOT"; chmod 0777 "$BOXMUNGE_ROOT/upgrade-state"
    run_shim check-probation
    if su -s /bin/bash nobody -c "exec 7<'$BOXMUNGE_ROOT/$LEGACY_LOCK'" 2>/dev/null; then
        fail "deploy can still open the legacy lock"
    else
        pass "deploy can no longer open root's legacy lock"
    fi
    drop_root

    # A deploy loop re-creating its own lock file as root replaces it: every
    # run either takes the lock or counts a skip; none dies uncounted.
    new_root a
    chmod 0711 "$BOXMUNGE_ROOT"; chmod 0777 "$BOXMUNGE_ROOT/upgrade-state"
    racer="$(mktemp -d)"
    chmod 0777 "$racer"
    su -s /bin/bash nobody -c "echo \$\$ > '$racer/pid'; while :; do [[ -e '$BOXMUNGE_ROOT/$LEGACY_LOCK' ]] || : > '$BOXMUNGE_ROOT/$LEGACY_LOCK' 2>/dev/null; done" \
        </dev/null >/dev/null 2>&1 &
    until [[ -s "$racer/pid" ]]; do sleep 0.1; done
    fatal=0
    for _ in 1 2 3 4 5; do
        run_shim check-probation
        [[ "$RC" -eq 0 && "$OUT" != *FATAL* ]] || fatal=$((fatal + 1))
    done
    kill -9 "$(cat "$racer/pid")"
    wait 2>/dev/null || true
    rm -rf "$racer"
    [[ "$fatal" -eq 0 ]] && pass "a racing deploy never makes check-probation die uncounted" \
        || fail "$fatal runs died: $OUT"
    drop_root
fi

# Shims up to 0.10.1 created the legacy lock 0644, which deploy can open
# read-only and lock. Every entry point that takes the lock makes it 0600, so
# deploy cannot newly open it.
for args in "check-probation" "run 1.2.3 ignored-url" "target 1.2.3"; do
    new_root a
    : > "$BOXMUNGE_ROOT/$LEGACY_LOCK"
    chmod 0644 "$BOXMUNGE_ROOT/$LEGACY_LOCK"
    # shellcheck disable=SC2086  # word-split the subcommand on purpose
    PATH="$FAILVISUDO:$PATH" run_shim $args
    [[ "$(mode_of "$BOXMUNGE_ROOT/$LEGACY_LOCK")" == 600 ]] && pass "${args%% *} makes a 0644 legacy lock 0600" \
        || fail "${args%% *} left the legacy lock $(mode_of "$BOXMUNGE_ROOT/$LEGACY_LOCK")"
    drop_root
done

# Deploy can win the race between root replacing a lock file that is not
# root's and opening it again. The opener then says so, and check-probation
# counts it like a held lock (so an hour of it is an error), rather than
# dying where nothing counts it; an upgrade refuses, logged.
new_root a
record_bm_log
RC=0
OUT="$(BM_UPGRADE_LOCK_FOREIGN="$BOXMUNGE_ROOT/$LEGACY_LOCK" bash "$SHIM" check-probation 2>&1)" || RC=$?
expect 0 "skipping (1 in a row: $BOXMUNGE_ROOT/$LEGACY_LOCK was not root's when opened)" \
    "a lock deploy swapped in as root opened it is a counted skip"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips")" == 1 ]] && pass "the skip is counted" || fail "not counted"
RC=0
OUT="$(BM_UPGRADE_LOCK_FOREIGN="$BOXMUNGE_ROOT/$LEGACY_LOCK" bash "$SHIM" target 1.2.3 2>&1)" || RC=$?
expect 1 "was replaced by a file that is not root's as it was opened" "an upgrade refuses it"
[[ "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" == *"bm_log error"*"not root's as it was opened"* ]] \
    && pass "and logs the refusal" || fail "not logged: $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
drop_root

finish
