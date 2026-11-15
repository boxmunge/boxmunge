#!/usr/bin/env bash
# tests/shim/test_jobs_gate.sh — an upgrade waits for running jobs.
#
# Every running job holds state/jobs/gate.lock shared (api/job_gate.py); the
# upgrade shim takes it exclusively, after upgrade.lock, and holds both for the
# whole run. An upgrade waits for running jobs to finish, up to
# JOBS_GATE_WAIT_SECS, as it waits for a held lock; check-probation skips
# instead, and the readiness check, which installs nothing, never takes it.
# state/jobs/ is deploy's, so the gate is opened without following a link,
# and a missing one is made with its directory, deploy's, as install makes them.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

GATE="state/jobs/gate.lock"

mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# hold_shared: take the gate shared through fd 7 of this test shell, as a
# running job does; release it with `exec 7<&-`. The lock belongs to the open
# file description, so it outlives the python that took it.
hold_shared() {
    mkdir -p "$BOXMUNGE_ROOT/state/jobs"
    : >> "$BOXMUNGE_ROOT/$GATE"
    exec 7<"$BOXMUNGE_ROOT/$GATE"
    python3 -c 'import fcntl; fcntl.flock(7, fcntl.LOCK_SH | fcntl.LOCK_NB)' \
        || { echo "could not take the gate shared for the test" >&2; exit 1; }
}

# record_bm_log: the live slot's python records what bm_log writes.
record_bm_log() {
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; fi' \
        > "$BOXMUNGE_ROOT/env-a/bin/python"
}

# test_upgrade_waits_for_a_shared_holder_then_proceeds
new_root a
hold_shared
PATH="$FAILVISUDO:$PATH" bash "$SHIM" target 1.2.3 > "$BOXMUNGE_ROOT/run.out" 2>&1 7<&- &
waiter=$!
sleep 2
kill -0 "$waiter" 2>/dev/null && pass "an upgrade waits while a job holds the gate" \
    || fail "the upgrade did not wait: $(cat "$BOXMUNGE_ROOT/run.out")"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/jobs-wait" 2>/dev/null)" =~ ^[0-9]+$ ]] \
    && pass "the waiting upgrade records when its wait began" || fail "no jobs-wait record"
exec 7<&-
RC=0; wait "$waiter" || RC=$?
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/jobs-wait" ]] && pass "the record goes once the wait ends" \
    || fail "jobs-wait left behind"
OUT="$(cat "$BOXMUNGE_ROOT/run.out")"
expect 1 "Waiting up to 60 minutes for running jobs to finish (see: boxmunge jobs --running)" \
    "the wait says what it waits for and where to see it"
expect 1 "failed visudo" "the upgrade goes ahead once the job finishes"
drop_root

# test_upgrade_dies_logged_after_the_wait
new_root a
record_bm_log
hold_shared
RC=0
OUT="$(JOBS_GATE_WAIT_SECS=1 PATH="$FAILVISUDO:$PATH" bash "$SHIM" target 1.2.3 2>&1 7<&-)" || RC=$?
exec 7<&-
expect 1 "Jobs were still running after the 60 minutes this upgrade waited, so nothing was installed. See them with: boxmunge jobs --running; the upgrade can be run again once they finish." \
    "an upgrade gives up after its wait, saying so"
[[ "$OUT" != *"failed visudo"* ]] && pass "nothing past the gate ran" || fail "went on: $OUT"
grep -q "^bm_log error Jobs were still running after the 60 minutes" "$BOXMUNGE_ROOT/calls" \
    && pass "the give-up is an error in the operational log" || fail "not logged: $(cat "$BOXMUNGE_ROOT/calls" 2>&1)"
drop_root

# test_check_probation_skips_while_a_job_runs: with no count and no alert,
# however many in a row (a job is not stuck upgrade work).
new_root a
record_bm_log
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
echo 11 > "$BOXMUNGE_ROOT/upgrade-root/lock-skips"
hold_shared
for _ in 1 2 3; do
    RC=0; OUT="$(bash "$SHIM" check-probation 2>&1 7<&-)" || RC=$?
done
exec 7<&-
expect 0 "Jobs are running; skipping until they finish (see: boxmunge jobs --running)" \
    "check-probation skips while a job runs"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips")" == 11 && "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" != *"bm_log error"* ]] \
    && pass "skips for running jobs feed no lock-skip count and raise no alert" \
    || fail "count $(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips"), calls: $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
run_shim check-probation
expect 0 "" "check-probation runs once the job finishes"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/lock-skips" ]] && pass "taking the gate resets the skip count" \
    || fail "count left: $(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips")"
drop_root

# An upgrade waiting for jobs holds upgrade.lock for up to 60 minutes: the
# check-probation runs it holds off skip with no count and no alert (the wait
# fails loudly at its end). A record older than the wait is one a killed
# upgrade left: that skip is counted, and alerts, as usual.
new_root a
record_bm_log
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
echo 11 > "$BOXMUNGE_ROOT/upgrade-root/lock-skips"
date +%s > "$BOXMUNGE_ROOT/upgrade-root/jobs-wait"
for _ in 1 2 3; do PATH="$BUSYLOCK:$PATH" run_shim check-probation; done
expect 0 "An upgrade is waiting for running jobs; skipping" "check-probation skips while an upgrade waits for jobs"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips")" == 11 && "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" != *"bm_log error"* ]] \
    && pass "skips while an upgrade waits for jobs feed no count and raise no lock alert" \
    || fail "count $(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips"), calls: $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
echo $(( $(date +%s) - 3700 )) > "$BOXMUNGE_ROOT/upgrade-root/jobs-wait"
PATH="$BUSYLOCK:$PATH" run_shim check-probation
expect 0 "skipping (12 in a row: upgrade.lock is held)" "a stale wait record does not hide a held lock"
[[ "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" == *"bm_log error check-probation could not take upgrade.lock 12 times"* ]] \
    && pass "the held lock alerts as usual" || fail "no alert: $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
drop_root

# test_readiness_check_does_not_take_the_gate: _check-run exits 75 when it
# cannot take the lock, 76 when it has it and the installed release differs
# from the one it names; with the gate held shared, 76 means it went past
# acquire_lock without waiting for (or trying) the gate.
new_root a
mkdir -p "$BOXMUNGE_ROOT/upgrade-check/out" "$BOXMUNGE_ROOT/upgrade-check/venv/bin"
printf '#!/usr/bin/env bash\nexit 0\n' > "$BOXMUNGE_ROOT/upgrade-check/venv/bin/boxmunge-server"
chmod +x "$BOXMUNGE_ROOT/upgrade-check/venv/bin/boxmunge-server"
hold_shared
RC=0; OUT="$(bash "$SHIM" _check-run 1.2.3 9.9.9 2>&1 7<&-)" || RC=$?
exec 7<&-
expect 76 "" "the readiness check takes upgrade.lock and not the gate"
[[ "$OUT" != *"Waiting up to"* ]] && pass "the readiness check never waits for jobs" || fail "waited: $OUT"
drop_root

# test_a_symlinked_gate_is_refused (and a linked jobs/ or state/, and a FIFO)
for planted in gate jobs state fifo file; do
    new_root a
    elsewhere="$(mktemp -d)"
    case "$planted" in
        gate) mkdir "$BOXMUNGE_ROOT/state/jobs"; ln -s "$elsewhere/gate.lock" "$BOXMUNGE_ROOT/$GATE"; want="gate.lock is a symlink" ;;
        jobs) ln -s "$elsewhere" "$BOXMUNGE_ROOT/state/jobs"; want="jobs is a symlink" ;;
        state) rm -rf "$BOXMUNGE_ROOT/state"; mkdir "$elsewhere/jobs"; ln -s "$elsewhere" "$BOXMUNGE_ROOT/state"; want="state is a symlink" ;;
        fifo) mkdir "$BOXMUNGE_ROOT/state/jobs"; mkfifo "$BOXMUNGE_ROOT/$GATE"; want="gate.lock is not a regular file" ;;
        file) : > "$BOXMUNGE_ROOT/state/jobs"; want="state/jobs is a symlink or not a directory" ;;
    esac
    run_shim_unless_blocked "$BOXMUNGE_ROOT/$GATE" check-probation
    expect 1 "$want" "a planted $planted is refused, not followed"
    [[ ! -e "$elsewhere/gate.lock" && ! -e "$elsewhere/jobs/gate.lock" ]] \
        && pass "no gate was created through the planted $planted" || fail "root created a gate through the planted $planted"
    rm -rf "$elsewhere"
    drop_root
done

# The opener itself, past acquire_lock's checks (a link swapped in after
# them): it refuses a linked gate, jobs/ or state/, and otherwise runs the
# shim again with upgrade.lock on fd 9 and the gate on fd 8.
PROBE="$(mktemp)"
printf '%s\n' '#!/usr/bin/env bash' \
    'echo "fds $BM_UPGRADE_LOCK_FD $BM_JOBS_GATE_FD"' \
    'python3 -c "import os, sys; [print(fd, os.fstat(fd).st_ino) for fd in (9, 8)]"' > "$PROBE"
# shellcheck disable=SC2034  # read by open_lock_and_reexec
open_directly() { SHIM_PATH="$PROBE"; SHIM_ARGS=(); open_lock_and_reexec; }
for planted in gate jobs state; do
    new_root a
    mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
    elsewhere="$(mktemp -d)"
    mkdir "$elsewhere/jobs"
    case "$planted" in
        gate) mkdir "$BOXMUNGE_ROOT/state/jobs"; ln -s "$elsewhere/jobs/gate.lock" "$BOXMUNGE_ROOT/$GATE"; want="$GATE is a symlink" ;;
        jobs) ln -s "$elsewhere/jobs" "$BOXMUNGE_ROOT/state/jobs"; want="state/jobs is a symlink or not a directory" ;;
        state) rm -rf "$BOXMUNGE_ROOT/state"; ln -s "$elsewhere" "$BOXMUNGE_ROOT/state"; want="/state is a symlink or not a directory" ;;
    esac
    RC=0; OUT="$(with_shim_functions open_directly 2>&1)" || RC=$?
    expect 1 "$want; refusing to use it as root" "the opener refuses a linked $planted itself"
    [[ ! -e "$elsewhere/jobs/gate.lock" ]] && pass "the opener made no gate through the linked $planted" \
        || fail "the opener created a gate through the linked $planted"
    rm -rf "$elsewhere"
    drop_root
done
new_root a
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
RC=0; OUT="$(with_shim_functions open_directly 2>&1)" || RC=$?
want="$(python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_ino, os.stat(sys.argv[2]).st_ino)' \
    "$BOXMUNGE_ROOT/upgrade-root/upgrade.lock" "$BOXMUNGE_ROOT/$GATE" 2>&1)"
[[ "$RC" -eq 0 && "$OUT" == *"fds 9 8"* && "$OUT" == *"9 ${want% *}"*"8 ${want#* }"* ]] \
    && pass "the shim runs again with upgrade.lock on fd 9 and the gate on fd 8" \
    || fail "rc=$RC want inodes $want: $OUT"
drop_root
rm -f "$PROBE"

# test_a_missing_gate_is_created_deploy_owned: a missing state/jobs/ (0750)
# and gate (0660) are made as install makes them, deploy's when root runs the
# shim (as on a box); a test run as another user cannot give a file away, so
# it checks the modes and that each is a plain directory or file.
new_root a
run_shim check-probation
expect 0 "" "check-probation runs with no jobs directory or gate yet"
[[ -d "$BOXMUNGE_ROOT/state/jobs" && ! -L "$BOXMUNGE_ROOT/state/jobs" && "$(mode_of "$BOXMUNGE_ROOT/state/jobs")" == 750 ]] \
    && pass "a missing jobs directory is made, a plain directory, 0750" \
    || fail "jobs: $(ls -ld "$BOXMUNGE_ROOT/state/jobs" 2>&1)"
[[ -f "$BOXMUNGE_ROOT/$GATE" && ! -L "$BOXMUNGE_ROOT/$GATE" && "$(mode_of "$BOXMUNGE_ROOT/$GATE")" == 660 ]] \
    && pass "a missing gate is made, a plain file, 0660" \
    || fail "gate: $(ls -l "$BOXMUNGE_ROOT/$GATE" 2>&1)"
[[ "$OUT" != *FATAL* && "$OUT" != *ERROR* ]] && pass "making them logs nothing alarming" || fail "said: $OUT"
if [[ "$(id -u)" -eq 0 ]] && id deploy >/dev/null 2>&1; then
    for made in state/jobs "$GATE"; do
        owner="$(stat -c %U:%G "$BOXMUNGE_ROOT/$made" 2>/dev/null || stat -f %Su:%Sg "$BOXMUNGE_ROOT/$made")"
        [[ "$owner" == deploy:deploy ]] && pass "root makes $made deploy:deploy" || fail "$made owned by $owner"
    done
fi
drop_root

finish
