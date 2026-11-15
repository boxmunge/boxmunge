#!/usr/bin/env bash
# tests/shim/test_jobs_gate.sh — an upgrade waits for running jobs.
#
# Every running job holds state/jobs/gate.lock shared (api/job_gate.py); the
# upgrade shim takes it exclusively, after upgrade.lock, and holds both for the
# whole run. An upgrade waits for running jobs to finish, up to
# JOBS_GATE_WAIT_SECS, as it waits for a held lock; check-probation takes it
# only right before it changes a slot or the units, and skips instead; the
# readiness check, which installs nothing, never takes it.
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
record_bm_log
hold_shared
PATH="$FAILVISUDO:$PATH" bash "$SHIM" target 1.2.3 > "$BOXMUNGE_ROOT/run.out" 2>&1 7<&- &
waiter=$!
for _ in $(seq 600); do  # up to a minute for the upgrade to reach its wait
    [[ ! -s "$BOXMUNGE_ROOT/upgrade-root/jobs-wait" ]] && kill -0 "$waiter" 2>/dev/null || break
    sleep 0.1
done
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
grep -q "^bm_log info Waiting up to 60 minutes for running jobs to finish" "$BOXMUNGE_ROOT/calls" \
    && pass "the wait is in the operational log" || fail "wait not logged: $(cat "$BOXMUNGE_ROOT/calls" 2>&1)"
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

# test_check_probation_skips_while_a_job_runs: a run with a slot to change
# (here the orphan standby, env-b) skips, with no count and no alert, however
# many in a row (a job is not stuck upgrade work). It took upgrade.lock, so
# the held-lock count starts again.
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
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/lock-skips" && "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" != *"bm_log error"* ]] \
    && pass "skips for running jobs feed no lock-skip count and raise no alert" \
    || fail "count $(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips" 2>&1), calls: $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
[[ -d "$BOXMUNGE_ROOT/env-b" ]] && pass "the skipped run left the orphan slot alone" || fail "env-b removed under a job"
run_shim check-probation
expect 0 "Cleaning up orphan venv in inactive slot b" "check-probation runs once the job finishes"
drop_root

# test_probation_health_run_leaves_jobs_free: check-probation holds
# upgrade.lock for its whole run, but the gate only right before it changes a
# slot or the units, never across its health run (up to 180 s, every five
# minutes for the whole probation). A job that starts meanwhile, taking the
# gate shared, is not held up, and nothing is skipped.
new_root a
record_bm_log
write_probation 1.2.3 b "$SOON"
# shellcheck disable=SC2016  # a mock body: literal bash
mock_server a 'if [[ "$1" == health ]]; then
    python3 -c "import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)" "$BOXMUNGE_ROOT/state/jobs/gate.lock" \
        && echo "job took the gate" >> "$BOXMUNGE_ROOT/calls" || echo "job refused" >> "$BOXMUNGE_ROOT/calls"
    exec health-report 0
fi
exit 0'
run_shim check-probation
expect 0 "" "check-probation runs its probation health check"
grep -q "^job took the gate" "$BOXMUNGE_ROOT/calls" \
    && pass "a job takes the gate shared while the probation health run runs" \
    || fail "the gate was held across the health run: $(cat "$BOXMUNGE_ROOT/calls" 2>&1) / $OUT"
[[ "$OUT" != *"Jobs are running"* && -d "$BOXMUNGE_ROOT/env-b" ]] \
    && pass "a mid-probation run changes nothing, so takes no gate" || fail "said: $OUT"
drop_root

# ... and a job that runs through a mid-probation run holds nothing up.
new_root a
write_probation 1.2.3 b "$SOON"
hold_shared
RC=0; OUT="$(bash "$SHIM" check-probation 2>&1 7<&-)" || RC=$?
exec 7<&-
[[ "$RC" -eq 0 && "$OUT" != *"Jobs are running"* ]] \
    && pass "a mid-probation run goes ahead while a job runs" || fail "rc=$RC: $OUT"
drop_root

# test_promotion_waits_for_jobs: promotion removes the previous slot, so it
# takes the gate first, and skips while a job runs.
new_root a
write_probation 1.2.3 b "2020-01-01T00:00:00+00:00"
hold_shared
RC=0; OUT="$(bash "$SHIM" check-probation 2>&1 7<&-)" || RC=$?
exec 7<&-
expect 0 "Jobs are running; skipping until they finish" "an expired probation is not promoted while a job runs"
[[ -d "$BOXMUNGE_ROOT/env-b" && -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
    && pass "the previous slot and the probation are left for the next run" || fail "promoted under a running job"
run_shim check-probation
expect 0 "Version 1.2.3 promoted" "it is promoted once the job finishes"
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
echo $(( $(date +%s) + 600 )) > "$BOXMUNGE_ROOT/upgrade-root/jobs-wait"
PATH="$BUSYLOCK:$PATH" run_shim check-probation
expect 0 "skipping (13 in a row: upgrade.lock is held)" "a future-dated wait record does not hide a held lock"
drop_root

# The wait is a test knob, never zero or less.
new_root a
JOBS_GATE_WAIT_SECS=0 run_shim check-probation
expect 1 "JOBS_GATE_WAIT_SECS must be a positive number of seconds, not '0'" "a zero wait is refused"
drop_root

# auto takes the gate only once discovery names an upgrade: with nothing to
# install, a running job holds nothing up, and nothing is logged.
for answer in up_to_date upgrade; do
    new_root a
    record_bm_log
    body='[[ "$1" != _discover-update ]] || { echo "{\"action\": \"'"$answer"'\", \"version\": \"1.2.3\", \"class\": \"feature\"}"; exit 0; }'
    mock_server a "$body"
    hold_shared
    RC=0
    OUT="$(JOBS_GATE_WAIT_SECS=1 PATH="$FAILVISUDO:$PATH" bash "$SHIM" auto 2>&1 7<&-)" || RC=$?
    exec 7<&-
    if [[ "$answer" == up_to_date ]]; then
        expect 0 "Already on latest version" "auto with nothing to install goes ahead while a job runs"
        [[ "$OUT" != *"Waiting up to"* && "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" != *"bm_log error"* ]] \
            && pass "auto with nothing to install never waits for jobs, and logs no error" \
            || fail "waited or logged: $OUT / $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
    else
        expect 1 "Waiting up to 60 minutes for running jobs" "auto that found an upgrade waits for running jobs"
        expect 1 "Jobs were still running after the 60 minutes" "and gives up at the end of its wait"
    fi
    drop_root
done

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

# Deploy, who may write state/, swaps another directory in at state/jobs
# between root's mkdir and its open: the stand-in is refused, not given.
RACE="$(mktemp -d)"
REAL_PYTHON3="$(command -v python3)"
cat > "$RACE/python3" <<EOS
#!/usr/bin/env bash
if [[ "\$1" == -c && "\$2" == *'os.mkdir("jobs"'* ]]; then
    script="\$2"; shift 2
    exec $(printf %q "$REAL_PYTHON3") -c "import os as _os
_mkdir = _os.mkdir
def _swap(name, mode=0o777, *, dir_fd=None):
    _mkdir(name, mode, dir_fd=dir_fd)
    _os.rename(name, name + '.moved', src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    _os.rename(_os.environ['STANDIN'], name, dst_dir_fd=dir_fd)
_os.mkdir = _swap
\$script" "\$@"
fi
exec $(printf %q "$REAL_PYTHON3") "\$@"
EOS
chmod +x "$RACE/python3"
new_root a
mkdir -m 0700 "$BOXMUNGE_ROOT/state/standin"
: > "$BOXMUNGE_ROOT/state/standin/keep"
STANDIN="$BOXMUNGE_ROOT/state/standin" PATH="$RACE:$PATH" run_shim check-probation
expect 1 "state/jobs was replaced while being made" "a directory swapped in while jobs/ is made is refused"
[[ "$(mode_of "$BOXMUNGE_ROOT/state/jobs")" == 700 && ! -e "$BOXMUNGE_ROOT/state/jobs/gate.lock" ]] \
    && pass "the swapped-in directory is left as it was" || fail "changed: $(ls -la "$BOXMUNGE_ROOT/state/jobs" 2>&1)"
drop_root
rm -rf "$RACE"

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
