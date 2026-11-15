# shellcheck shell=bash
# locks.sh — upgrade.lock, one upgrade at a time, and the jobs gate, which
# keeps an upgrade and running jobs apart.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.
#
# Every running job holds state/jobs/gate.lock shared (api/job_gate.py), and
# no job starts while it is held exclusively. acquire_lock opens it on fd 8
# and, with upgrade.lock held, takes it (take_jobs_gate): an upgrade waits for
# running jobs, as it waits for a held lock; check-probation skips.

LOCK_HELD=0
# How long the auto-update timer's run waits for upgrade.lock (acquire_lock).
LOCK_WAIT_SECS=900
# How long an upgrade waits for running jobs to finish: 3600, which the
# messages give as 60 minutes. The environment override is a test knob only
# (sudo and the timers start the shim with a clean environment).
JOBS_GATE_WAIT_SECS="${JOBS_GATE_WAIT_SECS:-3600}"
[[ "$JOBS_GATE_WAIT_SECS" =~ ^[1-9][0-9]*$ ]] || die "JOBS_GATE_WAIT_SECS must be a positive number of seconds, not '$(printable "$JOBS_GATE_WAIT_SECS")'"
# When an upgrade began waiting for jobs (epoch seconds), written under
# upgrade.lock and removed once the wait ends; root-only, as upgrade-root/ is.
JOBS_WAIT_FILE="$UPGRADE_ROOT_DIR/jobs-wait"
JOBS_GATE_HELD=0

# take_jobs_gate [skip|wait]: flock fd 8 exclusively, once per run. "skip" skips at once
# while jobs run, with no count and no alert: a job is not stuck upgrade work,
# and an upgrade bounds its own wait. Any other mode waits up to
# JOBS_GATE_WAIT_SECS for running jobs, then dies, logged.
take_jobs_gate() {
    [[ "$JOBS_GATE_HELD" -eq 0 ]] || return 0
    if flock -n 8; then
        rm -f "$JOBS_WAIT_FILE"  # one a killed wait left
        JOBS_GATE_HELD=1
        return 0
    fi
    if [[ "$1" == "skip" ]]; then
        log "Jobs are running; skipping until they finish (see: boxmunge jobs --running)"
        exit 0
    fi
    log "Waiting up to 60 minutes for running jobs to finish (see: boxmunge jobs --running)"
    bm_log info upgrade "Waiting up to 60 minutes for running jobs to finish (see: boxmunge jobs --running)"
    write_root_file "$JOBS_WAIT_FILE" "$(date +%s)"
    local rc=0
    flock -w "$JOBS_GATE_WAIT_SECS" 8 || rc=$?
    rm -f "$JOBS_WAIT_FILE"
    [[ "$rc" -eq 0 ]] \
        || die_logged "Jobs were still running after the 60 minutes this upgrade waited, so nothing was installed. See them with: boxmunge jobs --running; the upgrade can be run again once they finish."
    JOBS_GATE_HELD=1
}

# skip_while_upgrade_waits_for_jobs: check-probation found upgrade.lock held.
# If its holder is an upgrade waiting for jobs (JOBS_WAIT_FILE, written within
# the wait), skip without feeding lock-skips: that wait is bounded, and fails
# loudly at its end. A marker older than the wait is one a killed upgrade
# left, so the skip is counted as usual.
skip_while_upgrade_waits_for_jobs() {
    local since
    since="$(cat "$JOBS_WAIT_FILE" 2>/dev/null)" || return 0
    [[ "$since" =~ ^[0-9]+$ ]] || return 0
    local age=$(( $(date +%s) - since ))
    [[ "$age" -ge 0 && "$age" -le "$JOBS_GATE_WAIT_SECS" ]] || return 0  # a future one is no wait
    log "An upgrade is waiting for running jobs; skipping"
    exit 0
}

# acquire_lock [skip|try|wait|nogate]: take upgrade.lock once per run. With "skip",
# a busy lock exits 0 (the health timer retries on its next fire); with "try"
# (a readiness check), it returns 1 and counts no skip; with "wait" (the
# auto-update timer's run, whose discovery waited the same), it waits up to
# LOCK_WAIT_SECS, as a readiness check holds the lock for up to ten minutes,
# then dies, logged; otherwise it dies at once. Only "try" leaves
# check-probation's skip count (lock-skips) alone when it takes the lock: a
# readiness check is not a check-probation run.
#
# upgrade.lock is in root-only upgrade-root/, so deploy cannot replace it to
# let a second upgrade run. Every shim and release an upgrade can start from
# excludes the others on it. Every bash redirection follows a link, and the
# writing ones create a missing target, so bash never opens it:
# open_lock_and_reexec has Python open it without following a link or
# blocking on a FIFO, refuse anything but a plain regular file of root's, put
# it on fd 9 and run this shim again with the same arguments. That run finds
# BM_UPGRADE_LOCK_FD=9 and checks fd 9 is the lock file before it takes the
# flock.
#
# Then the jobs gate, state/jobs/gate.lock, on fd 8 (BM_JOBS_GATE_FD=8): every
# running job holds it shared (api/job_gate.py), and an upgrade takes it
# exclusively, so it waits for running jobs as it waits for a held lock, and
# no new job starts until it ends (take_jobs_gate, above). "try" (the
# readiness check, which installs nothing) does not take the gate; nor does
# "nogate" (auto's discovery, which may find nothing to install): a later
# acquire_lock, with the lock held, takes it. state/jobs/
# is deploy's, so the gate is opened without following a link, and made with
# its directory if missing (see open_lock_and_reexec). Children,
# the userns verbs' among them, inherit fds 8 and 9 and the locks with them.
acquire_lock() {
    if [[ "$LOCK_HELD" -eq 1 ]]; then
        [[ "${1:-}" == "try" || "${1:-}" == "nogate" ]] || take_jobs_gate "${1:-}"
        return 0
    fi
    if [[ "${BM_UPGRADE_LOCK_FD:-}" != 9 || "${BM_JOBS_GATE_FD:-}" != 8 ]]; then
        refuse_symlink "$UPGRADE_ROOT_DIR"
        [[ -d "$UPGRADE_ROOT_DIR" ]] || mkdir -m 0700 "$UPGRADE_ROOT_DIR"
        refuse_symlink "$LOCK_FILE"
        refuse_symlink "$BOXMUNGE_ROOT/state"
        refuse_symlink "$JOBS_DIR"
        refuse_symlink "$JOBS_GATE_FILE"
        open_lock_and_reexec
    fi
    unset BM_UPGRADE_LOCK_FD BM_JOBS_GATE_FD  # children inherit fds 8 and 9, never the claim that they are checked
    local why
    why="$(python3 -c 'import os, stat, sys
for fd, path in ((9, sys.argv[1]), (8, sys.argv[2])):
    try:
        held, name = os.fstat(fd), os.lstat(path)
    except OSError:
        sys.exit(f"fd {fd} is not {path}")
    if not (stat.S_ISREG(held.st_mode) and (held.st_dev, held.st_ino) == (name.st_dev, name.st_ino)):
        sys.exit(f"fd {fd} is not {path}")' "$LOCK_FILE" "$JOBS_GATE_FILE" 2>&1)" \
        || die "$why (it was replaced, or the descriptor came from elsewhere); refusing to lock it. Remove it and re-run."
    if [[ "${1:-}" == wait ]]; then
        if ! flock -w "$LOCK_WAIT_SECS" 9; then
            die_logged "upgrade.lock was held for the whole $((LOCK_WAIT_SECS / 60)) minutes the auto-update timer waited, so nothing was installed; it tries again on its next run. Find the holder as supervisor: sudo lslocks | grep upgrade.lock"
        fi
    elif ! flock -n 9; then
        [[ "${1:-}" != "skip" ]] || skip_while_upgrade_waits_for_jobs
        [[ "${1:-}" != "skip" ]] || lock_busy_skip "upgrade.lock is held"
        [[ "${1:-}" != "try" ]] || return 1
        die "Another upgrade is in progress"
    fi
    [[ "${1:-}" == "try" || "${1:-}" == "nogate" ]] || take_jobs_gate "${1:-}"
    [[ "${1:-}" == "try" ]] || rm -f "$LOCK_SKIPS_FILE"
    LOCK_HELD=1
}

# lock_busy_skip <why>: check-probation could not take upgrade.lock (<why>),
# and retries on the next health-timer fire (every five minutes). One skip is routine;
# LOCK_SKIPS_ALERT in a row (an hour) is not: no upgrade holds the lock that
# long, so something else does, and no
# probation is promoted or rolled back meanwhile. The count is kept in
# root-only upgrade-root/ (only the health timer skips, one run at a time),
# and an error goes to the operational log at every LOCK_SKIPS_ALERT.
LOCK_SKIPS_FILE="$UPGRADE_ROOT_DIR/lock-skips"
LOCK_SKIPS_ALERT=12
lock_busy_skip() {
    local count
    count="$(cat "$LOCK_SKIPS_FILE" 2>/dev/null)" || true
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    count=$((count + 1))
    write_root_file "$LOCK_SKIPS_FILE" "$count"
    log "Another upgrade is in progress; skipping ($count in a row: $1)"
    [[ $((count % LOCK_SKIPS_ALERT)) -ne 0 ]] || bm_log error upgrade \
        "check-probation could not take upgrade.lock $count times in a row (last: $1), so no probation is promoted or rolled back. Find the holder as supervisor: sudo lslocks | grep upgrade.lock"
    exit 0
}

# open_lock_and_reexec: see acquire_lock. Replaces this process; prints a
# FATAL line like die() when a lock file cannot be used. The gate is opened
# read-only (flock needs no more) under descriptors for state/ and jobs/, none
# followed if a link. A missing jobs/ or gate is made as install makes them
# (jobs/ deploy:deploy 0750, the gate O_EXCL, deploy:deploy 0660), so a box
# whose installer has not yet run this release's steps (the hop from 0.11.11)
# still upgrades; one a job's open made first is used as found.
open_lock_and_reexec() {
    exec python3 -c '
import errno, fcntl, os, stat, sys, time
lock, state, shell, shim, args = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]

def die(message):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sys.exit(f"{now} boxmunge-upgrade: FATAL: {message}")

def fatal(path, what):
    die(f"{path} {what}; refusing to use it as root. Remove it and re-run.")

def refused(path, e, linked="is a symlink"):
    planted = e.errno in (errno.ELOOP, errno.ENOTDIR)
    fatal(path, linked if planted else f"cannot be opened ({e.strerror})")

def deploy_owner():  # settled before anything is made, so nothing is left root-owned
    if os.geteuid() != 0:
        return None
    import grp, pwd
    try:
        return pwd.getpwnam("deploy").pw_uid, grp.getgrnam("deploy").gr_gid
    except KeyError:
        die(f"{gate} or its directory is missing, and there is no deploy user and group to own it; "
            "reinstall as root (sudo bash boxmunge-install.sh)")

def made(path, fd, mode, owner):
    try:
        if owner is not None:
            os.fchown(fd, *owner)
        os.fchmod(fd, mode)
    except OSError as e:
        fatal(path, f"was made, but not given its owner and mode ({e.strerror})")

def above_9(fd):  # out of the way of fds 8 and 9 until both are placed
    high = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(fd)
    return high

try:
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
except OSError as e:
    refused(lock, e)
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
    fatal(lock, "is not a plain regular file")
if st.st_uid != os.geteuid():
    fatal(lock, "is not root\x27s")
os.set_blocking(fd, True)
lock_fd = above_9(fd)

directory = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
jobs, gate = f"{state}/jobs", f"{state}/jobs/gate.lock"
not_a_dir = "is a symlink or not a directory"
try:
    state_fd = os.open(state, directory)
except OSError as e:
    refused(state, e, not_a_dir)
try:
    jobs_fd = os.open("jobs", directory, dir_fd=state_fd)
except FileNotFoundError:
    owner, created = deploy_owner(), True
    try:
        os.mkdir("jobs", 0o750, dir_fd=state_fd)
    except FileExistsError:
        created = False
    except OSError as e:
        refused(jobs, e, not_a_dir)
    try:
        jobs_fd = os.open("jobs", directory, dir_fd=state_fd)
    except OSError as e:
        refused(jobs, e, not_a_dir)
    # state/ is deploy-writable: between the mkdir and the open, deploy could
    # rename another directory in. Only the empty one root just made is given.
    if created and (os.fstat(jobs_fd).st_uid != os.geteuid() or os.listdir(jobs_fd)):
        fatal(jobs, "was replaced while being made")
    if created:
        made(jobs, jobs_fd, 0o750, owner)
except OSError as e:
    refused(jobs, e, not_a_dir)
flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
try:
    fd = os.open("gate.lock", flags, dir_fd=jobs_fd)
except FileNotFoundError:
    owner, created = deploy_owner(), True
    try:
        fd = os.open("gate.lock", flags | os.O_CREAT | os.O_EXCL, 0o660, dir_fd=jobs_fd)
    except FileExistsError:
        created = False
        try:
            fd = os.open("gate.lock", flags, dir_fd=jobs_fd)
        except OSError as e:
            refused(gate, e)
    except OSError as e:
        refused(gate, e)
    if created:
        made(gate, fd, 0o660, owner)
except OSError as e:
    refused(gate, e)
if not stat.S_ISREG(os.fstat(fd).st_mode):
    fatal(gate, "is not a regular file")
os.set_blocking(fd, True)
gate_fd = above_9(fd)
os.close(jobs_fd)
os.close(state_fd)

for high, low in ((lock_fd, 9), (gate_fd, 8)):
    os.dup2(high, low)
    os.close(high)
os.environ["BM_UPGRADE_LOCK_FD"] = "9"
os.environ["BM_JOBS_GATE_FD"] = "8"
os.execv(shell, [shell, shim, *args])
' "$LOCK_FILE" "$BOXMUNGE_ROOT/state" "$BASH" "$SHIM_PATH" "${SHIM_ARGS[@]+"${SHIM_ARGS[@]}"}"
}
