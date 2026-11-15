# shellcheck shell=bash
# jobsgate.sh — an upgrade and running jobs, kept apart on the jobs gate.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.
#
# Every running job holds state/jobs/gate.lock shared (api/job_gate.py), and
# no job starts while it is held exclusively. acquire_lock (state.sh) opens it
# on fd 8 and, with upgrade.lock held, takes it here: an upgrade waits for
# running jobs, as it waits for a held lock; check-probation skips.

# How long an upgrade waits for running jobs to finish. The messages say 60
# minutes; a test may shorten the wait (sudo and the timers start the shim
# with a clean environment).
JOBS_GATE_WAIT_SECS="${JOBS_GATE_WAIT_SECS:-3600}"
[[ "$JOBS_GATE_WAIT_SECS" =~ ^[0-9]+$ ]] || die "JOBS_GATE_WAIT_SECS must be a number of seconds, not '$(printable "$JOBS_GATE_WAIT_SECS")'"
# When an upgrade began waiting for jobs (epoch seconds), written under
# upgrade.lock and removed once the wait ends; root-only, as upgrade-root/ is.
JOBS_WAIT_FILE="$UPGRADE_ROOT_DIR/jobs-wait"

# take_jobs_gate [skip|wait]: flock fd 8 exclusively. "skip" skips at once
# while jobs run, with no count and no alert: a job is not stuck upgrade work,
# and an upgrade bounds its own wait. Any other mode waits up to
# JOBS_GATE_WAIT_SECS for running jobs, then dies, logged.
take_jobs_gate() {
    if flock -n 8; then
        rm -f "$JOBS_WAIT_FILE"  # one a killed wait left
        return 0
    fi
    if [[ "$1" == "skip" ]]; then
        log "Jobs are running; skipping until they finish (see: boxmunge jobs --running)"
        exit 0
    fi
    log "Waiting up to 60 minutes for running jobs to finish (see: boxmunge jobs --running)"
    write_root_file "$JOBS_WAIT_FILE" "$(date +%s)"
    local rc=0
    flock -w "$JOBS_GATE_WAIT_SECS" 8 || rc=$?
    rm -f "$JOBS_WAIT_FILE"
    [[ "$rc" -eq 0 ]] \
        || die_logged "Jobs were still running after the 60 minutes this upgrade waited, so nothing was installed. See them with: boxmunge jobs --running; the upgrade can be run again once they finish."
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
    [[ $(( $(date +%s) - since )) -le "$JOBS_GATE_WAIT_SECS" ]] || return 0
    log "An upgrade is waiting for running jobs; skipping"
    exit 0
}
