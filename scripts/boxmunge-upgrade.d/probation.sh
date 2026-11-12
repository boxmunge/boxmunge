# shellcheck shell=bash
# probation.sh — reading probation.json, deferring upgrades while a release
# is unproven, and check-probation: finishing interrupted rollbacks and
# upgrades, promotion, and rollback.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# A probation and root's record of it. probation.json is deploy-writable:
# deploy may end a probation early (by removing it), but must neither start
# one nor lengthen one, or it could defer every upgrade for good. So
# upgrade_to records each probation it starts, before writing probation.json,
# in root-only upgrade-root/probation-expiry:
#   "<slot> <version> <expiry>"  the live slot, the release on probation, and
#                                when the probation ends (seconds since 1970)
#   "none"                       no probation since the last one ended
# A probation.json that does not match the record (its live slot and version)
# was not started by an upgrade: it is removed, logged and alerted
# (refuse_unrecorded_probation). The probation ends at the earlier of the
# recorded expiry and expires_at. A recorded expiry more than a probation's
# length ahead means the clock went back (an NTP step, a VM restore); it is
# moved to a probation's length from now rather than promoting at once, which
# deleted the rollback target.
#
# A probation an older shim (0.11.5 or earlier) started has no record (none,
# or that shim's "<slot> <expiry>"). It is adopted when root's own state
# shows the upgrade it names (config/version is that release), and ends a
# probation's length after env-active was swapped: one past that (the box was
# off, say) is promoted at once, which is all a planted one could make
# happen, and the record then says none is running. Otherwise it is refused
# like any unrecorded one.
# The adoption goes when the upgrade floor reaches 0.11.6.
PROBATION_EXPIRY_FILE="$UPGRADE_ROOT_DIR/probation-expiry"

# record_probation <version>: root's record of a probation starting now.
record_probation() {
    write_root_file "$PROBATION_EXPIRY_FILE" "$ACTIVE_SLOT $1 $(( $(date +%s) + PROBATION_HOURS * 3600 ))"
}

# read_probation: parse probation.json, against root's record, into
# PROB_VERSION, PROB_PREV_SLOT, PROB_EXPIRED (yes/no), PROB_EXPIRES_AT
# (re-formatted in UTC, so safe to print), PROB_STATUS (recorded, adopted or
# unrecorded), PROB_NOTE (clock_back, lengthened or nothing), PROB_RECORD (the
# record to keep) and PROB_RECORDED (the record as found). It changes nothing:
# settle_probation acts on the result.
read_probation() {
    local out content installed valid='^([ab] [^ ]+ [0-9]+|[ab] [0-9]+|none)$'
    refuse_symlink "$PROBATION_FILE"
    content="$(read_untrusted "$PROBATION_FILE")" || exit 1
    refuse_symlink "$PROBATION_EXPIRY_FILE"
    PROB_RECORDED=""
    [[ ! -e "$PROBATION_EXPIRY_FILE" ]] || PROB_RECORDED="$(cat "$PROBATION_EXPIRY_FILE")"
    [[ -z "$PROB_RECORDED" || "$PROB_RECORDED" =~ $valid ]] \
        || die_logged "$PROBATION_EXPIRY_FILE is malformed. As supervisor, remove it and $PROBATION_FILE: that ends the probation, keeping the live release"
    installed="$(installed_version)"
    out="$(printf '%s' "$content" | BM_RECORDED="$PROB_RECORDED" BM_SLOT="$ACTIVE_SLOT" BM_HOURS="$PROBATION_HOURS" \
        BM_INSTALLED="$installed" BM_ENV_ACTIVE="$BOXMUNGE_ROOT/env-active" python3 -c '
import json, os, sys
from datetime import datetime, timedelta, timezone
d = json.loads(sys.stdin.read())
keys = ("version", "previous_slot", "expires_at")
if not isinstance(d, dict) or not all(isinstance(d.get(k), str) and "\n" not in d[k] for k in keys):
    sys.exit("probation.json must hold string version, previous_slot and expires_at")
expires = datetime.fromisoformat(d["expires_at"])
if expires.tzinfo is None:
    sys.exit("probation.json expires_at has no timezone")
now = datetime.now(timezone.utc)
length = timedelta(hours=int(os.environ["BM_HOURS"]))
record = os.environ["BM_RECORDED"].split()  # checked by the caller
status, note, recorded = "unrecorded", "", now
if len(record) == 3 and record[:2] == [os.environ["BM_SLOT"], d["version"]]:
    status, recorded = "recorded", datetime.fromtimestamp(int(record[2]), timezone.utc)
elif len(record) < 3 and record != ["none"] and d["version"] == os.environ["BM_INSTALLED"]:
    swapped = datetime.fromtimestamp(os.lstat(os.environ["BM_ENV_ACTIVE"]).st_mtime, timezone.utc)
    status, recorded = "adopted", swapped + length
if recorded > now + length:
    recorded, note = now + length, "clock_back"
elif expires > recorded + timedelta(minutes=1):
    note = "lengthened"
ends = min(expires, recorded)
print(d["version"])
print(d["previous_slot"])
print("yes" if now >= ends else "no")
print(ends.strftime("%Y-%m-%d %H:%M UTC"))
print(status)
print(note)
print(int(recorded.timestamp()))
'
)" || die_logged "$PROBATION_FILE is malformed; refusing to act on it"
    PROB_VERSION="$(echo "$out" | sed -n '1p')"
    PROB_PREV_SLOT="$(echo "$out" | sed -n '2p')"
    PROB_EXPIRED="$(echo "$out" | sed -n '3p')"
    PROB_EXPIRES_AT="$(echo "$out" | sed -n '4p')"
    PROB_STATUS="$(echo "$out" | sed -n '5p')"
    PROB_NOTE="$(echo "$out" | sed -n '6p')"
    require_semver "$PROB_VERSION" "$PROBATION_FILE"
    require_slot "$PROB_PREV_SLOT" "$PROBATION_FILE"
    PROB_RECORD="$ACTIVE_SLOT $PROB_VERSION $(echo "$out" | sed -n '7p')"
}

# settle_probation: act on what read_probation found.
settle_probation() {
    [[ "$PROB_STATUS" != unrecorded ]] || refuse_unrecorded_probation
    if [[ "$PROB_STATUS" == adopted ]]; then
        local ends="it ends at $PROB_EXPIRES_AT"
        [[ "$PROB_EXPIRED" == no ]] || ends="it ran past its end with no check ($PROB_EXPIRES_AT; was the box off?), so it is promoted now"
        log "WARN: the probation of $PROB_VERSION has no record (an older shim started it); adopted, as root's state shows that upgrade: $ends"
        bm_log warn upgrade "probation started by an older shim adopted" "{\"version\": \"$PROB_VERSION\"}"
    fi
    [[ "$PROB_RECORD" == "$PROB_RECORDED" ]] || write_root_file "$PROBATION_EXPIRY_FILE" "$PROB_RECORD"
    case "$PROB_NOTE" in
        lengthened)
            log "WARN: $PROBATION_FILE expires_at is later than the probation root recorded; it ends at $PROB_EXPIRES_AT" ;;
        clock_back)
            log "WARN: the probation of $PROB_VERSION was to end more than ${PROBATION_HOURS}h from now, so the clock went back; it now ends at $PROB_EXPIRES_AT"
            bm_log warn upgrade "probation expiry moved: the clock went back" "{\"version\": \"$PROB_VERSION\"}" ;;
    esac
}

# refuse_unrecorded_probation: probation.json names a probation no upgrade on
# this box started (root's record names another slot or release, says none
# is running, or an older shim's probation lacks the evidence above). Deploy
# can write that file, and one it planted would defer upgrades and refuse
# targets for a probation's length, again each time it is planted. It has no
# authority, so it is removed, with an error in the operational log and an
# alert: the run stops, and the next one carries on as if it was never there.
refuse_unrecorded_probation() {
    local msg="$PROBATION_FILE names $PROB_VERSION on probation, but no upgrade on this box started that probation (root's record, $PROBATION_EXPIRY_FILE, does not match it; one an older shim started counts only for the installed release), so it was removed and nothing else changed; the next run carries on. If it comes back, something running as the deploy user is writing it: find and stop it."
    rm -f "$PROBATION_FILE"
    send_notification "boxmunge: planted probation removed" "$msg" 1
    die_logged "$msg"
}

# load_probation: 0 with PROB_* set while a release is on probation, 1 when
# there is none. A probation naming the live slot as previous_slot is stale
# (an older shim's rollback left it behind; deploy may remove it anyway), so
# it is removed with a warning. previous_slot need not hold a working venv:
# a pre-0.11 shim could recycle it mid-probation. Only a rollback needs it
# (do_rollback checks); promotion deletes it, and demanding it here left such
# a probation unable to expire, deferring every upgrade for good (#119).
load_probation() {
    [[ -e "$PROBATION_FILE" || -L "$PROBATION_FILE" ]] || return 1
    read_probation
    if [[ "$PROB_PREV_SLOT" == "$ACTIVE_SLOT" ]]; then
        [[ ! -e "$(inflight_marker "$ACTIVE_SLOT")" ]] \
            || die_logged "$PROBATION_FILE names the live slot during an interrupted upgrade; refusing to act on it"
        log "WARN: removing stale $PROBATION_FILE: previous_slot '$PROB_PREV_SLOT' is the live slot"
        bm_log warn upgrade "stale probation removed" "{\"version\": \"$PROB_VERSION\"}"
        rm -f "$PROBATION_FILE"
        return 1
    fi
    settle_probation
}

# work_interrupted: an upgrade or rollback was cut short, and check-probation
# has yet to finish it.
work_interrupted() {
    [[ -e "$(inflight_marker "$ACTIVE_SLOT")" || -e "$(rollback_marker a)" || -e "$(rollback_marker b)" ]]
}

# refuse_during_probation <version> <mode>: while a release is on probation,
# the standby slot holds the last proven release and is the only rollback
# target. Building another release there would leave nothing proven to fall
# back to, so every entry point, force-target included, waits until
# check-probation promotes or rolls back; likewise while it has an interrupted
# upgrade or rollback to finish. This is a deferral, not a failure of
# <version>: no blocklist entry and no failure report. The timer (run) exits
# 0 like a blocklisted version, and retries on its next run.
refuse_during_probation() {
    local version="$1" mode="$2" why retry
    if work_interrupted; then
        why="an earlier upgrade or rollback was interrupted, and the health timer's check-probation finishes it within minutes"
        retry="Retry after that."
    elif load_probation; then
        why="$PROB_VERSION is on probation (it ends $PROB_EXPIRES_AT)"
        [[ "$PROB_EXPIRED" == "no" ]] || why="$PROB_VERSION is on probation (it has expired and the health timer promotes it within minutes)"
        if rollback_target_ok "$PROB_PREV_SLOT"; then
            why="$why and slot $PROB_PREV_SLOT holds the previous release, the only rollback target"
        else
            why="$why; its rollback target, slot $PROB_PREV_SLOT, is not a working venv, so a failing health check cannot roll it back"
        fi
        retry="Retry after the probation ends."
        [[ "$mode" != "force" ]] || retry="To accept $PROB_VERSION now and end its probation, remove $PROBATION_FILE and re-run."
    else
        return 0
    fi
    bm_log warn upgrade "upgrade deferred: probation active" "{\"version\": \"$version\", \"mode\": \"$mode\"}"
    if [[ "$mode" == "run" ]]; then
        log "Not upgrading to $version: $why. Deferred; auto-update retries on its next run."
        exit 0
    fi
    die "Not upgrading to $version: $why. $retry"
}

# resume_rollback: a rollback-inflight marker means a rollback was cut short.
# Finish it onto the slot holding the marker: the swap if it never happened,
# then the stash restore and re-apply again, then the bookkeeping.
resume_rollback() {
    local slot marker version="" stage="" count=""
    for slot in "$ACTIVE_SLOT" "$(standby_slot)"; do
        marker="$(rollback_marker "$slot")"
        [[ -e "$marker" ]] || continue
        { read -r version; read -r stage; read -r count; } < "$marker" || true
        require_semver "$version" "$marker"
        [[ "$stage" =~ ^[a-z_]+$ && "$count" =~ ^[0-9]+$ ]] \
            || die_logged "$marker is malformed; inspect both slots as supervisor"
        rollback_target_ok "$slot" \
            || die_logged "$marker is in env-$slot, which is not a working venv; inspect both slots as supervisor"
        log "Resuming the interrupted rollback of $version (stage $stage) onto slot $slot"
        complete_rollback "$version" "$("$BOXMUNGE_ROOT/env-$slot/bin/boxmunge-server" --version 2>/dev/null || echo "unknown")" \
            "$stage" "$slot" "$count"
    done
}

# recover_interrupted_upgrade: the live slot still carries upgrade-inflight,
# so the shim died after the swap and before probation was recorded (unless
# it died just after recording it). Apply may not have finished, so roll back
# to the standby, the proven release. A marker left in the standby means the
# swap never happened; the orphan cleanup that follows removes that slot.
recover_interrupted_upgrade() {
    local marker version
    marker="$(inflight_marker "$ACTIVE_SLOT")"
    [[ -e "$marker" ]] || return 0
    version="$(cat "$marker")"
    require_semver "$version" "$marker"
    if load_probation && [[ "$PROB_VERSION" == "$version" ]]; then
        rm -f "$marker"
        return 0
    fi
    log "Upgrade to $version was interrupted after the venv swap — rolling back"
    do_rollback "$version" "$("$BOXMUNGE_ROOT/env-$(standby_slot)/bin/boxmunge-server" --version 2>/dev/null || echo "unknown")" \
        interrupted "$(standby_slot)"
}

# clear_probation_markers: forget what check-probation counted or said about
# a probation (all in root-only upgrade-root/), and record that none is
# running. Whenever a probation ends or starts, so a new one never inherits
# them.
clear_probation_markers() {
    rm -f "$UPGRADE_ROOT_DIR/rollback-impossible" "$UPGRADE_ROOT_DIR/rollback-impossible.logged" \
        "$UPGRADE_ROOT_DIR/live-slot-failed" "$HEALTH_BASELINE_FILE" "$HEALTH_UNJUDGED_FILE"
    [[ "$(cat "$PROBATION_EXPIRY_FILE" 2>/dev/null)" == none ]] || write_root_file "$PROBATION_EXPIRY_FILE" none
}

# rollback_impossible <version> <prev_slot> <why>: the release on probation
# failed (<why>), but the previous slot cannot take over (a pre-0.11 shim may
# have recycled it). Said once per probation, as an error and an alert; later
# timer fires only print it, rather than adding an error to the log every five
# minutes. With a live slot that still runs, expiry promotes the release; with
# one that does not, nothing can until it is reinstalled.
rollback_impossible() {
    local version="$1" prev_slot="$2" why="$3" next
    next="Run boxmunge health as supervisor to see what failed; the probation ends, promoting $version, at $PROB_EXPIRES_AT."
    slot_works "$ACTIVE_SLOT" \
        || next="Nothing runs the platform until $version is reinstalled into the live slot: as root, run the installer from the $version GitHub release (sudo bash boxmunge-install.sh). The health timer then carries on with the probation."
    local msg="$version $why, but cannot be rolled back: env-$prev_slot, its rollback target, is not a working venv. $next"
    alert_once "$version" "$prev_slot" "$msg"
    die "$msg"
}

# alert_once <version> <prev_slot> <msg>: put <msg> in the operational log and
# send it as an alert, each once per probation: a marker in upgrade-root/
# records each that went out, and the next fire retries only what did not.
# Either venv's python may be the broken one, so each is tried, the live
# slot's first. An alert counts as sent when Pushover took it or is not
# configured. What did not go out is said on stderr and in the system
# journal, which the health timer keeps.
alert_once() {
    local version="$1" prev_slot="$2" msg="$3" python rc missing=()
    local alerted="$UPGRADE_ROOT_DIR/rollback-impossible" logged="$UPGRADE_ROOT_DIR/rollback-impossible.logged"
    local pythons=("$(active_venv)/bin/python" "$BOXMUNGE_ROOT/env-$prev_slot/bin/python")
    if [[ "$(cat "$logged" 2>/dev/null)" != "$version" ]]; then
        for python in "${pythons[@]}"; do
            if [[ -x "$python" ]] && bm_log_via "$python" error upgrade "$msg"; then
                echo "$version" > "$logged"
                break
            fi
        done
        [[ "$(cat "$logged" 2>/dev/null)" == "$version" ]] || missing+=("to the operational log")
    fi
    if [[ "$(cat "$alerted" 2>/dev/null)" != "$version" ]]; then
        for python in "${pythons[@]}"; do
            [[ -x "$python" ]] || continue
            rc=0
            notify_via "$python" "boxmunge rollback needed but impossible" "$msg" 1 || rc=$?
            if [[ "$rc" -eq 0 || "$rc" -eq 3 ]]; then
                echo "$version" > "$alerted"
                break
            fi
        done
        [[ "$(cat "$alerted" 2>/dev/null)" == "$version" ]] || missing+=("as an alert")
    fi
    [[ "${#missing[@]}" -gt 0 ]] || return 0
    local where="${missing[0]}"
    [[ "${#missing[@]}" -eq 1 ]] || where="${missing[0]} or ${missing[1]}"
    log "ALERT NOT DELIVERED ($where): $msg"
    logger -t boxmunge-upgrade -p user.crit -- "ALERT NOT DELIVERED ($where): $msg" \
        || log "ERROR: the system journal did not take it either"
}

# probation_failed <version> <prev_slot> <why> [detail]: roll the release on
# probation back to the previous slot, or say why it cannot be. [detail] goes
# with the failure report and into the log once the rollback has swapped.
probation_failed() {
    local version="$1" prev_slot="$2" why="$3" detail="${4:-}" from_version
    rollback_target_ok "$prev_slot" || rollback_impossible "$version" "$prev_slot" "$why"
    from_version="$("$BOXMUNGE_ROOT/env-$prev_slot/bin/boxmunge-server" --version 2>/dev/null || echo "unknown")"
    log "CRITICAL: $version $why during probation — rolling back"
    do_rollback "$version" "$from_version" "health_probation" "$prev_slot" "$detail"
}

# check_live_slot <version> <prev_slot>: a live slot that cannot run
# boxmunge-server cannot be checked or promoted (promotion deletes the
# previous slot, which remove_slot refuses while the live one is dead), so it
# is rolled back, expired or not. Not on one failure: a healthy release must
# not be rolled back and blocklisted for a blip. Every failure counts, a crash
# (a signal: 128 and up) included; consecutive ones are counted in a
# root-only marker, which a working run resets. The count is keyed by the
# live slot, not by the version in deploy-writable probation.json, which deploy
# could rewrite between runs to start it again. Two in a row roll back, or
# four when the latest only timed out (124, or 137 once timeout escalated to
# SIGKILL), since a busy box can be slow for a while.
check_live_slot() {
    local version="$1" prev_slot="$2" server out rc=0 why count=0 seen="" needed=2
    local marker="$UPGRADE_ROOT_DIR/live-slot-failed"
    server="$(active_venv)/bin/boxmunge-server"
    if [[ -x "$server" ]]; then
        out="$(timeout --kill-after=10 60 "$server" --version 2>&1)" || rc=$?
    else
        out="not executable"
        rc=126
    fi
    if [[ "$rc" -eq 0 ]]; then
        rm -f "$marker"
        return 0
    fi
    out="$(printf '%s' "$out" | tail -n 1 | tr -d '\n' | tr -c '[:print:]' '?')"
    why="env-$ACTIVE_SLOT/bin/boxmunge-server --version exited $rc: ${out:0:200}"
    read -r seen count < "$marker" 2>/dev/null || true
    [[ "$seen" == "$ACTIVE_SLOT" && "$count" =~ ^[0-9]+$ ]] || count=0
    count=$((count + 1))
    local state="does not run"
    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
        state="did not answer"
        needed=4
    fi
    if [[ "$count" -lt "$needed" ]]; then
        echo "$ACTIVE_SLOT $count" > "$marker"
        log "WARN: the live slot $state ($why), $count time(s) in a row; $version is rolled back at $needed"
        bm_log warn upgrade "live slot $state" \
            "{\"version\": \"$version\", \"slot\": \"$ACTIVE_SLOT\", \"exit\": $rc, \"in_a_row\": $count}"
        exit 0
    fi
    probation_failed "$version" "$prev_slot" "is broken: $why" "live_venv_dead: $why"
}

cmd_check_probation() {
    load_active_slot
    acquire_lock skip  # an upgrade is in progress; retry on the next health-timer fire
    resume_rollback
    recover_interrupted_upgrade

    local inactive
    inactive="$(standby_slot)"
    if ! load_probation; then
        clear_probation_markers
        rm -rf "$STASH_RECORD_FILE" "$STASH_COPY_DIR"
        # No probation, so a standby venv is an orphan: left by a rollback, an
        # upgrade that failed before its swap, or a promotion made from the
        # deploy context (deploy cannot rmtree root-owned dirs).
        if [[ -d "$BOXMUNGE_ROOT/env-$inactive" ]]; then
            log "Cleaning up orphan venv in inactive slot $inactive"
            remove_slot "$inactive"
        fi
        exit 0
    fi
    local version="$PROB_VERSION" prev_slot="$PROB_PREV_SLOT"

    check_live_slot "$version" "$prev_slot"

    # Expiry next: promotion needs no rollback target (it deletes it).
    if [[ "$PROB_EXPIRED" == "yes" ]]; then
        log "Probation expired for $version — promoting"
        remove_slot "$prev_slot"
        rm -f "$PROBATION_FILE"
        clear_probation_markers
        rm -rf "$STASH_RECORD_FILE" "$STASH_COPY_DIR"
        interruptions "$version" 0
        log "Version $version promoted"
        bm_log info upgrade "probation passed" "{\"version\": \"$version\"}"
        exit 0
    fi

    # The health check (health.sh), 180 s. A health error the baseline from
    # before the upgrade lacks rolls back. One that could not run at all
    # (126/127) has the live slot checked again, as above, and rolled back if
    # it still does not run on the next fire. One that gave no verdict (it did
    # not finish, or gave no valid report) is counted (health_unjudged).
    local baseline
    baseline="$(probation_baseline)"
    health_run 180 "$baseline"
    case "${HEALTH_VERDICT%% *}" in
        failed)
            log "New health errors since the upgrade: ${HEALTH_VERDICT#failed }"
            probation_failed "$version" "$prev_slot" "failed its probation health check" \
                "new_health_errors: ${HEALTH_VERDICT#failed }" ;;
        not_run)
            log "WARN: the probation health check of $version could not run (exit ${HEALTH_VERDICT#not_run }); checking the live slot"
            check_live_slot "$version" "$prev_slot"
            log "WARN: the live slot runs; the next health-timer run checks $version again" ;;
        ok)
            rm -f "$HEALTH_UNJUDGED_FILE"
            [[ "$HEALTH_VERDICT" == ok ]] \
                || log "WARN: health errors that were there before the upgrade, not counted against $version: ${HEALTH_VERDICT#ok }" ;;
        *) health_unjudged "$version" "$prev_slot" "$baseline" ;;
    esac

    exit 0
}
