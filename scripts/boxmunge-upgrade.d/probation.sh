# shellcheck shell=bash
# probation.sh — reading probation.json, deferring upgrades while a release
# is unproven, and check-probation: finishing interrupted rollbacks and
# upgrades, promotion, and rollback.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# read_probation: parse probation.json into PROB_VERSION, PROB_PREV_SLOT,
# PROB_EXPIRED (yes/no) and PROB_EXPIRES_AT (re-formatted in UTC, so safe to
# print). The file is deploy-writable: deploy may end a probation early, but
# must not lengthen one (a far-future expires_at would defer upgrades for
# good). So the first run that reads a probation records its expiry in
# root-only upgrade-root/probation-expiry, keyed by the live slot, at most a
# fresh probation's length from then, and the probation ends at the earlier
# of that and expires_at. A recorded expiry more than a probation's length
# ahead means the clock went back (an NTP step, a VM restore); it is moved to
# a probation's length from now rather than promoting at once, which deleted
# the rollback target.
PROBATION_EXPIRY_FILE="$UPGRADE_ROOT_DIR/probation-expiry"
read_probation() {
    local out content recorded=""
    refuse_symlink "$PROBATION_FILE"
    content="$(read_untrusted "$PROBATION_FILE")" || exit 1
    refuse_symlink "$PROBATION_EXPIRY_FILE"
    [[ ! -e "$PROBATION_EXPIRY_FILE" ]] || recorded="$(cat "$PROBATION_EXPIRY_FILE")"
    out="$(BM_PROBATION="$content" BM_RECORDED="$recorded" BM_SLOT="$ACTIVE_SLOT" BM_HOURS="$PROBATION_HOURS" python3 - <<'PYPROB'
import json, os, re, sys
from datetime import datetime, timedelta, timezone
d = json.loads(os.environ["BM_PROBATION"])
keys = ("version", "previous_slot", "expires_at")
if not isinstance(d, dict) or not all(isinstance(d.get(k), str) and "\n" not in d[k] for k in keys):
    sys.exit("probation.json must hold string version, previous_slot and expires_at")
expires = datetime.fromisoformat(d["expires_at"])
if expires.tzinfo is None:
    sys.exit("probation.json expires_at has no timezone")
now = datetime.now(timezone.utc)
cap = now + timedelta(hours=int(os.environ["BM_HOURS"]))
recorded, note = None, ""
m = re.fullmatch(r"([ab]) ([0-9]+)\n?", os.environ["BM_RECORDED"])
if os.environ["BM_RECORDED"] and not m:
    sys.exit("upgrade-root/probation-expiry is malformed; remove it (the next run records the expiry again)")
if m and m.group(1) == os.environ["BM_SLOT"]:
    recorded = datetime.fromtimestamp(int(m.group(2)), timezone.utc)
if recorded is None:
    recorded = min(expires, cap)
    note = "beyond_cap" if expires > cap else ""
elif recorded > cap:
    recorded, note = cap, "clock_back"
ends = min(expires, recorded)
print(d["version"])
print(d["previous_slot"])
print("yes" if now >= ends else "no")
print(ends.strftime("%Y-%m-%d %H:%M UTC"))
print(note)
print(int(recorded.timestamp()))
PYPROB
)" || die_logged "$PROBATION_FILE is malformed; refusing to act on it"
    PROB_VERSION="$(echo "$out" | sed -n '1p')"
    PROB_PREV_SLOT="$(echo "$out" | sed -n '2p')"
    PROB_EXPIRED="$(echo "$out" | sed -n '3p')"
    PROB_EXPIRES_AT="$(echo "$out" | sed -n '4p')"
    require_semver "$PROB_VERSION" "$PROBATION_FILE"
    require_slot "$PROB_PREV_SLOT" "$PROBATION_FILE"
    local record
    record="$ACTIVE_SLOT $(echo "$out" | sed -n '6p')"
    [[ "$record" == "${recorded%$'\n'}" ]] || write_root_file "$PROBATION_EXPIRY_FILE" "$record"
    case "$(echo "$out" | sed -n '5p')" in
        beyond_cap)
            log "WARN: $PROBATION_FILE expires_at is beyond a ${PROBATION_HOURS}h probation; it ends at $PROB_EXPIRES_AT"
            bm_log warn upgrade "probation expiry beyond cap" "{\"version\": \"$PROB_VERSION\"}" ;;
        clock_back)
            log "WARN: the probation of $PROB_VERSION was to end more than ${PROBATION_HOURS}h from now, so the clock went back; it now ends at $PROB_EXPIRES_AT"
            bm_log warn upgrade "probation expiry moved: the clock went back" "{\"version\": \"$PROB_VERSION\"}" ;;
    esac
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
# a probation (all in root-only upgrade-root/). Whenever a probation ends or
# starts, so a new one never inherits them.
clear_probation_markers() {
    rm -f "$UPGRADE_ROOT_DIR/rollback-impossible" "$UPGRADE_ROOT_DIR/rollback-impossible.logged" \
        "$UPGRADE_ROOT_DIR/live-slot-failed" "$PROBATION_EXPIRY_FILE"
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
        interruptions "$version" 0
        log "Version $version promoted"
        bm_log info upgrade "probation passed" "{\"version\": \"$version\"}"
        exit 0
    fi

    # Probation health check semantics:
    #   exit 2        -> CRITICAL: real health regression -> rollback
    #   exit 126/127  -> health could not run at all (timeout's exit when the
    #                    command cannot be executed or found): the live slot
    #                    is checked again, as above, and rolled back if it
    #                    still does not run on the next fire
    #   other 124+    -> OPERATIONAL: timed out / killed (e.g. multiple
    #                    sequential docker subprocess timeouts on a busy host
    #                    can exceed our budget without any platform
    #                    regression). Skip rollback; the next health-timer
    #                    fire will retry.
    #   else          -> healthy (or warnings only) -> continue probation
    # --kill-after=10 escalates SIGTERM -> SIGKILL if the health subprocess
    # ignores the initial SIGTERM (e.g. wedged docker socket). Without it,
    # `timeout 180` waits indefinitely for an unresponsive process and
    # successive timer fires stack stuck health invocations.
    local health_exit=0
    timeout --kill-after=10 180 "$(active_venv)/bin/boxmunge-server" health --json >/dev/null 2>&1 || health_exit=$?

    case "$health_exit" in
        2) probation_failed "$version" "$prev_slot" "failed its probation health check" ;;
        126|127)
            log "WARN: the probation health check of $version could not run (exit $health_exit); checking the live slot"
            check_live_slot "$version" "$prev_slot"
            log "WARN: the live slot runs; the next health-timer run checks $version again" ;;
        *) [[ "$health_exit" -lt 124 ]] \
            || log "WARN: probation health check timed out (exit $health_exit) for $version — skipping rollback, next health-timer will retry" ;;
    esac

    exit 0
}
