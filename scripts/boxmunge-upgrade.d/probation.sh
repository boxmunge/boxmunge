# shellcheck shell=bash
# probation.sh — reading probation.json, deferring upgrades while a release
# is unproven, and check-probation: finishing interrupted rollbacks and
# upgrades, promotion, and rollback.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# read_probation: parse probation.json into PROB_VERSION, PROB_PREV_SLOT,
# PROB_EXPIRED (yes/no) and PROB_EXPIRES_AT (re-formatted in UTC, so safe to
# print). The file is deploy-writable, so an expires_at beyond a fresh
# probation's length (plus slack for clock steps) is forged or corrupt: it
# counts as expired, or a far-future value would defer upgrades for good.
read_probation() {
    local out content
    refuse_symlink "$PROBATION_FILE"
    content="$(read_untrusted "$PROBATION_FILE")" || exit 1
    out="$(BM_PROBATION="$content" BM_HOURS="$PROBATION_HOURS" python3 - <<'PYPROB'
import json, os, sys
from datetime import datetime, timedelta, timezone
d = json.loads(os.environ["BM_PROBATION"])
keys = ("version", "previous_slot", "expires_at")
if not isinstance(d, dict) or not all(isinstance(d.get(k), str) and "\n" not in d[k] for k in keys):
    sys.exit("probation.json must hold string version, previous_slot and expires_at")
expires = datetime.fromisoformat(d["expires_at"])
if expires.tzinfo is None:
    sys.exit("probation.json expires_at has no timezone")
now = datetime.now(timezone.utc)
beyond_cap = expires > now + timedelta(hours=int(os.environ["BM_HOURS"]), minutes=15)
print(d["version"])
print(d["previous_slot"])
print("yes" if now >= expires or beyond_cap else "no")
print(expires.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
print("beyond_cap" if beyond_cap else "")
PYPROB
)" || die_logged "$PROBATION_FILE is malformed; refusing to act on it"
    PROB_VERSION="$(echo "$out" | sed -n '1p')"
    PROB_PREV_SLOT="$(echo "$out" | sed -n '2p')"
    PROB_EXPIRED="$(echo "$out" | sed -n '3p')"
    PROB_EXPIRES_AT="$(echo "$out" | sed -n '4p')"
    require_semver "$PROB_VERSION" "$PROBATION_FILE"
    require_slot "$PROB_PREV_SLOT" "$PROBATION_FILE"
    if [[ "$(echo "$out" | sed -n '5p')" == beyond_cap ]]; then
        log "WARN: $PROBATION_FILE expires_at $PROB_EXPIRES_AT is beyond a ${PROBATION_HOURS}h probation; treating it as expired"
        bm_log warn upgrade "probation expiry beyond cap" "{\"version\": \"$PROB_VERSION\"}"
    fi
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

# rollback_impossible <version> <prev_slot>: health is critical, but the
# previous slot cannot take over (a pre-0.11 shim may have recycled it). Said
# once per probation, as an error and an alert; later timer fires only print
# it, rather than adding an error to the log every five minutes. The marker
# is in root-only upgrade-root/ and goes when the probation ends.
rollback_impossible() {
    local version="$1" prev_slot="$2" marker="$UPGRADE_ROOT_DIR/rollback-impossible"
    local msg="$version failed its probation health check, but cannot be rolled back: env-$prev_slot, its rollback target, is not a working venv. Run boxmunge health as supervisor to see what failed; the probation ends, promoting $version, at $PROB_EXPIRES_AT."
    if [[ "$(cat "$marker" 2>/dev/null)" != "$version" ]]; then
        bm_log error upgrade "$msg"
        send_notification "boxmunge rollback needed but impossible" "$msg" 1
        echo "$version" > "$marker"
    fi
    die "$msg"
}

cmd_check_probation() {
    load_active_slot
    acquire_lock skip  # an upgrade is in progress; retry on the next health-timer fire
    resume_rollback
    recover_interrupted_upgrade

    local inactive
    inactive="$(standby_slot)"
    if ! load_probation; then
        rm -f "$UPGRADE_ROOT_DIR/rollback-impossible"
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

    # Expiry first: promotion needs no rollback target (it deletes it).
    if [[ "$PROB_EXPIRED" == "yes" ]]; then
        log "Probation expired for $version — promoting"
        remove_slot "$prev_slot"
        rm -f "$PROBATION_FILE" "$UPGRADE_ROOT_DIR/rollback-impossible"
        interruptions "$version" 0
        log "Version $version promoted"
        bm_log info upgrade "probation passed" "{\"version\": \"$version\"}"
        exit 0
    fi

    # Probation health check semantics:
    #   exit 2     -> CRITICAL: real health regression -> rollback
    #   exit 124+  -> OPERATIONAL: timed out / killed (e.g. multiple sequential
    #                 docker subprocess timeouts on a busy host can exceed our
    #                 budget without any platform regression). Skip rollback;
    #                 the next health-timer fire will retry.
    #   else        -> healthy (or warnings only) -> continue probation
    # --kill-after=10 escalates SIGTERM -> SIGKILL if the health subprocess
    # ignores the initial SIGTERM (e.g. wedged docker socket). Without it,
    # `timeout 180` waits indefinitely for an unresponsive process and
    # successive timer fires stack stuck health invocations.
    local health_exit=0
    timeout --kill-after=10 180 "$(active_venv)/bin/boxmunge-server" health --json >/dev/null 2>&1 || health_exit=$?

    if [[ "$health_exit" -eq 2 ]]; then
        rollback_target_ok "$prev_slot" || rollback_impossible "$version" "$prev_slot"
        local from_version
        from_version="$("$BOXMUNGE_ROOT/env-$prev_slot/bin/boxmunge-server" --version 2>/dev/null || echo "unknown")"
        log "CRITICAL health failure during probation for $version — rolling back"
        do_rollback "$version" "$from_version" "health_probation" "$prev_slot"
    elif [[ "$health_exit" -ge 124 ]]; then
        log "WARN: probation health check timed out (exit $health_exit) for $version — skipping rollback, next health-timer will retry"
    fi

    exit 0
}
