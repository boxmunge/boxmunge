# shellcheck shell=bash
# slots.sh — the two venv slots: whether a slot can be trusted, the
# crash-safety markers, the swap, and rollback.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# ---------------------------------------------------------------------------
# Crash-safety markers. Both live inside a venv slot, which is root-owned, so
# deploy cannot forge them, and each is synced to disk before the swap it
# guards.
#
#   upgrade-inflight   "<version>"
#       In the slot an upgrade installs, from just before the swap until
#       probation is recorded. While it is in the live slot, the standby is
#       the proven release and must not be deleted.
#   rollback-inflight  "<version>\n<stage>\n<interruption count>"
#       In the slot a rollback returns to, from just before its swap until the
#       rollback has finished. check-probation finishes a rollback cut short.
#
# CROSS-VERSION CONTRACT: a box can crash under this shim and come back under
# a later one (the next upgrade self-updates the shim before its swap, and
# install.sh may be re-run). Every later shim must honour both markers as
# described in resume_rollback and recover_interrupted_upgrade (probation.sh),
# or migrate them, and must never delete a slot that holds one, or the slot a
# marker says is the rollback target, without resolving it first.
# ---------------------------------------------------------------------------
inflight_marker() { echo "$BOXMUNGE_ROOT/env-$1/upgrade-inflight"; }
rollback_marker() { echo "$BOXMUNGE_ROOT/env-$1/rollback-inflight"; }

# slot_works <slot>: the slot's boxmunge-server runs. Checked before a slot is
# trusted to take over, and before another slot is deleted on its strength.
slot_works() {
    local server="$BOXMUNGE_ROOT/env-$1/bin/boxmunge-server"
    [[ -x "$server" ]] && "$server" --version >/dev/null 2>&1
}

# rollback_target_ok <slot>: a working venv that is not a half-finished upgrade.
rollback_target_ok() { slot_works "$1" && [[ ! -e "$(inflight_marker "$1")" ]]; }

# remove_slot <slot>: the only way the shim deletes a venv slot. Never the one
# env-active points at, and never while the live slot does not work: then
# <slot> may be all that is left to run the platform.
remove_slot() {
    local slot="$1"
    require_slot "$slot" "slot removal"
    [[ "$slot" != "$ACTIVE_SLOT" && "$(readlink "$BOXMUNGE_ROOT/env-active" 2>/dev/null)" != "$BOXMUNGE_ROOT/env-$slot" ]] \
        || die "Refusing to remove env-$slot: it is the live slot"
    slot_works "$ACTIVE_SLOT" \
        || die "Refusing to remove env-$slot: the live slot env-$ACTIVE_SLOT is not a working venv; inspect both as supervisor"
    rm -rf "${BOXMUNGE_ROOT:?}/env-$slot"
}

swap_to() {
    local slot="$1"
    require_slot "$slot" "swap target"
    slot_works "$slot" || die "Refusing to swap to env-$slot: it is not a working venv"
    ln -sfn "$BOXMUNGE_ROOT/env-$slot" "$BOXMUNGE_ROOT/env-active"
    write_active_slot_file "$slot"
    ACTIVE_SLOT="$slot"
    # Durable before anything runs on the new slot: an apply that migrated
    # state must never come back after a crash under the other slot's code.
    sync
    # The user-facing /opt/boxmunge/bin/boxmunge-server wrapper already routes
    # through env-active/bin/boxmunge-server, so the symlink swap above
    # is sufficient — no need to touch the wrapper itself.
    log "Swapped active to slot $slot"
}

report_failure() {
    local version="$1" from_version="$2" stage="$3"
    BM_VERSION="$version" BM_FROM_VERSION="$from_version" BM_STAGE="$stage" "$(active_venv)/bin/python" -c "
import os
from boxmunge.report_failure import report_failure
report_failure(os.environ['BM_VERSION'], os.environ['BM_FROM_VERSION'], os.environ['BM_STAGE'])
" 2>/dev/null || true
}

send_notification() {
    local title="$1" message="$2" priority="${3:-0}"
    BM_TITLE="$title" BM_MESSAGE="$message" BM_PRIORITY="$priority" "$(active_venv)/bin/python" -c "
import os
from boxmunge.config import load_config
from boxmunge.pushover import send_notification
from boxmunge.paths import BoxPaths
config = load_config(BoxPaths())
po = config.get('pushover', {})
send_notification(po.get('user_key',''), po.get('app_token',''), os.environ['BM_TITLE'], os.environ['BM_MESSAGE'],
                  int(os.environ['BM_PRIORITY']))
" 2>/dev/null || true
}

# rollback_partial <new_version> <from_version> <stage> <prev_slot> <step> <exit> <output>
#
# The venv is back on the previous slot but disk state may be partly
# upgraded, a hybrid the old code is not guaranteed to handle. Hard failure
# demanding operator attention; exit 2 so monitoring can tell it from a
# clean rollback (exit 1). The rollback marker goes too: retrying on every
# health tick would only repeat the alert, and the operator now owns this.
rollback_partial() {
    local new_version="$1" from_version="$2" stage="$3" prev_slot="$4" step="$5" rc="$6" output="$7"
    log "ERROR: $step failed during rollback (exit $rc)"
    log "ERROR: $step output: $output"
    bm_log error upgrade "rollback partial — manual intervention required" \
        "{\"version\": \"$new_version\", \"stage\": \"$stage\", \"step\": \"$step\", \"exit\": $rc}"
    add_blocklist "$new_version" "${stage}_partial_rollback"
    [[ "$stage" == interrupted ]] || report_failure "$new_version" "$from_version" "apply_partial_rollback"
    # Truncate output in the alert body — Pushover messages are length-limited.
    send_notification "boxmunge ROLLBACK PARTIAL" \
        "ROLLBACK PARTIAL — manual intervention required.
Version: $new_version
Stage: $stage
Failed step: $step (exit $rc)
Output (truncated): ${output:0:500}"
    rm -f "$(rollback_marker "$prev_slot")"
    log "Rollback PARTIAL: venv reverted to slot $prev_slot but $step failed"
    exit 2
}

# do_rollback <new_version> <from_version> <stage> <prev_slot>: return to
# <prev_slot>. The rollback-inflight marker is on disk before the swap, so a
# crash anywhere from here on is finished by the next check-probation.
#
# An interruption (stage "interrupted": a power cut or kill) is rarely the
# release's fault. The first one of a version is not blocklisted, so
# auto-update retries it; a second one is, so a release whose apply reliably
# hangs or is killed cannot loop. The count is decided here, kept in the
# marker, and recorded only once the rollback has succeeded.
do_rollback() {
    local new_version="$1" from_version="$2" stage="$3" prev_slot="$4" count=0
    rollback_target_ok "$prev_slot" \
        || die "Cannot roll back $new_version: env-$prev_slot is not a working venv, or is itself a half-finished upgrade; inspect it as supervisor"
    [[ "$stage" != interrupted ]] || count=$(( $(interruptions "$new_version") + 1 ))
    printf '%s\n%s\n%s\n' "$new_version" "$stage" "$count" > "$(rollback_marker "$prev_slot")"
    sync
    complete_rollback "$new_version" "$from_version" "$stage" "$prev_slot" "$count"
}

# legacy_caddy_log_note <version>: what the active (previous) release costs CrowdSec. A
# release from before Caddy logged to stdout writes Caddy's access log to a
# tmpfs inside the container that nothing reads (caddy/compose.yml), so
# HTTP-layer detection is off until the next upgrade. Read from that
# release's own root-owned code, never from the deploy-writable site files.
legacy_caddy_log_note() {
    if grep -qsF "output file /var/log/caddy/access.log" \
            "$(active_venv)"/lib/python3*/site-packages/boxmunge/caddy.py; then
        echo " HTTP-layer detection is off until the next upgrade: $1 writes Caddy's access log to a file CrowdSec does not read."
    fi
}

# teardown_before_rollback: staging-teardown-all with the active (new)
# release. It alerts per project itself and exits 0 even when a project
# fails; a non-zero exit means it did not finish (killed by the timeout,
# crashed, or could not start), so which projects still hold a slot is
# unknown and the alert here names the generic manual commands. It never
# blocks the rollback. The 600 s budget covers one compose down per staged
# project; a box with many slack staging stacks may need longer, and then
# keeps the rest (harmless to the older release) with this alert.
teardown_before_rollback() {
    local rc=0
    timeout --kill-after=10 600 "$(active_venv)/bin/boxmunge-server" staging-teardown-all \
        --reason platform-rollback || rc=$?
    [[ "$rc" -ne 0 ]] || return 0
    local msg="staging teardown before the rollback did not finish (exit $rc); staged releases may remain under <p>/.releases/staged/; the older release ignores them; remove each with: docker compose -p <p>-staging --project-directory <p>/.releases/staged/release -f <p>/.releases/staged/compose.staging-base.yml -f <p>/.releases/staged/compose.boxmunge-staging.yml down, then rm -rf <p>/.releases/staged and rm caddy/sites/<p>-staging.conf"
    log "WARN: $msg"
    bm_log warn upgrade "staging teardown before the rollback did not finish" "{\"exit\": $rc}"
    send_notification "boxmunge rollback: staged releases not torn down" "$msg" 1
}

# complete_rollback <new_version> <from_version> <stage> <prev_slot> <count>:
# everything after the marker. Safe to run again after a crash part-way: the
# swap is skipped once done, the stash restore and re-apply are idempotent,
# and the interruption count is set, not incremented.
complete_rollback() {
    local new_version="$1" from_version="$2" stage="$3" prev_slot="$4" count="$5"
    log "ROLLBACK: $new_version failed at stage=$stage, reverting to slot $prev_slot"
    bm_log warn upgrade "rollback initiated" "{\"version\": \"$new_version\", \"from_version\": \"$from_version\", \"stage\": \"$stage\"}"

    # D14: the release being rolled back from tears down its staged releases
    # (an older release does not know .releases/staged/). Only before the
    # swap: once swapped, the active venv is the older release.
    if [[ "$ACTIVE_SLOT" != "$prev_slot" ]]; then
        teardown_before_rollback
    fi
    [[ "$ACTIVE_SLOT" == "$prev_slot" ]] || swap_to "$prev_slot"
    # Any probation ended with this rollback. Left behind, it would name the
    # now-live slot as previous_slot.
    rm -f "$PROBATION_FILE"

    # 1. Stash restore returns config + state to the pre-upgrade snapshot.
    local output rc=0
    output="$("$(active_venv)/bin/boxmunge-server" stash restore --latest 2>&1)" || rc=$?
    [[ "$rc" -eq 0 ]] || rollback_partial "$new_version" "$from_version" "$stage" "$prev_slot" \
        "stash restore" "$rc" "$output"

    # 2. Re-apply with the previous release's code. The stash holds inputs
    #    (manifests, compose, secrets), not generated output: the overlays and
    #    Caddy sites on disk, and the running containers, are still the new
    #    release's. --apply regenerates both with the old code, reloads Caddy
    #    and restarts projects, so a generator regression is really undone.
    rc=0
    output="$("$(active_venv)/bin/boxmunge-server" upgrade --apply 2>&1)" || rc=$?
    [[ "$rc" -eq 0 ]] || rollback_partial "$new_version" "$from_version" "$stage" "$prev_slot" \
        "re-apply of the previous release" "$rc" "$output"

    refresh_docs_for_slot "$prev_slot"
    local note
    note="$(legacy_caddy_log_note "$from_version")"
    if [[ -n "$note" ]]; then
        log "WARNING:$note"
        bm_log warn upgrade "HTTP-layer detection off after rollback" "{\"version\": \"$from_version\"}"
    fi
    # The box is back on the previous release. Drop the marker before any
    # bookkeeping, the interruption count included: if that fails (a corrupt
    # interrupted.json, say), the next fire must not restore and re-apply
    # (restarting every project) all over again. A crash right here loses
    # one interruption from the count: at worst one extra retry.
    rm -f "$(rollback_marker "$prev_slot")"
    [[ "$stage" != interrupted ]] || interruptions "$new_version" "$count"
    if [[ "$stage" == interrupted ]]; then
        # Not reported to the fleet service: a power cut must not count
        # toward suppressing a release. The operator still hears of it.
        local outcome="not blocklisted; auto-update will retry it"
        if [[ "$count" -ge 2 ]]; then
            add_blocklist "$new_version" "$stage"
            outcome="interrupted $count times, now blocklisted"
        fi
        bm_log warn upgrade "interrupted upgrade rolled back" "{\"version\": \"$new_version\", \"interruptions\": $count}"
        send_notification "boxmunge ROLLBACK" "Rolled back $new_version: the upgrade was interrupted ($outcome).$note"
    else
        add_blocklist "$new_version" "$stage"
        report_failure "$new_version" "$from_version" "$stage"
        send_notification "boxmunge ROLLBACK" "Rolled back $new_version (stage: $stage).$note"
    fi

    log "Rollback complete: reverted to $from_version"
    exit 1
}
