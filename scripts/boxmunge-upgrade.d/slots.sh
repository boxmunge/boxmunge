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

# slot_version <slot>: the X.Y.Z release the slot runs (`--version` prints
# "boxmunge X.Y.Z[+build]"), or nothing when it cannot say.
slot_version() {
    "$BOXMUNGE_ROOT/env-$1/bin/boxmunge-server" --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true
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
        || die_logged "Refusing to remove env-$slot: it is the live slot"
    slot_works "$ACTIVE_SLOT" \
        || die_logged "Refusing to remove env-$slot: the live slot env-$ACTIVE_SLOT is not a working venv; inspect both as supervisor"
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

# report_failure <version> <from_version> <stage> [detail]: best-effort report
# to the fleet service. Never fails the upgrade, but says on stderr when the
# report could not be sent (the python side prints the reason).
report_failure() {
    local version="$1" from_version="$2" stage="$3" detail="${4:-}"
    BM_VERSION="$version" BM_FROM_VERSION="$from_version" BM_STAGE="$stage" BM_DETAIL="$detail" "$(active_venv)/bin/python" -c "
import inspect, os
from boxmunge.report_failure import report_failure
# The active venv is the release being left: 0.11.0 has no detail parameter
# (the probe goes when the upgrade floor reaches 0.11.1).
extra = {'detail': os.environ['BM_DETAIL']} if 'detail' in inspect.signature(report_failure).parameters else {}
report_failure(os.environ['BM_VERSION'], os.environ['BM_FROM_VERSION'], os.environ['BM_STAGE'], **extra)
" || { log "WARNING: the upgrade failure report could not be sent"; } || :
}

# notify_via <python> <title> <message> [priority]: send a Pushover alert
# through that venv's python. Returns 0 when sent, 3 when Pushover is not
# configured, anything else when it could not be sent.
notify_via() {
    local python="$1" title="$2" message="$3" priority="${4:-0}"
    BM_TITLE="$title" BM_MESSAGE="$message" BM_PRIORITY="$priority" "$python" -c "
import os, sys
from boxmunge.config import load_config
from boxmunge.pushover import send_notification
from boxmunge.paths import BoxPaths
config = load_config(BoxPaths())
po = config.get('pushover', {})
if not (po.get('user_key') and po.get('app_token')):
    sys.exit(3)
sys.exit(0 if send_notification(po['user_key'], po['app_token'], os.environ['BM_TITLE'], os.environ['BM_MESSAGE'],
                                int(os.environ['BM_PRIORITY'])) else 1)
" 2>/dev/null
}

# send_notification <title> <message> [priority]: best effort through the live
# slot's python: no upgrade step fails on an alert, but one that could not be
# sent is said on stderr. rollback_impossible needs to know, and uses
# notify_via.
send_notification() {
    local rc=0
    notify_via "$(active_venv)/bin/python" "$@" || rc=$?
    [[ "$rc" -eq 0 || "$rc" -eq 3 ]] || log "WARN: alert not delivered (exit $rc): $1"
}

# ---------------------------------------------------------------------------
# The rollback's stash. stashes/ is deploy-writable (root:deploy 0770): deploy
# can add, rename and replace entries there, though not write the 0600 stash
# root makes. So a rollback neither takes the newest-named stash there nor
# opens one by name. The upgrade records the stash it made, with the version
# it installs, in root-only upgrade-root/upgrade-stash; the rollback copies
# exactly that archive into root-only upgrade-root/rollback-stash/, opened
# without following a link and only if it is a plain file root owns with the
# recorded size and sha256 (so another root-made stash renamed onto the name
# is refused), and has the previous release restore the copy (restore_stash
# takes an archive path since 0.10.0). The size and sha256 recorded are the
# ones `stash create` prints ("Stash digest: <size> <sha256>", since 0.11.6),
# of the bytes it wrote, and the file at the name must match them: hashing
# the name alone would record whatever deploy renamed over it meanwhile. A
# release before 0.11.6 prints no digest (it runs the stash of the upgrade
# away from it); then the file at the name is what is recorded. An upgrade a
# shim before 0.11.5 started recorded nothing: its rollback takes the
# newest-named stash, as that shim would, under the same checks. That goes
# when the upgrade floor reaches 0.11.5.
#
# upgrade-stash: "<version> <name> <size> <sha256>"
# ---------------------------------------------------------------------------
STASH_RECORD_FILE="$UPGRADE_ROOT_DIR/upgrade-stash"
STASH_COPY_DIR="$UPGRADE_ROOT_DIR/rollback-stash"
STASH_NAME_RE='^boxmunge-stash-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}\.tar\.gz$'

# stash_facts <stash>: print "<size> <sha256>" of the stash just made; on
# failure print why and return 1.
stash_facts() {
    BM_STASH="$1" python3 - <<'PYREC'
import hashlib, os, stat, sys
src = os.environ["BM_STASH"]
try:
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError as e:
    print(f"{src}, the stash just made, cannot be opened: {e.strerror}")
    sys.exit(1)
with os.fdopen(fd, "rb") as f:
    st = os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
        print(f"{src}, the stash just made, is not a plain file of root's")
        sys.exit(1)
    digest = hashlib.sha256()
    while chunk := f.read(1 << 20):
        digest.update(chunk)
print(f"{st.st_size} {digest.hexdigest()}")
PYREC
}

# record_stash <version> <stash create output>: record the stash `stash
# create` said it made; on failure print why and return 1.
record_stash() {
    local name printed facts
    name="$(printf '%s\n' "$2" | sed -n 's/^Stash created: //p' | tail -n 1)"
    [[ "$name" =~ $STASH_NAME_RE ]] \
        || { echo "stash create did not name the stash it made (no 'Stash created: <name>' line): $2"; return 1; }
    printed="$(printf '%s\n' "$2" | sed -n 's/^Stash digest: //p')"
    [[ -z "$printed" || "$printed" =~ ^[0-9]+\ [0-9a-f]{64}$ ]] \
        || { echo "stash create printed a digest line the shim cannot read (want one 'Stash digest: <size> <sha256>'): $2"; return 1; }
    facts="$(stash_facts "$BOXMUNGE_ROOT/stashes/$name")" || { echo "$facts"; return 1; }
    if [[ -n "$printed" && "$facts" != "$printed" ]]; then
        echo "$BOXMUNGE_ROOT/stashes/$name is not what stash create just wrote: it printed size and sha256 '$printed', the file there has '$facts' (stashes/ is deploy-writable: something renamed or wrote another file over the name). Nothing has changed. Find what wrote to stashes/, then retry: sudo $BOXMUNGE_ROOT/bin/boxmunge-upgrade target $1"
        return 1
    fi
    write_root_file "$STASH_RECORD_FILE" "$1 $name $facts"
}

# copy_rollback_stash <new_version>: copy the stash the rollback of
# <new_version> restores into STASH_COPY_DIR and print the copy's path; on
# failure print why and return 1.
copy_rollback_stash() {
    local recorded="" name="" size="" sha="" r_version r_name r_size r_sha r_extra
    local hash_re='^[0-9]+ [0-9a-f]{64}$'
    refuse_symlink "$STASH_RECORD_FILE"
    refuse_symlink "$STASH_COPY_DIR"
    [[ ! -e "$STASH_RECORD_FILE" ]] || recorded="$(cat "$STASH_RECORD_FILE")"
    if [[ -n "$recorded" ]]; then
        read -r r_version r_name r_size r_sha r_extra <<< "$recorded"
        if [[ ! "$r_name" =~ $STASH_NAME_RE || -n "${r_extra:-}" || ! "${r_size:-} ${r_sha:-}" =~ $hash_re ]]; then
            echo "$STASH_RECORD_FILE is malformed ('$(printable "$recorded")'); restore the stash this upgrade made by hand as supervisor: check that sudo boxmunge-server stash list names it first (stashes/ is deploy-writable), then run: sudo boxmunge-server stash restore --latest; sudo boxmunge-server upgrade --apply"
            return 1
        elif [[ "$r_version" == "$1" ]]; then
            name="$r_name" size="$r_size" sha="$r_sha"
        else
            log "WARN: $STASH_RECORD_FILE ('$(printable "$recorded")') is not the stash of the upgrade to $1; taking the newest-named stash"
        fi
    fi
    BM_STASHES="$BOXMUNGE_ROOT/stashes" BM_NAME="$name" BM_SIZE="$size" BM_SHA="$sha" BM_DEST="$STASH_COPY_DIR" python3 - <<'PYSTASH'
import errno, fnmatch, hashlib, os, stat, sys, tempfile
stashes, name, dest = os.environ["BM_STASHES"], os.environ["BM_NAME"], os.environ["BM_DEST"]
want = (int(os.environ["BM_SIZE"]), os.environ["BM_SHA"]) if os.environ["BM_SHA"] else None
fix = (" (stashes/ is deploy-writable: it was removed, planted or replaced). Put the right stash back"
       " or remove the wrong one, so that sudo boxmunge-server stash list names the stash this upgrade made"
       " first; then, as supervisor, run: sudo boxmunge-server stash restore --latest;"
       " sudo boxmunge-server upgrade --apply")

def refuse(why):
    print(why + fix)
    sys.exit(1)

if not name:
    names = sorted(n for n in os.listdir(stashes) if fnmatch.fnmatch(n, "boxmunge-stash-*.tar.gz"))
    if not names:
        refuse(f"no stash in {stashes} to restore")
    name = names[-1]
    print(f"WARN: no stash recorded for this upgrade; restoring the newest-named, {name}", file=sys.stderr)
src = os.path.join(stashes, name)
try:
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError as e:
    refuse(f"{src} {'is a symlink' if e.errno == errno.ELOOP else 'cannot be opened: ' + e.strerror}")
with os.fdopen(fd, "rb") as f:
    st = os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
        refuse(f"{src} is not a plain file of root's")
    os.makedirs(dest, mode=0o700, exist_ok=True)
    for old in os.listdir(dest):
        os.unlink(os.path.join(dest, old))
    out_fd, tmp = tempfile.mkstemp(dir=dest, prefix=".copy.")
    digest = hashlib.sha256()
    with os.fdopen(out_fd, "wb") as out:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())
    if want and (os.path.getsize(tmp), digest.hexdigest()) != want:
        os.unlink(tmp)
        refuse(f"{src} is not the stash this upgrade made (its size or sha256 differs from the record)")
copy = os.path.join(dest, name)
os.replace(tmp, copy)
print(copy)
PYSTASH
}

# restore_stash_copy <archive>: the previous (now live) release restores
# <archive>; prints what it says.
restore_stash_copy() {
    BM_STASH="$1" "$(active_venv)/bin/python" -c "
import os, sys
from pathlib import Path
from boxmunge.paths import BoxPaths
from boxmunge.stash import StashError, restore_stash
try:
    print('Restored from:', restore_stash(BoxPaths(), Path(os.environ['BM_STASH'])).name)
except (OSError, StashError) as e:
    sys.exit(f'ERROR: {e}')
"
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
    [[ "$stage" == interrupted ]] || report_failure "$new_version" "$from_version" "apply_partial_rollback" "rollback_step_failed: ${step} exit ${rc}"
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

# do_rollback <new_version> <from_version> <stage> <prev_slot> [detail]: return
# to <prev_slot>; [detail] says why, for complete_rollback. The rollback-inflight marker is on disk before the swap, so a
# crash anywhere from here on is finished by the next check-probation.
#
# An interruption (stage "interrupted": a power cut or kill) is rarely the
# release's fault. The first one of a version is not blocklisted, so
# auto-update retries it; a second one is, so a release whose apply reliably
# hangs or is killed cannot loop. The count is decided here, kept in the
# marker, and recorded only once the rollback has succeeded.
do_rollback() {
    local new_version="$1" from_version="$2" stage="$3" prev_slot="$4" detail="${5:-}" count=0
    rollback_target_ok "$prev_slot" \
        || die_logged "Cannot roll back $new_version: env-$prev_slot is not a working venv, or is itself a half-finished upgrade; inspect it as supervisor"
    [[ "$stage" != interrupted ]] || count=$(( $(interruptions "$new_version") + 1 ))
    printf '%s\n%s\n%s\n' "$new_version" "$stage" "$count" > "$(rollback_marker "$prev_slot")"
    sync
    complete_rollback "$new_version" "$from_version" "$stage" "$prev_slot" "$count" "$detail"
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

# complete_rollback <new_version> <from_version> <stage> <prev_slot> <count> [detail]:
# everything after the marker. [detail] (why, when the stage alone does not
# say) goes into the log once swapped, since before that the logging venv may
# be the broken one, and with the failure report; a resumed rollback has none. Safe to run again after a crash part-way: the
# swap is skipped once done, the stash restore and re-apply are idempotent,
# and the interruption count is set, not incremented.
complete_rollback() {
    local new_version="$1" from_version="$2" stage="$3" prev_slot="$4" count="$5" detail="${6:-}"
    log "ROLLBACK: $new_version failed at stage=$stage, reverting to slot $prev_slot"
    bm_log warn upgrade "rollback initiated" "{\"version\": \"$new_version\", \"from_version\": \"$from_version\", \"stage\": \"$stage\"}"

    # D14: the release being rolled back from tears down its staged releases
    # (an older release does not know .releases/staged/). Only before the
    # swap: once swapped, the active venv is the older release.
    if [[ "$ACTIVE_SLOT" != "$prev_slot" ]]; then
        teardown_before_rollback
    fi
    [[ "$ACTIVE_SLOT" == "$prev_slot" ]] || swap_to "$prev_slot"
    if [[ -n "$detail" ]]; then
        log "ROLLBACK reason: $detail"
        bm_log warn upgrade "rolling back $new_version: $detail" "{\"version\": \"$new_version\", \"stage\": \"$stage\"}"
    fi
    # Any probation ended with this rollback. Left behind, it would name the
    # now-live slot as previous_slot.
    rm -f "$PROBATION_FILE"
    clear_probation_markers

    # 1. Stash restore returns config + state to the pre-upgrade snapshot: a
    #    root-only copy of the stash this upgrade made (copy_rollback_stash).
    local output rc=0 archive
    archive="$(copy_rollback_stash "$new_version")" || rollback_partial "$new_version" "$from_version" "$stage" \
        "$prev_slot" "stash restore" 1 "$archive"
    output="$(restore_stash_copy "$archive" 2>&1)" || rc=$?
    [[ "$rc" -eq 0 ]] || rollback_partial "$new_version" "$from_version" "$stage" "$prev_slot" \
        "stash restore" "$rc" "$output"
    log "$output"

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
    # The box is back on the previous release. Drop the marker before any
    # bookkeeping, the interruption count included: if that fails (a corrupt
    # interrupted.json, say), the next fire must not restore and re-apply
    # (restarting every project) all over again. A crash right here loses
    # one interruption from the count: at worst one extra retry.
    rm -f "$(rollback_marker "$prev_slot")"
    rm -rf "$STASH_RECORD_FILE" "$STASH_COPY_DIR"
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
        send_notification "boxmunge ROLLBACK" "Rolled back $new_version: the upgrade was interrupted ($outcome)."
    else
        add_blocklist "$new_version" "$stage"
        report_failure "$new_version" "$from_version" "$stage" "$detail"
        send_notification "boxmunge ROLLBACK" "Rolled back $new_version (stage: $stage)."
    fi

    log "Rollback complete: reverted to $from_version"
    exit 1
}
