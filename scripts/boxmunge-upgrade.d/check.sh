# shellcheck shell=bash
# check.sh — what deploy may ask root before an upgrade: `check <version>`,
# the target release's own readiness check against this box (its part under
# upgrade.lock is `_check-run`, root only), and `guide <version>`, the
# release's signed upgrade notes. Neither changes any upgrade state (the
# blocklist, the slots, the failure counts, probation, the stash), whatever
# happens: every helper they share with an upgrade runs read-only.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# The first release that publishes upgrade-notes.json (at most
# NOTES_MAX_BYTES) and carries the readiness command.
FIRST_NOTES_RELEASE="0.11.8"
NOTES_MAX_BYTES=1048576
# One check at a time (check.lock), each starting at least CHECK_WINDOW_SECS
# after the last one began and after it ended (check-last, the epoch second
# of the later): a check downloads a release and builds a venv as root, and
# holds upgrade.lock for up to ten minutes, so back-to-back checks must not
# be able to keep it held. Both root-only, in upgrade-root/.
CHECK_WINDOW_SECS=600
CHECK_LOCK_FILE="$UPGRADE_ROOT_DIR/check.lock"
CHECK_STAMP_FILE="$UPGRADE_ROOT_DIR/check-last"
# The scratch, root's and 0755, cleared when a check begins and removed when
# it ends: download/ (0700) the verified bundle, venv/ the release's venv,
# which deploy runs its checks from (so not in 0700 upgrade-root/), out/
# (0700) what the confined runs reported. Not in /tmp, a tmpfs on Debian 13.
CHECK_DIR="$BOXMUNGE_ROOT/upgrade-check"
# Free there: the upgrade's own 250 MB floor, and the scratch (a venv is
# about 90 MB, the bundle a few).
CHECK_FREE_MB=400
CHECK_VERSION=""
CHECK_INSTALLED=""
CHECK_OUT=""
CHECK_STAMPED=0

usage_exit() { echo "Usage: $1" >&2; exit 2; }

# check <version>: the readiness check of <version> against this box. After
# the argument check, stdout is one JSON object (check contract 1; fd 3 is
# its, everything else goes to stderr) and the exit code is 0 only for a
# pass. A refusal comes first, before anything is fetched or written.
cmd_check() {
    [[ $# -eq 1 && "$1" =~ $SEMVER_RE ]] || usage_exit "boxmunge-upgrade check <version>"
    exec 3>&1 1>&2
    CHECK_VERSION="$1"
    CHECK_INSTALLED="$(installed_version)"
    require_systemd_run
    # Before load_active_slot, which repairs active-slot after a cut-short swap.
    ! check_interrupted || check_refused "an earlier upgrade or rollback was interrupted, and the health timer's check-probation finishes it within minutes; run upgrade-check again after that"
    load_active_slot
    take_check_lock || check_refused "a readiness check is already running; retry when it ends"
    check_refusals
    prepare_check_dir
    write_root_file "$CHECK_STAMP_FILE" "$(date +%s)"
    CHECK_STAMPED=1
    bm_log info upgrade "readiness check started" "{\"version\": \"$CHECK_VERSION\"}"

    local bundle="$CHECK_DIR/download/boxmunge" rc=0 missing
    fetch_release "$CHECK_VERSION" "$CHECK_DIR/download" readonly || check_finish cant_verify fetch "$FETCH_ERROR"
    run_prerequisites "$bundle" "$CHECK_OUT/prerequisites.jsonl" || rc=$?
    case "$rc" in
        0) ;;
        1) check_finish blocked prerequisites "this box does not meet what $CHECK_VERSION needs before it can be installed" ;;
        *) check_finish cant_verify prerequisites "could not tell whether this box meets what $CHECK_VERSION needs" ;;
    esac
    if missing="$(missing_requirement "$bundle")"; then
        check_finish cant_verify venv "the bundle of $CHECK_VERSION has no hash-pinned $missing, so no venv is built from it"
    fi
    build_check_venv "$bundle" "$CHECK_DIR/venv" "$CHECK_OUT/venv.txt" || rc=$?
    case "$rc" in
        0) ;;
        124) check_finish cant_verify venv "building $CHECK_VERSION's venv did not finish within $VENV_SECS s; retry when the box is less busy" ;;
        *) check_finish cant_verify venv "building $CHECK_VERSION's venv failed (exit $rc): $(tail -c 1024 "$CHECK_OUT/venv.txt")" ;;
    esac
    "$BASH" "$SHIM_PATH" _check-run "$CHECK_VERSION" "$CHECK_INSTALLED" >"$CHECK_OUT/check-run.log" 2>&1 || rc=$?
    check_outcome "$rc"
}

# check_interrupted: an upgrade or rollback marker in either slot.
check_interrupted() {
    [[ -e "$(inflight_marker a)" || -e "$(inflight_marker b)" || -e "$(rollback_marker a)" || -e "$(rollback_marker b)" ]]
}

# take_check_lock: check.lock, on fd 7 until the shim exits. In root-only
# upgrade-root/, which deploy cannot write, so it is opened by name.
take_check_lock() {
    refuse_symlink "$UPGRADE_ROOT_DIR"
    [[ -d "$UPGRADE_ROOT_DIR" ]] || mkdir -m 0700 "$UPGRADE_ROOT_DIR"
    refuse_symlink "$CHECK_LOCK_FILE"
    exec 7>>"$CHECK_LOCK_FILE"
    chmod 0600 "$CHECK_LOCK_FILE"
    flock -n 7
}

# check_refusals: what stops a check before it fetches anything.
check_refusals() {
    local v="$CHECK_VERSION" state
    semver_lt "$CHECK_INSTALLED" "$v" \
        || check_refused "this box runs $CHECK_INSTALLED, and upgrade-check checks a newer release: run upgrade-howto to see the latest"
    if semver_lt "$v" "$FIRST_NOTES_RELEASE" || ! semver_lt "$LAST_RELEASE_WITHOUT_MCP_LOCK" "$v"; then
        check_refused "$v predates the readiness check (releases carry it from $FIRST_NOTES_RELEASE on), so it cannot be checked; upgrade to it from the deploy shell: upgrade --target $v"
    fi
    ! is_blocklisted "$v" \
        || check_refused "$v is blocklisted on this box (it failed an earlier upgrade). The operator clears it as supervisor (sudo $BIN_DIR/boxmunge-upgrade clear-blocklist $v), then run upgrade-check again"
    check_probation
    state="$(userns_state)" \
        || check_refused "the userns migration journal is malformed; the operator inspects it as supervisor: sudo $BIN_DIR/boxmunge-upgrade userns-migrate --check"
    case "${state#* }" in
        ""|applied|committed|rolled-back) ;;
        *) check_refused "a userns $state is stopped part-way, and no upgrade runs until it is finished. The operator finishes it as supervisor (sudo $BIN_DIR/boxmunge-upgrade $(userns_finish "$state")), then run upgrade-check again" ;;
    esac
    check_rate_limit
}

# check_probation: refuse while probation.json is there. deploy may write it,
# so it is only read (read_probation changes nothing): never settled or
# removed, as check-probation does.
check_probation() {
    [[ -e "$PROBATION_FILE" || -L "$PROBATION_FILE" ]] || return 0
    local found version ends expired status previous
    found="$( { read_probation && printf '%s|%s|%s|%s|%s' "$PROB_VERSION" "$PROB_EXPIRES_AT" "$PROB_EXPIRED" \
        "$PROB_STATUS" "$PROB_PREV_SLOT"; } 2>/dev/null)" \
        || check_refused "$PROBATION_FILE is unreadable or malformed, and defers every upgrade until it is removed. The operator inspects and removes it as supervisor (sudo rm $PROBATION_FILE), then run upgrade-check again"
    IFS='|' read -r version ends expired status previous <<< "$found"
    if [[ "$status" == unrecorded || "$previous" == "$ACTIVE_SLOT" ]]; then
        check_refused "$PROBATION_FILE names $version on probation, but no upgrade on this box is running that probation; the health timer's check-probation removes it within minutes, then run upgrade-check again"
    fi
    [[ "$expired" == no ]] \
        || check_refused "$version has finished its probation, and the health timer's check-probation promotes it within minutes; run upgrade-check again after that"
    check_refused "$version is on probation until $ends, and no upgrade runs until it ends; run upgrade-check again after that"
}

# check_rate_limit: one check every CHECK_WINDOW_SECS. A stamp in the future
# (the clock went back) does not refuse: a clock step must not stop checks
# for days.
check_rate_limit() {
    local last now
    refuse_symlink "$CHECK_STAMP_FILE"
    [[ -e "$CHECK_STAMP_FILE" ]] || return 0
    last="$(cat "$CHECK_STAMP_FILE")"
    [[ "$last" =~ ^[0-9]{1,15}$ ]] \
        || check_refused "$CHECK_STAMP_FILE is malformed; the operator removes it as supervisor (sudo rm $CHECK_STAMP_FILE), then run upgrade-check again"
    now="$(date +%s)"
    if (( now - 10#$last >= 0 && now - 10#$last < CHECK_WINDOW_SECS )); then
        check_refused "the last readiness check ran less than $((CHECK_WINDOW_SECS / 60)) minutes ago, and checks start at least $((CHECK_WINDOW_SECS / 60)) minutes after the last one ended; run upgrade-check again from $(utc_time $((10#$last + CHECK_WINDOW_SECS)))"
    fi
}

# check_exit: the EXIT trap of a check that owns the scratch. One that got as
# far as its stamp stamps again as it ends, however it ends, so the next can
# start only CHECK_WINDOW_SECS after this one has let go of upgrade.lock.
check_exit() {
    [[ "$CHECK_STAMPED" -eq 0 ]] || write_root_file "$CHECK_STAMP_FILE" "$(date +%s)"
    cleanup_scratch
}

utc_time() { python3 -I -c 'import sys, time; print(time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(sys.argv[1]))))' "$1"; }

# prepare_check_dir: CHECK_DIR, empty, root's; and the free space there. It
# is under BOXMUNGE_ROOT, which must be root's and writable by root alone:
# otherwise deploy could swap a link in for it between the checks and use.
prepare_check_dir() {
    local avail
    python3 -I -c 'import os, sys
st = os.stat(sys.argv[1])
sys.exit(st.st_uid != os.geteuid() or st.st_mode & 0o022)' "$BOXMUNGE_ROOT" \
        || check_refused "$BOXMUNGE_ROOT is not root's alone (another user owns it or may write it), so no scratch is made under it. The operator fixes it as supervisor: sudo chown root:root $BOXMUNGE_ROOT && sudo chmod 0755 $BOXMUNGE_ROOT"
    [[ ! -L "$CHECK_DIR" ]] \
        || check_refused "$CHECK_DIR is a symlink; the operator removes it as supervisor (sudo rm $CHECK_DIR), then run upgrade-check again"
    # From here this check owns the scratch (it holds check.lock): removed
    # however the shim exits. A refusal before here leaves everything as it was.
    # shellcheck disable=SC2034  # read by cleanup_scratch (release.sh)
    OWNED_CHECK_DIR="$CHECK_DIR"
    trap check_exit EXIT
    rm -rf "$CHECK_DIR"
    mkdir -m 0755 "$CHECK_DIR"
    mkdir -m 0700 "$CHECK_DIR/download" "$CHECK_DIR/out"
    if [[ "$(id -u)" -eq 0 ]]; then chown root:root "$CHECK_DIR" "$CHECK_DIR/download" "$CHECK_DIR/out"; fi
    CHECK_OUT="$CHECK_DIR/out"
    avail="$(df -P -m "$CHECK_DIR" | awk 'NR==2{print $4}')"
    [[ "$avail" =~ ^[0-9]+$ ]] || die "Cannot read the free space of $CHECK_DIR from df (got '$(printable "$avail")')"
    [[ "$avail" -ge "$CHECK_FREE_MB" ]] \
        || check_refused "$CHECK_DIR has ${avail} MB free, and a check needs $CHECK_FREE_MB MB (an upgrade's 250 MB, and the scratch venv). Free disk space, then run upgrade-check again"
}

# build_check_venv <bundle> <venv> <output>: the release's venv, built as an
# upgrade builds a slot (only the bundle's hash-pinned requirements, then the
# package with no further resolution), as root, confined, writing only
# CHECK_DIR; what it prints goes to <output>.
build_check_venv() {
    local script
    script="$(declare -p PINNED_REQUIREMENTS)
$(declare -f install_pinned_deps_into)
set -euo pipefail
python3 -m venv \"\$2\"
install_pinned_deps_into \"\$1\" \"\$2\"
\"\$2/bin/pip\" install --quiet --no-cache-dir --no-deps --no-build-isolation \"\$1\""
    confined_run venv "$VENV_SECS" root "$CHECK_DIR" "$3" + -- bash -c "$script" build-venv "$1" "$2"
}

# _check-run <version> <installed>: the part of a check that reads the live
# box, under upgrade.lock: the release's readiness command, then (when it
# answered) its `upgrade --dry-run`, each as deploy, confined, results in
# CHECK_DIR/out. Run by check, as root; not in deploy's sudo rule. The lock is
# taken here, not in check, because acquire_lock runs the shim again with
# the same arguments. Exits 75 when an upgrade holds the lock, 76 when the
# installed release changed since the check began.
cmd_check_run() {
    [[ $# -eq 2 && "$1" =~ $SEMVER_RE && "$2" =~ $SEMVER_RE ]] \
        || die "Usage: boxmunge-upgrade _check-run <version> <installed> (check runs it)"
    local venv="$CHECK_DIR/venv" out="$CHECK_DIR/out" rc=0 verdict
    [[ ! -L "$CHECK_DIR" && -d "$out" && -x "$venv/bin/boxmunge-server" ]] \
        || die "$CHECK_DIR holds no checked release; run: boxmunge-upgrade check $1"
    load_active_slot
    acquire_lock try || exit 75
    [[ "$(installed_version)" == "$2" ]] || exit 76
    run_readiness "$venv" "$out/readiness.json" || rc=$?
    echo "$rc" > "$out/readiness.rc"
    verdict="$(readiness_verdict "$out/readiness.json" "$rc")"
    echo "$verdict" > "$out/readiness.verdict"
    [[ "$verdict" != invalid ]] || exit 0
    rc=0
    confined_run dryrun "$DRY_RUN_SECS" deploy - "$out/dry_run.out" + \
        -- "$venv/bin/boxmunge-server" upgrade --dry-run || rc=$?
    tail -c 4096 "$out/dry_run.out" > "$out/dry_run.txt"
    echo "$rc" > "$out/dry_run.rc"
}

# check_outcome <_check-run exit code>: finish with what it found.
check_outcome() {
    local out="$CHECK_OUT" rc verdict dry err reasons=()
    case "$1" in
        0) ;;
        75) check_finish cant_verify readiness "an upgrade is in progress; retry after it" ;;
        76) check_finish cant_verify readiness "the box was upgraded during the check; run upgrade-check again" ;;
        *) check_finish cant_verify readiness "the readiness run stopped (exit $1): $(tail -c 1024 "$out/check-run.log")" ;;
    esac
    rc="$(cat "$out/readiness.rc")"
    verdict="$(cat "$out/readiness.verdict")"
    err="$(tail -c 1024 "$out/readiness.json.err")"
    case "$rc:$verdict" in
        124:*) check_finish cant_verify readiness "the readiness check of $CHECK_VERSION did not finish within $READINESS_SECS s; retry when the box is less busy" ;;
        125:*) check_finish cant_verify readiness "could not tell how the readiness check of $CHECK_VERSION ended: $err" ;;
        2:invalid) check_finish cant_verify readiness "$CHECK_VERSION has no working readiness command (boxmunge-server upgrade-readiness --json exited 2, a usage error: $err), so it cannot be checked" ;;
        0:pass) ;;
        1:blocked) reasons+=("the readiness check of $CHECK_VERSION found what blocks the upgrade: $(readiness_summary "$out/readiness.json")") ;;
        *) check_finish cant_verify readiness "the readiness command of $CHECK_VERSION gave no valid answer (exit $rc): $err" ;;
    esac
    dry="$(cat "$out/dry_run.rc")"
    case "$dry" in
        0) [[ "$verdict" != blocked ]] || check_finish blocked complete "${reasons[@]}"
           check_finish pass complete ;;
        124) reasons+=("the upgrade's own pre-flight (upgrade --dry-run) did not finish within $DRY_RUN_SECS s; retry when the box is less busy") ;;
        125) reasons+=("could not tell how the upgrade's own pre-flight (upgrade --dry-run) ended") ;;
        *) reasons+=("the upgrade's own pre-flight (upgrade --dry-run) of $CHECK_VERSION refused (exit $dry); dry_run.output says why")
           check_finish blocked dry_run "${reasons[@]}" ;;
    esac
    [[ "$verdict" != blocked ]] || check_finish blocked dry_run "${reasons[@]}"
    check_finish cant_verify dry_run "${reasons[@]}"
}

check_refused() { check_finish cant_verify refused "$1"; }

# check_finish <result> <stage> [<reason>...]: print the check's answer (one
# JSON object: check contract 1), log it, and exit 0 for pass, 1 otherwise.
# Reasons and output are cut and cleaned; the readiness answer is the
# release's own, at most READINESS_MAX_BYTES, re-serialised.
check_finish() {
    BM_TARGET="$CHECK_VERSION" BM_INSTALLED="$CHECK_INSTALLED" BM_RESULT="$1" BM_STAGE="$2" BM_OUT="$CHECK_OUT" \
        python3 -I -c "$PY_CLEAN"'
import json, os, sys
out, stage = os.environ["BM_OUT"], os.environ["BM_STAGE"]
def read(name, limit):
    if not out:
        return None
    try:
        with open(os.path.join(out, name), "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except FileNotFoundError:
        return None
prerequisites = [json.loads(line) for line in (read("prerequisites.jsonl", 1 << 20) or "").splitlines()]
reasons = [clean(r, 1000) for r in sys.argv[1:21]]
if stage == "prerequisites":
    reasons += [clean(p["script"] + ": " + p["message"], 1000) for p in prerequisites if not p["ok"]]
readiness = None
if (read("readiness.verdict", 16) or "").strip() in ("pass", "blocked"):
    readiness = json.loads(read("readiness.json", 1 << 20))
dry_run, rc = None, read("dry_run.rc", 16)
if rc is not None:
    output = "".join(c if c == "\n" or " " <= c <= "~" else "?" for c in (read("dry_run.txt", 4096) or ""))
    dry_run = {"ok": rc.strip() == "0", "output": output}
print(json.dumps({"check": 1, "target": os.environ["BM_TARGET"], "installed": os.environ["BM_INSTALLED"],
                  "result": os.environ["BM_RESULT"], "stage": stage, "reasons": reasons,
                  "prerequisites": prerequisites, "readiness": readiness, "dry_run": dry_run}))
' "${@:3}" >&3
    bm_log info upgrade "readiness check finished" \
        "{\"version\": \"$CHECK_VERSION\", \"result\": \"$1\", \"stage\": \"$2\"}"
    [[ "$1" == pass ]] || exit 1
    exit 0
}

# guide <version>: print release <version>'s upgrade-notes.json byte for
# byte, once its own line in the release's signed SHA256SUMS verifies it (the
# deploy side composes the guide). No lock and no rate limit: a few small
# downloads, and no release code runs.
cmd_guide() {
    [[ $# -eq 1 && "$1" =~ $SEMVER_RE ]] || usage_exit "boxmunge-upgrade guide <version>"
    exec 3>&1 1>&2
    local version="$1" installed notes size rc=0
    installed="$(installed_version)"
    semver_lt "$installed" "$version" \
        || die "Not fetching the upgrade notes of $version: this box runs $installed, and they are for a newer release; run upgrade-howto to see the latest"
    ! semver_lt "$version" "$FIRST_NOTES_RELEASE" \
        || die "$version has no upgrade notes: releases publish them from $FIRST_NOTES_RELEASE on; run upgrade-howto to see the latest"
    start_download
    notes="$TMP_DOWNLOAD/upgrade-notes.json"
    fetch_signed_sums "$version" "$TMP_DOWNLOAD" readonly || die "$FETCH_ERROR (the upgrade notes of $version)"
    download "$notes" "$(release_url "$version" upgrade-notes.json)" --max-filesize "$NOTES_MAX_BYTES" || rc=$?
    case "$rc" in
        0) ;;
        22) die "Release $version publishes no upgrade-notes.json (GitHub refused the download)" ;;
        63) die "upgrade-notes.json of $version is over $NOTES_MAX_BYTES bytes; refusing it" ;;
        *) die "Failed to download upgrade-notes.json of $version (curl exit $rc); retry later" ;;
    esac
    size="$(wc -c < "$notes" | tr -d ' ')"
    [[ "$size" -le "$NOTES_MAX_BYTES" ]] || die "upgrade-notes.json of $version is $size bytes, over $NOTES_MAX_BYTES; refusing it"
    verify_listed "$TMP_DOWNLOAD" upgrade-notes.json notes || die "$FETCH_ERROR (upgrade-notes.json of $version)"
    cat "$notes" >&3
}
