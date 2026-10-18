# shellcheck shell=bash
# userns.sh — the root-only user-namespace migration (OPERATIONS.md,
# "User-namespace remapping"). The supervisor runs these through sudo; they
# are not in deploy's sudo rule. The Python core (`boxmunge-server userns
# ...`) refuses to run unless it inherits this shim's upgrade.lock.

USERNS_JOURNAL="$UPGRADE_ROOT_DIR/userns-migration.json"
# The first release that understands a remapped daemon. A release before it
# would start the system container in the remapped namespace.
FIRST_USERNS_RELEASE="0.11.0"

# userns_state: "<direction> <phase>" from the journal ("forward commit"
# for an applied migration whose commit began), or nothing when there is
# none. The directory is root-only; the file is still opened
# without following a link.
userns_state() {
    refuse_symlink "$UPGRADE_ROOT_DIR"
    refuse_symlink "$USERNS_JOURNAL"
    [[ -e "$USERNS_JOURNAL" ]] || return 0
    BM_FILE="$USERNS_JOURNAL" python3 -c 'import json, os
fd = os.open(os.environ["BM_FILE"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd) as f:
    doc = json.load(f)
d, p = doc["direction"], doc["phase"]
assert isinstance(d, str) and isinstance(p, str) and d.isalpha() and p.replace("-", "").isalpha()
if p == "applied" and "commit-before" in (doc.get("items") or {}):
    p = "commit"
print(d, p)' 2>/dev/null || die "$USERNS_JOURNAL is malformed; inspect it (boxmunge-server userns check)"
}

# userns_guard_target <version>: force-target may not go below the first
# release that understands remapping while the box is remapped.
userns_guard_target() {
    local state
    state="$(userns_state)"
    if [[ "$state" == "forward applied" || "$state" == "forward commit" || "$state" == "forward committed" ]] \
            && semver_lt "$1" "$FIRST_USERNS_RELEASE"; then
        die "Refusing $1: this box's Docker daemon is remapped (userns migration ${state#* }), and releases before $FIRST_USERNS_RELEASE would start the system container in the remapped namespace."
    fi
}

# userns_finish <state>: the subcommand that finishes a stopped <state>.
userns_finish() {
    case "$1" in
        "forward commit") echo "userns-commit" ;;
        rollback\ *) echo "userns-rollback" ;;
        *) echo "userns-migrate (to resume) or userns-rollback" ;;
    esac
}

# userns_refuse_mid_migration <version> <mode>: no upgrade while a migration,
# its rollback or its commit is stopped part-way: an upgrade restarts
# projects, which would start them on data that is only partly shifted, or
# from a store being deleted.
userns_refuse_mid_migration() {
    local state
    state="$(userns_state)"
    case "${state#* }" in
        ""|applied|committed|rolled-back) return 0 ;;
    esac
    bm_log warn upgrade "upgrade deferred: userns migration in progress" "{\"version\": \"$1\"}"
    if [[ "$2" == "run" ]]; then
        log "Not upgrading to $1: a userns $state is in progress. Deferred; auto-update retries on its next run."
        exit 0
    fi
    die "Not upgrading to $1: a userns $state is stopped part-way. Finish it first: sudo $BOXMUNGE_ROOT/bin/boxmunge-upgrade $(userns_finish "$state")."
}

userns_run() {  # userns_run <check|migrate|rollback|commit>
    load_active_slot
    if [[ "$1" != "check" ]]; then
        acquire_lock
        if [[ "$1" == "migrate" ]]; then
            if [[ -e "$(inflight_marker "$ACTIVE_SLOT")" || -e "$(rollback_marker a)" || -e "$(rollback_marker b)" ]]; then
                die "Not migrating: an upgrade or rollback was interrupted; the health timer's check-probation finishes it within minutes. Retry after that."
            fi
            if load_probation; then
                die "Not migrating: $PROB_VERSION is on probation until $PROB_EXPIRES_AT. Migrate after it ends."
            fi
        fi
    fi
    bm_log info userns "userns $1 started" "{}"
    "$(active_venv)/bin/boxmunge-server" userns "$1"
}

cmd_userns_migrate() {
    case "$#:${1:-}" in
        0:) userns_run migrate ;;
        1:--check) userns_run check ;;
        *) die "Usage: boxmunge-upgrade userns-migrate [--check]" ;;
    esac
}

cmd_userns_rollback() { [[ $# -eq 0 ]] || die "Usage: boxmunge-upgrade userns-rollback"; userns_run rollback; }
cmd_userns_commit() { [[ $# -eq 0 ]] || die "Usage: boxmunge-upgrade userns-commit"; userns_run commit; }
