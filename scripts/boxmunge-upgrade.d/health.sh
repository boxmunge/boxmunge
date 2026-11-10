# shellcheck shell=bash
# health.sh — the `health --json` report a release is judged by: run within a
# time budget, required to be a valid report, and compared with the report
# the previous release gave just before the upgrade.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.
#
# A health error that was already there before the upgrade (a firewall left
# off, a project's Caddy site the operator broke) is not the new release's
# doing, and rolling the platform back would not fix it, so it does not roll
# the release back; an error that was not there does. The comparison is by
# check name. The report from before the upgrade is kept for the probation in
# root-only upgrade-root/health-baseline, keyed by the slot the upgrade
# installed:
#   "<slot> report [<check name>...]"  the errors health reported before
#   "<slot> unanswered"                health did not finish before either
# With no baseline (health gave no valid report before the upgrade, or an
# older shim started the probation), every error counts.

HEALTH_BASELINE_FILE="$UPGRADE_ROOT_DIR/health-baseline"
HEALTH_UNJUDGED_FILE="$UPGRADE_ROOT_DIR/health-unjudged"

# health_run <budget> [<baseline>]: run the live slot's `health --json` within
# <budget> seconds (--kill-after escalates to SIGKILL for a wedged docker
# socket) and set HEALTH_VERDICT to its verdict against <baseline> (see
# health_judge).
health_run() {
    local budget="$1" baseline="${2:-}" rc=0 out
    out="$(timeout --kill-after=10 "$budget" "$(active_venv)/bin/boxmunge-server" health --json 2>/dev/null)" || rc=$?
    HEALTH_VERDICT="$(health_judge "$rc" "$out" "$baseline")"
}

# health_judge <exit> <stdout> <baseline>: one line, the verdict word first:
#   ok [<pre-existing error>...]  a valid report with no new error
#   failed <new error>...         a valid report with an error the baseline lacks
#   not_run <exit>                126/127: timeout could not run health at all
#   unanswered <exit>             it timed out or was killed (124 and up)
#   no_report <why>               anything else: a crash before the report (an
#                                 import failure), output that is not the
#                                 report, or a report its exit code disagrees with
# <baseline> is a health-baseline line without its slot, or empty.
health_judge() {
    case "$1" in
        126|127) echo "not_run $1"; return 0 ;;
    esac
    [[ "$1" -lt 124 ]] || { echo "unanswered $1"; return 0; }
    BM_RC="$1" BM_REPORT="$2" BM_BASELINE="$3" python3 - <<'PYHEALTH'
import json, os, re, sys
rc, baseline = int(os.environ["BM_RC"]), os.environ["BM_BASELINE"].split()

def no_report(why):
    print(f"no_report {why}")
    sys.exit(0)

try:
    report = json.loads(os.environ["BM_REPORT"])
except ValueError:
    no_report(f"exit {rc} without a JSON report")
checks = report.get("checks") if isinstance(report, dict) else None
if not isinstance(checks, list) or not checks or not all(
        isinstance(c, dict) and isinstance(c.get("name"), str) and re.fullmatch(r"[a-z0-9][a-z0-9-]*", c["name"])
        and c.get("status") in ("ok", "warn", "error", "skip") for c in checks):
    no_report(f"exit {rc} with JSON that is not a health report")
statuses = {c["status"] for c in checks}
expected = 2 if "error" in statuses else 1 if "warn" in statuses else 0
if report.get("exit_code") != expected or rc != expected:
    no_report(f"exit {rc} with a report whose checks mean exit {expected}")
errors = sorted({c["name"] for c in checks if c["status"] == "error"})
known = set(baseline[1:]) if baseline[:1] == ["report"] else set()
new = [e for e in errors if e not in known]
print(" ".join(["failed", *new] if new else ["ok", *errors]))
PYHEALTH
}

# health_baseline_line: the baseline (without the slot) that HEALTH_VERDICT
# gives, a run of the release about to be replaced judged against no baseline
# (so "failed" lists every error), or nothing.
health_baseline_line() {
    case "${HEALTH_VERDICT%% *}" in
        ok) echo "report" ;;
        failed) echo "report${HEALTH_VERDICT#failed}" ;;
        unanswered) echo "unanswered" ;;
    esac
}

# probation_baseline: the recorded baseline for the live slot (without the
# slot), or nothing.
probation_baseline() {
    local line valid='^[ab] (report( [a-z0-9][a-z0-9-]*)*|unanswered)$'
    refuse_symlink "$HEALTH_BASELINE_FILE"
    [[ -e "$HEALTH_BASELINE_FILE" ]] || return 0
    line="$(cat "$HEALTH_BASELINE_FILE")"
    [[ "$line" =~ $valid ]] \
        || die_logged "$HEALTH_BASELINE_FILE is malformed; remove it (every health error then counts against the release on probation)"
    [[ "${line%% *}" != "$ACTIVE_SLOT" ]] || echo "${line#* }"
}

# health_unjudged <version> <prev_slot> <baseline>: the probation health check
# gave no verdict (HEALTH_VERDICT is unanswered or no_report). Counted, like a
# live slot that does not run (check_live_slot), in a root-only marker keyed
# by the live slot that a judged run resets: two in a row without a report
# roll the release back, or six (half an hour) when the latest only did not
# finish in time, since a busy box can be slow for a while. A health that did
# not finish before the upgrade either is not counted.
health_unjudged() {
    local version="$1" prev_slot="$2" baseline="$3" kind="${HEALTH_VERDICT%% *}" detail="${HEALTH_VERDICT#* }"
    local seen="" count=0 needed=2 what="gave no valid report ($detail)"
    if [[ "$kind" == unanswered ]]; then
        what="did not finish within its time budget (exit $detail)"
        needed=6
        if [[ "$baseline" == unanswered ]]; then
            log "WARN: the probation health check of $version $what, as it did before the upgrade; not counted against it"
            return 0
        fi
    fi
    read -r seen count < "$HEALTH_UNJUDGED_FILE" 2>/dev/null || true
    [[ "$seen" == "$ACTIVE_SLOT" && "$count" =~ ^[0-9]+$ ]] || count=0
    count=$((count + 1))
    if [[ "$count" -lt "$needed" ]]; then
        write_root_file "$HEALTH_UNJUDGED_FILE" "$ACTIVE_SLOT $count"
        log "WARN: the probation health check of $version $what, $count time(s) in a row; $version is rolled back at $needed"
        bm_log warn upgrade "probation health check without a verdict" \
            "{\"version\": \"$version\", \"slot\": \"$ACTIVE_SLOT\", \"verdict\": \"$kind\", \"in_a_row\": $count}"
        exit 0
    fi
    probation_failed "$version" "$prev_slot" "health check $what $count times in a row" "health_${kind}: $detail"
}
