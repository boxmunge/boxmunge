#!/usr/bin/env bash
# tests/shim/test_probation_dead_live.sh — a release on probation whose live
# venv can no longer run boxmunge-server (a dependency install that broke it,
# say) is rolled back to the proven previous slot. Before, check-probation
# rolled back only on health exit 2: a health check that could not run at all
# (exit 126/127, or a server that dies on start) passed, and at expiry the
# promotion refused to delete the previous slot while the live one was dead,
# so the probation never ended and every upgrade entry point refused.
#
# A healthy release must not be rolled back and blocklisted for a blip, so it
# takes two health-timer runs in a row that find the live slot dead, or four
# when `--version` only timed out. When nothing can take over, the once-only
# alert is marked sent only once it really went out.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

EXPIRED="2000-01-01T00:00:00+00:00"
DEAD='echo "ImportError: broken venv" >&2; exit 1'
WORKS='exit 0'

# logger records what reaches the system journal.
LOGGERBIN="$(mktemp -d)"
printf '#!/usr/bin/env bash\necho "journal $*" >> "$BOXMUNGE_ROOT/calls"\n' > "$LOGGERBIN/logger"
chmod +x "$LOGGERBIN/logger"
export PATH="$LOGGERBIN:$PATH"

# python_mock <slot> <notify exit>: env-<slot>/bin/python records bm_log,
# alert and failure-report calls; an alert exits <notify exit> (0 sent, 3
# Pushover not configured, 1 failed). python_dead <slot>: it does not start.
python_mock() {
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log '"$1"' $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
        'if [[ -n "${BM_TITLE:-}" ]]; then echo "notify '"$1"' p=$BM_PRIORITY $BM_TITLE: $BM_MESSAGE" >> "$BOXMUNGE_ROOT/calls"; exit '"$2"'; fi' \
        'if [[ -n "${BM_STAGE:-}" ]]; then echo "report stage=$BM_STAGE detail=$BM_DETAIL" >> "$BOXMUNGE_ROOT/calls"; fi' \
        'exit 0' > "$BOXMUNGE_ROOT/env-$1/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-$1/bin/python"
}
python_dead() { printf '#!/usr/bin/env bash\nexit 127\n' > "$BOXMUNGE_ROOT/env-$1/bin/python"; }

# box <live server body> <expires_at> [prev]: slot a is live on 1.5.0 and on
# probation, with slot b as its previous slot: 1.4.0 and working, or with
# prev=gone removed, or with prev=dead a boxmunge-server that does not run.
box() {
    new_root a
    echo "1.5.0" > "$BOXMUNGE_ROOT/config/version"
    mock_server a "$1"
    mock_server b '[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    rm "$BOXMUNGE_ROOT/env-a/bin/python" "$BOXMUNGE_ROOT/env-b/bin/python"
    python_mock a 0
    python_mock b 0
    case "${3:-}" in
        gone) rm -r "$BOXMUNGE_ROOT/env-b" ;;
        dead) mock_server b "$DEAD" ;;
    esac
    write_probation "1.5.0" "b" "$2"
    : > "$BOXMUNGE_ROOT/calls"
}
calls() { cat "$BOXMUNGE_ROOT/calls"; }
live() { readlink "$BOXMUNGE_ROOT/env-active"; }
probation_left() { [[ -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]]; }
alerted_marker() { [[ -f "$BOXMUNGE_ROOT/upgrade-root/rollback-impossible" ]]; }

# --- a dead live slot rolls back on the second run that finds it ------------

for expiry in "$SOON" "$EXPIRED"; do
    box "$DEAD" "$expiry"
    run_shim check-probation
    expect 0 "the live slot does not run" "the first run that finds the live slot dead waits (expires_at $expiry)"
    [[ "$(live)" == "$BOXMUNGE_ROOT/env-a" ]] && probation_left && pass "nothing is rolled back or promoted yet" \
        || fail "acted on one failure: live $(live)"
    run_shim check-probation
    expect 1 "Rollback complete" "the second run in a row rolls back (expires_at $expiry)"
    [[ "$(live)" == "$BOXMUNGE_ROOT/env-b" ]] && pass "env-b, the previous release, is live again" \
        || fail "still live: $(live)"
    probation_left && fail "probation.json left behind" || pass "the rollback ends the probation"
    [[ ! -e "$BOXMUNGE_ROOT/upgrade-root/live-slot-failed" ]] && pass "the rollback clears the failure count" \
        || fail "live-slot-failed survived the rollback"
    [[ "$OUT" == *"ROLLBACK reason: live_venv_dead: env-a/bin/boxmunge-server --version exited 1: ImportError: broken venv"* ]] \
        && pass "the reason, with the server's own error, is logged after the swap" || fail "no reason given: $OUT"
    [[ "$(calls)" == *"bm_log b warn rolling back 1.5.0: live_venv_dead: "*"ImportError: broken venv"* ]] \
        && pass "the reason reaches the operational log through the previous release" || fail "calls: $(calls)"
    [[ "$(calls)" == *"report stage=health_probation detail=live_venv_dead: "*"ImportError: broken venv"* ]] \
        && pass "the failure report carries the reason" || fail "calls: $(calls)"
    drop_root
done

# A blip in between starts the count again.
box "$DEAD" "$SOON"
run_shim check-probation
mock_server a "$WORKS"
run_shim check-probation
expect 0 "" "a run that finds the live slot working carries on"
mock_server a "$DEAD"
run_shim check-probation
expect 0 "the live slot does not run" "a failure after a working run is a first failure again"
[[ "$(live)" == "$BOXMUNGE_ROOT/env-a" ]] && pass "no rollback for failures that were not in a row" || fail "rolled back"
drop_root

# The count is the live slot's, kept root-only: deploy rewriting the version
# in its probation.json between runs does not start it again.
box "$DEAD" "$SOON"
run_shim check-probation
write_probation "1.5.1" "b" "$SOON"
run_shim check-probation
expect 1 "Rollback complete" "a rewritten probation version does not reset the live-slot failure count"
drop_root

# A --version that crashes (a broken C extension: SIGSEGV) counts like any
# other failure.
box 'kill -SEGV $$' "$SOON"
run_shim check-probation
expect 0 "the live slot does not run" "a crashing --version is a first failure"
run_shim check-probation
expect 1 "Rollback complete" "a crashing --version rolls back on the second run"
drop_root

# One that only times out needs four runs in a row, but is never skipped.
box 'exit 124' "$EXPIRED"
for n in 1 2 3; do
    run_shim check-probation
    expect 0 "the live slot did not answer" "timed-out --version, run $n: waits"
done
[[ "$(calls)" == *"bm_log a warn live slot did not answer"* ]] && pass "each timeout reaches the operational log" \
    || fail "timeouts not logged: $(calls)"
[[ "$(live)" == "$BOXMUNGE_ROOT/env-a" ]] && probation_left && pass "no rollback or promotion after three timeouts" \
    || fail "acted after three timeouts"
run_shim check-probation
expect 1 "Rollback complete" "the fourth timed-out run in a row rolls back"
drop_root

# --- a health check that cannot run: the live slot is checked again ----------

for rc in 126 127; do
    box "if [[ \"\$1\" == health ]]; then exit $rc; fi; exit 0" "$SOON"
    run_shim check-probation
    expect 0 "the live slot runs; the next health-timer run checks" "health exit $rc with a working live slot is not a rollback"
    [[ "$(live)" == "$BOXMUNGE_ROOT/env-a" ]] && probation_left && pass "health exit $rc: the probation carries on" \
        || fail "health exit $rc: rolled back"
    drop_root
done

box 'if [[ "$1" == health ]]; then exec health-report 1; fi; exit 0' "$SOON"
run_shim check-probation
expect 0 "" "health warnings (exit 1) do not roll back"
[[ "$(live)" == "$BOXMUNGE_ROOT/env-a" ]] && probation_left && pass "the probation carries on" \
    || fail "warnings ended the probation"
drop_root

# --- no working slot to roll back to: said once, with the way out -----------

for expiry in "$SOON" "$EXPIRED"; do
    box "$DEAD" "$expiry" gone
    run_shim check-probation
    run_shim check-probation
    expect 1 "cannot be rolled back" "a dead live slot without a rollback target refuses (expires_at $expiry)"
    [[ "$OUT" == *"sudo bash boxmunge-install.sh"* && "$OUT" == *"1.5.0"* ]] \
        && pass "the refusal names the reinstall of 1.5.0" || fail "no recovery named: $OUT"
    [[ "$OUT" != *"Refusing to remove"* ]] && pass "no slot removal is attempted" || fail "tried to remove a slot: $OUT"
    [[ "$(calls)" == *"bm_log a error 1.5.0 "*"cannot be rolled back"* ]] && pass "logged as an error" \
        || fail "not logged: $(calls)"
    [[ "$(calls)" == *"notify a p=1 boxmunge rollback needed but impossible"* ]] && pass "alerted" \
        || fail "not alerted: $(calls)"
    alerted_marker && pass "the alert is marked sent" || fail "no once-only marker"
    probation_left && pass "the probation stays for the operator" || fail "probation removed"
    : > "$BOXMUNGE_ROOT/calls"
    run_shim check-probation
    expect 1 "cannot be rolled back" "the next run still refuses"
    [[ "$(calls)" != *"bm_log a error"* && "$(calls)" != *notify* ]] && pass "the next run neither logs nor alerts again" \
        || fail "the next run repeated the error or alert: $(calls)"
    drop_root
done

# Once the live slot is reinstalled, the probation carries on as normal.
box "$DEAD" "$SOON" gone
run_shim check-probation
run_shim check-probation
mock_server a "$WORKS"
run_shim check-probation
expect 0 "" "after the reinstall check-probation carries on"
probation_left && pass "the probation is still running" || fail "probation ended"
drop_root

# --- the alert itself: through whichever python can send it, and only marked
# --- sent once it went out ---------------------------------------------------

# The live venv's python is dead too; the previous slot's server is broken
# (so no rollback target) but its python sends the alert.
box "$DEAD" "$SOON" dead
python_dead a
run_shim check-probation
run_shim check-probation
expect 1 "cannot be rolled back" "both servers dead: refused"
[[ "$(calls)" == *"bm_log b error 1.5.0 "*"cannot be rolled back"* && "$(calls)" == *"notify b p=1 boxmunge rollback needed but impossible"* ]] \
    && pass "logged and alerted through the previous slot's python" || fail "calls: $(calls)"
alerted_marker && pass "and marked sent" || fail "not marked sent"
drop_root

# The live python can alert but not write the log (a full disk): the alert
# goes out once, and only the log entry is retried.
box "$DEAD" "$SOON" gone
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "$1" == "-" ]]; then cat >/dev/null; exit 1; fi' \
    'if [[ -n "${BM_TITLE:-}" ]]; then echo "notify a $BM_TITLE" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
    'exit 0' > "$BOXMUNGE_ROOT/env-a/bin/python"
run_shim check-probation
run_shim check-probation
[[ "$(calls)" == *"notify a boxmunge rollback needed but impossible"* ]] && pass "the alert is sent although the log write failed" \
    || fail "no alert: $(calls)"
expect 1 "ALERT NOT DELIVERED (to the operational log): 1.5.0 is broken" "the missing log entry is said"
: > "$BOXMUNGE_ROOT/calls"
run_shim check-probation
[[ "$(calls)" != *notify* ]] && pass "the alert is not repeated on the next run" || fail "alert repeated: $(calls)"
drop_root

# Pushover not configured: the log entry is the delivery.
box "$DEAD" "$SOON" gone
python_mock a 3
run_shim check-probation
run_shim check-probation
alerted_marker && pass "with Pushover not configured, the logged error is enough" || fail "not marked sent: $(calls)"
drop_root

# No python can deliver it: not marked, said on stderr and in the journal, and
# tried again on the next run.
for how in dead pushover_down; do
    box "$DEAD" "$SOON" gone
    if [[ "$how" == dead ]]; then python_dead a; else python_mock a 1; fi
    run_shim check-probation
    run_shim check-probation
    expect 1 "ALERT NOT DELIVERED (" "an alert that did not go out says so ($how)"
    [[ "$OUT" == *"ALERT NOT DELIVERED ("*"as an alert): 1.5.0 is broken"* ]] && pass "it says the alert is what failed ($how)" || fail "out: $OUT"
    [[ "$(calls)" == *"journal -t boxmunge-upgrade -p user.crit -- ALERT NOT DELIVERED ("*"): 1.5.0"* ]] \
        && pass "it reaches the system journal ($how)" || fail "not in the journal: $(calls)"
    alerted_marker && fail "marked sent although it was not ($how)" || pass "not marked sent ($how)"
    : > "$BOXMUNGE_ROOT/calls"
    [[ "$how" == dead ]] || python_mock a 0
    run_shim check-probation
    if [[ "$how" == dead ]]; then
        [[ "$OUT" == *"ALERT NOT DELIVERED"* ]] && pass "the next run tries again ($how)" || fail "not retried: $OUT"
    else
        [[ "$(calls)" == *"notify a p=1 boxmunge rollback needed but impossible"* ]] && alerted_marker \
            && pass "the next run sends it once Pushover is back" || fail "not resent: $(calls)"
    fi
    drop_root
done

rm -rf "$LOGGERBIN"
finish
