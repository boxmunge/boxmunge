#!/usr/bin/env bash
# tests/shim/test_probation_dead_live.sh — a release on probation whose live
# venv can no longer run boxmunge-server (a dependency install that broke it,
# say) is rolled back to the proven previous slot. Before, check-probation
# rolled back only on health exit 2: a health check that could not run at all
# (exit 126/127, or a server that dies on start) passed, and at expiry the
# promotion refused to delete the previous slot while the live one was dead,
# so the probation never ended and every upgrade entry point refused.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

EXPIRED="2000-01-01T00:00:00+00:00"
DEAD='echo "ImportError: broken venv" >&2; exit 1'

# box <live server body> <expires_at> [prev]: slot a is live on 1.5.0 and on
# probation, with slot b (1.4.0, working) as its previous slot; prev=gone
# removes b. Both pythons record bm_log and alert calls.
box() {
    new_root a
    echo "1.5.0" > "$BOXMUNGE_ROOT/config/version"
    mock_server a "$1"
    mock_server b '[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    local s
    for s in a b; do
        rm "$BOXMUNGE_ROOT/env-$s/bin/python"
        printf '%s\n' '#!/usr/bin/env bash' \
            'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
            'if [[ -n "${BM_TITLE:-}" ]]; then echo "notify p=$BM_PRIORITY $BM_TITLE: $BM_MESSAGE" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
            'exit 0' > "$BOXMUNGE_ROOT/env-$s/bin/python"
        chmod +x "$BOXMUNGE_ROOT/env-$s/bin/python"
    done
    [[ "${3:-}" != gone ]] || rm -r "$BOXMUNGE_ROOT/env-b"
    write_probation "1.5.0" "b" "$2"
    : > "$BOXMUNGE_ROOT/calls"
}
calls() { cat "$BOXMUNGE_ROOT/calls"; }
live() { readlink "$BOXMUNGE_ROOT/env-active"; }
probation_left() { [[ -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]]; }

# --- a dead live slot rolls back to a working previous slot -------------------

for expiry in "$SOON" "$EXPIRED"; do
    box "$DEAD" "$expiry"
    run_shim check-probation
    expect 1 "Rollback complete" "a dead live slot is rolled back (expires_at $expiry)"
    [[ "$(live)" == "$BOXMUNGE_ROOT/env-b" ]] && pass "env-b, the previous release, is live again" \
        || fail "still live: $(live)"
    probation_left && fail "probation.json left behind" || pass "the rollback ends the probation"
    [[ "$OUT" == *"env-a/bin/boxmunge-server does not run"* ]] && pass "the reason is given" \
        || fail "no reason given: $OUT"
    drop_root
done

# --- a health check that cannot run counts as critical ------------------------

for rc in 126 127; do
    box "if [[ \"\$1\" == health ]]; then exit $rc; fi; exit 0" "$SOON"
    run_shim check-probation
    expect 1 "Rollback complete" "health exit $rc during probation rolls back"
    [[ "$(live)" == "$BOXMUNGE_ROOT/env-b" ]] && pass "health exit $rc: env-b is live again" \
        || fail "health exit $rc: still live: $(live)"
    drop_root
done

box 'if [[ "$1" == health ]]; then exit 1; fi; exit 0' "$SOON"
run_shim check-probation
expect 0 "" "health warnings (exit 1) do not roll back"
[[ "$(live)" == "$BOXMUNGE_ROOT/env-a" ]] && probation_left && pass "the probation carries on" \
    || fail "warnings ended the probation"
drop_root

# --- no working slot at all: said once, with the way out ----------------------

for expiry in "$SOON" "$EXPIRED"; do
    box "$DEAD" "$expiry" gone
    run_shim check-probation
    expect 1 "cannot be rolled back" "a dead live slot without a rollback target refuses (expires_at $expiry)"
    [[ "$OUT" == *"sudo bash boxmunge-install.sh"* && "$OUT" == *"1.5.0"* ]] \
        && pass "the refusal names the reinstall of 1.5.0" || fail "no recovery named: $OUT"
    [[ "$OUT" != *"Refusing to remove"* ]] && pass "no slot removal is attempted" || fail "tried to remove a slot: $OUT"
    [[ "$(calls)" == *"bm_log error 1.5.0 "*"cannot be rolled back"* ]] && pass "logged as an error" \
        || fail "not logged: $(calls)"
    [[ "$(calls)" == *"notify p=1 boxmunge rollback needed but impossible"* ]] && pass "alerted" \
        || fail "not alerted: $(calls)"
    probation_left && pass "the probation stays for the operator" || fail "probation removed"
    : > "$BOXMUNGE_ROOT/calls"
    run_shim check-probation
    expect 1 "cannot be rolled back" "the next fire still refuses"
    [[ "$(calls)" != *"bm_log error"* && "$(calls)" != *notify* ]] && pass "the next fire neither logs nor alerts again" \
        || fail "the next fire repeated the error or alert: $(calls)"
    drop_root
done

# Once the live slot is reinstalled, the probation carries on as normal.
box "$DEAD" "$SOON" gone
run_shim check-probation
mock_server a 'exit 0'
run_shim check-probation
expect 0 "" "after the reinstall check-probation carries on"
probation_left && pass "the probation is still running" || fail "probation ended"
drop_root

finish
