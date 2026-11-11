#!/usr/bin/env bash
# tests/shim/test_upgrade_health.sh — the health report a release is judged
# by (health.sh). It must be a valid `health --json` report: a crash before the
# report (an import failure), output that is not the report, or a report its
# exit code disagrees with gives no verdict, never "healthy". A health error
# that was already there before the upgrade does not roll the release back;
# one that was not, does. Health that keeps giving no verdict on probation is
# rolled back, so it cannot go on until the probation simply expires.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# --- the upgrade: a baseline before it, the quick check after the swap -------

# A complete upgrade from 1.4.0 (slot a) to 1.5.0 (slot b) against stand-ins:
# curl serves a local release, cosign and sha256sum accept it, python3 -m venv
# copies in a mock venv. OLD_HEALTH and NEW_HEALTH are what each release's
# `health --json` runs (health-report <exit> [<error check>...], say).
FIXTURE="$(mktemp -d)"
REAL_PYTHON3="$(command -v python3)"
mkdir -p "$FIXTURE/bin" "$FIXTURE/release/boxmunge/on-server" "$FIXTURE/venv/bin"
stub() {  # stub <path> <bash body>
    printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"
    chmod +x "$1"
}
stub "$FIXTURE/bin/python3" "if [[ \"\$1 \$2\" == '-m venv' ]]; then mkdir -p \"\$3\"; cp -R '$FIXTURE/venv/bin' \"\$3/\"; exit 0; fi
exec '$REAL_PYTHON3' \"\$@\""
stub "$FIXTURE/bin/curl" 'cp "'"$FIXTURE"'/release/$(basename "${@: -1}")" "$3"'
stub "$FIXTURE/bin/cosign" 'exit 0'
stub "$FIXTURE/bin/sha256sum" 'cat >/dev/null; exit 0'
stub "$FIXTURE/venv/bin/pip" 'exit 0'
stub "$FIXTURE/venv/bin/boxmunge-server" 'case "$1" in
    --version) echo "boxmunge 1.5.0" ;;
    health) eval "$NEW_HEALTH"; exit ;;
esac
exit 0'
stub "$FIXTURE/venv/bin/python" 'if [[ "$1" == "-" ]]; then cat >/dev/null; exit 0; fi
[[ -z "${BM_STAGE:-}" ]] || echo "report stage=$BM_STAGE detail=$BM_DETAIL" >> "$BOXMUNGE_ROOT/calls"
case "$2" in
    *write_probation*)
        printf "{\"version\": \"%s\", \"previous_slot\": \"%s\", \"expires_at\": \"'"$SOON"'\"}\n" \
            "$BM_VERSION" "$BM_PREV_SLOT" > "$BOXMUNGE_ROOT/upgrade-state/probation.json" ;;
    *get_build_version*) echo "1.5.0" ;;
esac
exit 0'
for f in requirements-build.txt requirements-tui.txt requirements-mcp.txt; do echo "x==1" > "$FIXTURE/release/boxmunge/$f"; done
echo "1.5.0 ops" > "$FIXTURE/release/boxmunge/on-server/OPERATIONS.md"
tar czf "$FIXTURE/release/boxmunge-1.5.0.tar.gz" -C "$FIXTURE/release" boxmunge
echo "0000  boxmunge-1.5.0.tar.gz" > "$FIXTURE/release/SHA256SUMS"
touch "$FIXTURE/release/SHA256SUMS.sig" "$FIXTURE/release/SHA256SUMS.cert"
export PATH="$FIXTURE/bin:$PATH"

# installed: slot a holds the proven 1.4.0, whose python records failure reports.
installed() {
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    mock_server a 'case "$1" in
    --version) echo "boxmunge 1.4.0" ;;
    health) eval "$OLD_HEALTH"; exit ;;
esac
exit 0'
    stub "$BOXMUNGE_ROOT/env-a/bin/python" 'if [[ "$1" == "-" ]]; then cat >/dev/null; exit 0; fi
[[ -z "${BM_STAGE:-}" ]] || echo "report stage=$BM_STAGE detail=$BM_DETAIL" >> "$BOXMUNGE_ROOT/calls"
exit 0'
    : > "$BOXMUNGE_ROOT/calls"
}
live() { readlink "$BOXMUNGE_ROOT/env-active" | sed 's|.*/env-||'; }
baseline() { cat "$BOXMUNGE_ROOT/upgrade-root/health-baseline" 2>/dev/null || true; }
upgrade() {  # upgrade <old health> <new health>
    installed
    OLD_HEALTH="$1" NEW_HEALTH="$2" run_shim target 1.5.0
}

upgrade "health-report 1" "health-report 1"
expect 0 "probation started" "a healthy upgrade enters probation"
[[ "$(baseline)" == "b report" ]] && pass "the baseline (no errors) is recorded for the new slot" || fail "baseline: $(baseline)"
drop_root

upgrade "health-report 2 ufw" "health-report 2 ufw"
expect 0 "not counted against 1.5.0: ufw" "an error that was there before the upgrade does not roll it back"
[[ "$(live)" == b && "$(baseline)" == "b report ufw" ]] && pass "1.5.0 is live, on probation with ufw in its baseline" \
    || fail "live $(live), baseline $(baseline)"
drop_root

upgrade "health-report 2 ufw" "health-report 2 ufw caddy"
expect 1 "Rollback complete" "a new error after the swap rolls back"
[[ "$OUT" == *"New health errors after the swap: caddy"* && "$(live)" == a ]] \
    && pass "the rollback names the new error and 1.4.0 is live" || fail "live $(live): $OUT"
grep -q "report stage=health_immediate detail=new_health_errors: caddy" "$BOXMUNGE_ROOT/calls" \
    && pass "the failure report names the new error" || fail "calls: $(cat "$BOXMUNGE_ROOT/calls")"
drop_root

# Health that gives no report before the upgrade leaves no baseline: every
# error after it counts.
upgrade "echo garbage" "health-report 2 ufw"
expect 1 "Rollback complete" "without a baseline every error after the swap counts"
[[ "$OUT" == *"health gave no report before the upgrade"* ]] && pass "the missing baseline is said" || fail "out: $OUT"
drop_root

# No valid report after the swap: not healthy, but not a rollback here either;
# the probation counts it.
for new in "exit 1" "echo not-json" "health-report 2; exit 0"; do
    upgrade "health-report 0" "$new"
    expect 0 "the health check after the swap gave no verdict (no_report" "no valid report after the swap ($new) is left to the probation"
    [[ "$(live)" == b ]] && pass "($new) 1.5.0 is live, on probation" || fail "($new) live $(live)"
    drop_root
done

rm -rf "$FIXTURE"

# --- the probation ---------------------------------------------------------

# on_probation <health> [<baseline line>]: slot a is live on 1.5.0 and on
# probation, and its `health --json` runs <health>; b holds the proven 1.4.0.
on_probation() {
    new_root a
    echo "1.5.0" > "$BOXMUNGE_ROOT/config/version"
    mock_server a "case \"\$1\" in --version) echo 'boxmunge 1.5.0' ;; health) $1; exit ;; esac; exit 0"
    rm "$BOXMUNGE_ROOT/env-b/bin/python"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$BOXMUNGE_ROOT/env-b/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
    write_probation "1.5.0" "b" "$SOON"  # also makes upgrade-root/
    [[ -z "${2:-}" ]] || echo "$2" > "$BOXMUNGE_ROOT/upgrade-root/health-baseline"
}
rolled_back() { [[ "$(readlink "$BOXMUNGE_ROOT/env-active")" == "$BOXMUNGE_ROOT/env-b" ]]; }

# Linux caps one environment variable at 128 KiB: a report bigger than that
# must still be judged (it reaches Python on stdin), not kill the shim.
BIGBIN="$(mktemp -d)"
printf '%s\n' '#!/usr/bin/env bash' \
    'python3 -c '"'"'import json; print(json.dumps({"healthy": True, "exit_code": 0, "checks": [{"name": "docker", "status": "ok", "detail": "x" * 140000}]}))'"'" \
    > "$BIGBIN/big-report"
chmod +x "$BIGBIN/big-report"
PATH="$BIGBIN:$PATH" on_probation "big-report"
PATH="$BIGBIN:$PATH" run_shim check-probation
expect 0 "" "a 140 KB health report is judged"
[[ "$OUT" != *"rgument list too long"* && -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
    && pass "a large report keeps the probation going" || fail "out: $OUT"
drop_root
rm -rf "$BIGBIN"

on_probation "health-report 2 ufw" "a report ufw"
run_shim check-probation
expect 0 "not counted against 1.5.0: ufw" "probation: an error from before the upgrade carries on"
! rolled_back && pass "probation: no rollback for a pre-existing error" || fail "rolled back"
drop_root

on_probation "health-report 2 ufw caddy" "a report ufw"
run_shim check-probation
expect 1 "New health errors since the upgrade: caddy" "probation: a new error rolls back"
rolled_back && pass "probation: 1.4.0 is live again" || fail "not rolled back"
drop_root

# A baseline recorded for the other slot belongs to another upgrade.
on_probation "health-report 2 ufw" "b report ufw"
run_shim check-probation
expect 1 "Rollback complete" "probation: another slot's baseline does not excuse an error"
drop_root

on_probation "health-report 0" "a report ufw; rm -rf /"
run_shim check-probation
expect 1 "health-baseline is malformed" "probation: a malformed baseline stops the shim"
! rolled_back && pass "probation: nothing acted on a malformed baseline" || fail "rolled back"
drop_root

# No valid report: counted, two in a row roll back; a valid report between
# starts the count again.
for health in "exit 1" "echo not-json" "echo {\\\"exit_code\\\":0,\\\"checks\\\":[]}" "health-report 2; exit 0"; do
    on_probation "$health"
    run_shim check-probation
    expect 0 "gave no valid report" "probation: no valid report ($health) is a first failure"
    ! rolled_back && pass "probation ($health): no rollback yet" || fail "($health) rolled back at once"
    run_shim check-probation
    expect 1 "Rollback complete" "probation: a second run without a valid report ($health) rolls back"
    drop_root
done
on_probation "exit 1"
run_shim check-probation
mock_server a "case \"\$1\" in health) exec health-report 0 ;; esac; exit 0"
run_shim check-probation
mock_server a "case \"\$1\" in health) exit 1 ;; esac; exit 0"
run_shim check-probation
expect 0 "1 time(s) in a row" "probation: a valid report between failures starts the count again"
drop_root

# Health that never finishes: six runs in a row roll back, unless it did not
# finish before the upgrade either.
on_probation "exit 124"
for _ in 1 2 3 4 5; do run_shim check-probation; done
expect 0 "did not finish within its time budget (exit 124), 5 time(s) in a row" "probation: five timeouts in a row wait"
! rolled_back && pass "probation: no rollback after five timeouts" || fail "rolled back early"
run_shim check-probation
expect 1 "Rollback complete" "probation: the sixth timeout in a row rolls back"
drop_root

on_probation "exit 124" "a unanswered"
for _ in 1 2 3 4 5 6 7; do run_shim check-probation; done
expect 0 "as it did before the upgrade; not counted" "probation: timeouts that were there before the upgrade are not counted"
! rolled_back && pass "probation: no rollback for pre-existing timeouts" || fail "rolled back"
drop_root

finish
