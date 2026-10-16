#!/usr/bin/env bash
# tests/shim/test_probation_guard.sh — no upgrade may recycle the standby slot
# while a release is on probation: that slot holds the last proven release.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins for the venv build and the network. A venv build is recorded so a
# test can tell whether the shim got as far as recycling the standby slot;
# curl fails so an accepted upgrade stops at the first download.
UPGRADEBIN="$(mktemp -d)"
printf '#!/usr/bin/env bash\nif [[ "$1 $2" == "-m venv" ]]; then\n    echo "venv $3" >> "$BOXMUNGE_ROOT/calls"; mkdir -p "$3/bin"; exit 0\nfi\nexec %q "$@"\n' \
    "$(command -v python3)" > "$UPGRADEBIN/python3"
printf '#!/usr/bin/env bash\nexit 22\n' > "$UPGRADEBIN/curl"
chmod +x "$UPGRADEBIN"/*
export PATH="$UPGRADEBIN:$PATH"

# on_probation [expires_at]: active a is 1.4.0 on probation; b is the proven
# previous release. a's python records bm_log, blocklist and report calls.
on_probation() {
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    echo "proven" > "$BOXMUNGE_ROOT/env-b/known-good"
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
        'printf "%s\n" "$*" >> "$BOXMUNGE_ROOT/calls"' > "$BOXMUNGE_ROOT/env-a/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-a/bin/python"
    write_probation "1.4.0" "b" "${1:-2999-01-01T00:00:00+00:00}"
}

calls() { cat "$BOXMUNGE_ROOT/calls" 2>/dev/null || true; }

# expect_deferred <description>: the last run_shim refused without touching
# either slot, the probation, the blocklist or the failure report.
expect_deferred() {
    expect 1 "1.4.0 is on probation" "$1 is refused during probation"
    [[ "$OUT" == *"slot b holds the previous release"* ]] && pass "$1: refusal names the protected slot" \
        || fail "$1: refusal does not name the protected slot: $OUT"
    [[ "$(cat "$BOXMUNGE_ROOT/env-b/known-good" 2>/dev/null)" == "proven" ]] \
        && pass "$1: the proven slot survives" || fail "$1: the proven slot was destroyed"
    [[ "$(calls)" != *"venv "* ]] && pass "$1: no standby venv was built" \
        || fail "$1: a standby venv was built: $(calls)"
    [[ -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] && pass "$1: probation left in place" \
        || fail "$1: probation removed"
    [[ "$(calls)" != *add_to_blocklist* && ! -e "$BOXMUNGE_ROOT/upgrade-state/blocklist.json" ]] \
        && pass "$1: version not blocklisted" || fail "$1: version blocklisted: $(calls)"
    [[ "$(calls)" != *report_failure* ]] && pass "$1: no failure report" \
        || fail "$1: failure reported: $(calls)"
    [[ "$(calls)" == *"bm_log warn upgrade deferred: probation active"* ]] \
        && pass "$1: deferral logged" || fail "$1: deferral not logged: $(calls)"
}

# --- every entry point defers ----------------------------------------------

on_probation
run_shim run 1.5.0 https://example.com/x security
expect_deferred "auto-update (run)"
[[ "$OUT" == *"ends 2999-01-01 00:00 UTC"* && "$OUT" == *"Retry after the probation ends"* ]] \
    && pass "refusal says when to retry" || fail "refusal lacks the retry time: $OUT"
drop_root

on_probation
mock_server a 'if [[ "$1" == "_discover-update" ]]; then echo "{\"action\": \"upgrade\", \"version\": \"1.5.0\"}"; fi'
run_shim auto
expect_deferred "auto (deploy)"
drop_root

on_probation
run_shim target 1.5.0
expect_deferred "target"
drop_root

on_probation
run_shim force-target 1.3.0
expect_deferred "force-target"
[[ "$OUT" == *"remove $BOXMUNGE_ROOT/upgrade-state/probation.json and re-run"* ]] \
    && pass "force-target says how to end the probation explicitly" \
    || fail "force-target refusal lacks the explicit resolution: $OUT"
drop_root

# Expired, but the health timer has not yet run check-probation.
on_probation "2000-01-01T00:00:00+00:00"
run_shim target 1.5.0
expect_deferred "target (probation expired, not yet promoted)"
[[ "$OUT" == *"health timer promotes it"* ]] && pass "expired refusal says promotion is imminent" \
    || fail "expired refusal lacks the promotion note: $OUT"
drop_root

on_probation
echo '{"version": "1.4.0"}' > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
run_shim target 1.5.0
expect 1 "malformed" "a malformed probation stops the upgrade"
[[ -f "$BOXMUNGE_ROOT/env-b/known-good" ]] && pass "malformed probation: proven slot survives" \
    || fail "malformed probation: proven slot destroyed"
drop_root

# --- once promoted, upgrades proceed as before ------------------------------

on_probation "2000-01-01T00:00:00+00:00"
run_shim check-probation
expect 0 "promoted" "check-probation promotes the expired probation"
run_shim target 1.5.0
expect 1 "Failed to download bundle" "target after promotion proceeds to the download"
[[ "$(calls)" == *"venv $BOXMUNGE_ROOT/env-b"* ]] && pass "target after promotion rebuilds the standby slot" \
    || fail "target after promotion did not build the standby: $(calls)"
[[ "$(calls)" != *"deferred"* ]] && pass "target after promotion is not deferred" \
    || fail "target after promotion was deferred: $(calls)"
drop_root

rm -rf "$UPGRADEBIN"
finish
