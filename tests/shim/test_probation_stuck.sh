#!/usr/bin/env bash
# tests/shim/test_probation_stuck.sh — #119: a probation whose previous slot is
# gone (a pre-0.11 shim recycled it mid-probation) still ends. Expiry promotes
# it without needing a rollback target; only a real rollback needs one, and a
# check-probation that cannot do its job says so in the operational log, not
# just on the health timer's discarded stderr.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# As in test_probation_guard.sh: a venv build is recorded, and curl fails so
# an accepted upgrade stops at the first download.
UPGRADEBIN="$(mktemp -d)"
printf '#!/usr/bin/env bash\nif [[ "$1 $2" == "-m venv" ]]; then\n    echo "venv $3" >> "$BOXMUNGE_ROOT/calls"; mkdir -p "$3/bin"; exit 0\nfi\nexec %q "$@"\n' \
    "$(command -v python3)" > "$UPGRADEBIN/python3"
printf '#!/usr/bin/env bash\nexit 22\n' > "$UPGRADEBIN/curl"
chmod +x "$UPGRADEBIN"/*
export PATH="$UPGRADEBIN:$PATH"

# slot_gone <expires_at> [health rc]: active a is 1.4.0 on probation, and its
# previous slot b no longer exists. a's python records bm_log calls; its
# health check exits with [health rc] (default 0).
slot_gone() {
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    mock_server a "if [[ \"\$1\" == health ]]; then exec health-report ${2:-0}; fi; exit 0"
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
        'if [[ -n "${BM_TITLE:-}" ]]; then echo "notify p=$BM_PRIORITY $BM_TITLE" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
        'printf "%s\n" "$*" >> "$BOXMUNGE_ROOT/calls"' > "$BOXMUNGE_ROOT/env-a/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-a/bin/python"
    rm -r "$BOXMUNGE_ROOT/env-b"
    write_probation "1.4.0" "b" "$1"
}

calls() { cat "$BOXMUNGE_ROOT/calls" 2>/dev/null || true; }
probation_left() { [[ -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]]; }
live_intact() {
    [[ -x "$BOXMUNGE_ROOT/env-a/bin/boxmunge-server" && "$(readlink "$BOXMUNGE_ROOT/env-active")" == "$BOXMUNGE_ROOT/env-a" ]] \
        && pass "$1: the live venv survives and stays live" || fail "$1: live venv lost or swapped away"
}

EXPIRED="2000-01-01T00:00:00+00:00"

# --- expiry promotes without a rollback target ------------------------------

slot_gone "$EXPIRED"
run_shim check-probation
expect 0 "Version 1.4.0 promoted" "an expired probation whose previous slot is gone is promoted"
probation_left && fail "promotion left probation.json behind" || pass "promotion removes probation.json"
[[ "$(calls)" == *"bm_log info probation passed"* ]] && pass "promotion is logged" \
    || fail "promotion not logged: $(calls)"
live_intact "promotion without a previous slot"
drop_root

# The upgrade that a stuck box needs: deferred (not refused) until the health
# timer promotes, then it proceeds.
slot_gone "$EXPIRED"
run_shim target 1.5.0
expect 1 "health timer promotes it" "an upgrade during an expired, slot-less probation is deferred"
[[ "$OUT" != *"rollback could use"* ]] && pass "the deferral does not demand a rollback target" \
    || fail "the deferral still demands a rollback target: $OUT"
run_shim check-probation
expect 0 "promoted" "check-probation then promotes"
run_shim target 1.5.0
expect 1 "Failed to download bundle" "after promotion the upgrade proceeds to the download"
drop_root

# --- before expiry: no rollback target is fine until a rollback is needed ---

slot_gone "$SOON"
run_shim check-probation
expect 0 "" "a healthy probation without a previous slot carries on"
probation_left && pass "the probation stays until it expires" || fail "probation ended early"
drop_root

slot_gone "$SOON"
run_shim target 1.5.0
expect 1 "1.4.0 is on probation" "an upgrade during a slot-less probation is deferred"
[[ "$OUT" == *"slot b"*"is not a working venv"* ]] && pass "the deferral says the rollback target is gone" \
    || fail "the deferral claims slot b holds the previous release: $OUT"
[[ "$(calls)" != *"venv "* ]] && pass "no standby venv was built" || fail "a standby venv was built: $(calls)"
drop_root

# A rollback that cannot happen fails loudly: the health timer discards the
# shim's exit status and stderr, so the reason reaches the operational log and
# an alert, once per probation rather than on every five-minute fire.
slot_gone "$SOON" 2
run_shim check-probation
expect 1 "1.4.0 failed its probation health check, but cannot be rolled back" "a needed rollback without a target refuses"
[[ "$(calls)" == *"bm_log error 1.4.0 failed its probation health check, but cannot be rolled back"* ]] \
    && pass "the refused rollback is logged as an error" \
    || fail "the refused rollback is not in the operational log: $(calls)"
[[ "$(calls)" == *"notify p=1 boxmunge rollback needed but impossible"* ]] && pass "the refused rollback is alerted" \
    || fail "the refused rollback is not alerted: $(calls)"
live_intact "refused rollback"
probation_left && pass "the probation stays for the operator" || fail "probation removed by a refused rollback"
rm "$BOXMUNGE_ROOT/calls"
run_shim check-probation
expect 1 "cannot be rolled back" "the next fire still refuses"
[[ "$(calls)" != *"bm_log error"* && "$(calls)" != *notify* ]] && pass "the next fire neither logs nor alerts again" \
    || fail "the next fire repeated the error or alert: $(calls)"
# Once the probation ends, a new probation that needs it gets its own alert.
write_probation "1.4.0" "b" "$EXPIRED"
run_shim check-probation
expect 0 "promoted" "the slot-less probation is promoted at expiry"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/rollback-impossible" ]] && pass "promotion clears the once-only marker" \
    || fail "the once-only marker survived promotion"
drop_root

# A malformed marker is just as silent under the timer.
slot_gone "$SOON"
echo '{"version": "1.4.0"}' > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
run_shim check-probation
expect 1 "malformed" "check-probation refuses a malformed marker"
[[ "$(calls)" == *"bm_log error"*"malformed"* ]] && pass "the malformed marker is logged as an error" \
    || fail "the malformed marker is not in the operational log: $(calls)"
drop_root

rm -rf "$UPGRADEBIN"
finish
