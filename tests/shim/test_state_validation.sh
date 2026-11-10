#!/usr/bin/env bash
# tests/shim/test_state_validation.sh — A-05: the root shim must refuse
# hostile values in deploy-writable upgrade-state before they reach an
# executable path or an rm -rf.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

PAST="2000-01-01T00:00:00+00:00"
FUTURE="$SOON"

# --- active-slot ----------------------------------------------------------

for bad in "../../tmp/x" "c" "a b" "a\\nb" "ab"; do
    new_root a
    printf '%s' "$bad" > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
    run_shim check-probation
    expect 1 "Invalid slot" "check-probation refuses active-slot '$bad'"
    [[ -d "$BOXMUNGE_ROOT/env-b" ]] && pass "env-b untouched for active-slot '$bad'" \
        || fail "env-b removed for active-slot '$bad'"
    drop_root
done

# record_bm_log: both slots' pythons record what bm_log writes (before the
# live slot is settled, either may write it).
record_bm_log() {
    local s
    for s in a b; do
        printf '%s\n' '#!/usr/bin/env bash' \
            'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; fi' \
            > "$BOXMUNGE_ROOT/env-$s/bin/python"
    done
}
logged() { [[ "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" == *"bm_log error $1"* ]]; }

new_root a
record_bm_log
echo "b" > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
run_shim check-probation
expect 1 "refusing to guess" "active-slot disagreeing with env-active is refused"
[[ "$OUT" == *"echo a | sudo tee $BOXMUNGE_ROOT/upgrade-state/active-slot"* ]] \
    && pass "the refusal names the fix" || fail "no fix named: $OUT"
logged "active-slot says 'b' but env-active points at env-a" \
    && pass "the refusal is in the operational log (the health timer drops stderr)" \
    || fail "not logged: $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
[[ -d "$BOXMUNGE_ROOT/env-a" ]] && pass "live env-a survives a forged active-slot" \
    || fail "forged active-slot made the shim delete the live venv"
drop_root

new_root a
rm "$BOXMUNGE_ROOT/upgrade-state/active-slot"
ln -s /etc/hostname "$BOXMUNGE_ROOT/upgrade-state/active-slot"
run_shim check-probation
expect 1 "is a symlink" "symlinked active-slot is refused"
drop_root

new_root a
rm "$BOXMUNGE_ROOT/env-active"
ln -s /tmp "$BOXMUNGE_ROOT/env-active"
record_bm_log
run_shim check-probation
expect 1 "not env-a or env-b" "env-active pointing elsewhere is refused"
logged "env-active points at" && pass "that refusal is logged too" || fail "not logged"
drop_root

new_root a
rm "$BOXMUNGE_ROOT/env-active" "$BOXMUNGE_ROOT/upgrade-state/active-slot"
record_bm_log
run_shim check-probation
expect 1 "No active slot" "missing active slot is refused, not defaulted"
logged "No active slot" && pass "that refusal is logged too" || fail "not logged"
drop_root

# The env-active symlink alone is enough (it is root-owned).
new_root b
rm "$BOXMUNGE_ROOT/upgrade-state/active-slot"
run_shim check-probation
expect 0 "" "env-active alone identifies the active slot"
[[ ! -d "$BOXMUNGE_ROOT/env-a" ]] && pass "orphan standby env-a cleaned when active is b" \
    || fail "orphan standby env-a not cleaned"
drop_root

# --- upgrade.lock ---------------------------------------------------------

new_root a
victim="$(mktemp)"
echo "precious" > "$victim"
ln -s "$victim" "$BOXMUNGE_ROOT/upgrade-state/upgrade.lock"
run_shim check-probation
expect 1 "is a symlink" "symlinked upgrade.lock is refused"
[[ "$(cat "$victim")" == "precious" ]] && pass "lock symlink target not truncated" \
    || fail "root truncated the lock symlink target"
rm -f "$victim"
drop_root

# --- probation.json -------------------------------------------------------

for bad_slot in "../env-a" "a/../../etc" "c" "a"; do
    new_root a  # standby is b; previous_slot a is the live venv
    write_probation "1.2.3" "$bad_slot" "$PAST"
    run_shim check-probation
    if [[ "$bad_slot" == "a" ]]; then
        # Left by an older shim's rollback: stale, removed, and the standby
        # (the failed release) is then an orphan.
        expect 0 "removing stale" "probation previous_slot naming the live slot is removed as stale"
        [[ -d "$BOXMUNGE_ROOT/env-a" && ! -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
            && pass "stale probation removed, live venv kept" || fail "stale probation handling: $OUT"
    else
        expect 1 "Invalid slot" "probation previous_slot '$bad_slot' is refused"
        [[ -d "$BOXMUNGE_ROOT/env-a" && -d "$BOXMUNGE_ROOT/env-b" ]] \
            && pass "no venv removed for previous_slot '$bad_slot'" \
            || fail "a venv was removed for previous_slot '$bad_slot'"
    fi
    drop_root
done

for bad_version in '1.2.3; rm -rf /' '../../x' '1.2' 'v1.2.3' '1.2.3-'; do
    new_root a
    forge_probation "$bad_version" "b" "$PAST"  # root would never record it
    run_shim check-probation
    expect 1 "Invalid version" "probation version '$bad_version' is refused"
    [[ -d "$BOXMUNGE_ROOT/env-b" ]] && pass "env-b kept for version '$bad_version'" \
        || fail "env-b removed for version '$bad_version'"
    drop_root
done

new_root a
echo '{"version": "1.2.3", "previous_slot": "b"}' > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
run_shim check-probation
expect 1 "malformed" "probation without expires_at is refused"
drop_root

new_root a
echo '["not", "an", "object"]' > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
run_shim check-probation
expect 1 "malformed" "non-object probation is refused"
drop_root

new_root a
write_probation "1.2.3" "b" "2000-01-01T00:00:00"
run_shim check-probation
expect 1 "malformed" "probation expiry without timezone is refused"
drop_root

new_root a
ln -s /etc/hostname "$BOXMUNGE_ROOT/upgrade-state/probation.json"
run_shim check-probation
expect 1 "is a symlink" "symlinked probation.json is refused"
drop_root

# Positive: a valid expired probation promotes and removes the old slot.
new_root a
write_probation "1.2.3" "b" "$PAST"
run_shim check-probation
expect 0 "promoted" "valid expired probation is promoted"
[[ ! -d "$BOXMUNGE_ROOT/env-b" && ! -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
    && pass "promotion removed env-b and probation.json" \
    || fail "promotion left env-b or probation.json behind"
[[ -d "$BOXMUNGE_ROOT/env-a" ]] && pass "promotion kept the live venv" || fail "promotion removed env-a"
drop_root

# Positive: a valid unexpired probation with healthy health keeps both slots.
new_root a
write_probation "1.2.3" "b" "$FUTURE"
run_shim check-probation
expect 0 "" "valid unexpired probation with a healthy box exits 0"
[[ -d "$BOXMUNGE_ROOT/env-b" && -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
    && pass "unexpired probation keeps the previous slot" \
    || fail "unexpired probation removed state"
drop_root

# --- blocklist.json -------------------------------------------------------

for bad_blocklist in '["1.2.3"]' '{"../x": {}}' '{"1.2.3": {}, "evil\nkey": {}}' 'not json'; do
    new_root a
    printf '%s' "$bad_blocklist" > "$BOXMUNGE_ROOT/upgrade-state/blocklist.json"
    run_shim run 1.2.3 ignored-url
    expect 1 "blocklist.json is malformed" "malformed blocklist is refused: $bad_blocklist"
    drop_root
done

finish
