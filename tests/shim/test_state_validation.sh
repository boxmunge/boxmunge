#!/usr/bin/env bash
# tests/shim/test_state_validation.sh — A-05: the root shim must refuse
# hostile values in deploy-writable upgrade-state before they reach an
# executable path or an rm -rf.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

PAST="2000-01-01T00:00:00+00:00"
FUTURE="2999-01-01T00:00:00+00:00"

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

new_root a
echo "b" > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
run_shim check-probation
expect 1 "refusing to guess" "active-slot disagreeing with env-active is refused"
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
run_shim check-probation
expect 1 "not env-a or env-b" "env-active pointing elsewhere is refused"
drop_root

new_root a
rm "$BOXMUNGE_ROOT/env-active" "$BOXMUNGE_ROOT/upgrade-state/active-slot"
run_shim check-probation
expect 1 "No active slot" "missing active slot is refused, not defaulted"
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
        expect 1 "is the live slot" "probation previous_slot naming the live slot is refused"
    else
        expect 1 "Invalid slot" "probation previous_slot '$bad_slot' is refused"
    fi
    [[ -d "$BOXMUNGE_ROOT/env-a" && -d "$BOXMUNGE_ROOT/env-b" ]] \
        && pass "no venv removed for previous_slot '$bad_slot'" \
        || fail "a venv was removed for previous_slot '$bad_slot'"
    drop_root
done

for bad_version in '1.2.3; rm -rf /' '../../x' '1.2' 'v1.2.3' '1.2.3-'; do
    new_root a
    write_probation "$bad_version" "b" "$PAST"
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
