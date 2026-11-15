#!/usr/bin/env bash
# tests/shim/test_probation_record.sh — deploy cannot start a probation.
#
# probation.json is deploy-writable. A probation in it defers the timer's
# upgrades and refuses every target, so deploy writing one on a box with no
# probation, again each time it ends, would hold off security updates for
# good. The shim acts only on a probation root recorded when an upgrade
# started it (upgrade-root/probation-expiry: "<slot> <version> <expiry>", or
# "none"); anything else is removed, logged and alerted.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# A venv build is recorded, so a test can tell whether an upgrade went ahead.
UPGRADEBIN="$(mktemp -d)"
printf '#!/usr/bin/env bash\nif [[ "$1 $2" == "-m venv" ]]; then\n    echo "venv $3" >> "$BOXMUNGE_ROOT/calls"; mkdir -p "$3/bin"; exit 0\nfi\nexec %q "$@"\n' \
    "$(command -v python3)" > "$UPGRADEBIN/python3"
printf '#!/usr/bin/env bash\nexit 22\n' > "$UPGRADEBIN/curl"
chmod +x "$UPGRADEBIN"/*
export PATH="$UPGRADEBIN:$PATH"

RECORD="upgrade-root/probation-expiry"
PROBATION="upgrade-state/probation.json"

# box: slot a live on 1.4.0, b the previous release; a's python records
# bm_log lines and alerts.
box() {
    new_root a
    echo "1.4.0+abc1234" > "$BOXMUNGE_ROOT/config/version"
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
        '[[ -z "${BM_TITLE:-}" ]] || echo "alert $BM_TITLE" >> "$BOXMUNGE_ROOT/calls"' > "$BOXMUNGE_ROOT/env-a/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-a/bin/python"
    : > "$BOXMUNGE_ROOT/calls"
}
calls() { cat "$BOXMUNGE_ROOT/calls"; }
record() { cat "$BOXMUNGE_ROOT/$RECORD" 2>/dev/null || true; }

# expect_refused <description>: the last run removed a planted probation,
# loudly, and changed nothing else.
expect_refused() {
    expect 1 "but no upgrade on this box started that probation" "$1: refused"
    [[ ! -e "$BOXMUNGE_ROOT/$PROBATION" ]] && pass "$1: the planted probation.json is removed" \
        || fail "$1: probation.json left in place"
    [[ "$(calls)" == *"bm_log error"*"no upgrade on this box started"* ]] \
        && pass "$1: the refusal is in the operational log" || fail "$1: not logged: $(calls)"
    [[ "$(calls)" == *"alert boxmunge: planted probation removed"* ]] \
        && pass "$1: the refusal is alerted" || fail "$1: no alert: $(calls)"
    [[ "$(calls)" != *"venv "* ]] && pass "$1: no slot built" || fail "$1: a slot was built: $(calls)"
}

# --- a probation deploy wrote, with no upgrade behind it ----------------------

# The timer's run is not deferred by it: the run stops loudly, and the next
# one goes ahead.
box
forge_probation 9.9.9 b "$SOON"
run_shim run 1.5.0 https://example.com/x security
expect_refused "a planted probation before the timer's run"
[[ "$OUT" != *"Deferred"* ]] && pass "the run is not deferred by it" || fail "deferred: $OUT"
: > "$BOXMUNGE_ROOT/calls"
run_shim run 1.5.0 https://example.com/x security
[[ "$(calls)" == *"venv $BOXMUNGE_ROOT/env-b"* ]] && pass "the next run goes ahead" \
    || fail "the next run did not build the standby: $OUT"
drop_root

# check-probation does not count it down and promote it; target is not refused.
box
forge_probation 9.9.9 b "$SOON"
run_shim check-probation
expect_refused "a planted probation at check-probation"
[[ -d "$BOXMUNGE_ROOT/env-b" ]] && pass "the slot it names is not removed" || fail "env-b removed"
PATH="$FAILVISUDO:$PATH" run_shim target 1.5.0
expect 1 "failed visudo" "target goes past the probation guard once it is removed"
drop_root

# With no record at all, even a probation of the installed release just
# after a swap is refused: every upgrade records the probation it starts.
box
forge_probation 1.4.0 b "$SOON"
run_shim check-probation
expect_refused "an unrecorded probation of the installed release"
drop_root

# After a probation ends (promoted here), root records that none is running,
# so a planted one is refused even right after a swap.
box
write_probation 1.4.0 b "2000-01-01T00:00:00+00:00"
run_shim check-probation
expect 0 "promoted" "a recorded, expired probation is promoted"
[[ "$(record)" == none ]] && pass "promotion records that no probation runs" || fail "record: $(record)"
: > "$BOXMUNGE_ROOT/calls"
forge_probation 1.4.0 b "$SOON"
run_shim check-probation
expect_refused "a planted probation after a promotion"
drop_root

# A record for another release or another slot does not cover it.
box
write_probation 1.4.0 b "$SOON"
forge_probation 1.4.1 b "$SOON"
run_shim check-probation
expect_refused "a probation of another release than the recorded one"
drop_root
box
write_probation 1.4.0 b "$SOON"
echo "b 1.4.0 $(( $(date +%s) + 3600 ))" > "$BOXMUNGE_ROOT/$RECORD"
run_shim check-probation
expect_refused "a probation recorded for the other slot"
drop_root

# --- a probation root recorded --------------------------------------------------

box
write_probation 1.4.0 b "$SOON"
before="$(record)"
run_shim check-probation
expect 0 "" "a recorded probation carries on"
[[ -f "$BOXMUNGE_ROOT/$PROBATION" && "$(record)" == "$before" ]] \
    && pass "a recorded probation and its record are kept as they are" || fail "record $(record), was $before"
drop_root

# A record without the release ("<slot> <expiry>") is not one: it is named
# as malformed, and nothing acts on the probation.
box
forge_probation 1.4.0 b "$SOON"
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
echo "a $(( $(date +%s) + 6 * 3600 ))" > "$BOXMUNGE_ROOT/$RECORD"
run_shim check-probation
expect 1 "probation-expiry is malformed" "a record without the release is malformed"
[[ -f "$BOXMUNGE_ROOT/$PROBATION" ]] && pass "a malformed record: nothing acted on the probation" || fail "probation removed"
drop_root

rm -rf "$UPGRADEBIN"
finish
