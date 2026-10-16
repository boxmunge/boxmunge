#!/usr/bin/env bash
# tests/shim/test_slot_safety.sh — the shim never swaps to, or deletes on the
# strength of, a slot it cannot prove works; stale state from older shims
# heals; and the shim refuses to run on missing or mismatched libraries.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

run_past_policy() { PATH="$FAILVISUDO:$PATH" run_shim "$@"; }
live_intact() {  # live_intact <description>: env-a still runs and is live
    [[ -x "$BOXMUNGE_ROOT/env-a/bin/boxmunge-server" && "$(readlink "$BOXMUNGE_ROOT/env-active")" == "$BOXMUNGE_ROOT/env-a" ]] \
        && pass "$1: the live venv survives and stays live" || fail "$1: live venv lost or swapped away"
}

# --- a probation naming an unusable standby ---------------------------------
# deploy can write probation.json. Naming a standby that is absent, half
# built or itself a half-finished upgrade must not lead to a swap onto it,
# nor to the orphan cleanup deleting the real venv afterwards.

for standby in absent half-built inflight; do
    new_root a
    mock_server a 'if [[ "$1" == "health" ]]; then exit 2; fi; exit 0'
    case "$standby" in
        absent) rm -r "$BOXMUNGE_ROOT/env-b" ;;
        half-built) rm "$BOXMUNGE_ROOT/env-b/bin/boxmunge-server" ;;
        inflight) echo "9.9.9" > "$BOXMUNGE_ROOT/env-b/upgrade-inflight" ;;
    esac
    write_probation "9.9.9" "b" "$SOON"
    for fire in 1 2; do
        run_shim check-probation
        expect 1 "is not a working venv a rollback could use" "$standby standby: check-probation fire $fire refuses"
        live_intact "$standby standby, fire $fire"
    done
    run_shim target 9.9.10
    expect 1 "is not a working venv a rollback could use" "$standby standby: an upgrade is refused too"
    live_intact "$standby standby, upgrade"
    drop_root
done

# --- the orphan cleanup needs a working live slot ----------------------------

new_root a
mock_server a 'exit 1'
run_shim check-probation
expect 1 "the live slot env-a is not a working venv" "orphan cleanup refuses while the live slot is broken"
[[ -x "$BOXMUNGE_ROOT/env-b/bin/boxmunge-server" ]] && pass "the standby, possibly all that works, survives" \
    || fail "standby deleted while the live slot was broken"
drop_root

# --- a stale probation left by an older shim's rollback ----------------------

new_root a
write_probation "0.6.0" "a" "$SOON"
run_past_policy target 1.5.0
expect 1 "failed visudo" "a stale probation does not block an upgrade"
[[ "$OUT" == *"removing stale"* && ! -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
    && pass "the stale probation is removed with a warning" || fail "stale probation: $OUT"
drop_root

# --- the shipped shim is one file -----------------------------------------
# Whatever installs the shim (install.sh, or an older release's shim
# self-updating) copies only scripts/boxmunge-upgrade, so the built shim
# must run with nothing next to it.

BUILT_DIR="$(mktemp -d)"
python3 "$REPO_DIR/scripts/build-shim.py" "$REPO_DIR/scripts/boxmunge-upgrade" "$BUILT_DIR/boxmunge-upgrade"
new_root a
RC=0; OUT="$(bash "$BUILT_DIR/boxmunge-upgrade" check-probation 2>&1)" || RC=$?
expect 0 "" "the built shim runs on its own"
grep -q '^# >>> boxmunge-upgrade.d:' "$BUILT_DIR/boxmunge-upgrade" && fail "built shim still has the source loader" \
    || pass "built shim has no source loader"
cp "$REPO_DIR/scripts/boxmunge-upgrade" "$BUILT_DIR/unbuilt"
RC=0; OUT="$(bash "$BUILT_DIR/unbuilt" check-probation 2>&1)" || RC=$?
expect 1 "unbuilt source shim" "the unbuilt shim on its own refuses, saying why"
drop_root
rm -r "$BUILT_DIR"

grep -q 'boxmunge-upgrade.d/"\*' "$REPO_DIR/install.sh" && fail "install.sh still installs shim libraries" \
    || pass "install.sh installs the shim as one file"
grep -q 'rm -rf "${BOXMUNGE_ROOT}/bin/boxmunge-upgrade.d"' "$REPO_DIR/install.sh" \
    && pass "install.sh removes a leftover library directory" || fail "install.sh leaves bin/boxmunge-upgrade.d"

finish
