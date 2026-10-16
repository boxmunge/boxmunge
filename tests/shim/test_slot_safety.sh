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

# --- shim libraries -------------------------------------------------------

api="$(sed -n 's/^UPGRADE_LIB_API=//p' "$SHIM")"
for lib in "$REPO_DIR"/scripts/boxmunge-upgrade.d/*.sh; do
    [[ "$(sed -n 's/^BM_LIB_API=//p' "$lib")" == "$api" ]] && pass "$(basename "$lib") declares API $api" \
        || fail "$(basename "$lib") does not declare the shim's API $api"
done

# copy_shim: a private copy of the shim and its libraries in $COPY.
copy_shim() {
    COPY="$(mktemp -d)"
    cp "$REPO_DIR/scripts/boxmunge-upgrade" "$COPY/"
    cp -R "$REPO_DIR/scripts/boxmunge-upgrade.d" "$COPY/"
    chmod -R go-w "$COPY"
}
run_copy() { RC=0; OUT="$(bash "$COPY/boxmunge-upgrade" "$@" 2>&1)" || RC=$?; }

new_root a
copy_shim
run_copy check-probation
expect 0 "" "a complete copy of the shim runs"
rm "$COPY/boxmunge-upgrade.d/probation.sh"
run_copy check-probation
expect 1 "probation.sh is missing" "a missing library stops the shim"
rm -r "$COPY"
copy_shim
sed -i.bak 's/^BM_LIB_API=.*/BM_LIB_API=999/' "$COPY/boxmunge-upgrade.d/slots.sh"
rm "$COPY/boxmunge-upgrade.d/slots.sh.bak"
run_copy check-probation
expect 1 "slots.sh is for API '999'" "a library for another API stops the shim"
rm -r "$COPY"
copy_shim
chmod g+w "$COPY/boxmunge-upgrade.d/state.sh"
run_copy check-probation
expect 1 "writable by group or others" "a group-writable library is not sourced"
rm -r "$COPY"
copy_shim
rm -r "$COPY/boxmunge-upgrade.d"
run_copy check-probation
expect 1 "library directory" "a missing library directory stops the shim"
rm -r "$COPY"
drop_root

# Libraries are installed before the shim, by install.sh (which is also how
# they reach a box upgraded by a shim from before the split) and by the
# shim's self-update.
lib_line="$(grep -n 'scripts/boxmunge-upgrade.d/"\*.sh' "$REPO_DIR/install.sh" | cut -d: -f1)"
shim_line="$(grep -n 'scripts/boxmunge-upgrade" "${BOXMUNGE_ROOT}/bin/boxmunge-upgrade"' "$REPO_DIR/install.sh" | cut -d: -f1)"
[[ -n "$lib_line" && -n "$shim_line" && "$lib_line" -lt "$shim_line" ]] \
    && pass "install.sh installs the libraries before the shim" || fail "install.sh order: libs=$lib_line shim=$shim_line"
system="$REPO_DIR/scripts/boxmunge-upgrade.d/system.sh"
lib_line="$(grep -n 'install -m 0644 -o root -g root "$f" "$UPGRADE_LIB_INSTALL_DIR' "$system" | cut -d: -f1)"
shim_line="$(grep -n 'install -m 0755 -o root -g root "$new_shim"' "$system" | cut -d: -f1)"
[[ -n "$lib_line" && -n "$shim_line" && "$lib_line" -lt "$shim_line" ]] \
    && pass "self-update installs the libraries before the shim" || fail "self-update order: libs=$lib_line shim=$shim_line"
grep -qE '^BUNDLE_DIRS .*\bscripts\b' "$REPO_DIR/Makefile" && pass "the bundle ships scripts/, libraries included" \
    || fail "BUNDLE_DIRS does not ship scripts/"

finish
