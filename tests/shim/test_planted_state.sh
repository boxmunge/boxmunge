#!/usr/bin/env bash
# tests/shim/test_planted_state.sh — upgrade-state/ is deploy-writable, so
# deploy can plant a FIFO or a link at any name in it. The root shim must
# refuse each without blocking (a hang holds upgrade.lock, so every later
# upgrade and probation check is skipped) and without creating or reading
# a link's target, naming the file and saying to remove it.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

STATE="upgrade-state"

# planted_fifo <name> <description> <shim args...>
planted_fifo() {
    local name="$1" what="$2"
    shift 2
    new_root a
    rm -f "$BOXMUNGE_ROOT/$STATE/$name"
    mkfifo "$BOXMUNGE_ROOT/$STATE/$name"
    run_shim_within 10 "$BOXMUNGE_ROOT/$STATE/$name" "$@"
    expect 1 "$BOXMUNGE_ROOT/$STATE/$name" "$what: a FIFO $name is refused without blocking"
    expect 1 "Remove it" "$what: the refusal of a FIFO $name says to remove it"
    [[ -d "$BOXMUNGE_ROOT/env-a" && -d "$BOXMUNGE_ROOT/env-b" ]] \
        && pass "$what: no venv removed for a FIFO $name" || fail "$what: a venv was removed"
    drop_root
}

planted_fifo upgrade.lock check-probation check-probation
planted_fifo probation.json check-probation check-probation
planted_fifo active-slot check-probation check-probation
planted_fifo blocklist.json run run 1.2.3 ignored-url

# A dangling link at upgrade.lock: root must not create its target.
new_root a
target="$(mktemp -d)/created-by-root"
ln -s "$target" "$BOXMUNGE_ROOT/$STATE/upgrade.lock"
run_shim check-probation
expect 1 "is a symlink" "a dangling upgrade.lock link is refused"
[[ ! -e "$target" ]] && pass "root did not create the lock link's target" \
    || fail "root created $target through the lock link"
rm -rf "$(dirname "$target")"
drop_root

# A link at blocklist.json is refused rather than read through.
new_root a
victim="$(mktemp)"
echo '{}' > "$victim"
ln -s "$victim" "$BOXMUNGE_ROOT/$STATE/blocklist.json"
run_shim run 1.2.3 ignored-url
expect 1 "is a symlink" "a linked blocklist.json is refused"
rm -f "$victim"
drop_root

# A directory at upgrade.lock is not a lock file.
new_root a
mkdir "$BOXMUNGE_ROOT/$STATE/upgrade.lock"
run_shim check-probation
expect 1 "Remove it" "a directory at upgrade.lock is refused"
drop_root

# The lock is still taken through a regular upgrade.lock left by a run.
new_root a
: > "$BOXMUNGE_ROOT/$STATE/upgrade.lock"
run_shim check-probation
expect 0 "" "an existing regular upgrade.lock is used"
[[ -f "$BOXMUNGE_ROOT/$STATE/upgrade.lock" && ! -L "$BOXMUNGE_ROOT/$STATE/upgrade.lock" ]] \
    && pass "upgrade.lock stays a regular file" || fail "upgrade.lock was replaced"
drop_root

# --- writes and opens by name in upgrade-state ----------------------------

# HOSTILE: prepend to PATH. Its mktemp, python3 and timeout stand in for
# deploy winning a race: each swaps a name in upgrade-state for a link to
# $VICTIM just after root created or checked it, then runs the real tool.
HOSTILE="$(mktemp -d)"
REAL_MKTEMP="$(command -v mktemp)"
REAL_PYTHON="$(command -v python3)"
cat > "$HOSTILE/mktemp" <<EOS
#!/usr/bin/env bash
out="\$("$REAL_MKTEMP" "\$@")"
if [[ "\$*" == *upgrade-state/.active-slot.* ]]; then rm -f "\$out"; ln -s "\$VICTIM" "\$out"; fi
echo "\$out"
EOS
cat > "$HOSTILE/python3" <<EOS
#!/usr/bin/env bash
for a in "\$@"; do
    if [[ "\$a" == */upgrade-state/upgrade.lock && -n "\${SWAP_LOCK:-}" ]]; then
        rm -f "\$a"; ln -s "\$VICTIM" "\$a"
    fi
done
exec "$REAL_PYTHON" "\$@"
EOS
chmod +x "$HOSTILE"/*

# The active-slot rewrite after an interrupted swap (env-active is the truth)
# never writes through a temp file deploy swapped for a link.
new_root a
echo "b" > "$BOXMUNGE_ROOT/$STATE/active-slot"
echo "1.2.3" > "$BOXMUNGE_ROOT/env-b/upgrade-inflight"
VICTIM="$(mktemp)"
echo "precious" > "$VICTIM"
export VICTIM
PATH="$HOSTILE:$PATH" run_shim check-probation
[[ "$(cat "$VICTIM")" == "precious" ]] && pass "active-slot rewrite did not write through a swapped temp" \
    || fail "root wrote the active slot through a swapped temp: $(cat "$VICTIM")"
[[ "$(cat "$BOXMUNGE_ROOT/$STATE/active-slot")" == "a" && ! -L "$BOXMUNGE_ROOT/$STATE/active-slot" ]] \
    && pass "active-slot rewritten to the live slot" || fail "active-slot not rewritten: $OUT"
rm -f "$VICTIM"
drop_root

# upgrade.lock swapped for a link after the shim's checks, right before it
# is opened: neither an existing target nor a missing one is opened or made.
for victim_kind in existing missing; do
    new_root a
    VICTIM="$(mktemp -d)/victim"
    [[ "$victim_kind" == missing ]] || echo "precious" > "$VICTIM"
    export VICTIM
    SWAP_LOCK=1 PATH="$HOSTILE:$PATH" run_shim check-probation
    expect 1 "is a symlink" "upgrade.lock swapped for a link to a $victim_kind file is refused"
    if [[ "$victim_kind" == missing ]]; then
        [[ ! -e "$VICTIM" ]] && pass "root did not create the swapped link's target" \
            || fail "root created $VICTIM through a swapped upgrade.lock"
    else
        [[ "$(cat "$VICTIM")" == "precious" ]] && pass "swapped link's existing target untouched" \
            || fail "swapped link's target changed"
    fi
    rm -rf "$(dirname "$VICTIM")"
    drop_root
done
unset VICTIM

# A lock descriptor handed in by the environment must be upgrade.lock itself.
new_root a
other="$(mktemp)"
RC=0
OUT="$(BM_UPGRADE_LOCK_FD=9 bash "$SHIM" check-probation 9<>"$other" 2>&1)" || RC=$?
expect 1 "is not $BOXMUNGE_ROOT/$STATE/upgrade.lock" "a lock descriptor for another file is refused"
rm -f "$other"
drop_root

# --- root's Python never imports from the caller's directory ---------------

new_root a
write_probation "1.2.3" "b" "$SOON"
evil="$(mktemp -d)"
printf 'import os\nopen(os.environ["BOXMUNGE_ROOT"] + "/pwned", "w").close()\nfrom importlib import import_module\n' > "$evil/json.py"
mkdir "$evil/boxmunge"
printf 'import os\nopen(os.environ["BOXMUNGE_ROOT"] + "/pwned", "w").close()\n' > "$evil/boxmunge/__init__.py"
pushd "$evil" >/dev/null
run_shim check-probation
popd >/dev/null
expect 0 "" "check-probation runs from a deploy-controlled directory"
[[ ! -e "$BOXMUNGE_ROOT/pwned" ]] && pass "no module was imported from the caller's directory" \
    || fail "root imported a planted module from its working directory"
rm -rf "$evil"
drop_root

rm -rf "$HOSTILE"

finish
