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
    run_shim_unless_blocked "$BOXMUNGE_ROOT/$STATE/$name" "$@"
    expect 1 "$BOXMUNGE_ROOT/$STATE/$name" "$what: a FIFO $name is refused without blocking"
    expect 1 "Remove it" "$what: the refusal of a FIFO $name says to remove it"
    [[ -d "$BOXMUNGE_ROOT/env-a" && -d "$BOXMUNGE_ROOT/env-b" ]] \
        && pass "$what: no venv removed for a FIFO $name" || fail "$what: a venv was removed"
    drop_root
}

planted_fifo probation.json check-probation check-probation
planted_fifo active-slot check-probation check-probation
planted_fifo blocklist.json run run 1.2.3 ignored-url feature

# upgrade-state/upgrade.lock (where shims up to 0.10.1 locked) is no lock
# now: a dangling link there is never opened, so its target is never made.
new_root a
target="$(mktemp -d)/created-by-root"
ln -s "$target" "$BOXMUNGE_ROOT/$STATE/upgrade.lock"
run_shim check-probation
expect 0 "" "a link at the old lock name does not stop check-probation"
[[ ! -e "$target" ]] && pass "root did not create the old lock link's target" \
    || fail "root created $target through the old lock link"
rm -rf "$(dirname "$target")"
drop_root

# A link at blocklist.json is refused rather than read through.
new_root a
victim="$(mktemp)"
echo '{}' > "$victim"
ln -s "$victim" "$BOXMUNGE_ROOT/$STATE/blocklist.json"
run_shim run 1.2.3 ignored-url feature
expect 1 "is a symlink" "a linked blocklist.json is refused"
rm -f "$victim"
drop_root


# --- writes and opens by name in upgrade-state ----------------------------

# HOSTILE: prepend to PATH. Its python3 stands in for deploy winning a race:
# with SLOT_PLANT it runs that Python file ahead of the script
# that rewrites active-slot (the only stdin script naming .active-slot.).
HOSTILE="$(mktemp -d)"
REAL_PYTHON="$(command -v python3)"
export REAL_PYTHON
cat > "$HOSTILE/python3" <<'EOS'
#!/usr/bin/env bash
if [[ "$#" -eq 1 && "$1" == - && -n "${SLOT_PLANT:-}" ]]; then
    script="$(cat)"
    [[ "$script" == *'prefix=".active-slot."'* ]] && script="$(cat "$SLOT_PLANT")
$script"
    exec "$REAL_PYTHON" -c "$script"
fi
exec "$REAL_PYTHON" "$@"
EOS
chmod +x "$HOSTILE"/*
PLANTS="$(mktemp -d)"
# mkstemp's names are random: make its first two tries the names deploy
# planted links at, as if deploy had guessed them.
cat > "$PLANTS/guessed_names.py" <<'EOS'
import tempfile as _t
_random = _t._get_candidate_names
def _guessed():
    yield from ("planted1", "planted2")
    yield from _random()
_t._get_candidate_names = _guessed
EOS
# Deploy renames a link to $VICTIM over the temp the moment mkstemp made it.
cat > "$PLANTS/swapped_temp.py" <<'EOS'
import os as _os, tempfile as _t
_real = _t.mkstemp
def _swapped(*args, **kwargs):
    fd, tmp = _real(*args, **kwargs)
    _os.unlink(tmp)
    _os.symlink(_os.environ["VICTIM"], tmp)
    return fd, tmp
_t.mkstemp = _swapped
EOS

# slot_rewrite_root: an interrupted swap (env-active says a, active-slot b,
# an upgrade-inflight marker), so check-probation rewrites active-slot; and
# a precious $VICTIM outside upgrade-state, mode 0600.
slot_rewrite_root() {
    new_root a
    echo "b" > "$BOXMUNGE_ROOT/$STATE/active-slot"
    echo "1.2.3" > "$BOXMUNGE_ROOT/env-b/upgrade-inflight"
    VICTIM="$(mktemp -d)/victim"
    echo "precious" > "$VICTIM"
    chmod 600 "$VICTIM"
    export VICTIM
}

victim_untouched() {  # victim_untouched <description>
    [[ "$(cat "$VICTIM")" == "precious" && "$(stat -c %a "$VICTIM" 2>/dev/null \
        || stat -f %Lp "$VICTIM")" == 600 ]] \
        && pass "$1" || fail "$1: $VICTIM is now $(ls -l "$VICTIM"): $(cat "$VICTIM")"
}

# Links planted at the temp names the rewrite tries (one to $VICTIM, one
# dangling) are skipped, never opened, followed or replaced.
slot_rewrite_root
dangling="$(dirname "$VICTIM")/created-by-root"
ln -s "$VICTIM" "$BOXMUNGE_ROOT/$STATE/.active-slot.planted1"
ln -s "$dangling" "$BOXMUNGE_ROOT/$STATE/.active-slot.planted2"
SLOT_PLANT="$PLANTS/guessed_names.py" PATH="$HOSTILE:$PATH" run_shim check-probation
expect 0 "following env-active" "active-slot rewrite with links planted at its temp names runs"
victim_untouched "a link planted at a temp name was not written through"
[[ ! -e "$dangling" ]] && pass "a dangling link at a temp name was not followed to create its target" \
    || fail "root created $dangling through a planted temp name"
[[ "$(readlink "$BOXMUNGE_ROOT/$STATE/.active-slot.planted1")" == "$VICTIM" \
    && "$(readlink "$BOXMUNGE_ROOT/$STATE/.active-slot.planted2")" == "$dangling" ]] \
    && pass "the planted links were left as they were" || fail "a planted link was replaced"
[[ -f "$BOXMUNGE_ROOT/$STATE/active-slot" && ! -L "$BOXMUNGE_ROOT/$STATE/active-slot" \
    && "$(cat "$BOXMUNGE_ROOT/$STATE/active-slot")" == "a" ]] \
    && pass "active-slot rewritten as a regular file naming the live slot" \
    || fail "active-slot not rewritten as a regular file: $OUT"
rm -rf "$(dirname "$VICTIM")"
drop_root

# A link renamed over the temp after mkstemp made it: root writes, fchmods
# and fsyncs the file it created, so $VICTIM is untouched. The rename then
# puts deploy's link at active-slot (as deploy could itself, the directory
# being deploy's), and the next run refuses it rather than reading through.
slot_rewrite_root
SLOT_PLANT="$PLANTS/swapped_temp.py" PATH="$HOSTILE:$PATH" run_shim check-probation
victim_untouched "a link swapped over the temp was not written or chmod'd through"
[[ -L "$BOXMUNGE_ROOT/$STATE/active-slot" ]] && pass "the race left deploy's link at active-slot" \
    || fail "the swap stand-in did not run: $OUT"
run_shim check-probation
expect 1 "is a symlink" "the next run refuses the link the race left at active-slot"
victim_untouched "the next run did not read or write through that link"
rm -rf "$(dirname "$VICTIM")"
drop_root
unset VICTIM

# Descriptors handed in by the environment must be upgrade.lock (fd 9) and the
# jobs gate (fd 8) themselves.
new_root a
other="$(mktemp)"
RC=0
# shellcheck disable=SC2094  # the same file on both descriptors, on purpose
OUT="$(BM_UPGRADE_LOCK_FD=9 BM_JOBS_GATE_FD=8 bash "$SHIM" check-probation 9<>"$other" 8<"$other" 2>&1)" || RC=$?
expect 1 "fd 9 is not $BOXMUNGE_ROOT/upgrade-root/upgrade.lock" "a lock descriptor for another file is refused"
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
: > "$BOXMUNGE_ROOT/upgrade-root/upgrade.lock"
: > "$BOXMUNGE_ROOT/state/jobs/gate.lock"
RC=0
OUT="$(BM_UPGRADE_LOCK_FD=9 BM_JOBS_GATE_FD=8 bash "$SHIM" check-probation \
    9<>"$BOXMUNGE_ROOT/upgrade-root/upgrade.lock" 8<"$other" 2>&1)" || RC=$?
expect 1 "fd 8 is not $BOXMUNGE_ROOT/state/jobs/gate.lock" "a gate descriptor for another file is refused"
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

rm -rf "$HOSTILE" "$PLANTS"

finish
