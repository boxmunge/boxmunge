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

finish
