#!/usr/bin/env bash
# tests/shim/test_rollback_stash.sh — which stash a rollback restores (U3).
# stashes/ is deploy-writable, so a rollback neither takes the newest-named
# stash there nor opens one by name: it restores a root-only copy of the stash
# the upgrade recorded, opened without following a link and only if it is a
# plain file of root's with the recorded size and sha256. An upgrade a shim
# before 0.11.5 ran recorded none; its rollback takes the newest-named stash,
# under the same checks.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

RECORDED="boxmunge-stash-2026-06-01T120000.tar.gz"
PLANTED="boxmunge-stash-9999-12-31T235959.tar.gz"

digest() { python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }
# record_of <stash>: the size and sha256 an upgrade records for it.
record_of() { echo "$(wc -c < "$1" | tr -d ' ') $(digest "$1")"; }

# box [record]: slot a (1.5.0) fails its probation health check; b holds the
# proven 1.4.0, whose python records the archive it is asked to restore.
# stashes/ holds the stash the upgrade made, with its record unless
# record=none, beside the older one new_root leaves.
box() {
    new_root a
    mock_server a 'if [[ "$1" == "health" ]]; then exec health-report 2; fi; exit 0'
    rm "$BOXMUNGE_ROOT/env-b/bin/python"
    printf '%s\n' '#!/usr/bin/env bash' \
        '[[ -z "${BM_STASH:-}" ]] || { echo "restore $BM_STASH: $(cat "$BM_STASH")" >> "$BOXMUNGE_ROOT/calls"; echo "Restored from: ${BM_STASH##*/}"; }' \
        'exit 0' > "$BOXMUNGE_ROOT/env-b/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
    echo "the upgrade's stash" > "$BOXMUNGE_ROOT/stashes/$RECORDED"
    chmod 0600 "$BOXMUNGE_ROOT/stashes/$RECORDED"
    mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
    [[ "${1:-}" == none ]] || echo "1.5.0 $RECORDED $(record_of "$BOXMUNGE_ROOT/stashes/$RECORDED")" \
        > "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash"
    write_probation "1.5.0" "b" "$SOON"
    : > "$BOXMUNGE_ROOT/calls"
}
calls() { cat "$BOXMUNGE_ROOT/calls"; }
restored() { grep -q "^restore $BOXMUNGE_ROOT/upgrade-root/rollback-stash/$1: $2\$" "$BOXMUNGE_ROOT/calls"; }

# Deploy plants a newer-named stash, as a link and as its own file: the
# recorded one is restored, from root's copy.
for planted in link file; do
    box
    if [[ "$planted" == link ]]; then
        echo "deploy's stash" > "$BOXMUNGE_ROOT/deploy-owned.tar.gz"
        ln -s "$BOXMUNGE_ROOT/deploy-owned.tar.gz" "$BOXMUNGE_ROOT/stashes/$PLANTED"
    else
        echo "deploy's stash" > "$BOXMUNGE_ROOT/stashes/$PLANTED"
    fi
    run_shim check-probation
    expect 1 "Rollback complete" "a newer-named $planted in stashes/: the rollback completes"
    restored "$RECORDED" "the upgrade's stash" && pass "a newer-named $planted: the recorded stash is restored, from root's copy" \
        || fail "a newer-named $planted: $(calls)"
    [[ ! -e "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash" && ! -e "$BOXMUNGE_ROOT/upgrade-root/rollback-stash" ]] \
        && pass "a newer-named $planted: the record and the copy go once the rollback is done" || fail "record or copy left"
    drop_root
done

# The recorded stash replaced by a link, or by a second link to one file, is
# refused: a partial rollback, naming the file and what to do.
for swap in symlink hardlink; do
    box
    rm "$BOXMUNGE_ROOT/stashes/$RECORDED"
    echo "elsewhere" > "$BOXMUNGE_ROOT/elsewhere.tar.gz"
    if [[ "$swap" == symlink ]]; then
        ln -s "$BOXMUNGE_ROOT/elsewhere.tar.gz" "$BOXMUNGE_ROOT/stashes/$RECORDED"
        want="stashes/$RECORDED is a symlink"
    else
        ln "$BOXMUNGE_ROOT/elsewhere.tar.gz" "$BOXMUNGE_ROOT/stashes/$RECORDED"
        want="stashes/$RECORDED is not a plain file of root's"
    fi
    run_shim check-probation
    expect 2 "$want" "the recorded stash as a $swap is refused"
    [[ "$OUT" == *"sudo boxmunge-server stash restore --latest"* ]] && pass "the refusal says what to do" || fail "out: $OUT"
    [[ "$(calls)" != *restore* ]] && pass "a $swap: nothing is restored" || fail "restored: $(calls)"
    drop_root
done

box
rm "$BOXMUNGE_ROOT/stashes/$RECORDED"
run_shim check-probation
expect 2 "stashes/$RECORDED cannot be opened" "a missing recorded stash is refused"
drop_root

# The record a released shim's own record_stash writes (0.11.5 is the first
# that records one, 0.11.6 the bridge release) is the one this shim's rollback
# restores, not the newer-named stash planted beside it.
for released in v0.11.5 v0.11.6; do
    box none
    echo "deploy's stash" > "$BOXMUNGE_ROOT/stashes/$PLANTED"
    written="$(
        UPGRADE_ROOT_DIR="$BOXMUNGE_ROOT/upgrade-root"
        # shellcheck disable=SC2034  # read by the released record_stash
        STASH_RECORD_FILE="$UPGRADE_ROOT_DIR/upgrade-stash"
        # shellcheck disable=SC2329  # both are called by the released functions
        log() { echo "log: $*"; }
        # shellcheck disable=SC2329
        die_logged() { echo "die: $*"; exit 1; }
        # The functions cut from the released shim (eval: bash 3.2 cannot source a pipe).
        eval "$(sed -n '/^STASH_NAME_RE=/p;/^refuse_symlink() {/,/^}/p;/^replace_file() {/,/^}/p;/^write_root_file() {/,/^}/p;/^stash_facts() {/,/^}/p;/^record_stash() {/,/^}/p' \
            "$REPO_DIR/tests/integration/old_shims/boxmunge-upgrade-$released")"
        record_stash 1.5.0 "Stash created: $RECORDED" 2>&1
    )" && [[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash")" == "1.5.0 $RECORDED $(record_of "$BOXMUNGE_ROOT/stashes/$RECORDED")" ]] \
        && pass "the $released shim records the stash with its size and sha256" || fail "the $released record_stash: $written"
    run_shim check-probation
    expect 1 "Rollback complete" "a record of the $released shim: the rollback completes"
    restored "$RECORDED" "the upgrade's stash" && [[ "$OUT" != *"no stash recorded"* ]] \
        && pass "a record of the $released shim: the recorded stash is restored" || fail "$(calls); out: $OUT"
    drop_root
done

# No record (a shim before 0.11.5 ran the upgrade): the newest-named stash, checked.
box none
run_shim check-probation
expect 1 "no stash recorded for this upgrade; restoring the newest-named, $RECORDED" "no record: the newest-named stash, said"
restored "$RECORDED" "the upgrade's stash" && pass "no record: the newest-named stash is restored" || fail "$(calls)"
drop_root
box none
ln -s "$BOXMUNGE_ROOT/stashes/$RECORDED" "$BOXMUNGE_ROOT/stashes/$PLANTED"
run_shim check-probation
expect 2 "stashes/$PLANTED is a symlink" "no record: a newest-named link is refused, not skipped"
drop_root

# The record carries the stash's size and sha256: a different root-made
# stash renamed onto the recorded name is refused.
box
mv "$BOXMUNGE_ROOT/stashes/$OLD_STASH" "$BOXMUNGE_ROOT/stashes/$RECORDED"
run_shim check-probation
expect 2 "stashes/$RECORDED is not the stash this upgrade made (its size or sha256 differs from the record)" \
    "another root-made stash under the recorded name is refused"
[[ "$(calls)" != *restore* && -z "$(ls -A "$BOXMUNGE_ROOT/upgrade-root/rollback-stash")" ]] \
    && pass "a mismatched stash: nothing restored, no copy left" || fail "restored: $(calls)"
drop_root
for record in "1.5.0 $RECORDED 12 nothex" "1.5.0 $RECORDED"; do
    box
    echo "$record" > "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash"
    run_shim check-probation
    expect 2 "upgrade-stash is malformed" "a malformed stash record is refused: $record"
    [[ "$(calls)" != *restore* ]] && pass "a malformed record: nothing is restored" || fail "restored: $(calls)"
    drop_root
done

# A record of another upgrade is not this one's.
box
echo "1.4.9 $OLD_STASH $(record_of "$BOXMUNGE_ROOT/stashes/$OLD_STASH")" > "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash"
run_shim check-probation
expect 1 "is not the stash of the upgrade to 1.5.0" "a record of another version is not used"
restored "$RECORDED" "the upgrade's stash" && pass "another version's record: the newest-named stash is restored" || fail "$(calls)"
drop_root

finish
