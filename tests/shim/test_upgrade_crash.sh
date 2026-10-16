#!/usr/bin/env bash
# tests/shim/test_upgrade_crash.sh — the shim is killed at each point between
# the venv swap and the probation record. The next check-probation (the
# health timer, e.g. after a reboot) must never delete the proven slot, and
# must leave the box on a release it can account for.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# A complete upgrade from 1.4.0 (slot a) to 1.5.0 (slot b) runs against
# stand-ins: curl serves a local release, cosign and sha256sum accept it,
# python3 -m venv copies in a mock venv. KILL_AT names the step at which a
# stand-in SIGKILLs the shim (its pid is in $BOXMUNGE_ROOT/shim.pid).
FIXTURE="$(mktemp -d)"
REAL_PYTHON3="$(command -v python3)"
REAL_LN="$(command -v ln)"
mkdir -p "$FIXTURE/bin" "$FIXTURE/release/boxmunge/on-server" "$FIXTURE/venv/bin"

kill_shim='kill -9 "$(cat "$BOXMUNGE_ROOT/shim.pid")"; exit 0'
stub() {  # stub <path> <bash body>
    printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"
    chmod +x "$1"
}
stub "$FIXTURE/bin/python3" "if [[ \"\$1 \$2\" == '-m venv' ]]; then mkdir -p \"\$3\"; cp -R '$FIXTURE/venv/bin' \"\$3/\"; exit 0; fi
exec '$REAL_PYTHON3' \"\$@\""
stub "$FIXTURE/bin/curl" 'cp "'"$FIXTURE"'/release/$(basename "${@: -1}")" "$3"'
stub "$FIXTURE/bin/cosign" 'exit 0'
stub "$FIXTURE/bin/sha256sum" 'cat >/dev/null; exit 0'
stub "$FIXTURE/bin/sync" 'echo "sync link=$(readlink "$BOXMUNGE_ROOT/env-active" | sed "s|.*/||") marker=$([[ -f "$BOXMUNGE_ROOT/env-b/upgrade-inflight" ]] && echo yes || echo no)" >> "$BOXMUNGE_ROOT/calls"
n=$(grep -c "^sync" "$BOXMUNGE_ROOT/calls")
[[ "${KILL_AT:-}" != "sync$n" ]] || { '"$kill_shim"'; }'
stub "$FIXTURE/bin/ln" "'$REAL_LN' \"\$@\" || exit
[[ \"\${@: -1}\" == */env-active ]] || exit 0
echo link >> \"\$BOXMUNGE_ROOT/calls\"
[[ \"\${KILL_AT:-}\" != \"link\$(grep -c '^link\$' \"\$BOXMUNGE_ROOT/calls\")\" ]] || { $kill_shim; }"

# The new release's venv.
stub "$FIXTURE/venv/bin/pip" 'exit 0'
stub "$FIXTURE/venv/bin/boxmunge-server" 'case "$1 ${2:-}" in
    "--version "*) echo "boxmunge 1.5.0" ;;
    "upgrade --apply") [[ "${KILL_AT:-}" != apply ]] || { '"$kill_shim"'; }; [[ -z "${FAIL_APPLY:-}" ]] || exit 1 ;;
    "health "*) [[ "${KILL_AT:-}" != health ]] || { '"$kill_shim"'; }; [[ -z "${FAIL_HEALTH:-}" ]] || exit 2 ;;
esac
exit 0'
stub "$FIXTURE/venv/bin/python" 'if [[ "$1" == "-" ]]; then
    cat >/dev/null; echo "bm_log $BM_MSG" >> "$BOXMUNGE_ROOT/calls"
    [[ "${KILL_AT:-}" != probation_logged || "$BM_MSG" != "probation entered" ]] || { '"$kill_shim"'; }
    exit 0
fi
case "$2" in
    *write_probation*)
        [[ "${KILL_AT:-}" != probation ]] || { '"$kill_shim"'; }
        printf "{\"version\": \"%s\", \"previous_slot\": \"%s\", \"expires_at\": \"'"$SOON"'\"}\n" \
            "$BM_VERSION" "$BM_PREV_SLOT" > "$BOXMUNGE_ROOT/upgrade-state/probation.json" ;;
    *get_build_version*) echo "1.5.0" ;;
esac
exit 0'

# The release itself.
echo "build==1" > "$FIXTURE/release/boxmunge/requirements-build.txt"
echo "tui==1" > "$FIXTURE/release/boxmunge/requirements-tui.txt"
echo "1.5.0 ops" > "$FIXTURE/release/boxmunge/on-server/OPERATIONS.md"
tar czf "$FIXTURE/release/boxmunge-1.5.0.tar.gz" -C "$FIXTURE/release" boxmunge
echo "0000  boxmunge-1.5.0.tar.gz" > "$FIXTURE/release/SHA256SUMS"
touch "$FIXTURE/release/SHA256SUMS.sig" "$FIXTURE/release/SHA256SUMS.cert"
export PATH="$FIXTURE/bin:$PATH"

# installed: slot a holds the proven 1.4.0, whose server and python record
# every call so a rollback onto it can be seen.
installed() {
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    echo "proven" > "$BOXMUNGE_ROOT/env-a/known-good"
    mock_server a 'echo "a: $*" >> "$BOXMUNGE_ROOT/calls"; [[ "$1" != --version ]] || echo "boxmunge 1.4.0"
case "$1 ${2:-}" in
    "stash restore") [[ "${KILL_AT:-}" != restore ]] || { '"$kill_shim"'; } ;;
    "upgrade --apply") [[ "${KILL_AT:-}" != reapply ]] || { '"$kill_shim"'; } ;;
esac'
    stub "$BOXMUNGE_ROOT/env-a/bin/python.new" 'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_MSG" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi
printf "a-python: stage=%s msg=%s %s\n" "${BM_STAGE:-}" "${BM_MESSAGE:-}" "$*" >> "$BOXMUNGE_ROOT/calls"'
    mv "$BOXMUNGE_ROOT/env-a/bin/python.new" "$BOXMUNGE_ROOT/env-a/bin/python"
    : > "$BOXMUNGE_ROOT/calls"
}

# upgrade_killed_at <point>: run `target 1.5.0`, SIGKILLed at <point>.
upgrade_killed_at() {
    RC=0
    OUT="$(KILL_AT="$1" bash -c 'echo $$ > "$BOXMUNGE_ROOT/shim.pid"; exec bash "$0" target 1.5.0' "$SHIM" 2>&1)" || RC=$?
}

live() { readlink "$BOXMUNGE_ROOT/env-active" | sed 's|.*/env-||'; }
proven_intact() {  # proven_intact <description>
    [[ "$(cat "$BOXMUNGE_ROOT/env-a/known-good" 2>/dev/null)" == "proven" ]] \
        && pass "$1: proven slot survives" || fail "$1: proven slot destroyed"
}

interruptions() { cat "$BOXMUNGE_ROOT/upgrade-root/interrupted.json" 2>/dev/null || true; }
reports() { grep -c "a-python: stage=interrupted" "$BOXMUNGE_ROOT/calls" || true; }
blocklisted() { grep -q "add_to_blocklist" "$BOXMUNGE_ROOT/calls"; }

# expect_rolled_back <point>: check-probation finds the interrupted upgrade
# live and returns the box to the proven release. A first interruption is
# counted and alerted locally, but neither blocklisted nor reported to the
# fleet service (a power cut must not count toward suppressing a release).
expect_rolled_back() {
    run_shim check-probation
    expect 1 "interrupted after the venv swap" "$1: check-probation rolls back the interrupted upgrade"
    proven_intact "$1"
    [[ "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/upgrade-state/active-slot")" == a ]] \
        && pass "$1: proven release is live again" || fail "$1: live slot is $(live)"
    grep -q "a: stash restore --latest" "$BOXMUNGE_ROOT/calls" && grep -q "a: upgrade --apply" "$BOXMUNGE_ROOT/calls" \
        && pass "$1: stash restored and previous release re-applied" || fail "$1: rollback steps missing: $(cat "$BOXMUNGE_ROOT/calls")"
    ! blocklisted && pass "$1: a first interruption is not blocklisted" \
        || fail "$1: a first interruption blocklisted the version"
    [[ "$(reports)" -eq 0 ]] && pass "$1: not reported to the fleet service" \
        || fail "$1: interruption reported: $(cat "$BOXMUNGE_ROOT/calls")"
    grep -q "msg=Rolled back 1.5.0: the upgrade was interrupted (not blocklisted" "$BOXMUNGE_ROOT/calls" \
        && pass "$1: operator alerted locally" || fail "$1: no local alert: $(cat "$BOXMUNGE_ROOT/calls")"
    [[ "$(interruptions)" == '{"1.5.0": 1}' ]] && pass "$1: interruption counted" \
        || fail "$1: interruption count is $(interruptions)"
    [[ ! -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] && pass "$1: no probation left" \
        || fail "$1: probation left behind"
    run_shim check-probation
    expect 0 "orphan venv in inactive slot b" "$1: the next check-probation clears the failed slot"
    proven_intact "$1 (after cleanup)"
}

# --- baseline: an uninterrupted upgrade ------------------------------------

installed
upgrade_killed_at none
expect 0 "probation started" "the fixture upgrade completes"
[[ "$(live)" == b && -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
    && pass "baseline: 1.5.0 live and on probation" || fail "baseline: live=$(live)"
[[ ! -e "$BOXMUNGE_ROOT/env-b/upgrade-inflight" ]] && pass "baseline: inflight marker removed" \
    || fail "baseline: inflight marker left behind"
[[ "$(grep '^sync' "$BOXMUNGE_ROOT/calls" | head -2 | tr '\n' ';')" == "sync link=env-a marker=yes;sync link=env-b marker=yes;" ]] \
    && pass "marker is synced before the swap, and the swap before apply" \
    || fail "unexpected sync order: $(grep '^sync' "$BOXMUNGE_ROOT/calls" | tr '\n' ';')"
proven_intact "baseline"
drop_root

# --- killed before the swap: nothing to undo -------------------------------

installed
upgrade_killed_at sync1
[[ "$RC" -eq 137 && "$(live)" == a ]] && pass "sync1: killed before the swap" || fail "sync1: rc=$RC live=$(live) $OUT"
run_shim check-probation
expect 0 "orphan venv in inactive slot b" "sync1: check-probation clears the half-built slot"
proven_intact "sync1"
[[ "$(live)" == a ]] && pass "sync1: proven release still live" || fail "sync1: live=$(live)"
drop_root

# --- killed after the swap: roll back --------------------------------------

for point in link1 sync2 apply health probation; do
    installed
    upgrade_killed_at "$point"
    [[ "$RC" -eq 137 && "$(live)" == b ]] && pass "$point: killed after the swap" \
        || fail "$point: rc=$RC live=$(live) $OUT"
    upgrade_killed_at none  # an upgrade before recovery must not recycle the proven slot
    expect 1 "an earlier upgrade or rollback was interrupted" "$point: a new upgrade waits for recovery"
    proven_intact "$point (upgrade before recovery)"
    expect_rolled_back "$point"
    drop_root
done

# --- after a first interruption, the next upgrade proceeds -----------------

installed
upgrade_killed_at apply
expect_rolled_back "retry"
upgrade_killed_at none
expect 0 "probation started" "retry: the next upgrade of the same version completes"
[[ "$(live)" == b && -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
    && pass "retry: 1.5.0 live and on probation" || fail "retry: live=$(live)"
write_probation "1.5.0" "a" "2000-01-01T00:00:00+00:00"
run_shim check-probation
expect 0 "promoted" "retry: 1.5.0 is promoted"
[[ "$(interruptions)" == "{}" ]] && pass "promotion forgets the interruption count" \
    || fail "count after promotion: $(interruptions)"
drop_root

installed
upgrade_killed_at apply
run_shim check-probation
run_shim clear-blocklist 1.5.0
[[ "$(interruptions)" == "{}" ]] && pass "clear-blocklist forgets the interruption count" \
    || fail "count after clear-blocklist: $(interruptions)"
drop_root

# --- a second interruption of the same version blocklists it ----------------

installed
upgrade_killed_at apply
expect_rolled_back "twice"
: > "$BOXMUNGE_ROOT/calls"
upgrade_killed_at apply
[[ "$RC" -eq 137 && "$(live)" == b ]] && pass "twice: second upgrade got as far as apply" \
    || fail "twice: rc=$RC live=$(live) $OUT"
run_shim check-probation
expect 1 "Rollback complete" "twice: the second interruption is rolled back"
blocklisted && grep -q "msg=.*interrupted 2 times, now blocklisted" "$BOXMUNGE_ROOT/calls" \
    && pass "twice: the second interruption blocklists the version, and says so" \
    || fail "twice: version not blocklisted: $(cat "$BOXMUNGE_ROOT/calls")"
[[ "$(reports)" -eq 0 && "$(interruptions)" == '{"1.5.0": 2}' ]] && pass "twice: counted, not reported" \
    || fail "twice: reports=$(reports) count=$(interruptions)"
proven_intact "twice"
drop_root

# --- a malformed interruption count stops recovery without deleting ---------

installed
upgrade_killed_at apply
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
echo '{"1.5.0": "x"}' > "$BOXMUNGE_ROOT/upgrade-root/interrupted.json"
run_shim check-probation
expect 1 "interrupted.json is malformed" "a malformed interruption count stops recovery"
proven_intact "malformed count"
drop_root

# --- killed inside a rollback: the next check-probation finishes it --------
# Apply fails, so upgrade_to rolls back; the rollback itself is killed.
# sync3 is its marker (before the swap back), link2 inside the swap back
# (env-active switched, active-slot not yet), sync4 just after it.

for point in sync3 link2 sync4 restore reapply; do
    installed
    RC=0
    OUT="$(FAIL_APPLY=1 KILL_AT="$point" bash -c 'echo $$ > "$BOXMUNGE_ROOT/shim.pid"; exec bash "$0" target 1.5.0' "$SHIM" 2>&1)" || RC=$?
    [[ "$RC" -eq 137 && -e "$BOXMUNGE_ROOT/env-a/rollback-inflight" ]] \
        && pass "rollback $point: killed with the rollback marker in the proven slot" || fail "rollback $point: rc=$RC $OUT"
    : > "$BOXMUNGE_ROOT/calls"
    run_shim check-probation
    expect 1 "Resuming the interrupted rollback of 1.5.0 (stage apply)" "rollback $point: check-probation resumes it"
    [[ "$(live)" == a && ! -e "$BOXMUNGE_ROOT/env-a/rollback-inflight" ]] \
        && pass "rollback $point: proven release live, marker cleared" || fail "rollback $point: live=$(live) $OUT"
    grep -q "a: stash restore --latest" "$BOXMUNGE_ROOT/calls" && grep -q "a: upgrade --apply" "$BOXMUNGE_ROOT/calls" \
        && pass "rollback $point: stash restore and re-apply redone" || fail "rollback $point: steps: $(cat "$BOXMUNGE_ROOT/calls")"
    blocklisted && grep -q "a-python: stage=apply" "$BOXMUNGE_ROOT/calls" \
        && pass "rollback $point: the failed apply is blocklisted and reported" || fail "rollback $point: bookkeeping missing"
    proven_intact "rollback $point"
    run_shim check-probation
    expect 0 "orphan venv in inactive slot b" "rollback $point: the next check-probation clears the failed slot"
    proven_intact "rollback $point (after cleanup)"
    drop_root
done

# --- a probation rollback killed inside its own swap ------------------------
# No upgrade-inflight marker exists by then; rollback-inflight alone must
# prove the env-active/active-slot disagreement is an interrupted swap.

installed
upgrade_killed_at none
RC=0
OUT="$(FAIL_HEALTH=1 KILL_AT=link2 bash -c 'echo $$ > "$BOXMUNGE_ROOT/shim.pid"; exec bash "$0" check-probation' "$SHIM" 2>&1)" || RC=$?
[[ "$RC" -eq 137 && "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/upgrade-state/active-slot")" == b ]] \
    && pass "probation rollback: killed between env-active and active-slot" || fail "probation rollback: rc=$RC live=$(live) $OUT"
: > "$BOXMUNGE_ROOT/calls"
run_shim check-probation
expect 1 "Resuming the interrupted rollback of 1.5.0 (stage health_probation)" "probation rollback: check-probation resumes it"
[[ "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/upgrade-state/active-slot")" == a ]] \
    && pass "probation rollback: env-active and active-slot agree on the proven slot" || fail "probation rollback: live=$(live)"
grep -q "a: stash restore --latest" "$BOXMUNGE_ROOT/calls" && grep -q "a: upgrade --apply" "$BOXMUNGE_ROOT/calls" \
    && pass "probation rollback: stash restore and re-apply ran" || fail "probation rollback: steps: $(cat "$BOXMUNGE_ROOT/calls")"
run_shim check-probation
expect 0 "orphan venv in inactive slot b" "probation rollback: the next check-probation clears the failed slot"
proven_intact "probation rollback"
drop_root

# --- killed after probation was recorded: the upgrade stands ---------------

installed
upgrade_killed_at probation_logged
[[ "$RC" -eq 137 && -e "$BOXMUNGE_ROOT/env-b/upgrade-inflight" ]] \
    && pass "probation_logged: killed with the marker still in place" || fail "probation_logged: rc=$RC $OUT"
run_shim check-probation
expect 0 "" "probation_logged: check-probation continues the probation"
[[ "$(live)" == b && -f "$BOXMUNGE_ROOT/upgrade-state/probation.json" && ! -e "$BOXMUNGE_ROOT/env-b/upgrade-inflight" ]] \
    && pass "probation_logged: 1.5.0 stays on probation, marker cleared" || fail "probation_logged: live=$(live) $OUT"
proven_intact "probation_logged"
drop_root

# --- a forged active-slot without a marker is still refused ----------------

installed
echo b > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
run_shim check-probation
expect 1 "refusing to guess" "a mismatch without an inflight marker is still refused"
proven_intact "forged active-slot"
drop_root

rm -rf "$FIXTURE"
finish
