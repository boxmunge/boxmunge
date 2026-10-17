#!/usr/bin/env bash
# tests/shim/test_rollback_teardown.sh — D14: before a rollback swaps back,
# the release being rolled back from tears down its staged releases. A
# failure there never blocks the rollback, and a rollback resumed after the
# swap does not run it again.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# probation_failure <teardown rc>: active a (new release) fails its probation
# health check; both slots record every call; a's teardown exits <rc>.
probation_failure() {
    new_root a
    mock_server a "echo \"a \$*\" >> \"$BOXMUNGE_ROOT/calls\"
if [[ \"\$1\" == health ]]; then exit 2; fi
if [[ \"\$1\" == staging-teardown-all ]]; then exit $1; fi
exit 0"
    mock_server b 'echo "b $*" >> "$BOXMUNGE_ROOT/calls"; exit 0'
    rm "$BOXMUNGE_ROOT/env-b/bin/python"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$BOXMUNGE_ROOT/env-b/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
    # a's python records the notifications it is asked to send.
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    printf '#!/usr/bin/env bash\n[[ -z "${BM_TITLE:-}" ]] || echo "notify p=${BM_PRIORITY:-} ${BM_TITLE}: ${BM_MESSAGE}" >> "$BOXMUNGE_ROOT/notes"\nexit 0\n' \
        > "$BOXMUNGE_ROOT/env-a/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-a/bin/python"
    write_probation "1.2.3" "b" "$SOON"
    run_shim check-probation
}
calls() { grep -v -- '--version' "$BOXMUNGE_ROOT/calls" | grep -v ' health' | tr '\n' ';'; }
notes() { cat "$BOXMUNGE_ROOT/notes" 2>/dev/null || true; }

probation_failure 0
expect 1 "Rollback complete" "a rollback with a clean teardown completes"
[[ "$(calls)" == "a staging-teardown-all --reason platform-rollback;b stash restore --latest;b upgrade --apply;" ]] \
    && pass "the rolled-back release tears its stages down before the swap" \
    || fail "unexpected calls: $(calls)"
[[ "$(notes)" != *"staging teardown"* ]] && pass "a clean teardown sends no shim alert" \
    || fail "unexpected alert: $(notes)"
drop_root

probation_failure 1
expect 1 "Rollback complete" "a failed teardown still completes the rollback"
[[ "$(calls)" == "a staging-teardown-all --reason platform-rollback;b stash restore --latest;b upgrade --apply;" ]] \
    && pass "a failed teardown does not block the rollback" || fail "rollback blocked: $(calls)"
[[ "$OUT" == *"staging teardown before the rollback did not finish (exit 1)"* ]] \
    && pass "a failed teardown is logged" || fail "no WARN for the failed teardown: $OUT"
drop_root

# Killed by the timeout (124), it alerts no project itself: the shim does.
probation_failure 124
expect 1 "Rollback complete" "a timed-out teardown still completes the rollback"
[[ "$(calls)" == *"b stash restore --latest;b upgrade --apply;"* ]] \
    && pass "a timed-out teardown does not block the rollback" || fail "rollback blocked: $(calls)"
[[ "$(notes)" == "notify p=1 "*"staging teardown before the rollback did not finish (exit 124)"*".releases/staged"*"down"*"rm -rf"* ]] \
    && pass "a timed-out teardown sends a high-priority alert with the manual commands" \
    || fail "no alert for the timed-out teardown: $(notes)"
drop_root

# resumed <active slot>: a rollback onto b was cut short; the marker is in
# env-b. Before the swap (active a) the teardown runs; after it (active b,
# the older release, which does not know the slot) it must not run again.
resumed() {
    new_root "$1"
    mock_server a 'echo "a $*" >> "$BOXMUNGE_ROOT/calls"; exit 0'
    mock_server b 'echo "b $*" >> "$BOXMUNGE_ROOT/calls"; exit 0'
    printf '1.2.3\nprobation\n0\n' > "$BOXMUNGE_ROOT/env-b/rollback-inflight"
    run_shim check-probation
}

resumed a
[[ "$(calls)" == "a staging-teardown-all --reason platform-rollback;b stash restore --latest;b upgrade --apply;"* ]] \
    && pass "a rollback resumed before the swap tears down first" \
    || fail "unexpected calls: $(calls) $OUT"
drop_root

resumed b
[[ "$(calls)" == "b stash restore --latest;b upgrade --apply;"* && "$(calls)" != *staging-teardown-all* ]] \
    && pass "a rollback resumed after the swap does not tear down again" \
    || fail "unexpected calls: $(calls) $OUT"
drop_root
finish
