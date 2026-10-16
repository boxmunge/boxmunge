#!/usr/bin/env bash
# tests/shim/test_rollback.sh — C-06: a rollback restores the stash and then
# re-applies the previous release (regenerated configs, restarted projects).
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# probation_failure <stash rc> <apply rc>: active a (new release) fails its
# probation health check; b is the previous release, whose boxmunge-server
# records every call and exits with the given codes.
probation_failure() {
    new_root a
    mock_server a 'if [[ "$1" == "health" ]]; then exit 2; fi; exit 0'
    mock_server b "echo \"\$*\" >> \"$BOXMUNGE_ROOT/calls\"
case \"\$1 \$2\" in
    'stash restore') exit $1 ;;
    'upgrade --apply') exit $2 ;;
esac
exit 0"
    rm "$BOXMUNGE_ROOT/env-b/bin/python"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$BOXMUNGE_ROOT/env-b/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
    write_probation "1.2.3" "b" "$SOON"
    run_shim check-probation
}

calls() { grep -v -- '--version' "$BOXMUNGE_ROOT/calls" | tr '\n' ';'; }

probation_failure 0 0
expect 1 "Rollback complete" "clean rollback exits 1"
[[ "$(calls)" == "stash restore --latest;upgrade --apply;" ]] \
    && pass "rollback restores the stash, then re-applies the previous release" \
    || fail "unexpected rollback calls: $(calls)"
[[ "$(readlink "$BOXMUNGE_ROOT/env-active")" == "$BOXMUNGE_ROOT/env-b" ]] \
    && pass "rollback swapped back to the previous slot" || fail "env-active not swapped"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] && pass "rollback ends the probation" \
    || fail "probation.json survived the rollback"
run_shim check-probation
expect 0 "orphan venv in inactive slot a" "the next check-probation clears the failed release's slot"
[[ ! -d "$BOXMUNGE_ROOT/env-a" ]] && pass "failed release's slot removed" || fail "env-a left behind"
drop_root

probation_failure 0 1
expect 2 "re-apply of the previous release failed" "a failed re-apply is a partial rollback"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] && pass "a partial rollback ends the probation" \
    || fail "probation.json survived a partial rollback"
drop_root

probation_failure 1 0
expect 2 "stash restore failed" "a failed stash restore is a partial rollback"
[[ "$(calls)" == "stash restore --latest;" ]] && pass "no re-apply after a failed restore" \
    || fail "re-apply ran after a failed restore: $(calls)"
drop_root

# The rollback is done once restore and re-apply succeed: a failure in the
# bookkeeping after them must not make every later fire restore and re-apply
# (restarting every project) again.
probation_failure_setup() {
    new_root a
    mock_server a 'if [[ "$1" == "health" ]]; then exit 2; fi; exit 0'
    mock_server b 'echo "$*" >> "$BOXMUNGE_ROOT/calls"; exit 0'
    rm "$BOXMUNGE_ROOT/env-b/bin/python"
    printf '#!/usr/bin/env bash\n[[ "$*" != *add_to_blocklist* ]] || exit 1\nexit 0\n' > "$BOXMUNGE_ROOT/env-b/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
    write_probation "1.2.3" "b" "$SOON"
}
probation_failure_setup
run_shim check-probation
[[ "$RC" -ne 0 && "$(calls)" == "stash restore --latest;upgrade --apply;" ]] \
    && pass "rollback whose blocklist write fails still restored and re-applied" \
    || fail "unexpected: rc=$RC calls=$(calls)"
: > "$BOXMUNGE_ROOT/calls"
run_shim check-probation
[[ "$(calls)" != *"stash restore"* ]] && pass "a failed bookkeeping step does not repeat the restore" \
    || fail "the next fire restored again: $(calls)"
drop_root

# Likewise for the interruption count: a resumed rollback of an interrupted
# upgrade whose interrupted.json is corrupt fails noisily, once.
new_root a  # a: proven, already swapped back to; b: the interrupted release
mock_server a 'echo "$*" >> "$BOXMUNGE_ROOT/calls"; exit 0'
printf '1.5.0\ninterrupted\n1\n' > "$BOXMUNGE_ROOT/env-a/rollback-inflight"
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
echo 'not json' > "$BOXMUNGE_ROOT/upgrade-root/interrupted.json"
run_shim check-probation
[[ "$RC" -ne 0 && "$OUT" == *"interrupted.json is malformed"* && "$(calls)" == *"stash restore --latest;upgrade --apply;"* ]] \
    && pass "a corrupt interruption count fails the bookkeeping after restore and re-apply" \
    || fail "unexpected: rc=$RC calls=$(calls) $OUT"
: > "$BOXMUNGE_ROOT/calls"
run_shim check-probation
[[ "$(calls)" != *"stash restore"* ]] && pass "a corrupt interruption count does not repeat the restore" \
    || fail "the next fire restored again: $(calls)"
drop_root

finish
