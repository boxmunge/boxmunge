#!/usr/bin/env bash
# tests/shim/test_userns.sh — the root-only userns subcommands, the
# force-target guard on a remapped box, and no upgrade mid-migration.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# recording_server: env-a's boxmunge-server records its arguments, and
# whether it inherited the shim's lock descriptor.
recording_server() {
    mock_server a 'printf "%s fd9=%s\n" "$*" "$([[ -e /proc/self/fd/9 || -e /dev/fd/9 ]] && echo yes || echo no)" >> "$BOXMUNGE_ROOT/calls"; exit 0'
}
calls() { cat "$BOXMUNGE_ROOT/calls" 2>/dev/null || true; }

# journal <direction> <phase>
journal() {
    mkdir -p -m 700 "$BOXMUNGE_ROOT/upgrade-root"
    printf '{"version": 1, "direction": "%s", "phase": "%s", "offset": 1048576}\n' "$1" "$2" \
        > "$BOXMUNGE_ROOT/upgrade-root/userns-migration.json"
}

new_root a; recording_server
run_shim userns-migrate --check
expect 0 "" "userns-migrate --check runs"
[[ "$(calls)" == *"userns check"* ]] && pass "--check calls userns check" || fail "--check: $(calls)"
drop_root

new_root a; recording_server
run_shim userns-migrate
expect 0 "" "userns-migrate runs"
[[ "$(calls)" == "userns migrate fd9=yes" ]] && pass "migrate calls userns migrate holding the lock" \
    || fail "migrate: $(calls)"
run_shim userns-rollback
run_shim userns-commit
[[ "$(calls)" == *"userns rollback fd9=yes"*"userns commit fd9=yes"* ]] \
    && pass "rollback and commit run under the lock" || fail "rollback/commit: $(calls)"
drop_root

new_root a; recording_server
write_probation "1.4.0" "b" "$SOON"
run_shim userns-migrate
expect 1 "1.4.0 is on probation" "migrate is refused during a probation"
[[ "$(calls)" != *"userns migrate"* ]] && pass "nothing ran during the probation" || fail "ran: $(calls)"
run_shim userns-rollback
[[ "$(calls)" == *"userns rollback"* ]] && pass "rollback is allowed during a probation" || fail "rollback: $(calls)"
drop_root

new_root a; recording_server
touch "$BOXMUNGE_ROOT/env-a/upgrade-inflight"
run_shim userns-migrate
expect 1 "an upgrade or rollback was interrupted" "migrate is refused after an interrupted upgrade"
drop_root

new_root a; recording_server
run_shim userns-migrate --now
expect 1 "Usage: boxmunge-upgrade userns-migrate [--check]" "unknown argument refused"
run_shim userns-migrate --check extra
expect 1 "Usage: boxmunge-upgrade userns-migrate [--check]" "extra argument after --check refused"
run_shim userns-commit extra
expect 1 "Usage: boxmunge-upgrade userns-commit" "extra argument refused"
run_shim userns-rollback --force
expect 1 "Usage: boxmunge-upgrade userns-rollback" "rollback takes no argument"
[[ -z "$(calls)" ]] && pass "no usage error reached the core" || fail "ran: $(calls)"
drop_root

for phase in applied committed; do
    new_root a; journal forward "$phase"
    run_shim force-target 0.10.2
    expect 1 "this box's Docker daemon is remapped (userns migration $phase)" \
        "force-target below the first remap-aware release is refused ($phase)"
    drop_root
done

new_root a; journal rollback rolled-back
PATH="$FAILVISUDO:$PATH" run_shim force-target 0.10.2
expect 1 "failed visudo" "force-target to an old release passes the guard once rolled back"
drop_root

new_root a; journal forward applied
PATH="$FAILVISUDO:$PATH" run_shim force-target 0.11.0
expect 1 "failed visudo" "force-target to the first remap-aware release passes the guard"
drop_root

new_root a; journal forward rebuilt
run_shim target 1.5.0
expect 1 "a userns migration stopped at rebuilt" "no upgrade while a migration is stopped part-way"
run_shim run 1.5.0 https://example.com/x security
expect 0 "Deferred" "the timer's run is deferred mid-migration"
journal rollback rb-restored
run_shim target 1.5.0
expect 1 "stopped at rb-restored" "no upgrade while a rollback is stopped part-way"
drop_root

new_root a; mkdir -m 700 "$BOXMUNGE_ROOT/upgrade-root"
echo 'not json' > "$BOXMUNGE_ROOT/upgrade-root/userns-migration.json"
run_shim target 1.5.0
expect 1 "is malformed" "a malformed journal stops an upgrade"
drop_root

new_root a; mkdir -m 700 "$BOXMUNGE_ROOT/upgrade-root"
ln -s /etc/passwd "$BOXMUNGE_ROOT/upgrade-root/userns-migration.json"
run_shim force-target 0.10.2
expect 1 "is a symlink" "a linked journal is refused"
drop_root

new_root a
run_shim install-sudoers
[[ "$(cat "$BOXMUNGE_SUDOERS_FILE" 2>/dev/null)" != *userns* ]] && pass "deploy's sudo rule has no userns" \
    || fail "sudoers mentions userns"
drop_root

finish
