#!/usr/bin/env bash
# tests/shim/test_check_refusals.sh — what `check <version>` refuses before
# it fetches anything: each refusal is check JSON (cant_verify, stage
# refused) naming a command that works from where the box is, and changes no
# upgrade state (run_check asserts that on every run). deploy may write
# probation.json and the blocklist, so they are read, never acted on.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016,SC2119  # SC2016: mock bodies are literal bash; SC2119: release takes no args
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=tests/shim/check_fixture.sh
source "$(dirname "$0")/check_fixture.sh"

release
refused() {  # refused <in a reason> <description>: the last check was refused, fetching nothing
    expect_check 1 cant_verify refused "$1" "$2"
    ran "^curl " && fail "$2: fetched after the refusal: $(calls)" || true
}

# --- the version -------------------------------------------------------------------

box
for older in 1.4.0 1.3.9 1.4.0-rc.1; do
    CHECK_TARGET="$older" run_check "$older"
    CHECK_TARGET="$older" refused "this box runs 1.4.0, and upgrade-check checks a newer release: run upgrade-howto" \
        "check: a downgrade or the installed version is refused: $older"
done
drop_root

box
echo "0.11.6" > "$BOXMUNGE_ROOT/config/version"
CHECK_TARGET=0.11.7 run_check 0.11.7
CHECK_TARGET=0.11.7 refused "0.11.7 predates the readiness check (releases carry it from 0.11.8 on), so it cannot be checked; upgrade to it from the deploy shell: upgrade --target 0.11.7" \
    "check: a release before the first with a readiness check is refused, naming upgrade --target"
echo "0.9.0" > "$BOXMUNGE_ROOT/config/version"
CHECK_TARGET=0.10.1 run_check 0.10.1
CHECK_TARGET=0.10.1 refused "0.10.1 predates the hash-pinned requirements every install needs, so this box can neither check nor install it; run upgrade-howto to see the latest release" \
    "check: a release without the hash-pinned MCP requirements is refused, naming no command that refuses it"
[[ "$(field 'd["reasons"][0]')" != *"upgrade --target"* ]] && pass "no upgrade --target for a release target refuses" \
    || fail "names target: $JSON"
drop_root

box
printf '{"1.5.0": {"reason": "apply", "failed_at": "x"}}\n' > "$BOXMUNGE_ROOT/upgrade-state/blocklist.json"
run_check 1.5.0
refused "sudo $BOXMUNGE_ROOT/bin/boxmunge-upgrade clear-blocklist 1.5.0" "check: a blocklisted version is refused, naming clear-blocklist"
printf 'not json' > "$BOXMUNGE_ROOT/upgrade-state/blocklist.json"
run_check 1.5.0
[[ "$RC" -eq 1 && -z "$JSON" && "$ERR" == *"blocklist.json is malformed; inspect it and repair or remove it"* ]] \
    && pass "a malformed blocklist stops the check, saying so" || fail "malformed blocklist: rc=$RC $JSON $ERR"
drop_root

# --- interrupted work, probation, userns ------------------------------------------

# A swap cut short: active-slot disagrees with env-active, and the marker
# proves the swap. check-probation repairs active-slot; a check must not.
box
echo b > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
echo 1.4.0 > "$BOXMUNGE_ROOT/env-a/upgrade-inflight"
run_check 1.5.0
refused "check-probation finishes it within minutes; run upgrade-check again after that" \
    "check: an interrupted upgrade is refused, active-slot left as it is"
rm "$BOXMUNGE_ROOT/env-a/upgrade-inflight"
echo a > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
printf '1.5.0\napply\n0\n' > "$BOXMUNGE_ROOT/env-b/rollback-inflight"
run_check 1.5.0
refused "check-probation finishes it within minutes" "check: an interrupted rollback is refused"
drop_root

box
write_probation 1.4.0 b "$SOON"
run_check 1.5.0
refused "1.4.0 is on probation until" "check: a recorded probation is refused, naming when it ends"
[[ "$(field 'd["reasons"][0]')" == *"UTC, and no upgrade runs until it ends; run upgrade-check again after that" ]] \
    && pass "the probation refusal says to run upgrade-check again after it" || fail "probation: $JSON"
write_probation 1.4.0 b "2026-01-01T00:00:00+00:00"
run_check 1.5.0
refused "1.4.0 has finished its probation, and the health timer's check-probation promotes it within minutes" \
    "check: an expired probation is refused until check-probation promotes it"
drop_root

box
forge_probation 1.4.0 b "$SOON"
run_check 1.5.0
refused "no upgrade on this box is running that probation; the health timer's check-probation removes it within minutes" \
    "check: a planted probation is refused, and left for check-probation"
[[ -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] && pass "the planted probation.json is not removed by a check" \
    || fail "a check removed probation.json"
write_probation 1.4.0 a "$SOON"
run_check 1.5.0
refused "check-probation removes it within minutes" "check: a stale probation (the live slot as previous) is refused"
printf 'garbage' > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
run_check 1.5.0
refused "is unreadable or malformed, and defers every upgrade until it is removed. The operator inspects and removes it as supervisor (sudo rm $BOXMUNGE_ROOT/upgrade-state/probation.json)" \
    "check: a malformed probation.json is refused, naming its removal"
rm "$BOXMUNGE_ROOT/upgrade-state/probation.json"
mkfifo "$BOXMUNGE_ROOT/upgrade-state/probation.json"
RUN_DESC="probation.json a FIFO" run_check 1.5.0
refused "is unreadable or malformed" "check: a FIFO at probation.json is refused, not read"
rm "$BOXMUNGE_ROOT/upgrade-state/probation.json"
head -c 1048577 /dev/zero > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
RUN_DESC="probation.json over 1 MiB" run_check 1.5.0
refused "is unreadable or malformed" "check: a planted probation.json over 1 MiB is refused, not read whole"
rm "$BOXMUNGE_ROOT/upgrade-state/probation.json"
head -c 1048577 /dev/zero > "$BOXMUNGE_ROOT/upgrade-state/blocklist.json"
RUN_DESC="blocklist.json over 1 MiB" run_check 1.5.0
[[ "$RC" -eq 1 && -z "$JSON" && "$ERR" == *"blocklist.json is over 1048576 bytes; refusing to read it as root"* ]] \
    && pass "check: a planted blocklist over 1 MiB stops the check, saying so" || fail "huge blocklist: rc=$RC $ERR"
rm "$BOXMUNGE_ROOT/upgrade-state/blocklist.json"
ln -s /etc/hostname "$BOXMUNGE_ROOT/upgrade-state/probation.json"
RUN_DESC="probation.json a link" run_check 1.5.0
refused "is unreadable or malformed" "check: a link at probation.json is refused, not followed"
drop_root

box
printf '{"direction": "forward", "phase": "shifting", "items": {}}' > "$BOXMUNGE_ROOT/upgrade-root/userns-migration.json"
run_check 1.5.0
refused "a userns forward shifting is stopped part-way" "check: a userns migration stopped part-way is refused"
[[ "$(field 'd["reasons"][0]')" == *"sudo $BOXMUNGE_ROOT/bin/boxmunge-upgrade userns-migrate (to resume) or userns-rollback)"* ]] \
    && pass "the userns refusal names how to finish it" || fail "userns: $JSON"
printf '{"direction": "forward", "phase": "applied"}' > "$BOXMUNGE_ROOT/upgrade-root/userns-migration.json"
run_check 1.5.0
expect_check 0 pass complete "" "an applied userns migration does not stop a check"
printf 'garbage' > "$BOXMUNGE_ROOT/upgrade-root/userns-migration.json"
run_check 1.5.0
refused "sudo $BOXMUNGE_ROOT/bin/boxmunge-upgrade userns-migrate --check" "check: a malformed userns journal is refused"
drop_root

# --- one at a time, at most one every ten minutes ---------------------------------

box
mkdir -m 0755 "$BOXMUNGE_ROOT/upgrade-check"
echo "another check's" > "$BOXMUNGE_ROOT/upgrade-check/marker"
exec 6>>"$BOXMUNGE_ROOT/upgrade-root/check.lock"
flock -n 6
KEEP_SCRATCH=1 RUN_DESC="check.lock held" run_check 1.5.0
exec 6>&-
expect_check 1 cant_verify refused "a readiness check is already running; retry when it ends" "check: a second check at once is refused"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-check/marker" 2>/dev/null)" == "another check's" ]] \
    && pass "the running check's scratch is left alone" || fail "the refused check touched the running one's scratch"
rm -rf "$BOXMUNGE_ROOT/upgrade-check"

echo $(( $(date +%s) - 60 )) > "$BOXMUNGE_ROOT/upgrade-root/check-last"
KEEP_STAMP=1 run_check 1.5.0
refused "checks start at least 10 minutes after the last one ended; run upgrade-check again from 20" "check: a second check within 600 s is refused naming the time"
[[ "$(field 'd["reasons"][0]')" =~ again\ from\ [0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}\ UTC$ ]] \
    && pass "the rate limit names the UTC time of the next check" || fail "rate limit: $JSON"
echo $(( $(date +%s) + 86400 )) > "$BOXMUNGE_ROOT/upgrade-root/check-last"
KEEP_STAMP=1 run_check 1.5.0
expect_check 0 pass complete "" "check: a stamp in the future does not rate-limit"
echo $(( $(date +%s) - 601 )) > "$BOXMUNGE_ROOT/upgrade-root/check-last"
KEEP_STAMP=1 run_check 1.5.0
expect_check 0 pass complete "" "a check more than 600 s after the last runs"
printf '12ab' > "$BOXMUNGE_ROOT/upgrade-root/check-last"
KEEP_STAMP=1 run_check 1.5.0
refused "sudo rm $BOXMUNGE_ROOT/upgrade-root/check-last" "a malformed stamp is refused, naming its removal"
drop_root

# --- the scratch -------------------------------------------------------------------

box
LOWDISK="$(mktemp -d)"
printf '#!/usr/bin/env bash\necho "Filesystem 1048576-blocks Used Available Capacity Mounted on"\necho "/dev/x 1000 700 300 70%% /"\n' > "$LOWDISK/df"
chmod +x "$LOWDISK/df"
PATH="$LOWDISK:$PATH" run_check 1.5.0
refused "has 300 MB free, and a check needs 400 MB" "check: too little free space for the scratch is refused"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/check-last" ]] && pass "a check refused for disk space is not rate-limited" \
    || fail "the refused check stamped"
rm -rf "$LOWDISK"
elsewhere="$(mktemp -d)"
echo kept > "$elsewhere/kept"
ln -s "$elsewhere" "$BOXMUNGE_ROOT/upgrade-check"
KEEP_SCRATCH=1 run_check 1.5.0
refused "upgrade-check is a symlink" "check: a link at the scratch is refused, not followed"
[[ "$(cat "$elsewhere/kept")" == kept && -L "$BOXMUNGE_ROOT/upgrade-check" ]] \
    && pass "the refused link and what is behind it are left as they were" || fail "the refused link was touched"
rm -f "$BOXMUNGE_ROOT/upgrade-check"
rm -rf "$elsewhere"
chmod 0775 "$BOXMUNGE_ROOT"
run_check 1.5.0
refused "is not root's alone" "check: a BOXMUNGE_ROOT others may write is refused, naming the fix"
chmod 0700 "$BOXMUNGE_ROOT"
drop_root

rm -rf "$RELEASE" "$FIXTURE"
finish
