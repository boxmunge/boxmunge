#!/usr/bin/env bash
# tests/shim/test_upgrade_policy.sh — A-06: deploy's sudo rule and what each
# shim entry point may install.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# run_past_policy <args...>: run the shim with a visudo that rejects everything,
# so an accepted request stops at the sudoers step instead of downloading.
run_past_policy() { PATH="$FAILVISUDO:$PATH" run_shim "$@"; }

blocklist() { printf '{"%s": {"reason": "apply", "failed_at": "x"}}\n' "$1" \
    > "$BOXMUNGE_ROOT/upgrade-state/blocklist.json"; }

# --- the sudoers rule -----------------------------------------------------

new_root a
run_shim install-sudoers
expect 0 "Wrote deploy sudo rule" "install-sudoers writes the rule"
expected_rule="deploy ALL=(root) NOPASSWD: $BOXMUNGE_ROOT/bin/boxmunge-upgrade auto, $BOXMUNGE_ROOT/bin/boxmunge-upgrade target *"
rules="$(grep -v '^#' "$BOXMUNGE_SUDOERS_FILE")"
[[ "$rules" == "$expected_rule" ]] && pass "sudoers grants exactly auto and target" \
    || fail "unexpected sudoers rule: $rules"
for forbidden in "upgrade run" "check-probation" "clear-blocklist" "force-target" "install-sudoers"; do
    grep -v "^#" "$BOXMUNGE_SUDOERS_FILE" | grep -q -- "$forbidden" && fail "sudoers mentions $forbidden" \
        || pass "sudoers does not grant $forbidden"
done
mode="$(stat -c %a "$BOXMUNGE_SUDOERS_FILE" 2>/dev/null || stat -f %Lp "$BOXMUNGE_SUDOERS_FILE")"
[[ "$mode" == "440" ]] && pass "sudoers file is 0440" || fail "sudoers file mode is $mode"
if [[ -n "$REAL_VISUDO" ]]; then
    "$REAL_VISUDO" -cf "$BOXMUNGE_SUDOERS_FILE" >/dev/null && pass "visudo -cf accepts the rule" \
        || fail "visudo -cf rejects the rule"
else
    echo "SKIP: visudo not installed; rule text checked only"
fi
run_shim install-sudoers
expect 0 "" "install-sudoers is idempotent"
[[ "$OUT" != *"Wrote"* ]] && pass "unchanged rule is not rewritten" || fail "unchanged rule rewritten"

# An older, wider rule is tightened.
rm -f "$BOXMUNGE_SUDOERS_FILE"
echo "deploy ALL=(root) NOPASSWD: $BOXMUNGE_ROOT/bin/boxmunge-upgrade" > "$BOXMUNGE_SUDOERS_FILE"
run_shim install-sudoers
expect 0 "Wrote deploy sudo rule" "install-sudoers replaces a wide legacy rule"
[[ "$(grep -v '^#' "$BOXMUNGE_SUDOERS_FILE")" == "$expected_rule" ]] && pass "legacy rule tightened" \
    || fail "legacy rule not tightened"

# A rule visudo rejects is never installed.
rm -f "$BOXMUNGE_SUDOERS_FILE"
echo "legacy" > "$BOXMUNGE_SUDOERS_FILE"
PATH="$FAILVISUDO:$PATH" run_shim install-sudoers
expect 1 "failed visudo" "install-sudoers refuses a rule visudo rejects"
[[ "$(cat "$BOXMUNGE_SUDOERS_FILE")" == "legacy" ]] && pass "rejected rule leaves the old file" \
    || fail "rejected rule replaced the old file"
compgen -G "$BOXMUNGE_ROOT/sudoers.d/.boxmunge-deploy.*" >/dev/null && fail "temp sudoers file left behind" \
    || pass "no temp sudoers file left behind"
drop_root

# --- target (reachable by deploy) ----------------------------------------

new_root a
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
run_shim target 1.5.0 --force
expect 1 "Usage: boxmunge-upgrade target" "target refuses extra arguments"
run_shim target "1.5.0 --force"
expect 1 "Invalid version" "target refuses a version with embedded words"
run_shim target 1.3.9
expect 1 "Refusing to downgrade from 1.4.0 to 1.3.9" "target refuses a downgrade"
[[ "$OUT" == *"force-target 1.3.9"* ]] && pass "downgrade refusal names the operator override" \
    || fail "downgrade refusal lacks the override hint"
run_shim target 1.4.0-rc.1
expect 1 "Refusing to downgrade" "target refuses a pre-release of the installed version"
blocklist 1.5.0
run_shim target 1.5.0
expect 1 "is blocklisted" "target refuses a blocklisted version"
rm "$BOXMUNGE_ROOT/upgrade-state/blocklist.json"
run_past_policy target 1.5.0
expect 1 "failed visudo" "target accepts a newer version"
run_past_policy target 1.4.0
expect 1 "failed visudo" "target accepts reinstalling the installed version"
echo "1.4.0-rc.2" > "$BOXMUNGE_ROOT/config/version"
run_past_policy target 1.4.0-rc.10
expect 1 "failed visudo" "pre-release identifiers compare numerically"
run_past_policy target 1.4.0
expect 1 "failed visudo" "a release outranks its pre-releases"
rm "$BOXMUNGE_ROOT/config/version"
run_shim target 1.5.0
expect 1 "No installed version" "target refuses when the installed version is unknown"
drop_root

# --- force-target (operator only) ----------------------------------------

new_root a
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
blocklist 1.3.0
run_past_policy force-target 1.3.0
expect 1 "failed visudo" "force-target installs a blocklisted older version"
[[ "$OUT" == *"operator override"* ]] && pass "force-target logs the override" \
    || fail "force-target did not log the override"
run_shim force-target "../../x"
expect 1 "Invalid version" "force-target still requires semver"
run_shim force-target 1.3.0 extra
expect 1 "Usage: boxmunge-upgrade force-target" "force-target refuses extra arguments"
drop_root

# --- run (auto-update timer) ---------------------------------------------

new_root a
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
# shellcheck disable=SC2016  # the $(id) must reach the shim unexpanded
run_shim run '1.5.0$(id)' https://example.com/x
expect 1 "Invalid version" "run requires semver"
blocklist 1.5.0
run_shim run 1.5.0 https://example.com/x
expect 0 "blocklisted, skipping" "run skips a blocklisted version"
run_shim run 1.3.0 https://example.com/x
expect 1 "Refusing to downgrade" "run refuses a downgrade"
drop_root

# --- auto and clear-blocklist --------------------------------------------

new_root a
run_shim auto extra
expect 1 "Usage: boxmunge-upgrade auto" "auto refuses arguments"
mock_server a 'echo "{\"action\": \"upgrade\", \"version\": \"1.0.0;id\", \"url\": \"x\"}"'
run_shim auto
expect 1 "Invalid version" "auto refuses a malformed discovered version"
run_shim clear-blocklist "1.0.0' or '1"
expect 1 "Invalid version" "clear-blocklist requires semver"
drop_root

# --- install.sh delegates to the shim ------------------------------------

grep -q 'bin/boxmunge-upgrade" install-sudoers' "$REPO_DIR/install.sh" \
    && pass "install.sh writes the sudo rule through install-sudoers" \
    || fail "install.sh does not call install-sudoers"
grep -q 'NOPASSWD' "$REPO_DIR/install.sh" && fail "install.sh carries its own sudo rule" \
    || pass "install.sh carries no sudo rule of its own"

finish
