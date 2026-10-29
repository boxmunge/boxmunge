#!/usr/bin/env bash
# tests/shim/test_failure_report.sh — the failure report carries the bare
# from-version and the reason, and can never reach the production service.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: mock bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

UPGRADEBIN="$(mktemp -d)"
printf '#!/usr/bin/env bash\nexit 22\n' > "$UPGRADEBIN/curl"
chmod +x "$UPGRADEBIN"/*
export PATH="$UPGRADEBIN:$PATH"

[[ "$BOXMUNGE_VERSION_CHECK_URL" == http://127.0.0.1:* ]] \
    && pass "tests point the service at a local address" \
    || fail "BOXMUNGE_VERSION_CHECK_URL is '$BOXMUNGE_VERSION_CHECK_URL'; the tests could reach production"

# Active venv's python records what the shim hands report_failure.
new_root a
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
mock_server a 'echo "boxmunge 1.4.0+abc1234"'
rm "$BOXMUNGE_ROOT/env-a/bin/python"
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "$1" == "-c" ]]; then echo "report|$BM_VERSION|$BM_FROM_VERSION|$BM_STAGE|$BM_DETAIL" >> "$BOXMUNGE_ROOT/calls"; fi' \
    'exit 0' > "$BOXMUNGE_ROOT/env-a/bin/python"
chmod +x "$BOXMUNGE_ROOT/env-a/bin/python"

run_shim target 1.5.0
expect 1 "Failed to download bundle" "a failed download aborts the upgrade"
[[ "$(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)" == *"report|1.5.0|1.4.0|preflight|preflight_failed: bundle_download"* ]] \
    && pass "report carries the bare from-version and the reason" \
    || fail "report args: $(cat "$BOXMUNGE_ROOT/calls" 2>/dev/null)"
drop_root

# A report that cannot be sent warns on stderr but never changes the outcome.
new_root a
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
mock_server a 'echo "boxmunge 1.4.0"'
rm "$BOXMUNGE_ROOT/env-a/bin/python"
printf '#!/usr/bin/env bash\n[[ -z "${BM_DETAIL+x}" ]] || exit 1\nexit 0\n' > "$BOXMUNGE_ROOT/env-a/bin/python"
chmod +x "$BOXMUNGE_ROOT/env-a/bin/python"
run_shim target 1.5.0
expect 1 "the upgrade failure report could not be sent" "an unsendable report is announced, and the upgrade still fails cleanly"
drop_root

rm -rf "$UPGRADEBIN"
finish
