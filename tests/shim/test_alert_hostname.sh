#!/usr/bin/env bash
# tests/shim/test_alert_hostname.sh — every alert the shim sends names its box.
#
# boxmunge.notify starts every alert's title with [<hostname>], so an operator
# with several boxes knows which one is talking. The shim sends its own alerts
# (upgrade applied, failed, rolled back, blocklisted, probation) through
# notify_via, past boxmunge.notify, and sent them with no hostname. This runs
# the real notify_via against a real config, with the Pushover POST caught.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: the python body is literal
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/config"
printf 'hostname: box-one.example\nadmin_email: ops@example.com\npushover:\n  user_key: u\n  app_token: t\n' \
    > "$ROOT/config/boxmunge.yml"

# A venv python that points BoxPaths() at the throwaway root (it defaults to
# /opt/boxmunge) and catches the Pushover POST instead of making it: it takes
# the shim's `-c <code>` and runs the code with those two replaced.
PYBIN="$ROOT/python"
cat > "$PYBIN" <<EOF2
#!/usr/bin/env bash
[[ "\$1" == -c ]] || exit 64
exec env PYTHONPATH="$REPO_DIR/src" python3 -c '
import json, os, sys
from pathlib import Path
import boxmunge.pushover as p
from boxmunge.paths import BoxPaths
BoxPaths.__init__.__defaults__ = (Path(os.environ["BOXMUNGE_ROOT"]),)
def post(data):
    print(json.dumps({"title": data["title"], "message": data["message"]}))
    return True
p._post_pushover = post
exec(sys.argv[1])' "\$2"
EOF2
chmod +x "$PYBIN"

# notify_via, lifted from the shim as written (it needs nothing else of it).
eval "$(sed -n '/^notify_via() {$/,/^}$/p' "$REPO_DIR/scripts/boxmunge-upgrade.d/slots.sh")"
export BOXMUNGE_ROOT="$ROOT"

# The snippet sends its stderr to /dev/null, so a failure shows as the rc.
rc=0
sent="$(notify_via "$PYBIN" "boxmunge upgrade applied" "Updated to 9.9.9" 1)" || rc=$?
[[ "$rc" -eq 0 && "$sent" == *'"title": "[box-one.example] boxmunge upgrade applied"'* ]] \
    && pass "an alert's title starts with the box's hostname" \
    || fail "alert not named for its box (rc=$rc): $sent"
[[ "$sent" == *'"message": "Updated to 9.9.9"'* ]] \
    && pass "the message is sent as given" || fail "message changed: $sent"

# No Pushover configured: nothing is sent, and that is exit 3, as before.
printf 'hostname: box-one.example\nadmin_email: ops@example.com\n' > "$ROOT/config/boxmunge.yml"
rc=0
sent="$(notify_via "$PYBIN" "boxmunge upgrade applied" "m")" || rc=$?
[[ "$rc" -eq 3 && -z "$sent" ]] \
    && pass "with no Pushover configured nothing is sent (exit 3)" || fail "rc=$rc sent=$sent"

finish
