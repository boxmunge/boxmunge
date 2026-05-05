#!/usr/bin/env bash
# tests/test_boxmunge_upgrade_shim.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHIM="$SCRIPT_DIR/../scripts/boxmunge-upgrade"

PASS=0
FAIL=0

assert_exit() {
    local expected="$1" desc="$2"
    shift 2
    local actual=0
    "$@" >/dev/null 2>&1 || actual=$?
    if [[ "$actual" -eq "$expected" ]]; then
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected exit=$expected, got exit=$actual)"
        FAIL=$((FAIL + 1))
    fi
}

assert_exit 1 "no arguments shows usage" bash "$SHIM"
assert_exit 1 "unknown subcommand fails" bash "$SHIM" unknown
assert_exit 1 "run without version fails" bash "$SHIM" run
assert_exit 1 "clear-blocklist without version fails" bash "$SHIM" clear-blocklist

# `auto` subcommand is dispatched (not rejected by the case statement).
# It will fail later at discovery without a real venv, but the failure mode
# must not be the "Usage:" line from the case-statement default.
auto_stderr="$(bash "$SHIM" auto 2>&1 >/dev/null || true)"
if echo "$auto_stderr" | grep -q "Usage: boxmunge-upgrade {run|auto"; then
    echo "FAIL: auto subcommand was rejected by case statement"
    FAIL=$((FAIL + 1))
else
    echo "PASS: auto subcommand is dispatched"
    PASS=$((PASS + 1))
fi

BOXMUNGE_ROOT="$(mktemp -d)"
export BOXMUNGE_ROOT
mkdir -p "$BOXMUNGE_ROOT/upgrade-state"
assert_exit 0 "check-probation exits 0 with no probation file" bash "$SHIM" check-probation
rm -rf "$BOXMUNGE_ROOT"

# Orphan venv cleanup: no probation file + standby venv exists => venv removed
# Skip this test when flock(1) is not available (macOS without util-linux).
if command -v flock >/dev/null 2>&1; then
    BOXMUNGE_ROOT="$(mktemp -d)"
    export BOXMUNGE_ROOT
    mkdir -p "$BOXMUNGE_ROOT/upgrade-state"
    # Active slot is "a" (default), so standby is "b"
    echo "a" > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
    mkdir -p "$BOXMUNGE_ROOT/env-b/bin"  # simulate orphan standby venv
    assert_exit 0 "check-probation cleans up orphan standby venv" bash "$SHIM" check-probation
    if [[ -d "$BOXMUNGE_ROOT/env-b" ]]; then
        echo "FAIL: orphan env-b should have been removed"
        FAIL=$((FAIL + 1))
    else
        echo "PASS: orphan env-b was cleaned up"
        PASS=$((PASS + 1))
    fi
    rm -rf "$BOXMUNGE_ROOT"
else
    echo "SKIP: orphan venv cleanup test (flock not available on this platform)"
fi

# ---------------------------------------------------------------------------
# cmd_auto dispatch tests — mock boxmunge-server _discover-update
# ---------------------------------------------------------------------------

test_dir="$(mktemp -d)"
export BOXMUNGE_ROOT="$test_dir"
mkdir -p "$BOXMUNGE_ROOT/upgrade-state" "$BOXMUNGE_ROOT/env-a/bin"

# Helper: install a mock boxmunge-server that returns canned JSON for
# _discover-update and short-circuits cmd_run by exiting 0.
mock_boxmunge_server() {
    local response="$1"
    cat > "$BOXMUNGE_ROOT/env-a/bin/boxmunge-server" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "_discover-update" ]]; then
    cat <<JSON
$response
JSON
    exit 0
fi
# Any other invocation: succeed silently (covers --version probes etc.)
exit 0
EOF
    chmod +x "$BOXMUNGE_ROOT/env-a/bin/boxmunge-server"
}

# Case 1: up_to_date — shim should log + exit 0
mock_boxmunge_server '{"action":"up_to_date","current_version":"0.4.0"}'
set +e
out="$(bash "$SHIM" auto 2>&1)"
rc=$?
set -e
if [[ $rc -eq 0 && "$out" == *"Already on latest version"* ]]; then
    echo "PASS: cmd_auto/up_to_date logs and exits 0"
    PASS=$((PASS + 1))
else
    echo "FAIL: cmd_auto/up_to_date (rc=$rc, out='$out')"
    FAIL=$((FAIL + 1))
fi

# Case 2: error — shim should die with the error message
mock_boxmunge_server '{"action":"error","message":"endpoint down"}'
set +e
out="$(bash "$SHIM" auto 2>&1)"
rc=$?
set -e
if [[ $rc -ne 0 && "$out" == *"endpoint down"* ]]; then
    echo "PASS: cmd_auto/error dies with discovery message"
    PASS=$((PASS + 1))
else
    echo "FAIL: cmd_auto/error (rc=$rc, out='$out')"
    FAIL=$((FAIL + 1))
fi

# Case 3: blocklisted — shim should log + exit 0
mock_boxmunge_server '{"action":"blocklisted","version":"0.4.1"}'
set +e
out="$(bash "$SHIM" auto 2>&1)"
rc=$?
set -e
if [[ $rc -eq 0 && "$out" == *"blocklisted"* ]]; then
    echo "PASS: cmd_auto/blocklisted logs and exits 0"
    PASS=$((PASS + 1))
else
    echo "FAIL: cmd_auto/blocklisted (rc=$rc, out='$out')"
    FAIL=$((FAIL + 1))
fi

rm -rf "$test_dir"
unset BOXMUNGE_ROOT

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
