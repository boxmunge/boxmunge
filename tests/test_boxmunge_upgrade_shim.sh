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

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
