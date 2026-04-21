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

BOXMUNGE_ROOT="$(mktemp -d)"
export BOXMUNGE_ROOT
mkdir -p "$BOXMUNGE_ROOT/upgrade-state"
assert_exit 0 "check-probation exits 0 with no probation file" bash "$SHIM" check-probation
rm -rf "$BOXMUNGE_ROOT"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
