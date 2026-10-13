#!/usr/bin/env bash
# tests/shim/lib.sh — shared helpers for the upgrade-shim shell tests.
#
# Source this from a test script. It provides PASS/FAIL counters, assertions,
# a throwaway BOXMUNGE_ROOT with a mock venv, and stand-ins for flock(1) and
# timeout(1) on hosts that lack them (macOS), so the locking and probation
# paths run everywhere. The stand-ins only exist when the real tool is
# missing; on Debian the real util-linux and coreutils binaries are used.

SHIM_TEST_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SHIM_TEST_LIB_DIR/../.." && pwd)"
SHIM="${SHIM_UNDER_TEST:-$REPO_DIR/scripts/boxmunge-upgrade}"

PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# run_shim <args...>: run the shim, capturing combined output in OUT and the
# exit code in RC.
run_shim() {
    RC=0
    OUT="$(bash "$SHIM" "$@" 2>&1)" || RC=$?
}

# expect <rc> <substring> <description>: check the last run_shim.
expect() {
    if [[ "$RC" -eq "$1" && "$OUT" == *"$2"* ]]; then
        pass "$3"
    else
        fail "$3 (rc=$RC, want $1 and '$2'; out: $OUT)"
    fi
}

FAKEBIN="$(mktemp -d)"
if ! command -v flock >/dev/null 2>&1; then
    printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKEBIN/flock"
fi
if ! command -v timeout >/dev/null 2>&1; then
    # timeout [--kill-after=N] <secs> cmd...
    cat > "$FAKEBIN/timeout" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == --kill-after=* ]] && shift
shift
exec "$@"
EOF
fi
chmod +x "$FAKEBIN"/* 2>/dev/null || true
export PATH="$FAKEBIN:$PATH"

# new_root [slot]: fresh BOXMUNGE_ROOT whose active slot is <slot> (default a),
# with a mock boxmunge-server and python in both slots and a consistent
# active-slot file and env-active symlink.
new_root() {
    local slot="${1:-a}"
    BOXMUNGE_ROOT="$(mktemp -d)"
    export BOXMUNGE_ROOT
    mkdir -p "$BOXMUNGE_ROOT/upgrade-state" "$BOXMUNGE_ROOT/bin" "$BOXMUNGE_ROOT/state"
    for s in a b; do
        mkdir -p "$BOXMUNGE_ROOT/env-$s/bin"
        mock_server "$s" 'exit 0'
        ln -s "$(command -v python3)" "$BOXMUNGE_ROOT/env-$s/bin/python"
    done
    echo "$slot" > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
    ln -s "$BOXMUNGE_ROOT/env-$slot" "$BOXMUNGE_ROOT/env-active"
}

# mock_server <slot> <bash body>: install env-<slot>/bin/boxmunge-server.
mock_server() {
    printf '#!/usr/bin/env bash\n%s\n' "$2" > "$BOXMUNGE_ROOT/env-$1/bin/boxmunge-server"
    chmod +x "$BOXMUNGE_ROOT/env-$1/bin/boxmunge-server"
}

# write_probation <version> <previous_slot> <expires_at>
write_probation() {
    printf '{"version": "%s", "previous_slot": "%s", "started_at": "2026-01-01T00:00:00+00:00", "expires_at": "%s"}\n' \
        "$1" "$2" "$3" > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
}

drop_root() { rm -rf "$BOXMUNGE_ROOT"; unset BOXMUNGE_ROOT; }

finish() {
    rm -rf "$FAKEBIN"
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    [[ "$FAIL" -eq 0 ]]
}
