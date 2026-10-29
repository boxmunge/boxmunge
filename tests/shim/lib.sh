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

# The shim's report_failure runs a real python that would POST to the
# production version-check service; point it at a closed local port instead.
export BOXMUNGE_VERSION_CHECK_URL="http://127.0.0.1:9"

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

# run_shim_within <secs> <fifo> <args...>: run_shim, but a shim still running
# after <secs> (blocked on the planted FIFO <fifo>) has the FIFO opened
# read-write, which unblocks a blocked reader or writer, and gets RC=124.
run_shim_within() {
    local secs="$1" fifo="$2" out pid ticks=0
    shift 2
    out="$(mktemp)"
    bash "$SHIM" "$@" >"$out" 2>&1 &
    pid=$!
    while kill -0 "$pid" 2>/dev/null && [[ "$ticks" -lt $((secs * 10)) ]]; do
        sleep 0.1
        ticks=$((ticks + 1))
    done
    RC=0
    if kill -0 "$pid" 2>/dev/null; then
        exec 8<>"$fifo"
        sleep 0.5
        exec 8>&-
        kill -9 "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        RC=124
    else
        wait "$pid" || RC=$?
    fi
    OUT="$(cat "$out")"
    rm -f "$out"
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
    # `flock -n <fd>`, the one form the shim uses. A flock(2) lock belongs to
    # the open file description, which Python shares with its caller, so the
    # lock is held, and contended, exactly as with util-linux flock.
    cat > "$FAKEBIN/flock" <<'EOF'
#!/usr/bin/env bash
[[ "$#" -eq 2 && "$1" == -n ]] || { echo "flock stand-in: only 'flock -n <fd>'" >&2; exit 64; }
exec python3 -c 'import fcntl, sys
try:
    fcntl.flock(int(sys.argv[1]), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(1)' "$2"
EOF
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
REAL_VISUDO=""
if command -v visudo >/dev/null 2>&1; then
    REAL_VISUDO="$(command -v visudo)"
elif [[ -x /usr/sbin/visudo ]]; then
    REAL_VISUDO=/usr/sbin/visudo
    ln -s "$REAL_VISUDO" "$FAKEBIN/visudo"
else
    printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKEBIN/visudo"
fi
chmod +x "$FAKEBIN"/* 2>/dev/null || true
export PATH="$FAKEBIN:$PATH"

# FAILVISUDO: prepend to PATH to make visudo reject everything. The upgrade
# path writes the sudo rule right after its policy checks, so "failed visudo"
# in the output proves a request got past policy without running the
# download, venv build and pip install that follow.
FAILVISUDO="$(mktemp -d)"
printf '#!/usr/bin/env bash\nexit 1\n' > "$FAILVISUDO/visudo"
chmod +x "$FAILVISUDO/visudo"

# BUSYLOCK: prepend to PATH to make every flock report the lock as held.
BUSYLOCK="$(mktemp -d)"
printf '#!/usr/bin/env bash\nexit 1\n' > "$BUSYLOCK/flock"
chmod +x "$BUSYLOCK/flock"

# new_root [slot]: fresh BOXMUNGE_ROOT whose active slot is <slot> (default a),
# with a mock boxmunge-server and python in both slots and a consistent
# active-slot file and env-active symlink.
new_root() {
    local slot="${1:-a}"
    BOXMUNGE_ROOT="$(mktemp -d)"
    export BOXMUNGE_ROOT
    mkdir -p "$BOXMUNGE_ROOT/upgrade-state" "$BOXMUNGE_ROOT/bin" "$BOXMUNGE_ROOT/state" \
        "$BOXMUNGE_ROOT/config" "$BOXMUNGE_ROOT/sudoers.d"
    echo "0.5.0+abc1234" > "$BOXMUNGE_ROOT/config/version"
    export BOXMUNGE_SUDOERS_FILE="$BOXMUNGE_ROOT/sudoers.d/boxmunge-deploy"
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

# SOON: an expiry inside a fresh probation's length. The shim treats one
# further out than that as forged, i.e. already expired.
# shellcheck disable=SC2034  # used by the sourcing tests
SOON="$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())')"

# write_probation <version> <previous_slot> <expires_at>
write_probation() {
    printf '{"version": "%s", "previous_slot": "%s", "started_at": "2026-01-01T00:00:00+00:00", "expires_at": "%s"}\n' \
        "$1" "$2" "$3" > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
}

drop_root() { rm -rf "$BOXMUNGE_ROOT"; unset BOXMUNGE_ROOT; }

finish() {
    rm -rf "$FAKEBIN" "$FAILVISUDO" "$BUSYLOCK"
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    [[ "$FAIL" -eq 0 ]]
}
