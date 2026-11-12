#!/usr/bin/env bash
# tests/shim/lib.sh — shared helpers for the upgrade-shim shell tests.
#
# Source this from a test script. It provides PASS/FAIL counters, assertions,
# a throwaway BOXMUNGE_ROOT with a mock venv, and stand-ins for flock(1),
# sha256sum(1) and timeout(1) on hosts that lack them (macOS), so the locking,
# checksum and probation paths run everywhere. The stand-ins only exist when
# the real tool is missing; on Debian the real util-linux and coreutils
# binaries are used.

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

# A shim blocked on a planted FIFO never finishes, so this budget only has to
# outlast an honest run on a loaded runner, where one shim run can take tens
# of seconds (under pytest-xdist, 10 was not enough). A real hang still fails,
# after the budget, as RC=124.
SHIM_BLOCKED_SECS=120

# run_shim_unless_blocked <fifo> <args...>: run_shim, but a shim still running
# after SHIM_BLOCKED_SECS (blocked on the planted FIFO <fifo>) has the FIFO
# opened read-write, which unblocks a blocked reader or writer, and gets
# RC=124.
run_shim_unless_blocked() {
    local fifo="$1" secs="$SHIM_BLOCKED_SECS" out pid ticks=0
    shift
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
    # `flock -n <fd>` and `flock -w <secs> <fd>`, the forms the shim uses. A
    # flock(2) lock belongs to the open file description, which Python shares
    # with its caller, so the lock is held, and contended, exactly as with
    # util-linux flock.
    cat > "$FAKEBIN/flock" <<'EOF'
#!/usr/bin/env bash
wait=0
if [[ "$#" -eq 3 && "$1" == -w ]]; then wait="$2"; shift 2; elif [[ "$#" -eq 2 && "$1" == -n ]]; then shift; else
    echo "flock stand-in: only 'flock -n <fd>' or 'flock -w <secs> <fd>'" >&2; exit 64; fi
exec python3 -c 'import fcntl, sys, time
deadline = time.monotonic() + float(sys.argv[2])
while True:
    try:
        fcntl.flock(int(sys.argv[1]), fcntl.LOCK_EX | fcntl.LOCK_NB)
        break
    except BlockingIOError:
        if time.monotonic() >= deadline:
            sys.exit(1)
        time.sleep(0.1)' "$1" "$wait"
EOF
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    # Same output, and the same `-c` check of "<hash>  <file>" lines.
    printf '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n' > "$FAKEBIN/sha256sum"
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
# health-report <exit> [<error check>...]: what a mock boxmunge-server prints
# for `health --json` and exits with: a valid report whose checks mean <exit>
# (0 ok, 1 a warning, 2 an error in each named check, caddy by default).
cat > "$FAKEBIN/health-report" <<'EOF'
#!/usr/bin/env bash
rc="$1"; shift
checks='{"name": "docker", "status": "ok", "detail": ""}'
[[ "$rc" -lt 1 ]] || checks="$checks, {\"name\": \"alerts\", \"status\": \"warn\", \"detail\": \"no pushover\"}"
if [[ "$rc" -ge 2 ]]; then
    for name in "${@:-caddy}"; do checks="$checks, {\"name\": \"$name\", \"status\": \"error\", \"detail\": \"down\"}"; done
fi
echo "{\"healthy\": $([[ "$rc" -eq 0 ]] && echo true || echo false), \"exit_code\": $rc, \"checks\": [$checks]}"
exit "$rc"
EOF
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

# SYSTEMD_RUN_STUB: prepend to PATH for a systemd-run that runs the unit's
# command here, as systemd 257 does (checked on Debian 13), and the systemctl
# that reports how it ended. systemd-run records its argv in
# $BOXMUNGE_ROOT/calls. The command gets a clean environment: the --setenv
# variables (STUB_UNIT_PATH is put in front of PATH, for the test's own
# stand-ins), INVOCATION_ID, LANG and SYSTEMD_EXEC_PID, USER, and for a
# User= HOME (/home/<user>), LOGNAME and SHELL. It honours
# --working-directory, StandardOutput= and StandardError= (truncate:<file>,
# null, inherit), LimitFSIZE= and RuntimeMaxSec= (cut to STUB_MAX_SECS when
# that is lower): at the limit, SIGTERM to every process of the unit, then
# SIGKILL TimeoutStopSec later (default 90). It ends as `systemd-run --wait`
# does: the command's exit code, 255 for a signal, 1 for Result=timeout; a
# unit that failed stays loaded for `systemctl show` until `systemctl
# reset-failed`, as a transient unit does without --collect.
SYSTEMD_RUN_STUB="$(mktemp -d)"
cat > "$SYSTEMD_RUN_STUB/systemd-run" <<'EOF'
#!/usr/bin/env bash
echo "systemd-run $*" >> "$BOXMUNGE_ROOT/calls"
unit="" secs="" stop=90 dir="" user=root fsize="" out=inherit err=inherit envs=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --) shift; break ;;
        --unit=*) unit="${1#--unit=}" ;;
        --setenv=PATH=*) envs+=("PATH=${STUB_UNIT_PATH:+$STUB_UNIT_PATH:}${1#--setenv=PATH=}") ;;
        --setenv=*) envs+=("${1#--setenv=}") ;;
        --working-directory=*) dir="${1#--working-directory=}" ;;
        -p) shift
            case "$1" in
                RuntimeMaxSec=*) secs="${1#*=}" ;;
                TimeoutStopSec=*) stop="${1#*=}" ;;
                User=*) user="${1#*=}" ;;
                LimitFSIZE=*) fsize="${1#*=}" ;;
                StandardOutput=*) out="${1#*=}" ;;
                StandardError=*) err="${1#*=}" ;;
            esac ;;
        --quiet|--wait) ;;
        *) echo "systemd-run stand-in: unexpected argument $1" >&2; exit 64 ;;
    esac
    shift
done
[[ -n "$unit" && -n "$secs" && -n "$dir" && $# -gt 0 ]] || { echo "systemd-run stand-in: no unit, limit, directory or command" >&2; exit 64; }
mkdir -p "$BOXMUNGE_ROOT/units"
[[ ! -e "$BOXMUNGE_ROOT/units/$unit" ]] || { echo "Failed to start transient service unit: Unit $unit.service was already loaded" >&2; exit 1; }
[[ -z "${STUB_MAX_SECS:-}" || "$secs" -le "$STUB_MAX_SECS" ]] || secs="$STUB_MAX_SECS"
envs+=("INVOCATION_ID=stand-in" "LANG=C.UTF-8" "SYSTEMD_EXEC_PID=$$" "USER=$user")
[[ "$user" == root ]] || envs+=("HOME=/home/$user" "LOGNAME=$user" "SHELL=/bin/sh")
cd "$dir"
rc=0
python3 -c 'import os, resource, signal, subprocess, sys
secs, stop, fsize, out, err = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
def stream(spec, inherit):
    if spec.startswith("truncate:"):
        return open(spec[len("truncate:"):], "wb")
    return subprocess.DEVNULL if spec == "null" else inherit
stdout = stream(out, None)
stderr = stream(err, subprocess.STDOUT if stdout is not None else None)
def limits():
    if fsize:
        resource.setrlimit(resource.RLIMIT_FSIZE, (int(fsize), int(fsize)))
p = subprocess.Popen(sys.argv[6:], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                     start_new_session=True, preexec_fn=limits)
try:
    rc = p.wait(timeout=secs)
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGTERM)
    try:
        p.wait(timeout=stop)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
    sys.exit(200)
sys.exit(201 if rc < 0 else rc)' "$secs" "$stop" "$fsize" "$out" "$err" env -i "${envs[@]}" "$@" || rc=$?
case "$rc" in
    0) exit 0 ;;
    200) echo timeout > "$BOXMUNGE_ROOT/units/$unit"; exit 1 ;;
    201) echo signal > "$BOXMUNGE_ROOT/units/$unit"; exit 255 ;;
    *) echo exit-code > "$BOXMUNGE_ROOT/units/$unit"; exit "$rc" ;;
esac
EOF
cat > "$SYSTEMD_RUN_STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$BOXMUNGE_ROOT/calls"
state="$BOXMUNGE_ROOT/units/${*: -1}"
state="${state%.service}"
case "$1" in
    show) if [[ -f "$state" ]]; then printf 'LoadState=loaded\nResult=%s\n' "$(cat "$state")"; else printf 'LoadState=not-found\nResult=success\n'; fi ;;
    reset-failed) [[ -f "$state" ]] || { echo "Unit ${*: -1} not loaded." >&2; exit 1; }; rm -f "$state" ;;
    *) echo "systemctl stand-in: unexpected $*" >&2; exit 64 ;;
esac
EOF
chmod +x "$SYSTEMD_RUN_STUB"/*

# with_shim_functions <cmd...>: run <cmd> in a subshell that has every
# constant and function of the shim under test (built first, when it is the
# source shim) and has run none of its commands.
SHIM_FUNCTIONS=""
with_shim_functions() {
    if [[ -z "$SHIM_FUNCTIONS" ]]; then
        local built="$SHIM"
        SHIM_FUNCTIONS="$(mktemp)"
        if grep -q '^# >>> boxmunge-upgrade.d:' "$SHIM"; then
            built="$SHIM_FUNCTIONS.built"
            python3 "$REPO_DIR/scripts/build-shim.py" "$SHIM" "$built"
        fi
        awk 'index($0, "case \"${1:-}\" in") == 1 { exit } { print }' "$built" > "$SHIM_FUNCTIONS"
    fi
    # shellcheck source=/dev/null
    ( source "$SHIM_FUNCTIONS"; "$@" )
}

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
        mock_python "$s"
    done
    echo "$slot" > "$BOXMUNGE_ROOT/upgrade-state/active-slot"
    ln -s "$BOXMUNGE_ROOT/env-$slot" "$BOXMUNGE_ROOT/env-active"
    # The stash a rollback restores when no upgrade recorded one.
    mkdir -m 0770 "$BOXMUNGE_ROOT/stashes"
    : > "$BOXMUNGE_ROOT/stashes/$OLD_STASH"
    chmod 0600 "$BOXMUNGE_ROOT/stashes/$OLD_STASH"
}

# OLD_STASH: the stash new_root leaves in stashes/.
OLD_STASH="boxmunge-stash-2026-01-01T000000.tar.gz"

# STASH_CREATE: what `stash create` does in a mock boxmunge-server whose body
# does not handle it itself: make an (empty) stash and name it, as the real one
# does, since the shim records the stash an upgrade made.
# shellcheck disable=SC2016  # a mock body: literal bash
STASH_CREATE='if [[ "$1 ${2:-}" == "stash create" ]]; then
    n="boxmunge-stash-$(date -u +%Y-%m-%dT%H%M%S).tar.gz"
    mkdir -p "$BOXMUNGE_ROOT/stashes"; : > "$BOXMUNGE_ROOT/stashes/$n"; echo "Stash created: $n"; exit 0
fi'

# HEALTHY: what `health --json` does in a mock boxmunge-server whose body does
# not handle health itself: a valid report of a healthy box.
# shellcheck disable=SC2016  # a mock body: literal bash
HEALTHY='if [[ "$1" == health ]]; then exec health-report 0; fi'

# mock_python <slot>: env-<slot>/bin/python is the system python3, except
# that the rollback's stash restore (restore_stash_copy, which names the
# archive in BM_STASH) is recorded in $BOXMUNGE_ROOT/calls as
# "<slot> stash restore <archive name>" and only says it restored it.
REAL_PYTHON3_FOR_VENV="$(command -v python3)"
mock_python() {
    # shellcheck disable=SC2016  # the script's own lines: literal bash
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ -n "${BM_STASH:-}" ]]; then' \
        "    echo \"$1 stash restore \${BM_STASH##*/}\" >> \"\$BOXMUNGE_ROOT/calls\"" \
        '    echo "Restored from: ${BM_STASH##*/}"; exit 0' \
        'fi' \
        "exec $(printf %q "$REAL_PYTHON3_FOR_VENV") \"\$@\"" > "$BOXMUNGE_ROOT/env-$1/bin/python"
    chmod +x "$BOXMUNGE_ROOT/env-$1/bin/python"
}

# mock_server <slot> <bash body>: install env-<slot>/bin/boxmunge-server.
mock_server() {
    local body="$2"
    [[ "$body" == *"stash create"* ]] || body="$STASH_CREATE
$body"
    [[ "$body" == *health* ]] || body="$HEALTHY
$body"
    printf '#!/usr/bin/env bash\n%s\n' "$body" > "$BOXMUNGE_ROOT/env-$1/bin/boxmunge-server"
    chmod +x "$BOXMUNGE_ROOT/env-$1/bin/boxmunge-server"
}

# SOON: an expiry inside a fresh probation's length. The shim treats one
# further out than that as forged, i.e. already expired.
# shellcheck disable=SC2034  # used by the sourcing tests
SOON="$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())')"

# write_probation <version> <previous_slot> <expires_at>: a probation an
# upgrade started: probation.json, and root's record of it (record_probation).
write_probation() {
    forge_probation "$@"
    record_probation "$1"
}

# forge_probation <version> <previous_slot> <expires_at>: probation.json
# alone, as deploy can write it.
forge_probation() {
    printf '{"version": "%s", "previous_slot": "%s", "started_at": "2026-01-01T00:00:00+00:00", "expires_at": "%s"}\n' \
        "$1" "$2" "$3" > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
}

# record_probation <version> [<expiry epoch>]: root's record of a probation of
# <version> in the live slot, ending a fresh probation's 6 hours from now.
record_probation() {
    local slot
    slot="$(readlink "$BOXMUNGE_ROOT/env-active")"
    [[ -d "$BOXMUNGE_ROOT/upgrade-root" ]] || mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
    echo "${slot##*/env-} $1 ${2:-$(( $(date +%s) + 6 * 3600 ))}" > "$BOXMUNGE_ROOT/upgrade-root/probation-expiry"
}

# age_swap <hours>: make env-active look swapped <hours> ago.
age_swap() {
    python3 -c 'import os, sys, time; t = time.time() - float(sys.argv[2]) * 3600; os.utime(sys.argv[1], (t, t), follow_symlinks=False)' \
        "$BOXMUNGE_ROOT/env-active" "$1"
}

drop_root() { rm -rf "$BOXMUNGE_ROOT"; unset BOXMUNGE_ROOT; }

finish() {
    rm -rf "$FAKEBIN" "$FAILVISUDO" "$BUSYLOCK" "$SYSTEMD_RUN_STUB"
    [[ -z "$SHIM_FUNCTIONS" ]] || rm -f "$SHIM_FUNCTIONS" "$SHIM_FUNCTIONS.built"
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    [[ "$FAIL" -eq 0 ]]
}
