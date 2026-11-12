#!/usr/bin/env bash
# tests/shim/test_check_confinement.sh — how the readiness check runs a
# release's code: confined_run (systemd-run with a fixed property list, a
# time limit told apart from the command's own exit by systemd's Result),
# and readiness_verdict and readiness_summary, which read what the
# release's readiness command answered.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016,SC2119  # SC2016: mock bodies are literal bash; SC2119: release takes no args
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=tests/shim/check_fixture.sh
source "$(dirname "$0")/check_fixture.sh"

# --- the exact confinement of each run in a check -----------------------------------

release
box
run_check 1.5.0
expect_check 0 pass complete "" "a passing check, to read its confined runs"
units="$(python3 - "$BOXMUNGE_ROOT" "$BOXMUNGE_ROOT/calls" <<'PY'
import re, sys
root = sys.argv[1]
common = {"ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes", "NoNewPrivileges=yes",
          "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes",
          "TimeoutStopSec=5"}
out = f"{root}/upgrade-check/out"
capped = "LimitFSIZE=2097152"
want = {
    "prereq-ok": {"RuntimeMaxSec=60", capped, "StandardOutput=null", f"StandardError=truncate:{out}/prerequisites.jsonl.err"},
    "prereq-floor": {"RuntimeMaxSec=60", capped, "StandardOutput=null", f"StandardError=truncate:{out}/prerequisites.jsonl.err"},
    "venv": {"RuntimeMaxSec=900", f"ReadWritePaths={root}/upgrade-check", f"StandardOutput=truncate:{out}/venv.txt",
             "StandardError=inherit"},
    "readiness": {"RuntimeMaxSec=300", "User=deploy", capped, f"StandardOutput=truncate:{out}/readiness.json",
                  f"StandardError=truncate:{out}/readiness.json.err"},
    "dryrun": {"RuntimeMaxSec=300", "User=deploy", capped, f"StandardOutput=truncate:{out}/dry_run.out",
               "StandardError=inherit"},
}
env = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"BOXMUNGE_ROOT={root}", "PYTHONSAFEPATH=1", "PYTHONDONTWRITEBYTECODE=1"}
seen = []
for line in open(sys.argv[2]):
    if not line.startswith("systemd-run "):
        continue
    words = line.split()[1:]
    cut = words.index("--")
    opts, props, unit = words[:cut], set(), None
    i = 0
    while i < len(opts):
        if opts[i] == "-p":
            props.add(opts[i + 1]); i += 2; continue
        m = re.fullmatch(r"--unit=boxmunge-check-([a-z0-9-]+)-[0-9]+", opts[i])
        if m:
            unit = m.group(1)
        i += 1
    flags = {o for o in opts if o.startswith("--") and not o.startswith(("--unit=", "--setenv="))}
    envs = {o[len("--setenv="):] for o in opts if o.startswith("--setenv=")}
    problems = []
    if props != common | want.get(unit, {"?"}):
        problems.append(f"properties {sorted(props ^ (common | want.get(unit, set())))}")
    if envs != env:
        problems.append(f"environment {sorted(envs ^ env)}")
    if flags != {"--quiet", "--wait", "--working-directory=/"}:
        problems.append(f"flags {sorted(flags)}")
    seen.append(f"{unit}: {'; '.join(problems) or 'ok'}")
print("\n".join(seen))
PY
)"
[[ "$units" == "prereq-ok: ok
prereq-floor: ok
venv: ok
readiness: ok
dryrun: ok" ]] && pass "confined_run passes exactly the K6 property list (User=deploy only for readiness/dry run), output to files" \
    || fail "confined runs: $units"
drop_root

# --- confined_run itself -----------------------------------------------------------

box
confined() {  # confined <secs> <cmd...>: confined_run's return code; the output in $BOXMUNGE_ROOT/unit.out
    local rc=0 secs="$1"
    shift
    confined_run t "$secs" root - "$BOXMUNGE_ROOT/unit.out" + -- "$@" || rc=$?
    echo "rc=$rc"
}
unit_out() { cat "$BOXMUNGE_ROOT/unit.out"; }
out="$(STUB_MAX_SECS=1 with_shim_functions confined 300 sleep 30 2>&1)"
[[ "$out" == *"rc=124" ]] && pass "confined_run returns 124 on RuntimeMaxSec" || fail "timeout: $out"
[[ -z "$(ls "$BOXMUNGE_ROOT/units")" ]] && pass "the timed-out unit is reset" || fail "units left: $(ls "$BOXMUNGE_ROOT/units")"
out="$(with_shim_functions confined 300 bash -c 'echo "Finished with result: timeout" >&2; exit 1' 2>&1)"
[[ "$out" == *"rc=1" ]] && pass "a command that prints systemd's timeout words is not a timeout" || fail "faked words: $out"
out="$(with_shim_functions confined 300 bash -c 'exit 124' 2>&1)"
[[ "$out" == *"rc=1" ]] && pass "a command's own exit 124 is not a timeout (reported as 1)" || fail "own 124: $out"
out="$(with_shim_functions confined 300 bash -c 'exit 7' 2>&1)"
[[ "$out" == *"rc=7" && -z "$(ls "$BOXMUNGE_ROOT/units")" ]] && pass "a failed command's exit code, and its unit reset" \
    || fail "exit 7: $out $(ls "$BOXMUNGE_ROOT/units")"
# The unit's environment: the variables set, and systemd's own; nothing of the
# shim's (LEAKED), and as root, no HOME (as systemd 257 runs a root unit).
out="$(LEAKED=x with_shim_functions confined 300 bash -c 'env' 2>&1)"
names="$(unit_out | sed 's/=.*//' | grep -v -e '^_$' -e '^SHLVL$' | sort | tr '\n' ' ')"
[[ "$out" == *"rc=0" && "$names" == "BOXMUNGE_ROOT INVOCATION_ID LANG PATH PWD PYTHONDONTWRITEBYTECODE PYTHONSAFEPATH SYSTEMD_EXEC_PID USER " ]] \
    && unit_out | grep -qx "PWD=/" && unit_out | grep -qx "USER=root" \
    && pass "a root unit gets only the set environment and systemd's own, in /" || fail "environment: $names $(unit_out)"
deploy_env() { confined_run t 300 deploy - "$BOXMUNGE_ROOT/unit.out" - -- bash -c 'echo "$USER $HOME $LOGNAME $SHELL"'; }
with_shim_functions deploy_env >/dev/null 2>&1
[[ "$(unit_out)" == "deploy /home/deploy deploy /bin/sh" ]] && pass "a User=deploy unit gets deploy's login environment" \
    || fail "deploy environment: $(unit_out)"
# Output goes to files systemd opens: nothing here waits on a reader, and a
# unit with nothing writable writes no file over CONFINED_FILE_MAX.
out="$(with_shim_functions confined 300 bash -c 'head -c 3000000 /dev/zero; echo done >&2' 2>&1)"
[[ "$(wc -c < "$BOXMUNGE_ROOT/unit.out" | tr -d ' ')" -le 2097152 && "$out" != *"rc=0" ]] \
    && pass "a unit with nothing writable writes at most 2 MiB of output, and fails past it" || fail "size cap: $out"
out="$(STUB_MAX_SECS=1 with_shim_functions confined 300 bash -c 'trap "" TERM; sleep 30 & wait; sleep 30' 2>&1)"
[[ "$out" == *"rc=124" ]] && pass "a unit that ignores SIGTERM is killed STOP_SECS after its limit, as a timeout" \
    || fail "TERM ignored: $out"
# A failed unit of the same name, left by a killed run (same pid), is reset first.
echo exit-code > "$BOXMUNGE_ROOT/units/boxmunge-check-t-$$"
out="$(with_shim_functions confined 300 true 2>&1)"
[[ "$out" == *"rc=0" ]] && pass "a failed unit left under the same name does not stop the run" || fail "stale unit: $out"
# systemd-run fails before systemd has the unit: whether it timed out is unknown.
NOUNIT="$(mktemp -d)"
printf '#!/usr/bin/env bash\necho "Failed to start transient service unit: Access denied" >&2\nexit 1\n' > "$NOUNIT/systemd-run"
chmod +x "$NOUNIT/systemd-run"
out="$(PATH="$NOUNIT:$PATH" with_shim_functions confined 300 true 2>&1)"
[[ "$out" == *"rc=125" && "$out" == *"systemd does not know the unit"* ]] \
    && pass "confined_run returns 125 when systemd cannot say how the unit ended" || fail "unknown unit: $out"
rm -rf "$NOUNIT"
missing() { PATH=/nonexistent confined_run t 5 root - - - -- true; }
out="$(with_shim_functions missing 2>&1)" && fail "ran without systemd-run: $out" \
    || { [[ "$out" == *"systemd-run is missing"*"apt-get install systemd"* ]] \
        && pass "confined_run dies naming systemd-run when it is missing" || fail "missing: $out"; }
for bad in "x/y 5 root - - - --" "x 0 root - - - --" "x 5 root relative - - --" "x 5 root - - - true" \
           "x 5 'root;id' - - - --" "x 5 root - relative - --" "x 5 root - - relative --" "x 5 root - --"; do
    eval "set -- $bad"
    out="$(with_shim_functions confined_run "$@" true 2>&1)" && fail "confined_run accepted: $bad" \
        || { [[ "$out" == *"Usage: confined_run"* ]] && pass "confined_run refuses: $bad" || fail "bad args $bad: $out"; }
done
set --
drop_root

# --- readiness_verdict and readiness_summary ---------------------------------------

box
verdict() {  # verdict <answer> [<exit code>]
    printf '%s' "$1" > "$BOXMUNGE_ROOT/answer.json"
    readiness_verdict "$BOXMUNGE_ROOT/answer.json" "${@:2}"
}
deep="$(printf '[%.0s' {1..5000})"
while IFS='|' read -r want answer rc; do
    got="$(with_shim_functions verdict "$answer" ${rc:+"$rc"} 2>&1)"
    [[ "$got" == "$want" ]] && pass "readiness_verdict: ${answer:0:60}${rc:+ (exit $rc)} is $want" \
        || fail "readiness_verdict: ${answer:0:60}${rc:+ (exit $rc)} gave $got, want $want"
done <<EOF
pass|{"contract": 1, "result": "pass"}|
pass|{"contract": 1, "result": "pass"}|0
invalid|{"contract": 1, "result": "pass"}|1
blocked|{"contract": 1, "result": "blocked"}|1
invalid|{"contract": 1, "result": "blocked"}|0
invalid|{"contract": 2, "result": "pass"}|0
invalid|{"contract": "1", "result": "pass"}|0
invalid|{"contract": true, "result": "pass"}|0
invalid|{"contract": 1.0, "result": "pass"}|0
invalid|{"contract": 1, "result": "cant_verify"}|0
invalid|{"contract": 1, "result": ["pass"]}|0
invalid|{"contract": 1}|0
invalid|["pass"]|0
invalid|null|0
invalid||0
invalid|$deep|0
EOF
[[ "$(with_shim_functions readiness_verdict "$BOXMUNGE_ROOT/no-such-file" 0 2>&1)" == invalid ]] \
    && pass "readiness_verdict: no answer at all is invalid" || fail "missing answer file"
python3 -c 'import json; print(json.dumps({"contract": 1, "result": "pass", "pad": "x" * 1048576}))' > "$BOXMUNGE_ROOT/big.json"
[[ "$(with_shim_functions readiness_verdict "$BOXMUNGE_ROOT/big.json" 0 2>&1)" == invalid ]] \
    && pass "readiness_verdict: an answer over 1 MiB is invalid" || fail "oversized answer"

cat > "$BOXMUNGE_ROOT/answer.json" <<'EOF'
{"contract": 1, "result": "blocked",
 "box": [{"severity": "todo", "message": "box to-do"}, {"severity": "block", "message": "box\tblock\u001b[31m"}],
 "projects": [{"name": "web", "findings": [{"severity": "todo", "message": "web to-do"}]},
              {"name": "db", "findings": [{"severity": "todo", "message": "db to-do"}, {"severity": "block", "message": "db block"}]},
              {"name": "quiet", "findings": []}, "not a project", {"name": "odd", "findings": "nope"}]}
EOF
[[ "$(with_shim_functions readiness_summary "$BOXMUNGE_ROOT/answer.json" 2>&1)" == "box: box block?[31m; web: web to-do; db: db block" ]] \
    && pass "readiness_summary names each one's first block, or else its first to-do, cleaned" \
    || fail "summary: $(with_shim_functions readiness_summary "$BOXMUNGE_ROOT/answer.json" 2>&1)"
python3 -c 'import json; print(json.dumps({"contract": 1, "result": "blocked", "box": [{"severity": "block", "message": "m" * 5000}]}))' \
    > "$BOXMUNGE_ROOT/answer.json"
[[ "$(with_shim_functions readiness_summary "$BOXMUNGE_ROOT/answer.json" 2>&1 | wc -c | tr -d ' ')" -le 401 ]] \
    && pass "readiness_summary is at most 400 characters" || fail "summary too long"
drop_root

rm -rf "$RELEASE" "$FIXTURE"
finish
