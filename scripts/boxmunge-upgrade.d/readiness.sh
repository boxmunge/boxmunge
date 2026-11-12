# shellcheck shell=bash
# readiness.sh — running a release's own checks against this box without
# letting them change it: confined runs (systemd-run), the bundle's
# prerequisite scripts, and the verdict of its readiness command
# (`boxmunge-server upgrade-readiness --json`, readiness contract 1).
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# Time limits of each confined run, in seconds. A unit still running at its
# limit gets SIGTERM, and STOP_SECS later SIGKILL, every process in it. The
# readiness check holds upgrade.lock only for the readiness and dry runs: at
# most READINESS_SECS + DRY_RUN_SECS + 2 * STOP_SECS = 610 s (and a few
# seconds of the shim's own), so the health timer (every 5 minutes) skips
# at most three check-probation runs, and auto-update waits it out.
STOP_SECS=5
PREREQ_SECS=60
# shellcheck disable=SC2034  # VENV_SECS and DRY_RUN_SECS are check.sh's
VENV_SECS=900
READINESS_SECS=300
# shellcheck disable=SC2034
DRY_RUN_SECS=300
# The readiness command's stdout, at most; a longer one is not contract 1.
READINESS_MAX_BYTES=1048576
# The largest file a unit with no writable path may write: its output files
# (and its private /tmp). A larger write fails (EFBIG, or SIGXFSZ).
CONFINED_FILE_MAX=2097152

# PY_CLEAN: Python that every message built from a release's output goes
# through. clean(text, limit, tail=False) gives one line of printable ASCII
# (line breaks and tabs as spaces, anything else unprintable as '?', runs of
# spaces as one) of at most <limit> characters, the last ones with tail=True.
PY_CLEAN='def clean(text, limit, tail=False):
    text = text[-4 * limit:] if tail else text[:4 * limit]
    text = " ".join("".join(c if " " <= c <= "~" else " " if c in "\n\r\t" else "?" for c in text).split())
    return text[-limit:] if tail else text[:limit]
'

# require_systemd_run: a release's code runs here only inside systemd-run.
require_systemd_run() {
    command -v systemd-run >/dev/null 2>&1 \
        || die "systemd-run is missing, and a readiness check runs a release's code only inside it. It comes with systemd: as supervisor, sudo apt-get install systemd"
}

# confined_run <name> <secs> <user> <rw-dir|-> <out> <err> -- <cmd...>: run
# <cmd> as <user> in the transient unit boxmunge-check-<name>-<pid>, stopped
# after <secs> seconds (STOP_SECS more to end), with the filesystem read-only
# except <rw-dir> (none for -; then no file over CONFINED_FILE_MAX either), a
# private /tmp, no new privileges and no kernel tunables, modules or cgroups;
# as root, also no capabilities, devices or namespaces, and only the system
# calls of @system-service.
# Its stdin is /dev/null. Its stdout goes to the file <out>, its stderr to
# <err> ("-" discards either, an <err> of "+" goes with stdout); systemd
# opens them, emptied first. So nothing here ever reads the unit's output
# while it runs: a process the unit's output is handed to (deploy can reach a
# deploy unit's) cannot keep this shell, or upgrade.lock, waiting. The
# environment is PATH, BOXMUNGE_ROOT, PYTHONSAFEPATH and
# PYTHONDONTWRITEBYTECODE, and what systemd adds (USER, and for a <user> not
# root HOME, LOGNAME and SHELL), the working directory /. Returns <cmd>'s
# exit code, or 124 when the time limit stopped it, or 125 when systemd can
# no longer say how the unit ended (confined_ending).
confined_run() {
    local name="$1" secs="$2" user="$3" rw="$4" out="$5" err="$6" stream
    [[ "${7:-}" == -- && $# -gt 7 && "$name" =~ ^[a-z0-9-]+$ && "$secs" =~ ^[1-9][0-9]*$ \
        && "$user" =~ ^[a-z_][a-z0-9_-]*$ && ( "$rw" == - || "$rw" == /* ) \
        && ( "$out" == - || "$out" == /* ) && ( "$err" == - || "$err" == + || "$err" == /* ) ]] \
        || die "Usage: confined_run <name> <secs> <user> <rw-dir|-> <out|-> <err|-|+> -- <cmd...>"
    shift 7
    require_systemd_run
    local unit="boxmunge-check-$name-$$" rc=0
    local props=(-p "RuntimeMaxSec=$secs" -p "TimeoutStopSec=$STOP_SECS" -p ProtectSystem=strict
        -p ProtectHome=read-only -p PrivateTmp=yes -p NoNewPrivileges=yes -p ProtectKernelTunables=yes
        -p ProtectKernelModules=yes -p ProtectControlGroups=yes)
    if [[ "$rw" == - ]]; then props+=(-p "LimitFSIZE=$CONFINED_FILE_MAX"); else props+=(-p "ReadWritePaths=$rw"); fi
    if [[ "$user" == root ]]; then
        # Root runs only the signed release's own scripts and pip, and needs
        # none of root's powers for them: no capabilities, no devices, no
        # namespaces, and only the system calls an ordinary service makes.
        props+=(-p CapabilityBoundingSet= -p PrivateDevices=yes -p RestrictNamespaces=yes
            -p SystemCallFilter=@system-service)
    else
        props+=(-p "User=$user")
    fi
    for stream in "$out" "$err"; do
        [[ "$stream" != /* ]] || : > "$stream"  # there, empty, even if the unit never starts
    done
    props+=(-p "StandardOutput=$(confined_stream "$out")")
    if [[ "$err" == + ]]; then props+=(-p StandardError=inherit); else props+=(-p "StandardError=$(confined_stream "$err")"); fi
    # A failed unit keeps its name until it is reset. One a killed run left
    # under this name (the same pid) would stop this one from starting; when
    # there is none, systemctl says so, and that is not an error here.
    systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
    systemd-run --quiet --wait --unit="$unit" "${props[@]}" \
        --setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin --setenv="BOXMUNGE_ROOT=$BOXMUNGE_ROOT" \
        --setenv=PYTHONSAFEPATH=1 --setenv=PYTHONDONTWRITEBYTECODE=1 --working-directory=/ \
        -- "$@" </dev/null || rc=$?
    [[ "$rc" -ne 0 ]] || return 0
    confined_ending "$unit.service" "$rc"
}

# confined_ending <unit> <rc>: how a unit `systemd-run --wait` reported as
# failed (<rc>) ended, asked of systemd, which keeps a failed transient unit
# loaded until it is reset: its Result, which nothing the command prints or
# exits with can fake. 124 for Result=timeout; 125 when systemd does not know
# the unit (systemd-run could not start it, or it is gone), so a timeout
# cannot be ruled out; otherwise <rc>, the command's own 124 or 125 as 1.
confined_ending() {
    local unit="$1" rc="$2" shown load="" result="" line
    shown="$(systemctl show --property=LoadState --property=Result "$unit" 2>/dev/null)" || shown=""
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    while IFS= read -r line; do
        case "$line" in
            LoadState=*) load="${line#LoadState=}" ;;
            Result=*) result="${line#Result=}" ;;
        esac
    done <<< "$shown"
    if [[ "$load" != loaded ]]; then
        log "ERROR: $unit exited $rc, and systemd does not know the unit (LoadState=${load:-unknown}), so whether it ran out of time cannot be told"
        return 125
    fi
    [[ "$result" != timeout ]] || return 124
    [[ "$rc" -ne 124 && "$rc" -ne 125 ]] || return 1
    return "$rc"
}

# confined_stream <file|->: a systemd StandardOutput= or StandardError= value.
confined_stream() { if [[ "$1" == - ]]; then echo null; else echo "truncate:$1"; fi; }

# run_prerequisites <bundle_dir> <out_jsonl>: run the box checks the bundle
# lists in bootstrap/prerequisites (one bootstrap/<name>.sh a line; # comments
# and blank lines allowed), each as `bash <script>` as root, confined with no
# writable path, PREREQ_SECS at most. Appends {"script", "ok", "message"} for
# each to <out_jsonl>; a script's message is the end of its stderr. Returns 0
# when all are met (or none is listed), 1 when one is not, and 2 when that
# cannot be told: the list is malformed (reported as the script
# bootstrap/prerequisites), or a script did not finish.
run_prerequisites() {
    local bundle="$1" out="$2" manifest="$1/bootstrap/prerequisites" line script rc verdict=0 scripts=()
    local skip='^[[:space:]]*(#.*)?$' valid='^bootstrap/[a-z0-9-]+\.sh$'
    [[ -e "$manifest" || -L "$manifest" ]] || return 0
    if [[ -L "$manifest" || ! -f "$manifest" ]]; then
        prerequisite_line "$out" bootstrap/prerequisites false "is not a regular file in the bundle"
        return 2
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ ! "$line" =~ $skip ]] || continue
        if [[ ! "$line" =~ $valid || -L "$bundle/$line" || ! -f "$bundle/$line" ]]; then
            prerequisite_line "$out" bootstrap/prerequisites false "lists '$line', which is not a bootstrap/<name>.sh script in the bundle"
            return 2
        fi
        scripts+=("$line")
    done < "$manifest"
    for script in "${scripts[@]+"${scripts[@]}"}"; do
        rc=0
        confined_run "prereq-$(basename "$script" .sh)" "$PREREQ_SECS" root - - "$out.err" \
            -- bash "$bundle/$script" || rc=$?
        case "$rc" in
            0) prerequisite_line "$out" "$script" true "" ;;
            124) prerequisite_line "$out" "$script" false "did not finish within $PREREQ_SECS s; retry when the box is less busy"
                 [[ "$verdict" -eq 1 ]] || verdict=2 ;;
            125) prerequisite_line "$out" "$script" false "could not tell how it ended" "$out.err"
                 [[ "$verdict" -eq 1 ]] || verdict=2 ;;
            *) prerequisite_line "$out" "$script" false "exited $rc and said nothing" "$out.err"
               verdict=1 ;;
        esac
    done
    rm -f "$out.err"
    return "$verdict"
}

# prerequisite_line <out_jsonl> <script> <ok> <message> [<stderr file>]: one
# result line; the message is the end of the stderr file when it says
# anything, <message> otherwise.
prerequisite_line() {
    python3 -I -c "$PY_CLEAN"'
import json, sys
out, script, ok, message = sys.argv[1:5]
if len(sys.argv) > 5:
    with open(sys.argv[5], "rb") as f:
        f.seek(0, 2)
        f.seek(max(0, f.tell() - 4096))
        message = clean(f.read().decode("utf-8", "replace"), 1024, tail=True) or message
with open(out, "a") as f:
    f.write(json.dumps({"script": script, "ok": ok == "true", "message": clean(message, 1024)}) + "\n")
' "$@"
}

# run_readiness <venv_dir> <out_file>: the readiness command of the release in
# <venv_dir> against this box, as deploy, confined with no writable path,
# READINESS_SECS at most. As deploy, so a project file deploy links elsewhere
# cannot make root read it into a finding. Its stdout goes to <out_file>
# (readiness_verdict reads at most READINESS_MAX_BYTES and one more byte),
# its stderr to <out_file>.err. Returns its exit code (124: timed out).
run_readiness() {
    confined_run readiness "$READINESS_SECS" deploy - "$2" "$2.err" \
        -- "$1/bin/boxmunge-server" upgrade-readiness --json
}

# readiness_verdict <out_file> [<exit code>]: pass, blocked or invalid. Only
# what the shim acts on is checked (the deploy side reads the findings): a
# JSON object of at most READINESS_MAX_BYTES whose contract is the integer 1
# and whose result is pass or blocked. With <exit code>, it must agree (0 for
# pass, 1 for blocked, readiness contract 1), or the answer is invalid.
readiness_verdict() {
    BM_MAX="$READINESS_MAX_BYTES" BM_RC="${2:-}" python3 -I -c 'import json, os, sys
limit, verdict = int(os.environ["BM_MAX"]), "invalid"
try:
    with open(sys.argv[1], "rb") as f:
        raw = f.read(limit + 1)
    d = json.loads(raw) if len(raw) <= limit else None
except (OSError, ValueError, RecursionError):
    d = None
if isinstance(d, dict) and type(d.get("contract")) is int and d["contract"] == 1 and d.get("result") in ("pass", "blocked"):
    verdict = d["result"]
rc = os.environ["BM_RC"]
if rc and verdict != "invalid" and rc != {"pass": "0", "blocked": "1"}[verdict]:
    verdict = "invalid"
print(verdict)' "$1"
}

# readiness_summary <out_file>: one line of at most 400 printable characters
# saying what the readiness answer found: for the box and for each project,
# its first block, or else its first to-do. Use it on an answer
# readiness_verdict accepted.
readiness_summary() {
    python3 -I -c "$PY_CLEAN"'
import json, sys
with open(sys.argv[1], "rb") as f:
    d = json.loads(f.read())
def first(findings):
    findings = [f for f in findings if isinstance(f, dict)] if isinstance(findings, list) else []
    for severity in ("block", "todo"):
        for f in findings:
            if f.get("severity") == severity and isinstance(f.get("message"), str):
                return f["message"]
parts = []
if first(d.get("box")):
    parts.append("box: " + first(d.get("box")))
for p in d.get("projects") if isinstance(d.get("projects"), list) else []:
    if isinstance(p, dict) and first(p.get("findings")):
        parts.append(str(p.get("name")) + ": " + first(p.get("findings")))
print(clean("; ".join(parts), 400))
' "$1"
}
