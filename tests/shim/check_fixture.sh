#!/usr/bin/env bash
# tests/shim/check_fixture.sh — a box and a release for the readiness check
# (`check <version>`) tests. Source it after lib.sh.
#
# Stand-ins: curl serves $RELEASE (exit 22, as for an HTTP error, when the
# file is not there); cosign accepts, or refuses while mock/cosign-fails
# exists; systemd-run and systemctl are lib.sh's (SYSTEMD_RUN_STUB), whose
# units find this fixture's python3 first. `python3 -m venv` copies in a
# scratch venv whose pip records its arguments (and fails while
# mock/pip-fails exists) and whose boxmunge-server answers
# `upgrade-readiness --json` and `upgrade --dry-run` from mock/<run>.out,
# .err and .rc, sleeping first while mock/<run>.sleep exists. Each venv build,
# readiness and dry run records whether upgrade.lock was held as it ran.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash

FIXTURE="$(mktemp -d)"
REAL_PYTHON3="$(command -v python3)"
mkdir -p "$FIXTURE/bin" "$FIXTURE/venv/bin"
stub() {  # stub <path> <bash body>
    printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"
    chmod +x "$1"
}
# lock_state <name>: "<name>: lock held" or "<name>: lock free" into calls.
LOCK_STATE='lock_state() {
    if python3 -c "import fcntl, sys; fcntl.flock(open(sys.argv[1], \"a\"), fcntl.LOCK_EX | fcntl.LOCK_NB)" \
            "$BOXMUNGE_ROOT/upgrade-root/upgrade.lock" 2>/dev/null; then
        echo "$1: lock free" >> "$BOXMUNGE_ROOT/calls"
    else
        echo "$1: lock held" >> "$BOXMUNGE_ROOT/calls"
    fi
}'
stub "$FIXTURE/bin/python3" "$LOCK_STATE
if [[ \"\$1 \$2\" == '-m venv' ]]; then
    lock_state venv
    if [[ -p \"\$BOXMUNGE_ROOT/mock/venv-fifo\" ]]; then
        : > \"\$BOXMUNGE_ROOT/mock/venv-started\"
        cat \"\$BOXMUNGE_ROOT/mock/venv-fifo\" >/dev/null
    fi
    [[ ! -e \"\$BOXMUNGE_ROOT/mock/bump-version\" ]] || echo 1.4.1 > \"\$BOXMUNGE_ROOT/config/version\"
    mkdir -p \"\$3\"; cp -R '$FIXTURE/venv/bin' \"\$3/\"; exit 0
fi
exec '$REAL_PYTHON3' \"\$@\""
stub "$FIXTURE/bin/curl" 'echo "curl ${*: -1}" >> "$BOXMUNGE_ROOT/calls"
f="$RELEASE/$(basename "${@: -1}")"
[[ -f "$f" ]] || exit 22
cp "$f" "$3"'
stub "$FIXTURE/bin/cosign" '[[ ! -e "$BOXMUNGE_ROOT/mock/cosign-fails" ]] || { echo "Error: invalid signature" >&2; exit 1; }'
stub "$FIXTURE/venv/bin/pip" 'echo "pip $*" >> "$BOXMUNGE_ROOT/calls"
[[ ! -e "$BOXMUNGE_ROOT/mock/pip-fails" ]] || { echo "ERROR: THESE PACKAGES DO NOT MATCH THE HASHES" >&2; exit 1; }'
stub "$FIXTURE/venv/bin/boxmunge-server" "$LOCK_STATE"'
case "$1 ${2:-}" in
    "upgrade-readiness --json") run=readiness ;;
    "upgrade --dry-run") run=dry_run ;;
    *) echo "unexpected boxmunge-server $*" >&2; exit 64 ;;
esac
lock_state "$run"
mock="$BOXMUNGE_ROOT/mock/$run"
[[ ! -e "$mock.sleep" ]] || sleep 30
[[ ! -e "$mock.err" ]] || cat "$mock.err" >&2
[[ ! -e "$mock.out" ]] || cat "$mock.out"
exit "$(cat "$mock.rc" 2>/dev/null || echo 0)"'
export PATH="$FIXTURE/bin:$PATH"
export STUB_UNIT_PATH="$FIXTURE/bin"
# Every confined run is cut to this in the stand-in; the mocks that sleep
# outlast it, so a time limit is met in seconds.
export STUB_MAX_SECS=3

PASSING='{"contract": 1, "release": "1.5.0", "installed": "1.4.0", "result": "pass", "box": [], "projects": [{"name": "app", "result": "pass", "findings": []}]}'

# release [<prerequisites>]: RELEASE serves a signed, checksummed 1.5.0 bundle
# with hash-pinned requirements, docs, and bootstrap/prerequisites (by
# default listing bootstrap/ok.sh, and bootstrap/floor.sh, which fails saying
# why while mock/prereq-fails exists and sleeps while mock/prereq-sleeps
# does; "none" ships no list).
release() {
    RELEASE="$(mktemp -d)"
    export RELEASE
    local b="$RELEASE/boxmunge" f
    mkdir -p "$b/on-server" "$b/bootstrap"
    for f in requirements-build.txt requirements-tui.txt requirements-mcp.txt; do echo "x==1" > "$b/$f"; done
    echo "ops" > "$b/on-server/OPERATIONS.md"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$b/bootstrap/ok.sh"
    cat > "$b/bootstrap/floor.sh" <<'EOS'
#!/usr/bin/env bash
[[ ! -e "$BOXMUNGE_ROOT/mock/prereq-sleeps" ]] || sleep 30
[[ -e "$BOXMUNGE_ROOT/mock/prereq-fails" ]] || exit 0
echo "checking the floor"
printf 'ERROR: boxmunge needs Python 3.13;\n\tthis host has \033[31m3.11\033[0m.\n' >&2
exit 1
EOS
    case "${1:-}" in
        none) ;;
        "") printf '# box checks\n\nbootstrap/ok.sh\n  # indented comment\nbootstrap/floor.sh\n' > "$b/bootstrap/prerequisites" ;;
        *) printf '%s\n' "$1" > "$b/bootstrap/prerequisites" ;;
    esac
    tar czf "$RELEASE/boxmunge-1.5.0.tar.gz" -C "$RELEASE" boxmunge
    (cd "$RELEASE" && sha256sum boxmunge-1.5.0.tar.gz > SHA256SUMS)
    touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"
}

# box: slot a live on 1.4.0, with the upgrade state a check must leave as it
# is (counts naming 1.5.0, root's probation record, the stash record, the
# skip count, both lock files, the sudo rule), and a readiness answer that
# passes. Slot a's python records what the shim logs (bm_log) in calls.
box() {
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    mock_server a '[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ "$1" == "-" ]]; then cat >/dev/null; echo "bm_log $BM_LEVEL $BM_MSG $BM_DETAIL" >> "$BOXMUNGE_ROOT/calls"; exit 0; fi' \
        "exec $(printf %q "$REAL_PYTHON3") \"\$@\"" > "$BOXMUNGE_ROOT/env-a/bin/python"
    local r="$BOXMUNGE_ROOT/upgrade-root"
    mkdir -m 0700 "$r"
    printf '{"1.3.0": {"reason": "apply", "failed_at": "x"}}\n' > "$BOXMUNGE_ROOT/upgrade-state/blocklist.json"
    for f in interrupted pip-failures cosign-failures; do printf '{"1.5.0": 1}' > "$r/$f.json"; done
    echo none > "$r/probation-expiry"
    echo "1.5.0 $OLD_STASH" > "$r/upgrade-stash"
    echo 3 > "$r/lock-skips"
    : > "$r/upgrade.lock"
    : > "$BOXMUNGE_ROOT/upgrade-state/upgrade.lock"
    chmod 0600 "$r/upgrade.lock" "$BOXMUNGE_ROOT/upgrade-state/upgrade.lock"
    run_shim install-sudoers
    mkdir "$BOXMUNGE_ROOT/mock"
    printf '%s' "$PASSING" > "$BOXMUNGE_ROOT/mock/readiness.out"
    : > "$BOXMUNGE_ROOT/calls"
}

# snapshot: every upgrade-state file, slot, stash and sudo rule, and root's
# counts and records, with mode, size, mtime and content hash.
snapshot() {
    python3 - "$BOXMUNGE_ROOT" <<'PY'
import hashlib, os, sys
root = sys.argv[1]
tops = ["upgrade-state", "env-a", "env-b", "stashes", "sudoers.d"] + [
    "upgrade-root/" + n for n in ("interrupted.json", "pip-failures.json", "cosign-failures.json",
                                  "probation-expiry", "upgrade-stash", "lock-skips", "upgrade.lock")]
def entry(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return f"{os.path.relpath(path, root)} missing"
    digest = ""
    if os.path.isfile(path) and not os.path.islink(path):
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
    return f"{os.path.relpath(path, root)} {st.st_mode:o} {st.st_size} {st.st_mtime_ns} {digest}"
lines = []
for top in tops:
    path = os.path.join(root, top)
    lines.append(entry(path))
    if os.path.isdir(path) and not os.path.islink(path):
        for d, dirs, files in os.walk(path):
            lines += [entry(os.path.join(d, n)) for n in dirs + files]
print("\n".join(sorted(lines)))
PY
}

# run_check <version> [<more args>]: run `check`, with the stamp of an
# earlier check removed (KEEP_STAMP=1 keeps it). JSON is its stdout, ERR its
# stderr, RC its exit code, calls what it ran. The upgrade state must come
# out byte-identical and the scratch removed (asserted, with RUN_DESC naming
# the run; with KEEP_SCRATCH=1, a scratch that was there before is the
# test's to check).
run_check() {
    local before after desc="${RUN_DESC:-check $*}"
    [[ -n "${KEEP_STAMP:-}" ]] || rm -f "$BOXMUNGE_ROOT/upgrade-root/check-last"
    : > "$BOXMUNGE_ROOT/calls"
    before="$(snapshot)"
    RC=0
    JSON="$(bash "$SHIM" check "$@" 2>"$BOXMUNGE_ROOT/stderr")" || RC=$?
    ERR="$(cat "$BOXMUNGE_ROOT/stderr")"
    after="$(snapshot)"
    [[ "$before" == "$after" ]] && pass "$desc: upgrade state byte-identical" \
        || fail "$desc: upgrade state changed: $(diff <(echo "$before") <(echo "$after") || true)"
    [[ -n "${KEEP_SCRATCH:-}" || ! -e "$BOXMUNGE_ROOT/upgrade-check" ]] && pass "$desc: scratch removed" \
        || fail "$desc: $BOXMUNGE_ROOT/upgrade-check left behind"
}

# field <python expression over d>: from the last check's JSON.
field() {
    python3 -c 'import json, sys
d = json.loads(sys.argv[1])
print(eval(sys.argv[2]))' "$JSON" "$1" 2>/dev/null || echo "(no JSON: $JSON)"
}

# expect_check <rc> <result> <stage> <in a reason> <description>
expect_check() {
    local got
    got="$(python3 -c 'import json, sys
d = json.loads(sys.argv[1])
assert set(d) == {"check", "target", "installed", "result", "stage", "reasons", "prerequisites", "readiness", "dry_run"}, sorted(d)
assert d["check"] == 1 and d["target"] == sys.argv[5], d["target"]
found = not sys.argv[4] or any(sys.argv[4] in r for r in d["reasons"])
print(d["result"], d["stage"], "found" if found else "missing", sep="|")' \
        "$JSON" "$2" "$3" "$4" "${CHECK_TARGET:-1.5.0}" 2>&1)" || got="not K3 JSON: $got"
    if [[ "$RC" -eq "$1" && "$got" == "$2|$3|found" ]]; then
        pass "$5"
    else
        fail "$5 (rc=$RC, want $1; got $got, want $2|$3 with '$4'; json: $JSON; stderr: ${ERR: -600})"
    fi
}

calls() { cat "$BOXMUNGE_ROOT/calls"; }
ran() { grep -q "$1" "$BOXMUNGE_ROOT/calls"; }
