#!/usr/bin/env bash
# tests/shim/test_venv_requirements.sh — the standby venv an upgrade builds
# gets every hash-pinned requirements file the bundle ships, MCP included,
# so nothing installed into the old venv by hand is lost on the swap. A
# bundle without one of them fails the upgrade's preflight with the proven
# release still live. A pip failure is retried once before it blocklists, and
# releases from before the MCP lock are refused without blocklisting.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins: curl serves a local release, cosign and sha256sum accept it,
# python3 -m venv copies in a mock venv whose pip records its arguments
# and fails when FAIL_PIP_ON names a file it was given.
FIXTURE="$(mktemp -d)"
REAL_PYTHON3="$(command -v python3)"
mkdir -p "$FIXTURE/bin" "$FIXTURE/venv/bin"
stub() {  # stub <path> <bash body>
    printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"
    chmod +x "$1"
}
stub "$FIXTURE/bin/python3" "if [[ \"\$1 \$2\" == '-m venv' ]]; then mkdir -p \"\$3\"; cp -R '$FIXTURE/venv/bin' \"\$3/\"; exit 0; fi
exec '$REAL_PYTHON3' \"\$@\""
stub "$FIXTURE/bin/curl" 'echo "curl ${*: -1}" >> "$BOXMUNGE_ROOT/calls"; cp "$RELEASE/$(basename "${@: -1}")" "$3"'
stub "$FIXTURE/bin/cosign" 'exit 0'
stub "$FIXTURE/bin/sha256sum" 'cat >/dev/null; exit 0'
stub "$FIXTURE/venv/bin/pip" 'echo "pip $0 $*" >> "$BOXMUNGE_ROOT/calls"
[[ -z "${FAIL_PIP_ON:-}" || "$*" != *"/$FAIL_PIP_ON"* ]] || exit 1'
stub "$FIXTURE/venv/bin/boxmunge-server" '[[ "$1" != --version ]] || echo "boxmunge 1.5.0"; exit 0'
stub "$FIXTURE/venv/bin/python" 'if [[ "$1" == "-" ]]; then cat >/dev/null; exit 0; fi
case "$2" in
    *write_probation*)
        printf "{\"version\": \"%s\", \"previous_slot\": \"%s\", \"expires_at\": \"'"$SOON"'\"}\n" \
            "$BM_VERSION" "$BM_PREV_SLOT" > "$BOXMUNGE_ROOT/upgrade-state/probation.json" ;;
    *get_build_version*) echo "1.5.0" ;;
esac
exit 0'
export PATH="$FIXTURE/bin:$PATH"

# release <requirements file>...: a 1.5.0 bundle shipping those files.
release() {
    RELEASE="$(mktemp -d)"
    export RELEASE
    mkdir -p "$RELEASE/boxmunge/on-server"
    local f
    for f in "$@"; do echo "${f%.txt}==1" > "$RELEASE/boxmunge/$f"; done
    echo "1.5.0 ops" > "$RELEASE/boxmunge/on-server/OPERATIONS.md"
    tar czf "$RELEASE/boxmunge-1.5.0.tar.gz" -C "$RELEASE" boxmunge
    echo "0000  boxmunge-1.5.0.tar.gz" > "$RELEASE/SHA256SUMS"
    touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"
}

installed() {
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    echo "proven" > "$BOXMUNGE_ROOT/env-a/known-good"
    mock_server a '[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
echo "a-python: reason=${BM_REASON:-} stage=${BM_STAGE:-} msg=${BM_MESSAGE:-} $*" >> "$BOXMUNGE_ROOT/calls"'
    : > "$BOXMUNGE_ROOT/calls"
}

live() { readlink "$BOXMUNGE_ROOT/env-active" | sed 's|.*/env-||'; }
dep_installs() { grep -- "--require-hashes" "$BOXMUNGE_ROOT/calls" || true; }
blocklisted() { grep -q "add_to_blocklist" "$BOXMUNGE_ROOT/calls"; }
reported() { grep -q "a-python: .*stage=preflight " "$BOXMUNGE_ROOT/calls"; }
pip_failures() { cat "$BOXMUNGE_ROOT/upgrade-root/pip-failures.json" 2>/dev/null || true; }
upgrade_failing_pip() {  # upgrade_failing_pip <file pip fails on, or empty>
    : > "$BOXMUNGE_ROOT/calls"
    RC=0
    OUT="$(FAIL_PIP_ON="$1" bash "$SHIM" target 1.5.0 2>&1)" || RC=$?
}

ALL=(requirements-build.txt requirements-tui.txt requirements-mcp.txt)

# --- a complete bundle: one hash-pinned install of every file, into standby ---

release "${ALL[@]}"
installed
run_shim target 1.5.0
expect 0 "probation started" "upgrade with every requirements file completes"
[[ "$(live)" == b ]] && pass "1.5.0 is live in slot b" || fail "live slot is $(live)"
deps="$(dep_installs)"
[[ "$(printf '%s\n' "$deps" | grep -c .)" -eq 1 ]] && pass "dependencies install in one pip run" \
    || fail "dependency installs: $deps"
[[ "$deps" == "pip $BOXMUNGE_ROOT/env-b/bin/pip "* ]] && pass "dependencies go into the standby slot" \
    || fail "dependencies installed by: $deps"
for f in "${ALL[@]}"; do
    [[ "$deps" == *" -r "*"/boxmunge/$f"* ]] && pass "standby gets $f with --require-hashes" \
        || fail "$f not in the hash-pinned install: $deps"
done
grep -q "env-a/bin/pip" "$BOXMUNGE_ROOT/calls" && fail "the proven slot's pip was used" \
    || pass "the proven slot is not installed into"
drop_root
rm -rf "$RELEASE"

# --- a bundle missing the MCP requirements is refused -------------------------

release requirements-build.txt requirements-tui.txt
installed
run_shim target 1.5.0
expect 1 "no hash-pinned requirements-mcp.txt" "a bundle without requirements-mcp.txt fails preflight"
[[ "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/env-a/known-good")" == proven ]] \
    && pass "missing MCP requirements: proven release still live" || fail "live slot is $(live)"
[[ -z "$(dep_installs)" ]] && pass "nothing is installed from an incomplete bundle" \
    || fail "installed anyway: $(dep_installs)"
drop_root
rm -rf "$RELEASE"

# --- a failed dependency install is retried once, then blocklisted ----------

release "${ALL[@]}"
installed
upgrade_failing_pip requirements-mcp.txt
expect 1 "not blocklisted, auto-update will retry 1.5.0" "a first failed MCP install fails the upgrade"
[[ "$(live)" == a && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
    && pass "first pip failure: proven release live, standby dropped" || fail "live=$(live)"
! blocklisted && ! reported && pass "first pip failure: neither blocklisted nor reported" \
    || fail "first pip failure blocklisted or reported: $(cat "$BOXMUNGE_ROOT/calls")"
grep -q "msg=Could not install the dependencies of 1.5.0 (not blocklisted" "$BOXMUNGE_ROOT/calls" \
    && pass "first pip failure: operator alerted locally" || fail "no local alert: $(cat "$BOXMUNGE_ROOT/calls")"
[[ "$(pip_failures)" == '{"1.5.0": 1}' ]] && pass "first pip failure: counted" \
    || fail "pip failure count is $(pip_failures)"
upgrade_failing_pip requirements-mcp.txt
expect 1 "2 times in a row" "a second failed install in a row fails the upgrade"
blocklisted && reported && pass "second pip failure: blocklisted and reported" \
    || fail "second pip failure not blocklisted and reported: $(cat "$BOXMUNGE_ROOT/calls")"
[[ "$(live)" == a && ! -e "$BOXMUNGE_ROOT/env-b" && "$(cat "$BOXMUNGE_ROOT/env-a/known-good")" == proven ]] \
    && pass "second pip failure: proven release live, standby dropped" || fail "live=$(live)"
run_shim clear-blocklist 1.5.0
[[ "$(pip_failures)" == "{}" ]] && pass "clear-blocklist forgets the pip failure count" \
    || fail "count after clear-blocklist: $(pip_failures)"
drop_root

installed
upgrade_failing_pip requirements-tui.txt
upgrade_failing_pip ""
expect 0 "probation started" "after one pip failure the retry completes"
[[ "$(pip_failures)" == "{}" ]] && pass "a successful install forgets the pip failure count" \
    || fail "count after success: $(pip_failures)"
! blocklisted && pass "a failure followed by success is never blocklisted" || fail "blocklisted: $(cat "$BOXMUNGE_ROOT/calls")"
drop_root
rm -rf "$RELEASE"

# --- releases from before the MCP lock are refused, not blocklisted ----------

for v in 0.10.1 0.9.16; do
    installed
    run_shim force-target "$v"
    expect 1 "Bundle $v predates the hash-pinned requirements-mcp.txt every install needs; force-target cannot go below the first release after 0.10.1" \
        "force-target $v is refused"
    ! blocklisted && ! reported && ! grep -q "^curl" "$BOXMUNGE_ROOT/calls" \
        && pass "force-target $v: not downloaded, blocklisted or reported" || fail "force-target $v: $(cat "$BOXMUNGE_ROOT/calls")"
    [[ "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/env-a/known-good")" == proven ]] && pass "force-target $v: proven release untouched" \
        || fail "force-target $v: live=$(live)"
    drop_root
done

rm -rf "$FIXTURE"
finish
