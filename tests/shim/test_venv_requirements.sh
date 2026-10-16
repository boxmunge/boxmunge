#!/usr/bin/env bash
# tests/shim/test_venv_requirements.sh — the standby venv an upgrade builds
# gets every hash-pinned requirements file the bundle ships, MCP included,
# so nothing installed into the old venv by hand is lost on the swap. A
# bundle without one of them, or a pip failure on any of them, fails the
# upgrade's preflight with the proven release still live.
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
stub "$FIXTURE/bin/curl" 'cp "$RELEASE/$(basename "${@: -1}")" "$3"'
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
echo "a-python: reason=${BM_REASON:-} $*" >> "$BOXMUNGE_ROOT/calls"'
    : > "$BOXMUNGE_ROOT/calls"
}

live() { readlink "$BOXMUNGE_ROOT/env-active" | sed 's|.*/env-||'; }
dep_installs() { grep -- "--require-hashes" "$BOXMUNGE_ROOT/calls" || true; }

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

# --- a failed MCP install fails preflight, like any other dependency ----------

release "${ALL[@]}"
installed
RC=0
OUT="$(FAIL_PIP_ON=requirements-mcp.txt bash "$SHIM" target 1.5.0 2>&1)" || RC=$?
expect 1 "Failed to install hash-pinned dependencies" "a failed MCP install fails preflight"
[[ "$(live)" == a && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
    && pass "failed MCP install: proven release live, standby dropped" || fail "live=$(live)"
grep -q "a-python: reason=preflight_failed: pip_install_deps -c" "$BOXMUNGE_ROOT/calls" \
    && pass "failed MCP install blocklists the version" || fail "not blocklisted: $(cat "$BOXMUNGE_ROOT/calls")"
drop_root
rm -rf "$RELEASE"

rm -rf "$FIXTURE"
finish
