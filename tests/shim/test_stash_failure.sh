#!/usr/bin/env bash
# tests/shim/test_stash_failure.sh — a refused or failed platform stash stops
# the upgrade before anything changes, and an unattended auto-update must not
# fail there silently: the shim logs the error, alerts the operator locally
# and drops the half-built standby venv, without blocklisting or reporting
# the release (a stray symlink on the box is not the release's fault).
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins: curl serves a local 1.5.0 release, cosign and sha256sum accept
# it, and python3 -m venv copies in a mock venv that passes preflight.
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
stub "$FIXTURE/venv/bin/pip" 'exit 0'
stub "$FIXTURE/venv/bin/boxmunge-server" '[[ "$1" != --version ]] || echo "boxmunge 1.5.0"; exit 0'
stub "$FIXTURE/venv/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
[[ "${2:-}" != *get_build_version* ]] || echo "1.5.0"
exit 0'
export PATH="$FIXTURE/bin:$PATH"

RELEASE="$(mktemp -d)"
export RELEASE
mkdir -p "$RELEASE/boxmunge/on-server"
for f in requirements-build.txt requirements-tui.txt requirements-mcp.txt; do
    echo "${f%.txt}==1" > "$RELEASE/boxmunge/$f"
done
echo "1.5.0 ops" > "$RELEASE/boxmunge/on-server/OPERATIONS.md"
tar czf "$RELEASE/boxmunge-1.5.0.tar.gz" -C "$RELEASE" boxmunge
echo "0000  boxmunge-1.5.0.tar.gz" > "$RELEASE/SHA256SUMS"
touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"

# The live 1.4.0 slot a: its stash refuses, as for a stray symlink. Its
# python records every log line, alert, blocklisting and failure report.
new_root a
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
mock_server a 'if [[ "$1 $2" == "stash create" ]]; then
    echo "ERROR: Cannot stash: these are symlinks: /opt/boxmunge/projects/app/secrets.env" >&2
    exit 1
fi
[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
rm "$BOXMUNGE_ROOT/env-a/bin/python"
stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
echo "a-python: level=${BM_LEVEL:-} logmsg=${BM_MSG:-} title=${BM_TITLE:-} msg=${BM_MESSAGE:-} reason=${BM_REASON:-} stage=${BM_STAGE:-} $*" >> "$BOXMUNGE_ROOT/calls"'
: > "$BOXMUNGE_ROOT/calls"
calls() { cat "$BOXMUNGE_ROOT/calls"; }

run_shim target 1.5.0
expect 1 "Cannot stash: these are symlinks" "a refused stash fails the upgrade, showing why"
[[ "$(readlink "$BOXMUNGE_ROOT/env-active")" == *env-a && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
    && pass "the proven slot stays live and the half-built standby is dropped" \
    || fail "live=$(readlink "$BOXMUNGE_ROOT/env-active"), env-b exists: $([[ -e "$BOXMUNGE_ROOT/env-b" ]] && echo yes || echo no)"
grep -q "level=error logmsg=upgrade to 1.5.0 aborted before any change: stash creation failed: ERROR: Cannot stash" "$BOXMUNGE_ROOT/calls" \
    && pass "the failure is logged as an error" || fail "no error log line: $(calls)"
grep -q "title=boxmunge upgrade failed msg=The platform stash failed, so the upgrade to 1.5.0 stopped before changing anything (not blocklisted; auto-update will retry it). Fix this and retry: ERROR: Cannot stash" "$BOXMUNGE_ROOT/calls" \
    && pass "the operator is alerted locally" || fail "no local alert: $(calls)"
! grep -q "add_to_blocklist" "$BOXMUNGE_ROOT/calls" && ! grep -q "stage=preflight" "$BOXMUNGE_ROOT/calls" \
    && pass "the release is neither blocklisted nor reported" || fail "blocklisted or reported: $(calls)"
[[ "$(cat "$BOXMUNGE_ROOT/config/version")" == 1.4.0 ]] && pass "the installed version is unchanged" \
    || fail "version is $(cat "$BOXMUNGE_ROOT/config/version")"
drop_root

rm -rf "$FIXTURE" "$RELEASE"
finish
