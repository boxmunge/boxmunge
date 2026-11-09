#!/usr/bin/env bash
# tests/shim/test_repair_deps.sh — repair-deps installs the installed
# release's hash-pinned dependencies into the live slot, from that release's
# bundle, fetched and verified as an upgrade fetches it. It runs during
# probation without touching the standby (the rollback target) or the
# probation, and refuses, before downloading anything, when the live slot is
# not the installed release or an upgrade or rollback is still unfinished.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins: curl serves a local release (and records what it fetched), cosign
# accepts it unless told not to, df reports 100MB free when LOW_DISK is set,
# and each slot's pip records its arguments and fails when FAIL_PIP is set
# (and with FAIL_PIP=break also stops the slot's boxmunge-server running).
# sha256sum is the real one: release() writes a true SHA256SUMS. No test
# reaches the network (tests/shim/test_bundle_verification.sh has the
# checksum failures).
FIXTURE="$(mktemp -d)"
mkdir -p "$FIXTURE/bin"
stub() {  # stub <path> <bash body>
    printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"
    chmod +x "$1"
}
stub "$FIXTURE/bin/curl" 'echo "curl ${*: -1}" >> "$BOXMUNGE_ROOT/calls"; cp "$RELEASE/$(basename "${@: -1}")" "$3"'
stub "$FIXTURE/bin/cosign" '[[ -z "${FAIL_COSIGN:-}" ]]'
REAL_DF="$(command -v df)"
stub "$FIXTURE/bin/df" "if [[ -n \"\${LOW_DISK:-}\" ]]; then printf 'Filesystem 1M-blocks Used Available\\nfake 1000 900 100\\n'; exit 0; fi
exec '$REAL_DF' \"\$@\""
export PATH="$FIXTURE/bin:$PATH"

# release <requirements file>...: a 1.5.0 bundle shipping those files.
release() {
    RELEASE="$(mktemp -d)"
    export RELEASE
    mkdir -p "$RELEASE/boxmunge"
    local f
    for f in "$@"; do echo "${f%.txt}==1" > "$RELEASE/boxmunge/$f"; done
    tar czf "$RELEASE/boxmunge-1.5.0.tar.gz" -C "$RELEASE" boxmunge
    (cd "$RELEASE" && sha256sum boxmunge-1.5.0.tar.gz > SHA256SUMS)
    touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"
}

# on_probation: 1.5.0 is live in slot a, on probation; slot b holds the proven
# 1.4.0, the rollback target. Each slot's pip and python record their calls.
on_probation() {
    new_root a
    echo "1.5.0+def5678" > "$BOXMUNGE_ROOT/config/version"
    echo "proven" > "$BOXMUNGE_ROOT/env-b/known-good"
    mock_server a '[[ "$1" != --version ]] || echo "boxmunge 1.5.0+def5678"; exit 0'
    mock_server b '[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    local s
    for s in a b; do
        stub "$BOXMUNGE_ROOT/env-$s/bin/pip" 'echo "pip $0 $*" >> "$BOXMUNGE_ROOT/calls"
[[ "${FAIL_PIP:-}" != break ]] || printf "#!/usr/bin/env bash\nexit 1\n" > "$(dirname "$0")/boxmunge-server"
[[ -z "${FAIL_PIP:-}" ]]'
        rm "$BOXMUNGE_ROOT/env-$s/bin/python"
        stub "$BOXMUNGE_ROOT/env-$s/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
echo "python $0 msg=${BM_MSG:-} reason=${BM_REASON:-} $*" >> "$BOXMUNGE_ROOT/calls"'
    done
    write_probation "1.5.0" "b" "$SOON"
    cp "$BOXMUNGE_ROOT/upgrade-state/probation.json" "$BOXMUNGE_ROOT/probation.before"
    : > "$BOXMUNGE_ROOT/calls"
}

calls() { cat "$BOXMUNGE_ROOT/calls"; }
installs() { grep "^pip " "$BOXMUNGE_ROOT/calls" || true; }
downloaded() { grep -q "^curl " "$BOXMUNGE_ROOT/calls"; }

# untouched <description>: the standby, probation, blocklist and slots are as
# on_probation left them.
untouched() {
    [[ "$(cat "$BOXMUNGE_ROOT/env-b/known-good")" == proven ]] && pass "$1: the rollback target survives" \
        || fail "$1: the rollback target was changed"
    cmp -s "$BOXMUNGE_ROOT/upgrade-state/probation.json" "$BOXMUNGE_ROOT/probation.before" \
        && pass "$1: probation left as it was" || fail "$1: probation changed"
    [[ "$(readlink "$BOXMUNGE_ROOT/env-active")" == "$BOXMUNGE_ROOT/env-a" ]] && pass "$1: no swap" \
        || fail "$1: env-active now $(readlink "$BOXMUNGE_ROOT/env-active")"
    [[ "$(calls)" != *add_to_blocklist* && "$(calls)" != *report_failure* ]] \
        && pass "$1: nothing blocklisted or reported" || fail "$1: blocklisted or reported: $(calls)"
}

ALL=(requirements-build.txt requirements-tui.txt requirements-mcp.txt)

# --- during probation: the live slot gets every pinned file -------------------

release "${ALL[@]}"
on_probation
run_shim repair-deps
expect 0 "Installed every hash-pinned dependency of 1.5.0 into the live slot a" "repair-deps works during probation"
[[ "$(calls)" == *"curl https://github.com/boxmunge/boxmunge/releases/download/v1.5.0/boxmunge-1.5.0.tar.gz"* ]] \
    && pass "it fetches the installed release's bundle" || fail "fetched: $(calls)"
[[ "$(calls)" == *"curl https://github.com/boxmunge/boxmunge/releases/download/v1.5.0/SHA256SUMS.sig"* ]] \
    && pass "it fetches the release's signature" || fail "fetched: $(calls)"
deps="$(installs)"
[[ "$(printf '%s\n' "$deps" | grep -c .)" -eq 1 && "$deps" == "pip $BOXMUNGE_ROOT/env-a/bin/pip "*"--require-hashes"* ]] \
    && pass "one hash-pinned pip run, in the live slot" || fail "installs: $deps"
for f in "${ALL[@]}"; do
    [[ "$deps" == *" -r "*"/boxmunge/$f"* ]] && pass "the live slot gets $f" || fail "$f not installed: $deps"
done
[[ "$deps" != *"--no-deps"* ]] && pass "the package itself is not reinstalled" || fail "installs: $deps"
[[ "$(calls)" == *"msg=dependencies repaired"* ]] && pass "the repair is logged" || fail "not logged: $(calls)"
untouched "repair during probation"
drop_root

# --- with no probation it works the same --------------------------------------

on_probation
rm "$BOXMUNGE_ROOT/upgrade-state/probation.json" "$BOXMUNGE_ROOT/probation.before"
run_shim repair-deps
expect 0 "Installed every hash-pinned dependency of 1.5.0" "repair-deps works with no probation"
[[ "$(installs)" == "pip $BOXMUNGE_ROOT/env-a/bin/pip "* ]] && pass "no probation: the live slot is installed into" \
    || fail "installs: $(installs)"
drop_root

# --- refusals before anything is downloaded ----------------------------------

on_probation
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
run_shim repair-deps
expect 1 "The live slot env-a runs boxmunge '1.5.0', but $BOXMUNGE_ROOT/config/version records 1.4.0" \
    "a live slot that is not the installed release is refused"
! downloaded && [[ -z "$(installs)" ]] && pass "mismatch: nothing downloaded or installed" || fail "mismatch: $(calls)"
untouched "mismatch"
drop_root

on_probation
echo "1.5.0" > "$BOXMUNGE_ROOT/env-a/upgrade-inflight"
run_shim repair-deps
expect 1 "an earlier upgrade or rollback was interrupted" "an unfinished upgrade is refused"
! downloaded && [[ -z "$(installs)" ]] && pass "unfinished upgrade: nothing downloaded or installed" \
    || fail "unfinished upgrade: $(calls)"
drop_root

on_probation
printf '1.6.0\napply\n0\n' > "$BOXMUNGE_ROOT/env-b/rollback-inflight"
run_shim repair-deps
expect 1 "an earlier upgrade or rollback was interrupted" "an unfinished rollback is refused"
! downloaded && pass "unfinished rollback: nothing downloaded" || fail "unfinished rollback: $(calls)"
drop_root

on_probation
run_shim repair-deps 1.5.0
expect 1 "Usage: boxmunge-upgrade repair-deps" "repair-deps takes no arguments"
! downloaded && pass "extra argument: nothing downloaded" || fail "extra argument: $(calls)"
drop_root

on_probation
PATH="$BUSYLOCK:$PATH" run_shim repair-deps
expect 1 "Another upgrade is in progress" "repair-deps waits for a running upgrade"
! downloaded && pass "busy lock: nothing downloaded" || fail "busy lock: $(calls)"
drop_root

# --- a bundle that fails verification, or lacks a pinned file, installs nothing

on_probation
RC=0
OUT="$(FAIL_COSIGN=1 bash "$SHIM" repair-deps 2>&1)" || RC=$?
expect 1 "Cosign verification of SHA256SUMS FAILED" "an unverified bundle is refused"
[[ "$OUT" == *"(nothing was changed)"* ]] && pass "the refusal says nothing changed" || fail "out: $OUT"
[[ -z "$(installs)" ]] && pass "unverified bundle: nothing installed" || fail "installed: $(installs)"
untouched "unverified bundle"
drop_root
rm -rf "$RELEASE"

release requirements-build.txt requirements-tui.txt
on_probation
run_shim repair-deps
expect 1 "Bundle 1.5.0 has no hash-pinned requirements-mcp.txt; refusing an unpinned install" \
    "a bundle without requirements-mcp.txt is refused"
[[ -z "$(installs)" ]] && pass "incomplete bundle: nothing installed" || fail "installed: $(installs)"
drop_root
rm -rf "$RELEASE"

# --- too little disk space is refused before downloading ----------------------

release "${ALL[@]}"
on_probation
RC=0
OUT="$(LOW_DISK=1 bash "$SHIM" repair-deps 2>&1)" || RC=$?
expect 1 "Insufficient disk space: 100MB available, need 250MB" "repair-deps checks free space"
! downloaded && [[ -z "$(installs)" ]] && pass "low disk: nothing downloaded or installed" || fail "low disk: $(calls)"
drop_root

# --- a pip failure fails noisily, without blocklisting, and says whether the
# --- live slot still runs ------------------------------------------------------

on_probation
RC=0
OUT="$(FAIL_PIP=1 bash "$SHIM" repair-deps 2>&1)" || RC=$?
expect 1 "pip could not install the hash-pinned dependencies of 1.5.0 into the live slot a" "a pip failure is reported"
[[ "$OUT" == *"its boxmunge-server still runs; retry once the cause"* ]] \
    && pass "the pip failure says the live slot still runs, and to retry" || fail "out: $OUT"
untouched "pip failure"
drop_root

on_probation
RC=0
OUT="$(FAIL_PIP="break" bash "$SHIM" repair-deps 2>&1)" || RC=$?
expect 1 "its boxmunge-server NO LONGER RUNS: inspect env-a as supervisor" \
    "a pip failure that breaks the live slot says so"
drop_root
rm -rf "$RELEASE"

rm -rf "$FIXTURE"
finish
