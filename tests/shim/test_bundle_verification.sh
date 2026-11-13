#!/usr/bin/env bash
# tests/shim/test_bundle_verification.sh — the bundle checksum check
# (fetch_release), shared by an upgrade and repair-deps, run with the real
# sha256sum against a SHA256SUMS that is wrong, misses the bundle, lists it
# twice with different hashes, or rightly lists a bundle that will not
# extract. A bad checksum fails the release: an upgrade blocklists it and
# reports it, repair-deps changes nothing. A bundle that passes its checksum
# but will not extract is the box's fault (a full disk): an upgrade is not
# blocklisted or reported, only alerted. Only cosign (and the network) is
# stubbed.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins: curl serves a local release, cosign accepts it, python3 -m venv
# copies in a mock venv whose pip records its arguments.
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
stub "$FIXTURE/venv/bin/pip" 'echo "pip $0 $*" >> "$BOXMUNGE_ROOT/calls"'
stub "$FIXTURE/venv/bin/boxmunge-server" '[[ "$1" != --version ]] || echo "boxmunge 1.5.0"; exit 0'
stub "$FIXTURE/venv/bin/python" 'if [[ "$1" == "-" ]]; then cat >/dev/null; exit 0; fi
[[ -z "${BM_TITLE:-}" ]] || echo "notify title=$BM_TITLE msg=$BM_MESSAGE" >> "$BOXMUNGE_ROOT/calls"
case "$2" in
    *write_probation*)
        printf "{\"version\": \"%s\", \"previous_slot\": \"%s\", \"expires_at\": \"'"$SOON"'\"}\n" \
            "$BM_VERSION" "$BM_PREV_SLOT" > "$BOXMUNGE_ROOT/upgrade-state/probation.json" ;;
    *get_build_version*) echo "1.5.0" ;;
esac
exit 0'
export PATH="$FIXTURE/bin:$PATH"

BUNDLE=boxmunge-1.5.0.tar.gz

# release <sums>: a complete 1.5.0 release whose SHA256SUMS is <sums>: good,
# bad_hash, missing_entry, duplicate_entry, or corrupt (the tarball is not a
# gzip, and SHA256SUMS rightly lists its hash).
release() {
    RELEASE="$(mktemp -d)"
    export RELEASE
    mkdir -p "$RELEASE/boxmunge/on-server"
    local f
    for f in requirements-build.txt requirements-tui.txt requirements-mcp.txt; do
        echo "${f%.txt}==1" > "$RELEASE/boxmunge/$f"
    done
    echo "1.5.0 ops" > "$RELEASE/boxmunge/on-server/OPERATIONS.md"
    tar czf "$RELEASE/$BUNDLE" -C "$RELEASE" boxmunge
    [[ "$1" != corrupt ]] || head -c 4096 /dev/urandom > "$RELEASE/$BUNDLE"
    local good
    good="$(cd "$RELEASE" && sha256sum "$BUNDLE")"
    case "$1" in
        good|corrupt) echo "$good" ;;
        bad_hash) echo "$(printf '0%.0s' {1..64})  $BUNDLE" ;;
        missing_entry) echo "${good%% *}  boxmunge-install.sh" ;;
        duplicate_entry) printf '%s\n%s  %s\n' "$good" "$(printf 'f%.0s' {1..64})" "$BUNDLE" ;;
    esac > "$RELEASE/SHA256SUMS"
    release_notes "$RELEASE" 1.5.0
    touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"
}

# box <installed version>: slot a live, running that version; its python
# records blocklist, report and alert calls.
box() {
    new_root a
    echo "$1" > "$BOXMUNGE_ROOT/config/version"
    echo "proven" > "$BOXMUNGE_ROOT/env-a/known-good"
    mock_server a "[[ \"\$1\" != --version ]] || echo \"boxmunge $1\"; exit 0"
    stub "$BOXMUNGE_ROOT/env-a/bin/pip" 'echo "pip $0 $*" >> "$BOXMUNGE_ROOT/calls"'
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
echo "a-python: reason=${BM_REASON:-} stage=${BM_STAGE:-} msg=${BM_MESSAGE:-} $*" >> "$BOXMUNGE_ROOT/calls"'
    : > "$BOXMUNGE_ROOT/calls"
}

calls() { cat "$BOXMUNGE_ROOT/calls"; }
installs() { grep "^pip " "$BOXMUNGE_ROOT/calls" || true; }
live() { readlink "$BOXMUNGE_ROOT/env-active" | sed 's|.*/env-||'; }
blocklisted_as() { grep -q "a-python: reason=$1 " "$BOXMUNGE_ROOT/calls"; }
blocklisted() { grep -q "add_to_blocklist" "$BOXMUNGE_ROOT/calls"; }
reported() { grep -q "report_failure" "$BOXMUNGE_ROOT/calls"; }

# want <sums>: for a bad checksum, the message, "|", and the blocklist reason
# an upgrade records.
want() {
    case "$1" in
        bad_hash|duplicate_entry) echo "Checksum verification FAILED|preflight_failed: checksum_mismatch" ;;
        missing_entry) echo "SHA256SUMS does not list $BUNDLE|preflight_failed: checksum_missing_entry" ;;
    esac
}

# --- control: a true SHA256SUMS passes the real check ---------------------------

release good
box 1.5.0
run_shim repair-deps
expect 0 "Installed every hash-pinned dependency of 1.5.0" "repair-deps: a true SHA256SUMS passes"
drop_root
box 1.4.0
run_shim target 1.5.0
expect 0 "probation started" "upgrade: a true SHA256SUMS passes"
[[ "$(live)" == b ]] && pass "upgrade: 1.5.0 is live" || fail "upgrade: live slot is $(live)"
# A targeted upgrade installs a release by version alone: its class is unknown.
grep -qx "notify title=boxmunge upgrade applied msg=Updated to 1.5.0 (targeted upgrade; probation: 6h)" "$BOXMUNGE_ROOT/calls" \
    && pass "a targeted upgrade alerts without claiming a release class" || fail "target alert: $(calls)"
drop_root

# The auto-update timer passes the class discovery gave; the alert names it.
for class in security breakfix feature; do
    box 1.4.0
    run_shim run 1.5.0 https://example.invalid/ignored "$class"
    expect 0 "probation started" "run: a $class release installs"
    case "$class" in
        security) title="boxmunge security update applied" ;;
        breakfix) title="boxmunge break-fix update applied" ;;
        feature) title="boxmunge feature update applied" ;;
    esac
    grep -qx "notify title=$title msg=Updated to 1.5.0 (probation: 6h)" "$BOXMUNGE_ROOT/calls" \
        && pass "a $class release alerts as $title" || fail "$class alert: $(calls)"
    drop_root
done
box 1.4.0
run_shim run 1.5.0 https://example.invalid/ignored urgent
expect 1 "Unknown release class 'urgent' for 1.5.0" "run refuses an unknown release class"
[[ -z "$(installs)" ]] && pass "an unknown class installs nothing" || fail "unknown class: $(installs)"
drop_root
rm -rf "$RELEASE"

# --- a bad checksum fails the release --------------------------------------------

for sums in bad_hash missing_entry duplicate_entry; do
    expected="$(want "$sums")"
    message="${expected%%|*}" reason="${expected#*|}"
    release "$sums"

    box 1.5.0
    run_shim repair-deps
    expect 1 "$message (nothing was changed)" "repair-deps refuses a bundle with $sums"
    [[ -z "$(installs)" ]] && pass "repair-deps, $sums: nothing installed" || fail "repair-deps, $sums: $(installs)"
    ! blocklisted && ! reported && pass "repair-deps, $sums: not blocklisted or reported" \
        || fail "repair-deps, $sums: $(calls)"
    drop_root

    box 1.4.0
    run_shim target 1.5.0
    expect 1 "$message" "upgrade refuses a bundle with $sums"
    blocklisted_as "$reason" && pass "upgrade, $sums: blocklisted as $reason" || fail "upgrade, $sums: $(calls)"
    [[ "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/env-a/known-good")" == proven && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
        && pass "upgrade, $sums: proven release live, standby dropped" || fail "upgrade, $sums: live=$(live)"
    [[ -z "$(installs)" ]] && pass "upgrade, $sums: nothing installed" || fail "upgrade, $sums: $(installs)"
    drop_root
    rm -rf "$RELEASE"
done

# --- a verified bundle that will not extract is the box's fault -------------------

release corrupt
box 1.5.0
run_shim repair-deps
expect 1 "Failed to extract the verified bundle" "repair-deps reports a bundle that will not extract"
[[ "$OUT" == *"(nothing was changed)"* && -z "$(installs)" ]] && pass "repair-deps, corrupt: nothing changed" \
    || fail "repair-deps, corrupt: $OUT $(installs)"
drop_root

box 1.4.0
run_shim target 1.5.0
expect 1 "Failed to extract the verified bundle" "upgrade reports a bundle that will not extract"
[[ "$OUT" == *"1.5.0 not blocklisted"* ]] && pass "upgrade, corrupt: says it is not blocklisted" || fail "out: $OUT"
! blocklisted && ! reported && pass "upgrade, corrupt: not blocklisted or reported" || fail "upgrade, corrupt: $(calls)"
grep -q "msg=The verified bundle of 1.5.0 did not extract" "$BOXMUNGE_ROOT/calls" \
    && pass "upgrade, corrupt: the operator is alerted" || fail "upgrade, corrupt: no alert: $(calls)"
[[ "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/env-a/known-good")" == proven && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
    && pass "upgrade, corrupt: proven release live, standby dropped" || fail "upgrade, corrupt: live=$(live)"
drop_root
rm -rf "$RELEASE"

# --- the signed sums alone, and one listed file -----------------------------------

# A readiness check or a guide fetches read-only: a verified signature leaves
# the cosign failure count of the version as it was (an upgrade clears it).
release good
box 1.4.0
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
seed='{"1.5.0": 1}'
printf '%s' "$seed" > "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json"
signed_sums() {  # signed_sums [readonly]: fetch 1.5.0's signed sums into a fresh directory
    local dir rc=0
    dir="$(mktemp -d)"
    fetch_signed_sums 1.5.0 "$dir" "$@" || rc=$?
    rm -rf "$dir"
    echo "rc=$rc"
}
out="$(with_shim_functions signed_sums readonly 2>/dev/null)"
[[ "$out" == rc=0 && "$(cat "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json")" == "$seed" ]] \
    && pass "a readonly fetch leaves cosign-failures.json byte-identical" \
    || fail "readonly fetch: $out, count now $(cat "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json")"
fetched() {  # fetched: fetch_release 1.5.0 read-only, as a readiness check does
    local dir rc=0
    dir="$(mktemp -d)"
    fetch_release 1.5.0 "$dir" readonly || rc=$?
    echo "rc=$rc extracted=$([[ -d "$dir/boxmunge" ]] && echo yes || echo no)"
    rm -rf "$dir"
}
out="$(with_shim_functions fetched 2>/dev/null)"
[[ "$out" == "rc=0 extracted=yes" && "$(cat "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json")" == "$seed" ]] \
    && pass "a readonly fetch_release verifies and extracts, leaving the cosign count" \
    || fail "readonly fetch_release: $out, count now $(cat "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json")"
out="$(with_shim_functions signed_sums 2>/dev/null)"
[[ "$out" == rc=0 && "$(cat "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json")" == "{}" ]] \
    && pass "an upgrade's fetch clears the cosign count of a verified version" \
    || fail "upgrade fetch: $out, count now $(cat "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json")"
drop_root
rm -rf "$RELEASE"

# verify_listed <dir> <file> <step>: exactly one line for the file, and its hash.
box 1.4.0
listed() {  # listed <sums content> <file content>: verify_listed of notes.json
    local dir rc=0
    dir="$(mktemp -d)"
    printf '%s' "$2" > "$dir/notes.json"
    printf '%s' "$1" > "$dir/SHA256SUMS"
    verify_listed "$dir" notes.json notes || rc=$?
    echo "rc=$rc step=$FETCH_STEP error=$FETCH_ERROR"
    rm -rf "$dir"
}
good_hash="$(printf 'notes' | sha256sum | awk '{print $1}')"
zeros="$(printf '0%.0s' {1..64})"
out="$(with_shim_functions listed "$good_hash  notes.json" notes 2>/dev/null)"
[[ "$out" == "rc=0 "* ]] && pass "verify_listed passes the one true line" || fail "verify_listed, true line: $out"
out="$(with_shim_functions listed "$good_hash  other.json
$good_hash  notesXjson" notes 2>/dev/null)"
[[ "$out" == "rc=1 step=notes_missing_entry error=Checksum verification FAILED: SHA256SUMS does not list notes.json" ]] \
    && pass "verify_listed refuses a SHA256SUMS without the file's line (a dot is not a wildcard)" \
    || fail "verify_listed, no line: $out"
out="$(with_shim_functions listed "$good_hash  notes.json
$good_hash  notes.json" notes 2>/dev/null)"
[[ "$out" == "rc=1 step=notes_mismatch "* ]] && pass "verify_listed refuses a file listed twice" \
    || fail "verify_listed, twice: $out"
out="$(with_shim_functions listed "$zeros  notes.json" notes 2>/dev/null)"
[[ "$out" == "rc=1 step=notes_mismatch error=Checksum verification FAILED" ]] \
    && pass "verify_listed refuses a wrong hash" || fail "verify_listed, wrong hash: $out"
out="$(with_shim_functions listed "$good_hash  notes.json" tampered 2>/dev/null)"
[[ "$out" == "rc=1 step=notes_mismatch "* ]] && pass "verify_listed refuses a tampered file" \
    || fail "verify_listed, tampered: $out"
drop_root

rm -rf "$FIXTURE"
finish
