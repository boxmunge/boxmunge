#!/usr/bin/env bash
# tests/shim/test_cosign_verify.sh — a release whose signature cosign refuses.
# A bad signature and a Sigstore outage (cosign asks Rekor online) look the
# same to the shim, so the first refusal of a version is alerted and logged
# with cosign's own reason but not blocklisted or reported, and auto-update
# retries it with a fresh download; a second refusal in a row blocklists and
# reports it. The count is kept in root-only upgrade-root/, and a verified
# signature clears it. Only cosign, curl and the venv are stubbed.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins: curl serves a local release; cosign records the directory it was
# asked to verify in, and with FAIL_COSIGN set refuses it, printing the
# deprecation warnings cosign 3 gives for the detached flags, then a reason
# over several lines with a terminal escape and a tab in it (and with
# FAIL_COSIGN=long, 5000 more characters); python3 -m venv copies in a mock
# venv that passes preflight.
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
stub "$FIXTURE/bin/cosign" 'echo "cosign-dir $(dirname "${@: -1}")" >> "$BOXMUNGE_ROOT/calls"
[[ -n "${FAIL_COSIGN:-}" ]] || { echo "Verified OK" >&2; exit 0; }
echo "Flag --signature has been deprecated, please use --bundle to provide a signature" >&2
echo "Flag --certificate has been deprecated, please use --bundle with --trusted-root to provide the public certificate" >&2
printf "Error: searching log: Get \"https://rekor.sigstore.dev\": \033[31m503\033[0m\n\tmain.go:74: error during command execution\n" >&2
[[ "$FAIL_COSIGN" != long ]] || head -c 5000 /dev/zero | tr "\\0" x >&2
exit 1'
stub "$FIXTURE/venv/bin/pip" 'exit 0'
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

# A complete, correctly checksummed release of 1.5.0 and of 1.6.0.
RELEASE="$(mktemp -d)"
export RELEASE
mkdir -p "$RELEASE/boxmunge/on-server"
for f in requirements-build.txt requirements-tui.txt requirements-mcp.txt; do
    echo "${f%.txt}==1" > "$RELEASE/boxmunge/$f"
done
echo "ops" > "$RELEASE/boxmunge/on-server/OPERATIONS.md"
for v in 1.5.0 1.6.0; do
    tar czf "$RELEASE/boxmunge-$v.tar.gz" -C "$RELEASE" boxmunge
    (cd "$RELEASE" && sha256sum "boxmunge-$v.tar.gz") >> "$RELEASE/SHA256SUMS"
done
touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"

# box <installed version>: slot a live, running that version; its python
# records blocklist, report, alert and log calls, with what they carry.
box() {
    new_root a
    echo "$1" > "$BOXMUNGE_ROOT/config/version"
    echo "proven" > "$BOXMUNGE_ROOT/env-a/known-good"
    mock_server a "[[ \"\$1\" != --version ]] || echo \"boxmunge $1\"; exit 0"
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
case "$*" in
    *add_to_blocklist*) echo "blocklist reason=$BM_REASON" ;;
    *report_failure*) echo "report stage=$BM_STAGE detail=$BM_DETAIL" ;;
    *send_notification*) echo "alert title=$BM_TITLE msg=$BM_MESSAGE" ;;
    -) echo "log level=$BM_LEVEL msg=$BM_MSG detail=$BM_DETAIL" ;;
esac >> "$BOXMUNGE_ROOT/calls"'
    : > "$BOXMUNGE_ROOT/calls"
}

COUNTER_REL="upgrade-root/cosign-failures.json"
counter() { cat "$BOXMUNGE_ROOT/$COUNTER_REL" 2>/dev/null || echo none; }
# count_of <version>: the refusals in a row counted for <version> (0: none).
count_of() {
    python3 -c 'import json, os, sys
p = sys.argv[1]
print(json.load(open(p)).get(sys.argv[2], 0) if os.path.exists(p) else 0)' "$BOXMUNGE_ROOT/$COUNTER_REL" "$1"
}
# seed_count <version> <count>: a count an earlier run left.
seed_count() {
    [[ -d "$BOXMUNGE_ROOT/upgrade-root" ]] || mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
    printf '{"%s": %s}\n' "$1" "$2" > "$BOXMUNGE_ROOT/$COUNTER_REL"
}
calls() { cat "$BOXMUNGE_ROOT/calls"; }
blocklisted() { grep -q "^blocklist " "$BOXMUNGE_ROOT/calls"; }
reported() { grep -q "^report " "$BOXMUNGE_ROOT/calls"; }
live() { readlink "$BOXMUNGE_ROOT/env-active" | sed 's|.*/env-||'; }
untouched() {  # untouched <what>: the proven release is live, the standby dropped
    [[ "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/env-a/known-good")" == proven && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
        && pass "$1: the proven release stays live, the standby is dropped" || fail "$1: live=$(live) $(ls "$BOXMUNGE_ROOT")"
}
file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
# cosign's reason, as the shim must pass it on: one line of printable text.
REASON='Error: searching log: Get "https://rekor.sigstore.dev": ?[31m503?[0m main.go:74: error during command execution'
REASON_RAW_ESC=$'\033'

# --- a verified signature -----------------------------------------------------

box 1.4.0
seed_count 1.5.0 1
run_shim target 1.5.0
expect 0 "probation started" "a verified signature installs"
[[ "$(count_of 1.5.0)" == 0 ]] && pass "a verified signature clears its version's failure count" || fail "count left: $(counter)"
drop_root

# --- the first refusal: alerted with cosign's reason, not blocklisted ----------

box 1.4.0
RC=0; OUT="$(FAIL_COSIGN=1 bash "$SHIM" run 1.5.0 https://example.invalid/ignored security 2>&1)" || RC=$?
expect 1 "Cosign verification of SHA256SUMS FAILED" "the first refusal fails the upgrade"
[[ "$OUT" == *"$REASON"* ]] && pass "the log line carries cosign's reason, on one line" || fail "no reason: $OUT"
[[ "$OUT" == *"1.5.0 not blocklisted"* ]] && pass "the log says it is not blocklisted" || fail "out: $OUT"
[[ "$OUT" != *"No such file"* ]] && pass "a first refusal finds no count without complaint" || fail "out: $OUT"
! blocklisted && ! reported && pass "the first refusal is neither blocklisted nor reported" || fail "calls: $(calls)"
grep -qF "alert title=boxmunge upgrade failed msg=Cosign could not verify the signature of 1.5.0: $REASON" "$BOXMUNGE_ROOT/calls" \
    && pass "the alert carries cosign's reason" || fail "alert: $(calls)"
grep -qF "$REASON" <(grep "^log level=warn " "$BOXMUNGE_ROOT/calls") \
    && pass "the operational log carries cosign's reason" || fail "log: $(calls)"
! grep -q "$REASON_RAW_ESC" "$BOXMUNGE_ROOT/calls" && [[ "$OUT" != *"$REASON_RAW_ESC"* ]] \
    && pass "no terminal escape reaches the log, the alert or the output" || fail "escape passed through"
[[ "$(count_of 1.5.0)" == 1 ]] && pass "the first refusal is counted for 1.5.0" || fail "count: $(counter)"
[[ "$(file_mode "$BOXMUNGE_ROOT/upgrade-root")" == 700 && "$(file_mode "$BOXMUNGE_ROOT/$COUNTER_REL")" == 600 ]] \
    && pass "the count is root-only" || fail "modes: $(file_mode "$BOXMUNGE_ROOT/upgrade-root") $(file_mode "$BOXMUNGE_ROOT/$COUNTER_REL")"
untouched "first refusal"
first_dir="$(sed -n 's/^cosign-dir //p' "$BOXMUNGE_ROOT/calls")"
[[ -n "$first_dir" && ! -e "$first_dir" ]] && pass "the refused download is removed" || fail "download left: '$first_dir'"

# --- the retry: a fresh download; a second refusal blocklists and reports -----

: > "$BOXMUNGE_ROOT/calls"
RC=0; OUT="$(FAIL_COSIGN=1 bash "$SHIM" run 1.5.0 https://example.invalid/ignored security 2>&1)" || RC=$?
expect 1 "blocklisting 1.5.0" "a second refusal in a row blocklists"
second_dir="$(sed -n 's/^cosign-dir //p' "$BOXMUNGE_ROOT/calls")"
[[ -n "$second_dir" && "$second_dir" != "$first_dir" ]] && pass "the retry downloads into a fresh directory" \
    || fail "dirs: '$first_dir' '$second_dir'"
grep -qx "blocklist reason=preflight_failed: cosign_verify" "$BOXMUNGE_ROOT/calls" \
    && pass "blocklisted as preflight_failed: cosign_verify" || fail "calls: $(calls)"
detail="$(sed -n 's/^report stage=preflight detail=//p' "$BOXMUNGE_ROOT/calls")"
[[ "$detail" == "preflight_failed: cosign_verify: Error: searching log:"* ]] \
    && pass "the failure report carries cosign's reason" || fail "report: $(calls)"
[[ "$OUT" == *"$REASON"* ]] && pass "the blocklisting log line carries cosign's reason" || fail "out: $OUT"
[[ "$(count_of 1.5.0)" == 0 ]] && pass "blocklisting forgets the count" || fail "count: $(counter)"
untouched "second refusal"
drop_root

# --- only refusals in a row of the same version count --------------------------

box 1.4.0
seed_count 1.6.0 1
RC=0; OUT="$(FAIL_COSIGN=1 bash "$SHIM" target 1.5.0 2>&1)" || RC=$?
expect 1 "1.5.0 not blocklisted" "another version's refusal does not count against 1.5.0"
! blocklisted && [[ "$(count_of 1.5.0)" == 1 && "$(count_of 1.6.0)" == 1 ]] && pass "each version keeps its own count" \
    || fail "count: $(counter) calls: $(calls)"
drop_root

# deploy can write upgrade-state/, not upgrade-root/: a count planted there is
# not read.
box 1.4.0
echo '{"1.5.0": 1}' > "$BOXMUNGE_ROOT/upgrade-state/cosign-failures.json"
RC=0; OUT="$(FAIL_COSIGN=1 bash "$SHIM" target 1.5.0 2>&1)" || RC=$?
expect 1 "1.5.0 not blocklisted" "a count planted in deploy-writable upgrade-state/ is ignored"
! blocklisted && pass "the planted count blocklists nothing" || fail "calls: $(calls)"
drop_root

# --- cosign's reason is bounded -------------------------------------------------

box 1.4.0
seed_count 1.5.0 1
RC=0; OUT="$(FAIL_COSIGN=long bash "$SHIM" target 1.5.0 2>&1)" || RC=$?
expect 1 "blocklisting 1.5.0" "a long reason still blocklists on the second refusal"
[[ "$OUT" != *"$(head -c 400 /dev/zero | tr '\0' x)"* ]] && pass "a long reason is cut short in the log" \
    || fail "unbounded reason in the log"
detail="$(sed -n 's/^report stage=preflight detail=//p' "$BOXMUNGE_ROOT/calls")"
[[ -n "$detail" && "${#detail}" -le 200 ]] && pass "the report detail fits the fleet service's 200 characters" \
    || fail "detail is ${#detail} long: $detail"
drop_root

# --- repair-deps refuses with the reason and leaves the count alone -------------

box 1.5.0
RC=0; OUT="$(FAIL_COSIGN=1 bash "$SHIM" repair-deps 2>&1)" || RC=$?
expect 1 "(nothing was changed)" "repair-deps refuses an unverified bundle"
[[ "$OUT" == *"$REASON"* ]] && pass "repair-deps says cosign's reason" || fail "out: $OUT"
[[ "$(count_of 1.5.0)" == 0 ]] && ! blocklisted && pass "repair-deps neither counts nor blocklists" \
    || fail "count: $(counter) calls: $(calls)"
drop_root

# deploy may sudo repair-deps. Verifying the installed release must not clear
# a pending release's count, or deploy could keep a release whose signature
# is always refused from ever being blocklisted.
box 1.5.0
stub "$BOXMUNGE_ROOT/env-a/bin/pip" 'exit 0'
seed_count 1.6.0 1
run_shim repair-deps
expect 0 "Installed every hash-pinned dependency of 1.5.0" "repair-deps verifies the installed release"
[[ "$(count_of 1.6.0)" == 1 ]] && pass "repair-deps leaves a pending release's count alone" || fail "count: $(counter)"
RC=0; OUT="$(FAIL_COSIGN=1 bash "$SHIM" target 1.6.0 2>&1)" || RC=$?
expect 1 "blocklisting 1.6.0" "the pending release's next refusal still blocklists it"
drop_root

rm -rf "$FIXTURE" "$RELEASE"
finish
