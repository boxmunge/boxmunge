#!/usr/bin/env bash
# tests/shim/test_readiness_gate.sh — an upgrade that crosses a breaking
# release (by the target's signed upgrade-notes.json) must pass the target's
# readiness check first, in every mode but force-target. A box that is not
# ready refuses it without blocklisting or reporting anything; a non-crossing
# upgrade installs ungated. After an upgrade the box alerts each project's
# to-dos, which can never fail the upgrade. And once the shim has
# self-updated, the new shim writes deploy's sudo rule.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016,SC2119  # SC2016: stub bodies are literal bash; SC2119: release takes no args
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins: curl serves $RELEASE (exit 22 when the file is not there) and
# records each URL; cosign accepts; python3 -m venv copies in the release's
# venv. Its boxmunge-server answers `upgrade-readiness --json` from
# mock/readiness.out and .rc (sleeping first while mock/readiness.sleep
# exists); its python records alerts, blocklist entries, failure reports and
# log lines in calls, like slot a's.
FIXTURE="$(mktemp -d)"
REAL_PYTHON3="$(command -v python3)"
mkdir -p "$FIXTURE/bin" "$FIXTURE/venv/bin"
stub() {  # stub <path> <bash body>
    printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"
    chmod +x "$1"
}
stub "$FIXTURE/bin/python3" "if [[ \"\$1 \$2\" == '-m venv' ]]; then mkdir -p \"\$3\"; cp -R '$FIXTURE/venv/bin' \"\$3/\"; exit 0; fi
exec '$REAL_PYTHON3' \"\$@\""
stub "$FIXTURE/bin/curl" 'echo "curl ${*: -1}" >> "$BOXMUNGE_ROOT/calls"
f="$RELEASE/$(basename "${@: -1}")"
[[ -f "$f" ]] || exit 22
cp "$f" "$3"'
stub "$FIXTURE/bin/cosign" 'exit 0'
stub "$FIXTURE/venv/bin/pip" 'echo "pip $*" >> "$BOXMUNGE_ROOT/calls"'
stub "$FIXTURE/venv/bin/boxmunge-server" 'case "$1" in
    --version) echo "boxmunge 1.5.0" ;;
    health) exec health-report 0 ;;
    upgrade-readiness)
        echo "readiness ran as $(id -un)" >> "$BOXMUNGE_ROOT/calls"
        [[ ! -e "$BOXMUNGE_ROOT/mock/readiness.sleep" ]] || sleep 30
        cat "$BOXMUNGE_ROOT/mock/readiness.out"
        exit "$(cat "$BOXMUNGE_ROOT/mock/readiness.rc")" ;;
esac
exit 0'
# RECORDER: a slot python that records what the shim does through it.
RECORDER='[[ "$1" != "-" ]] || cat >/dev/null
case "$*" in
    *write_probation*) printf "{\"version\": \"%s\", \"previous_slot\": \"%s\", \"expires_at\": \"'"$SOON"'\"}\n" \
        "$BM_VERSION" "$BM_PREV_SLOT" > "$BOXMUNGE_ROOT/upgrade-state/probation.json" ;;
    *get_build_version*) echo "1.5.0" ;;
    *add_to_blocklist*) echo "blocklist reason=$BM_REASON" >> "$BOXMUNGE_ROOT/calls" ;;
    *report_failure*) echo "report stage=$BM_STAGE" >> "$BOXMUNGE_ROOT/calls" ;;
    *send_notification*) printf "alert p=%s title=%s msg=%s\n" "$BM_PRIORITY" "$BM_TITLE" "$BM_MESSAGE" >> "$BOXMUNGE_ROOT/calls" ;;
    -) echo "log $BM_LEVEL $BM_MSG" >> "$BOXMUNGE_ROOT/calls" ;;
esac
exit 0'
stub "$FIXTURE/venv/bin/python" "$RECORDER"
export PATH="$FIXTURE/bin:$PATH"

TODO='{"contract": 1, "release": "1.5.0", "installed": "1.4.0", "result": "pass", "box": [],
 "projects": [{"name": "app", "result": "pass", "findings": [{"id": "project.compose", "severity": "todo", "when": "after", "message": "pull_policy must be set", "remedy": "add pull_policy: never"}]},
              {"name": "quiet", "result": "pass", "findings": []}]}'
BLOCKED='{"contract": 1, "release": "1.5.0", "installed": "1.4.0", "result": "blocked",
 "box": [{"id": "box.compose_version", "severity": "block", "when": "before", "message": "Docker Compose 2.30.0 is too old", "remedy": "upgrade it"}], "projects": []}'

# release [<breaking version>...]: RELEASE serves a signed 1.5.0 bundle (with
# bootstrap/floor.sh, which fails while mock/prereq-fails exists, and a built
# shim stand-in that records how it is run) and its upgrade-notes.json,
# whose releases table marks the versions named breaking.
release() {
    RELEASE="$(mktemp -d)"
    export RELEASE
    local b="$RELEASE/boxmunge" f
    mkdir -p "$b/on-server" "$b/bootstrap" "$b/scripts"
    for f in requirements-build.txt requirements-tui.txt requirements-mcp.txt; do echo "x==1" > "$b/$f"; done
    echo "ops" > "$b/on-server/OPERATIONS.md"
    echo "bootstrap/floor.sh" > "$b/bootstrap/prerequisites"
    printf '#!/usr/bin/env bash\n[[ -e "$BOXMUNGE_ROOT/mock/prereq-fails" ]] || exit 0\necho "ERROR: boxmunge needs Python 3.13" >&2\nexit 1\n' \
        > "$b/bootstrap/floor.sh"
    printf '#!/usr/bin/env bash\necho "new shim: $*" >> "$BOXMUNGE_ROOT/calls"\n[[ ! -e "$BOXMUNGE_ROOT/mock/sudoers-fails" ]]\n' \
        > "$b/scripts/boxmunge-upgrade"
    tar czf "$RELEASE/boxmunge-1.5.0.tar.gz" -C "$RELEASE" boxmunge
    (cd "$RELEASE" && sha256sum boxmunge-1.5.0.tar.gz > SHA256SUMS)
    release_notes "$RELEASE" 1.5.0 "$@"
    touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"
}

# box [<readiness answer> [<exit code>]]: slot a live on 1.4.0, recording
# like the release's venv; the readiness command will answer as given (the
# to-do answer, exit 0, by default).
box() {
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    echo "proven" > "$BOXMUNGE_ROOT/env-a/known-good"
    mock_server a '[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    stub "$BOXMUNGE_ROOT/env-a/bin/python" "$RECORDER"
    mkdir "$BOXMUNGE_ROOT/mock"
    printf '%s' "${1:-$TODO}" > "$BOXMUNGE_ROOT/mock/readiness.out"
    echo "${2:-0}" > "$BOXMUNGE_ROOT/mock/readiness.rc"
    : > "$BOXMUNGE_ROOT/calls"
}

calls() { cat "$BOXMUNGE_ROOT/calls"; }
ran() { grep -c "$1" "$BOXMUNGE_ROOT/calls" || true; }
live() { readlink "$BOXMUNGE_ROOT/env-active" | sed 's|.*/env-||'; }
# refused_unchanged <description>: the last run was refused by the gate, and
# left the box as it was: 1.4.0 live, no standby, nothing blocklisted or
# reported, no stash made, the operator alerted.
refused_unchanged() {
    [[ "$(live)" == a && "$(cat "$BOXMUNGE_ROOT/env-a/known-good")" == proven && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
        && pass "$1: 1.4.0 live, standby removed" || fail "$1: live=$(live), env-b: $(ls -d "$BOXMUNGE_ROOT"/env-b 2>&1)"
    [[ "$(ran 'blocklist reason')" == 0 && "$(ran 'report stage')" == 0 && ! -e "$BOXMUNGE_ROOT/upgrade-state/blocklist.json" ]] \
        && pass "$1: not blocklisted, no failure report" || fail "$1: $(calls)"
    [[ "$(ls "$BOXMUNGE_ROOT/stashes")" == "$OLD_STASH" && ! -e "$BOXMUNGE_ROOT/upgrade-state/probation.json" ]] \
        && pass "$1: no stash, no probation" || fail "$1: stashes $(ls "$BOXMUNGE_ROOT/stashes")"
    grep -q "^alert p=0 title=boxmunge upgrade to 1.5.0 refused msg=Not upgrading to 1.5.0: " "$BOXMUNGE_ROOT/calls" \
        && grep -q "^log warn upgrade refused: box not ready" "$BOXMUNGE_ROOT/calls" \
        && pass "$1: the operator is alerted (priority 0) and it is logged" || fail "$1: no alert: $(calls)"
}
REFUSAL_TAIL="Nothing was changed and 1.5.0 is not blocklisted. See what to fix: upgrade-check --version 1.5.0 (deploy shell). The operator can override as supervisor: sudo"

# --- crossing a breaking release ----------------------------------------------------

release 1.4.5
box "$BLOCKED" 1
run_shim target 1.5.0
expect 1 "Not upgrading to 1.5.0: its readiness check found what blocks it: box: Docker Compose 2.30.0 is too old. $REFUSAL_TAIL" \
    "gate: target crossing a breaking release with readiness blocked refuses"
[[ "$OUT" == *"crosses the breaking release 1.4.5"* && "$OUT" == *"boxmunge-upgrade force-target 1.5.0"* ]] \
    && pass "the refusal names the breaking release crossed and the operator's override" || fail "out: $OUT"
refused_unchanged "gate, blocked"
[[ "$(ran 'readiness ran as')" == 1 && "$(ran '^pip ')" -ge 1 ]] && pass "the readiness ran once, on the built standby" \
    || fail "readiness runs: $(calls)"
drop_root

box "$BLOCKED" 1
mock_server a 'case "$1" in
    --version) echo "boxmunge 1.4.0" ;;
    _discover-update) echo "{\"action\": \"upgrade\", \"version\": \"1.5.0\", \"class\": \"feature\"}" ;;
esac
exit 0'
run_shim auto
expect 1 "Not upgrading to 1.5.0: its readiness check found what blocks it" "gate: auto crossing a breaking release is gated too"
refused_unchanged "gate, auto"
drop_root

box "$BLOCKED" 1
run_shim run 1.5.0 https://example.invalid/ignored feature
expect 1 "Not upgrading to 1.5.0: its readiness check found what blocks it" "gate: the timer's run is gated too"
drop_root

box "$TODO"
touch "$BOXMUNGE_ROOT/mock/prereq-fails"
run_shim target 1.5.0
expect 1 "Not upgrading to 1.5.0: this box does not meet what 1.5.0 needs: bootstrap/floor.sh: ERROR: boxmunge needs Python 3.13. $REFUSAL_TAIL" \
    "gate: crossing with a failed prerequisite refuses"
[[ "$(ran '^pip ')" == 0 && "$(ran 'readiness ran')" == 0 ]] && pass "gate: crossing with a failed prerequisite refuses before pip runs" \
    || fail "pip ran: $(calls)"
refused_unchanged "gate, prerequisite"
drop_root

box "$TODO"
touch "$BOXMUNGE_ROOT/mock/readiness.sleep"
STUB_MAX_SECS=2 run_shim target 1.5.0
expect 1 "its readiness check did not finish within 300 s, so this box could not be verified; retry when it is less busy. $REFUSAL_TAIL" \
    "gate: readiness timeout refuses (can't verify), not blocklisted"
refused_unchanged "gate, timeout"
rm "$BOXMUNGE_ROOT/mock/readiness.sleep"
printf 'Traceback: no such command' > "$BOXMUNGE_ROOT/mock/readiness.out"
echo 2 > "$BOXMUNGE_ROOT/mock/readiness.rc"
run_shim target 1.5.0
expect 1 "its readiness check gave no valid answer (exit 2), so this box could not be verified" \
    "gate: a readiness answer that is not contract 1 refuses (can't verify)"
drop_root

# Crossing, and ready: installs, the readiness running as deploy.
box "$TODO"
run_shim target 1.5.0
expect 0 "The readiness check of 1.5.0 passed" "gate: crossing with readiness pass installs"
[[ "$(live)" == b && "$(ran 'readiness ran as')" == 2 ]] && pass "1.5.0 live; readiness ran at the gate and after" \
    || fail "live=$(live): $(calls)"
grep -q "^systemd-run .*--unit=boxmunge-check-readiness-[0-9]* .*-p User=deploy " "$BOXMUNGE_ROOT/calls" \
    && pass "the gate's readiness runs as deploy, confined" || fail "readiness unit: $(grep '^systemd-run' "$BOXMUNGE_ROOT/calls")"
drop_root
rm -rf "$RELEASE"

# --- not crossing ------------------------------------------------------------------

for breaking in "" 1.4.0 1.3.0 1.6.0; do
    # shellcheck disable=SC2086  # none, or one version
    release $breaking
    box "$BLOCKED" 1
    run_shim target 1.5.0
    expect 0 "probation started" "gate: a non-crossing target is not gated and installs (breaking: ${breaking:-none})"
    [[ "$(ran 'boxmunge-check-prereq-')" == 0 && "$(ran 'readiness ran')" == 1 && "$(live)" == b ]] \
        && pass "no prerequisites or gate readiness without a crossing (breaking: ${breaking:-none})" || fail "ran: $(calls)"
    drop_root
    rm -rf "$RELEASE"
done

release 1.4.5
box "$BLOCKED" 1
run_shim force-target 1.5.0
expect 0 "probation started" "gate: force-target skips the gate"
[[ "$(ran 'upgrade-notes.json')" == 0 && "$(ran 'boxmunge-check-prereq-')" == 0 ]] \
    && pass "gate: force-target skips the gate and downloads no notes" || fail "force-target: $(calls)"
# After it, the release's readiness still reports blocked: a release bug, alerted.
grep -q "^alert p=0 title=boxmunge 1.5.0: readiness reports blocked (a boxmunge bug) msg=1.5.0 is installed" "$BOXMUNGE_ROOT/calls" \
    && pass "post-install: a blocked answer after an install is alerted as a bug, priority 0" || fail "bug alert: $(calls)"
drop_root

# --- the notes are part of the signed release ----------------------------------------

note_case() {  # note_case <reason> <description>: target 1.5.0 fails its pre-flight, blocklisted as <reason>
    box "$TODO"
    run_shim target 1.5.0
    expect 1 "" "$2"
    grep -q "^blocklist reason=preflight_failed: $1$" "$BOXMUNGE_ROOT/calls" && [[ "$(live)" == a && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
        && pass "$2: blocklisted as $1, standby removed" || fail "$2: $(calls)"
    [[ "$(ran '^pip ')" == 0 ]] && pass "$2: nothing installed" || fail "$2: pip ran"
    drop_root
}
sums_without_notes() { grep -v ' upgrade-notes.json$' "$RELEASE/SHA256SUMS" > "$RELEASE/s"; mv "$RELEASE/s" "$RELEASE/SHA256SUMS"; }
release 1.4.5
sums_without_notes
note_case notes_missing_entry "gate: the notes missing from SHA256SUMS are a preflight failure (blocklisted)"
(cd "$RELEASE" && sha256sum boxmunge-1.5.0.tar.gz > SHA256SUMS)
release_notes "$RELEASE" 1.5.0 1.4.5
echo '{"format": 1, "release": "1.5.0", "releases": {"1.5.0": {"breaking": false}}}' > "$RELEASE/upgrade-notes.json"
note_case notes_mismatch "notes that do not match their signed hash are a preflight failure"
rm "$RELEASE/upgrade-notes.json"
note_case notes_download "notes the release does not publish are a preflight failure"
for bad in '{"format": 2, "release": "1.5.0", "releases": {"1.5.0": {"breaking": false}}}' \
           '{"format": 1, "release": "1.4.9", "releases": {"1.5.0": {"breaking": false}}}' \
           '{"format": 1, "release": "1.5.0", "releases": {"1.4.5": {"breaking": true}}}' \
           '{"format": 1, "release": "1.5.0", "releases": {"1.5.0": {"breaking": "no"}}}' \
           '{"format": true, "release": "1.5.0", "releases": {"1.5.0": {"breaking": false}}}' 'not json'; do
    (cd "$RELEASE" && sha256sum boxmunge-1.5.0.tar.gz > SHA256SUMS)
    printf '%s' "$bad" > "$RELEASE/upgrade-notes.json"
    (cd "$RELEASE" && sha256sum upgrade-notes.json >> SHA256SUMS)
    note_case notes_invalid "signed notes the shim cannot read are a preflight failure, never a skipped gate: $bad"
done
rm -rf "$RELEASE"

# --- the new shim writes the sudo rule; the to-do alert ------------------------------

release
box "$TODO"
run_shim target 1.5.0
expect 0 "probation started" "an upgrade with project to-dos installs"
order="$(grep -n "^log info shim self-updated\|^new shim: install-sudoers$" "$BOXMUNGE_ROOT/calls" | cut -d: -f2- | tr '\n' '|')"
[[ "$order" == "log info shim self-updated|new shim: install-sudoers|" ]] \
    && pass "upgrade: the new shim's install-sudoers runs after the self-update" || fail "order: $order"
todo="$(grep -A3 "^alert p=-1 title=boxmunge 1.5.0: project to-dos before their next deploy msg=" "$BOXMUNGE_ROOT/calls")"
[[ "$todo" == *"msg=app: pull_policy must be set (add pull_policy: never)
Run validate <project> before deploying each one."* && "$todo" != *quiet* ]] \
    && pass "upgrade: post-install to-do alerts at priority -1, one line per project with a to-do" || fail "to-do alert: $(calls)"
grep -n "^alert" "$BOXMUNGE_ROOT/calls" | tail -1 | grep -q "title=boxmunge break-fix update applied\|title=boxmunge upgrade applied" \
    && pass "the applied alert still goes out, last" || fail "applied alert: $(grep '^alert' "$BOXMUNGE_ROOT/calls")"
drop_root

box '{"contract": 1, "result": "pass", "box": [], "projects": [{"name": "app", "findings": []}]}'
run_shim target 1.5.0
expect 0 "probation started" "an upgrade with nothing to do installs"
[[ "$(ran '^alert p=-1')" == 0 ]] && pass "nothing to do: no to-do alert" || fail "to-do alert: $(calls)"
drop_root

box "garbage" 1
run_shim target 1.5.0
expect 0 "Upgrade to 1.5.0 complete, probation started" "upgrade: post-install to-do alerts at priority -1 and never fails the upgrade"
[[ "$OUT" == *"WARN: the readiness check of 1.5.0 gave no to-do list (exit 1)"* && "$(ran '^alert p=-1')" == 0 ]] \
    && grep -q "^log warn post-install to-do list unavailable" "$BOXMUNGE_ROOT/calls" \
    && pass "an unreadable to-do list is a logged warning, no alert" || fail "garbage to-do: $OUT"
drop_root

box "$TODO"
touch "$BOXMUNGE_ROOT/mock/sudoers-fails"
run_shim target 1.5.0
expect 1 "The new shim could not write deploy's sudo rule" "a new shim that cannot write the sudo rule fails the pre-flight"
grep -q "^blocklist reason=preflight_failed: install_sudoers$" "$BOXMUNGE_ROOT/calls" && [[ "$(live)" == a ]] \
    && pass "the sudo rule failure is blocklisted before the swap" || fail "sudoers failure: $(calls)"
drop_root
rm -rf "$RELEASE"

rm -rf "$FIXTURE"
finish
