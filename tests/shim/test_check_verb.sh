#!/usr/bin/env bash
# tests/shim/test_check_verb.sh — `check <version>`, deploy's readiness check
# of a newer release: one JSON answer (check contract 1) on stdout, pass only
# when the bundle's prerequisites hold, its readiness command passes the box
# and its own `upgrade --dry-run` accepts it. Whatever happens, at every
# stage, the upgrade state comes out byte-identical and the scratch is
# removed (run_check asserts both on every run). The refusals are in
# test_check_refusals.sh, the confined runs in test_check_confinement.sh.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016,SC2119  # SC2016: mock bodies are literal bash; SC2119: release takes no args
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=tests/shim/check_fixture.sh
source "$(dirname "$0")/check_fixture.sh"

release

# --- pass ---------------------------------------------------------------------------

box
run_check 1.5.0
expect_check 0 pass complete "" "check: pass prints dry_run.ok true and exits 0"
[[ "$(field 'd["dry_run"]["ok"], d["readiness"]["result"], d["installed"]')" == "(True, 'pass', '1.4.0')" ]] \
    && pass "pass: the readiness answer and the dry run are in the answer" || fail "pass: $JSON"
[[ "$(field '[(p["script"], p["ok"]) for p in d["prerequisites"]]')" == "[('bootstrap/ok.sh', True), ('bootstrap/floor.sh', True)]" ]] \
    && pass "pass: every listed prerequisite ran and is met" || fail "pass prerequisites: $JSON"
grep -q "^pip install --quiet --no-cache-dir --require-hashes -r .*requirements-mcp.txt" "$BOXMUNGE_ROOT/calls" \
    && grep -q "^pip install --quiet --no-cache-dir --no-deps --no-build-isolation .*/upgrade-check/download/boxmunge$" "$BOXMUNGE_ROOT/calls" \
    && pass "the scratch venv is built from the bundle's hash-pinned requirements, then the package alone" \
    || fail "venv build: $(calls)"
grep -qx "venv: lock free" "$BOXMUNGE_ROOT/calls" && grep -qx "readiness: lock held" "$BOXMUNGE_ROOT/calls" \
    && grep -qx "dry_run: lock held" "$BOXMUNGE_ROOT/calls" \
    && pass "upgrade.lock is held for the readiness and dry runs only" || fail "lock: $(calls)"
grep -q "^bm_log info readiness check started {\"version\": \"1.5.0\"}" "$BOXMUNGE_ROOT/calls" \
    && grep -q "^bm_log info readiness check finished {\"version\": \"1.5.0\", \"result\": \"pass\", \"stage\": \"complete\"}" "$BOXMUNGE_ROOT/calls" \
    && pass "the check is logged when it starts and when it ends" || fail "log: $(calls)"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/check-last")" =~ ^[0-9]+$ ]] && pass "a check stamps when it ran" \
    || fail "no stamp: $(ls -la "$BOXMUNGE_ROOT/upgrade-root")"
drop_root

# A bundle that lists no prerequisites has none.
rm -rf "$RELEASE"
release none
box
run_check 1.5.0
expect_check 0 pass complete "" "a bundle without bootstrap/prerequisites has none to run"
[[ "$(field 'd["prerequisites"]')" == "[]" ]] && pass "no prerequisites listed" || fail "prerequisites: $JSON"
drop_root
rm -rf "$RELEASE"
release

# --- fetch ------------------------------------------------------------------------------

box
mv "$RELEASE/boxmunge-1.5.0.tar.gz" "$RELEASE/held.tar.gz"
run_check 1.5.0
expect_check 1 cant_verify fetch "Failed to download bundle" "check: state byte-identical after failure at fetch (cant_verify)"
mv "$RELEASE/held.tar.gz" "$RELEASE/boxmunge-1.5.0.tar.gz"
touch "$BOXMUNGE_ROOT/mock/cosign-fails"
run_check 1.5.0
expect_check 1 cant_verify fetch "Cosign verification of SHA256SUMS FAILED" "check: state byte-identical after failure at cosign (the count is not raised)"
[[ "$(field 'd["readiness"], d["dry_run"]')" == "(None, None)" ]] && pass "a fetch failure has no readiness or dry run" \
    || fail "fetch failure: $JSON"
rm "$BOXMUNGE_ROOT/mock/cosign-fails"
cp "$RELEASE/SHA256SUMS" "$RELEASE/good-sums"
echo "$(printf '0%.0s' {1..64})  boxmunge-1.5.0.tar.gz" > "$RELEASE/SHA256SUMS"
run_check 1.5.0
expect_check 1 cant_verify fetch "Checksum verification FAILED" "check refuses a bundle whose checksum does not match"
mv "$RELEASE/good-sums" "$RELEASE/SHA256SUMS"
ran "^pip " && fail "a failed fetch built a venv: $(calls)" || pass "a failed fetch builds no venv"
drop_root

# --- prerequisites ------------------------------------------------------------------

box
touch "$BOXMUNGE_ROOT/mock/prereq-fails"
run_check 1.5.0
expect_check 1 blocked prerequisites "bootstrap/floor.sh: ERROR: boxmunge needs Python 3.13; this host has ?[31m3.11?[0m." \
    "check: prerequisites fail -> blocked, the script's stderr cleaned into the message"
[[ "$(field '[(p["script"], p["ok"]) for p in d["prerequisites"]], d["readiness"], d["dry_run"]')" \
    == "([('bootstrap/ok.sh', True), ('bootstrap/floor.sh', False)], None, None)" ]] \
    && pass "a failed prerequisite: listed, and no readiness or dry run" || fail "prerequisites: $JSON"
[[ "$(field 'd["prerequisites"][1]["message"]')" != *"checking the floor"* ]] \
    && pass "a prerequisite's stdout is not its message" || fail "stdout in the message: $JSON"
ran "^pip " && fail "pip ran after a failed prerequisite: $(calls)" || pass "check: prerequisites fail -> pip never called"
rm "$BOXMUNGE_ROOT/mock/prereq-fails"
touch "$BOXMUNGE_ROOT/mock/prereq-sleeps"
run_check 1.5.0
expect_check 1 cant_verify prerequisites "could not tell whether this box meets what 1.5.0 needs" \
    "a prerequisite that times out is cant_verify, never blocked"
[[ "$(field 'd["prerequisites"][1]["message"]')" == "did not finish within 60 s; retry when the box is less busy" ]] \
    && pass "the timed-out prerequisite names its limit" || fail "timeout message: $JSON"
drop_root
rm -rf "$RELEASE"

for bad in "../etc/evil.sh" "bootstrap/Floor.sh" "bootstrap/missing.sh" "bootstrap/ok.sh extra" "/bootstrap/ok.sh"; do
    release "bootstrap/ok.sh
$bad"
    box
    RUN_DESC="manifest line '$bad'" run_check 1.5.0
    expect_check 1 cant_verify prerequisites "bootstrap/prerequisites: lists '$bad'" \
        "a manifest line outside ^bootstrap/[a-z0-9-]+\\.sh\$ (or not in the bundle) is refused: $bad"
    ran "boxmunge-check-prereq-" && fail "a prerequisite ran from a refused list: $(calls)" \
        || pass "no prerequisite runs from a list with '$bad'"
    drop_root
    rm -rf "$RELEASE"
done
release

# --- venv -----------------------------------------------------------------------------

box
touch "$BOXMUNGE_ROOT/mock/pip-fails"
run_check 1.5.0
expect_check 1 cant_verify venv "DO NOT MATCH THE HASHES" "check: state byte-identical after failure at venv (pip's output quoted)"
ran "readiness: lock" && fail "the readiness ran without a venv: $(calls)" || pass "a failed venv runs no readiness"
drop_root

# --- readiness ------------------------------------------------------------------------

box
touch "$BOXMUNGE_ROOT/mock/readiness.sleep"
began="$(date +%s)"
run_check 1.5.0
expect_check 1 cant_verify readiness "did not finish within 300 s; retry when the box is less busy" \
    "check: readiness timeout is cant_verify naming the limit"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/check-last")" -ge $((began + STUB_MAX_SECS)) ]] \
    && pass "a check stamps again as it ends: the next waits 10 minutes from its end" \
    || fail "end stamp: $(cat "$BOXMUNGE_ROOT/upgrade-root/check-last"), began $began"
ran "dry_run: lock" && fail "a dry run after a timed-out readiness: $(calls)" || pass "no dry run after a readiness timeout"
rm "$BOXMUNGE_ROOT/mock/readiness.sleep"

rm "$BOXMUNGE_ROOT/mock/readiness.out"
echo "ERROR: unknown command 'upgrade-readiness'" > "$BOXMUNGE_ROOT/mock/readiness.err"
echo 2 > "$BOXMUNGE_ROOT/mock/readiness.rc"
run_check 1.5.0
expect_check 1 cant_verify readiness "upgrade-readiness --json exited 2, a usage error: ERROR: unknown command 'upgrade-readiness'" \
    "check: a target without upgrade-readiness is cant_verify naming it"

for answer in '{"contract": 2, "result": "pass"}|0' '{"contract": true, "result": "pass"}|0' \
              '{"contract": 1, "result": "cant_verify"}|0' '["pass"]|0' 'not json|0' "$PASSING|1" \
              '{"contract": 1, "result": "blocked"}|0'; do
    printf '%s' "${answer%|*}" > "$BOXMUNGE_ROOT/mock/readiness.out"
    echo "${answer##*|}" > "$BOXMUNGE_ROOT/mock/readiness.rc"
    printf 'Finished with result: timeout\n' > "$BOXMUNGE_ROOT/mock/readiness.err"
    RUN_DESC="readiness ${answer}" run_check 1.5.0
    expect_check 1 cant_verify readiness "gave no valid answer (exit ${answer##*|})" \
        "check: state byte-identical after failure at readiness invalid: ${answer}"
done
"$REAL_PYTHON3" -c 'import json; print(json.dumps({"contract": 1, "result": "pass", "pad": "x" * 1048576}))' \
    > "$BOXMUNGE_ROOT/mock/readiness.out"
echo 0 > "$BOXMUNGE_ROOT/mock/readiness.rc"
RUN_DESC="readiness over 1 MiB" run_check 1.5.0
expect_check 1 cant_verify readiness "gave no valid answer" "a readiness answer over 1 MiB is invalid"
rm "$BOXMUNGE_ROOT/mock/readiness.err"
cat > "$BOXMUNGE_ROOT/mock/readiness.out" <<'EOF'
{"contract": 1, "release": "1.5.0", "installed": "1.4.0", "result": "blocked",
 "box": [{"id": "box.compose_version", "severity": "block", "when": "before", "message": "Docker Compose 2.30.0 is too old", "remedy": "apt-get install --only-upgrade docker-compose-plugin"}],
 "projects": [{"name": "app", "result": "pass", "findings": [{"id": "project.compose", "severity": "todo", "when": "before", "message": "pull_policy\u001b[2J must be set", "remedy": "add pull_policy"}]}]}
EOF
echo 1 > "$BOXMUNGE_ROOT/mock/readiness.rc"
run_check 1.5.0
expect_check 1 blocked complete "found what blocks the upgrade: box: Docker Compose 2.30.0 is too old; app: pull_policy?[2J must be set" \
    "check: a blocked readiness gives blocked with the findings"
[[ "$(field 'd["readiness"]["box"][0]["id"], d["readiness"]["projects"][0]["findings"][0]["remedy"], d["dry_run"]["ok"]')" \
    == "('box.compose_version', 'add pull_policy', True)" ]] \
    && pass "the readiness findings are in the answer, and the dry run still ran" || fail "blocked answer: $JSON"
[[ "$JSON" != *$'\033'* ]] && pass "no raw control character reaches the answer" || fail "raw escape in: $JSON"
drop_root

# --- dry run ----------------------------------------------------------------------------

box
printf 'Checking projects...\nERROR: project app holds a staged release; resolve it first\n' > "$BOXMUNGE_ROOT/mock/dry_run.out"
echo 1 > "$BOXMUNGE_ROOT/mock/dry_run.rc"
run_check 1.5.0
expect_check 1 blocked dry_run "upgrade --dry-run) of 1.5.0 refused (exit 1)" "check: state byte-identical after failure at dry run"
[[ "$(field 'd["dry_run"]["ok"], d["dry_run"]["output"].splitlines()[-1]')" \
    == "(False, 'ERROR: project app holds a staged release; resolve it first')" ]] \
    && pass "the dry run's own words are in dry_run.output" || fail "dry run output: $JSON"
rm "$BOXMUNGE_ROOT/mock/dry_run.out" "$BOXMUNGE_ROOT/mock/dry_run.rc"
touch "$BOXMUNGE_ROOT/mock/dry_run.sleep"
run_check 1.5.0
expect_check 1 cant_verify dry_run "did not finish within 300 s; retry when the box is less busy" \
    "a dry run that times out is cant_verify"
drop_root

# --- the upgrade lock and the box changing under the check ------------------------

box
exec 6<>"$BOXMUNGE_ROOT/upgrade-root/upgrade.lock"
flock -n 6
run_check 1.5.0
expect_check 1 cant_verify readiness "an upgrade is in progress; retry after it" \
    "check: an upgrade holding the lock gives cant_verify \"an upgrade is in progress\""
exec 6>&-
ran "readiness: lock" && fail "the readiness ran while an upgrade held the lock" || pass "no readiness run beside an upgrade"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips")" == 3 ]] && pass "a busy lock counts no check-probation skip" \
    || fail "lock-skips: $(cat "$BOXMUNGE_ROOT/upgrade-root/lock-skips")"
touch "$BOXMUNGE_ROOT/mock/bump-version"
RUN_DESC="installed release changed" run_check 1.5.0
expect_check 1 cant_verify readiness "the box was upgraded during the check; run upgrade-check --version 1.5.0 again" \
    "a check whose box was upgraded meanwhile asks to be run again"
drop_root

# check-probation is not kept waiting while a check downloads and builds.
box
mkfifo "$BOXMUNGE_ROOT/mock/venv-fifo"
STUB_MAX_SECS=120 bash "$SHIM" check 1.5.0 > "$BOXMUNGE_ROOT/held.json" 2>&1 &
held=$!
for _ in $(seq 1 600); do [[ ! -e "$BOXMUNGE_ROOT/mock/venv-started" ]] || break; sleep 0.1; done
run_shim check-probation
expect 0 "" "check: check-probation is not blocked during fetch/venv"
[[ "$OUT" != *"Another upgrade is in progress"* ]] && pass "check-probation took upgrade.lock during the venv build" \
    || fail "check-probation skipped: $OUT"
# Opened read-write, the FIFO never blocks this shell, held reader or not.
exec 5<>"$BOXMUNGE_ROOT/mock/venv-fifo"
echo go >&5
exec 5>&-
rc=0; wait "$held" || rc=$?
[[ "$rc" -eq 0 ]] && pass "the held check then finishes" || fail "held check: rc=$rc $(cat "$BOXMUNGE_ROOT/held.json")"
drop_root

rm -rf "$RELEASE" "$FIXTURE"
finish
