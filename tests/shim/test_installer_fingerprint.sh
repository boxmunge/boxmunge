#!/usr/bin/env bash
# tests/shim/test_installer_fingerprint.sh — the installer fingerprint, which
# decides whether an upgrade re-runs the bundle's install.sh, is kept in
# root-only upgrade-root/. The old place, state/installer.sha256, is
# deploy-writable: read by name it let deploy point root at any file (leaking
# its first bytes to the shim's stderr and boxmunge.log), block the upgrade
# forever on a FIFO with upgrade.lock held, or plant the bundle's hash so
# root skipped install.sh. It is never read now; a box without a fingerprint
# in the new place runs install.sh once, the safe default.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins: curl serves a local release, cosign accepts it, python3 -m venv
# copies in a mock venv for 1.5.0.
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
stub "$FIXTURE/venv/bin/pip" 'exit 0'
stub "$FIXTURE/venv/bin/boxmunge-server" '[[ "$1" != --version ]] || echo "boxmunge 1.5.0"; exit 0'
stub "$FIXTURE/venv/bin/python" 'if [[ "$1" == "-" ]]; then cat >/dev/null; exit 0; fi
case "$2" in
    *write_probation*) printf "{\"version\": \"%s\", \"previous_slot\": \"%s\", \"expires_at\": \"'"$SOON"'\"}\n" \
        "$BM_VERSION" "$BM_PREV_SLOT" > "$BOXMUNGE_ROOT/upgrade-state/probation.json"
        echo "record before probation.json: $(cat "$BOXMUNGE_ROOT/upgrade-root/probation-expiry")" >> "$BOXMUNGE_ROOT/calls" ;;
    *get_build_version*) echo "1.5.0" ;;
esac
exit 0'
export PATH="$FIXTURE/bin:$PATH"

# A 1.5.0 release whose install.sh only records that it ran.
RELEASE="$(mktemp -d)"
export RELEASE
mkdir -p "$RELEASE/boxmunge/on-server" "$RELEASE/boxmunge/bootstrap"
for f in requirements-build.txt requirements-tui.txt requirements-mcp.txt; do echo "x==1" > "$RELEASE/boxmunge/$f"; done
echo "ops" > "$RELEASE/boxmunge/on-server/OPERATIONS.md"
echo "# helper" > "$RELEASE/boxmunge/bootstrap/helper.sh"
# A built shim and the SFTP wrapper, which the upgrade self-updates into bin/.
mkdir -p "$RELEASE/boxmunge/scripts"
for name in boxmunge-upgrade boxmunge-sftp; do printf '#!/usr/bin/env bash\necho new %s\n' "$name" > "$RELEASE/boxmunge/scripts/$name"; done
printf '#!/usr/bin/env bash\necho "install.sh ran: $*" >> "$BOXMUNGE_ROOT/calls"\nexit 0\n' > "$RELEASE/boxmunge/install.sh"
tar czf "$RELEASE/boxmunge-1.5.0.tar.gz" -C "$RELEASE" boxmunge
(cd "$RELEASE" && sha256sum boxmunge-1.5.0.tar.gz > SHA256SUMS)
touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"
# The fingerprint install.sh records for that bundle (the pipeline both use).
BUNDLE_HASH="$( (cd "$RELEASE/boxmunge" && find . \( -path ./install.sh -o -path './bootstrap/*' -o -path './src/boxmunge/sshd/*' -o -path './system/*' -o -path './systemd/*' -o -path ./caddy/compose.yml -o -path './caddy/maintenance/*' \) -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | awk '{print $1}')"

# box: slot a live on 1.4.0, with the running shim and SFTP wrapper in bin/;
# its python records bm_log messages and details.
box() {
    new_root a
    for name in boxmunge-upgrade boxmunge-sftp; do printf '#!/usr/bin/env bash\necho old\n' > "$BOXMUNGE_ROOT/bin/$name"; done
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    mock_server a '[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
echo "a-python: msg=${BM_MSG:-} detail=${BM_DETAIL:-}" >> "$BOXMUNGE_ROOT/calls"'
    : > "$BOXMUNGE_ROOT/calls"
}
calls() { cat "$BOXMUNGE_ROOT/calls"; }
root_print() { mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"; echo "$BUNDLE_HASH" > "$BOXMUNGE_ROOT/upgrade-root/installer.sha256"; }

# --- the fingerprint in upgrade-root/ decides ---------------------------------

box
root_print
echo "1.5.0 1" > "$BOXMUNGE_ROOT/upgrade-root/live-slot-failed"
run_shim target 1.5.0
expect 0 "install.sh unchanged" "a matching root-only fingerprint skips install.sh"
[[ "$(calls)" != *"install.sh ran"* ]] && pass "install.sh did not run" || fail "install.sh ran: $(calls)"
# Not about the fingerprint, but this is a whole upgrade: a new probation
# starts with no failure count left by an earlier one of the same version.
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/live-slot-failed" ]] && pass "entering probation clears the live-slot failure count" \
    || fail "live-slot-failed survived into the new probation"
# Root records the probation before probation.json exists: deploy can write
# that file, so only a recorded probation is acted on (test_probation_record).
recorded="$(calls | sed -n 's/^record before probation.json: //p')"
read -r slot version expiry <<< "$recorded"
[[ "$slot $version" == "b 1.5.0" && "$expiry" -gt $(( $(date +%s) + 6 * 3600 - 120 )) ]] \
    && pass "the probation is recorded root-only before probation.json is written" || fail "recorded: '$recorded'"
drop_root

# --- the shim's self-update ----------------------------------------------------

# The running shim is replaced by rename, never written through: bash reads a
# script from its file as it runs, and install(1) rewrites the destination's
# inode in place. Likewise the SFTP wrapper, which sshd runs for every request.
inode() { python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_ino)' "$1"; }
box
root_print
echo "half" > "$BOXMUNGE_ROOT/bin/.boxmunge-upgrade.AbC123"  # left by a killed run
before_shim="$(inode "$BOXMUNGE_ROOT/bin/boxmunge-upgrade")"
before_sftp="$(inode "$BOXMUNGE_ROOT/bin/boxmunge-sftp")"
exec 5< "$BOXMUNGE_ROOT/bin/boxmunge-upgrade"  # keep the old inode alive, as the running shim does
run_shim target 1.5.0
expect 0 "Self-updating upgrade shim" "the upgrade self-updates the shim"
for name in boxmunge-upgrade boxmunge-sftp; do
    [[ "$(cat "$BOXMUNGE_ROOT/bin/$name")" == *"echo new $name"* && -x "$BOXMUNGE_ROOT/bin/$name" ]] \
        && pass "bin/$name is the bundle's, executable" || fail "bin/$name: $(ls -l "$BOXMUNGE_ROOT/bin/$name")"
done
[[ "$(inode "$BOXMUNGE_ROOT/bin/boxmunge-upgrade")" != "$before_shim" \
    && "$(inode "$BOXMUNGE_ROOT/bin/boxmunge-sftp")" != "$before_sftp" ]] \
    && pass "both are new files renamed into place" || fail "a bin/ file was rewritten in place"
[[ "$(cat <&5)" == *"echo old"* ]] && pass "the running shim's file is left as it was" \
    || fail "the running shim's bytes changed under it"
exec 5<&-
[[ -z "$(find "$BOXMUNGE_ROOT/bin" -name '.boxmunge-*')" ]] && pass "no temp left in bin/" \
    || fail "temps left: $(ls -a "$BOXMUNGE_ROOT/bin")"
drop_root

box
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
echo "0000000000000000000000000000000000000000000000000000000000000000" > "$BOXMUNGE_ROOT/upgrade-root/installer.sha256"
run_shim target 1.5.0
expect 0 "running system upgrade" "a different root-only fingerprint runs install.sh"
[[ "$(calls)" == *"install.sh ran: --upgrade-shim"* ]] && pass "install.sh ran with --upgrade-shim" \
    || fail "install.sh did not run: $(calls)"
drop_root

# --- a box upgrading from a release that kept it in state/ --------------------

box
echo "$BUNDLE_HASH" > "$BOXMUNGE_ROOT/state/installer.sha256"
run_shim target 1.5.0
expect 0 "No installer fingerprint in $BOXMUNGE_ROOT/upgrade-root" \
    "with no root-only fingerprint the upgrade says so"
[[ "$(calls)" == *"install.sh ran: --upgrade-shim"* ]] \
    && pass "a hash in deploy-writable state/ (old place, or planted) does not skip install.sh" \
    || fail "install.sh skipped on the strength of state/installer.sha256: $(calls)"
drop_root

# A link there is not followed: nothing of its target reaches the output or log.
box
SECRET="$(mktemp)"
echo 'root:$y$j9T$SALTSALTSALT$hashhashhash' > "$SECRET"
chmod 600 "$SECRET"
ln -s "$SECRET" "$BOXMUNGE_ROOT/state/installer.sha256"
run_shim target 1.5.0
expect 0 "probation started" "a link at state/installer.sha256 does not stop the upgrade"
[[ "$OUT$(calls)" != *'root:$y$'* ]] && pass "the link's target is not read into the output or the log" \
    || fail "the link's target leaked: $OUT $(calls)"
drop_root
rm -f "$SECRET"

# A FIFO there does not block the upgrade with the lock held.
box
mkfifo "$BOXMUNGE_ROOT/state/installer.sha256"
run_shim_within 120 "$BOXMUNGE_ROOT/state/installer.sha256" target 1.5.0
expect 0 "probation started" "a FIFO at state/installer.sha256 does not block the upgrade"
drop_root

# --- upgrade-root/ is root's: anything but a regular file there is refused ----

box
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
ln -s "$BOXMUNGE_ROOT/config/version" "$BOXMUNGE_ROOT/upgrade-root/installer.sha256"
run_shim target 1.5.0
expect 1 "installer.sha256 is a symlink" "a link at upgrade-root/installer.sha256 is refused"
[[ "$(readlink "$BOXMUNGE_ROOT/env-active")" == "$BOXMUNGE_ROOT/env-a" ]] && pass "the refusal comes before the swap" \
    || fail "swapped despite the refusal"
drop_root

box
mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
mkfifo "$BOXMUNGE_ROOT/upgrade-root/installer.sha256"
run_shim_within 120 "$BOXMUNGE_ROOT/upgrade-root/installer.sha256" target 1.5.0
expect 1 "non-regular file" "a FIFO at upgrade-root/installer.sha256 is refused, not blocked on"
drop_root

# --- install.sh records it there (bootstrap/installer-fingerprint.sh) --------

FINGERPRINT="$REPO_DIR/bootstrap/installer-fingerprint.sh"
mode_of() { python3 -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])' "$1"; }

# Deploy can put anything at the old name, a directory included; install.sh
# must not trip over it (a failed install.sh blocklists the release).
box
mkdir "$BOXMUNGE_ROOT/state/installer.sha256"
RC=0
OUT="$(bash "$FINGERPRINT" record "$RELEASE/boxmunge" 2>&1)" || RC=$?
expect 0 "" "recording succeeds with a directory planted at state/installer.sha256"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/installer.sha256")" == "$BUNDLE_HASH" ]] \
    && pass "the fingerprint recorded is the one the shim computes" || fail "recorded: $(cat "$BOXMUNGE_ROOT/upgrade-root/installer.sha256" 2>&1)"
[[ "$(mode_of "$BOXMUNGE_ROOT/upgrade-root")" == 700 && "$(mode_of "$BOXMUNGE_ROOT/upgrade-root/installer.sha256")" == 600 ]] \
    && pass "upgrade-root/ is 0700 and the fingerprint 0600" \
    || fail "modes: $(mode_of "$BOXMUNGE_ROOT/upgrade-root") $(mode_of "$BOXMUNGE_ROOT/upgrade-root/installer.sha256")"
[[ -d "$BOXMUNGE_ROOT/state/installer.sha256" ]] && pass "the old name is left alone" || fail "the old name was touched"
run_shim target 1.5.0
expect 0 "install.sh unchanged" "the next upgrade of the same installer skips install.sh"
RC=0
OUT="$(bash "$FINGERPRINT" forget 2>&1)" || RC=$?
expect 0 "" "forget succeeds"
[[ ! -e "$BOXMUNGE_ROOT/upgrade-root/installer.sha256" ]] && pass "forget removes the fingerprint" || fail "fingerprint left"
drop_root

box
ln -s "$(mktemp -d)" "$BOXMUNGE_ROOT/upgrade-root"
RC=0
OUT="$(bash "$FINGERPRINT" record "$RELEASE/boxmunge" 2>&1)" || RC=$?
expect 1 "upgrade-root is a symlink" "a linked upgrade-root/ is refused"
drop_root

# install.sh forgets it (in fail_if_incomplete) before an incomplete
# run can exit, and records it last.
INSTALL_SH="$(cat "$REPO_DIR/install.sh")"
forget_at="${INSTALL_SH%%installer-fingerprint.sh\" forget*}"
stale_exit_at="${INSTALL_SH%%$'\n'fail_if_incomplete$'\n'*}"
record_at="${INSTALL_SH%%installer-fingerprint.sh\" record*}"
[[ "${#forget_at}" -lt "${#stale_exit_at}" && "${#stale_exit_at}" -lt "${#record_at}" && "${#record_at}" -lt "${#INSTALL_SH}" ]] \
    && pass "install.sh forgets the fingerprint before the incomplete-run exit and records it at the end" \
    || fail "install.sh does not call bootstrap/installer-fingerprint.sh in that order"
[[ "$INSTALL_SH" != *"state/installer.sha256"* ]] && pass "install.sh no longer touches state/installer.sha256" \
    || fail "install.sh still touches state/installer.sha256"

rm -rf "$FIXTURE" "$RELEASE"
finish
