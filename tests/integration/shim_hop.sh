#!/usr/bin/env bash
# tests/integration/shim_hop.sh <floor|ok|fail|rollback> <old-shim> <installed> — run
# as root in a throwaway container by test_shim_hop.py, whose image holds this
# tree's package, numbered $NEW, installed in /relvenv.
#
# A box on release <installed>, running an older release's upgrade shim,
# targets a $NEW bundle built from this tree (mounted at /bundle). The
# pre-flight the old shim runs in the venv it built (its import test,
# `--version` and `upgrade --dry-run`) is this tree's real code, run exactly
# as that shim invokes it: it decides whether the old shim goes any further.
#
#   floor    <installed> is below the upgrade floor. The pre-flight must
#            refuse and leave the box as it was. Then the box takes the way
#            out the refusal names: `target $BRIDGE` (a stand-in bundle that
#            ships the real $BRIDGE shim) and `clear-blocklist $NEW`.
#   ok|fail|rollback
#            <installed> is at or above the floor. The old shim installs the
#            bundle's scripts/boxmunge-upgrade over itself and runs the
#            bundle's install.sh, a stand-in: `fail` exits like an apt outage,
#            `ok` runs the real install.sh's steps that tell a shim's run from
#            one by hand and act on it (the floor check, the venv install, the
#            shim install, deploy's sudo rule as the new shim writes it, and
#            the version record) and installs the bundle's systemd units.
#            Then the installed shim must work, and deploy's rule must be the
#            new shim's. `rollback` is `ok` whose `upgrade --apply` fails
#            after the swap: the old shim rolls back, and must put the
#            previous release's units back.
# Network, signing, pip, systemctl and the venvs are stubbed: a venv is the
# stubs plus a `release` file naming what pip "installed" into it. pip and
# systemctl record their calls. Each release is served from /rel/v<version>/,
# with upgrade-notes.json (no release in it is breaking, so no readiness
# check runs) listed in its SHA256SUMS. The systemd units live in /tmp/units:
# the box starts with the units of the previous release, this tree's minus
# the ones 0.12 added, plus the timers 0.12 retired. visudo is the real one
# (the image has sudo): every rule a shim writes must pass it.
# shellcheck disable=SC2016  # stub bodies are literal bash
set -uo pipefail
MODE="$1" OLD="$2" WAS="$3"
NEW="$(/relvenv/bin/pip show boxmunge-server | sed -n 's/^Version: //p')"
BRIDGE="$(/relvenv/bin/python -c 'from boxmunge.upgrade_floor import BRIDGE_RELEASE; print(BRIDGE_RELEASE)')"
NEXT=99.0.0  # a release that does not exist
R=/opt/boxmunge
mkdir -p /stub/bin /rel /mockvenv/bin
REALPY="$(command -v python3)" REALSHA="$(command -v sha256sum)"
st() { printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"; chmod +x "$1"; }
st /stub/bin/python3 "if [[ \"\$1 \$2\" == '-m venv' ]]; then mkdir -p \"\$3\"; cp -R /mockvenv/bin \"\$3/\"; exit 0; fi; exec $REALPY \"\$@\""
st /stub/bin/curl 'u="${@: -1}"; cp "/rel/$(basename "$(dirname "$u")")/$(basename "$u")" "$3"'
st /stub/bin/cosign 'exit 0'
st /stub/bin/systemctl 'echo "$*" >> /tmp/systemctl.log'
st /stub/bin/sha256sum "if [[ \"\$1\" == -c ]]; then cat >/dev/null; exit 0; fi; exec $REALSHA \"\$@\""
st /mockvenv/bin/pip 'echo "$0 $*" >> /tmp/pip.log
venv="$(dirname "$0")/.."
[[ "$1" != show ]] || echo "Version: $(cat "$venv/release")"
src="${*: -1}"; src="${src%\[tui\]}"
[[ "$1" != install || ! -f "$src/pyproject.toml" ]] \
    || sed -n "s/^version = \"\(.*\)\"$/\1/p" "$src/pyproject.toml" > "$venv/release"'
# The pre-flight of the $NEW release is the real one. Its `upgrade --apply`
# runs while the old shim is mid-upgrade and has installed the new shim: with
# /tmp/watch-apply, the new shim must see that upgrade and stay out of it.
# Then the apply records the version, as the real one does, noting the one it
# found (install.sh must not have recorded $NEW before the swap).
st /mockvenv/bin/boxmunge-server 'rel="$(cat "$(dirname "$0")/../release")"
case "$1 ${2:-}" in
    "--version "*) [[ "$rel" != '"$NEW"' ]] || exec /relvenv/bin/boxmunge-server --version
        echo "boxmunge $rel" ;;
    "upgrade --dry-run") [[ "$rel" != '"$NEW"' ]] || exec /relvenv/bin/boxmunge-server upgrade --dry-run ;;
    "upgrade --apply")
        [[ ! -e /tmp/fail-apply || "$rel" != '"$NEW"' ]] || { echo "apply failed (simulated)"; exit 1; }
        [[ -e /tmp/watch-apply ]] && for c in "target '"$NEXT"'" check-probation; do
            rc=0; bash /opt/boxmunge/bin/boxmunge-upgrade $c > "/tmp/during-${c%% *}.log" 2>&1 || rc=$?
            echo "rc=$rc" >> "/tmp/during-${c%% *}.log"
        done
        cp /opt/boxmunge/config/version /tmp/version-before-apply
        echo "$rel+abc1234" > /opt/boxmunge/config/version ;;
    "stash create") n="boxmunge-stash-$(date -u +%Y-%m-%dT%H%M%S).tar.gz"
        tar czf "/opt/boxmunge/stashes/$n" -T /dev/null; chmod 0600 "/opt/boxmunge/stashes/$n"
        echo "Stash created: $n" ;;
    "health --json") echo "{\"healthy\": true, \"exit_code\": 0, \"checks\": [{\"name\": \"docker\", \"status\": \"ok\", \"detail\": \"\"}]}" ;;
esac; exit 0'
# The blocklist is written as every release since 0.6.3 writes it.
cat > /stub/blocklist.py <<'EOF'
import json, os
path = "/opt/boxmunge/upgrade-state/blocklist.json"
data = json.load(open(path)) if os.path.exists(path) else {}
if "BM_REASON" in os.environ:
    data[os.environ["BM_VERSION"]] = {"reason": os.environ["BM_REASON"], "failed_at": "2026-01-01T00:00:00+00:00"}
else:
    data.pop(os.environ["BM_VERSION"], None)
json.dump(data, open(path, "w"))
EOF
# Every old shim's import test (`import boxmunge; print(boxmunge.__version__)`
# up to v0.9.1, `get_build_version()` after) runs as written in /relvenv.
st /mockvenv/bin/python 'if [[ "$1" == "-" ]]; then cat >/dev/null; exit 0; fi
rel="$(cat "$(dirname "$0")/../release")"
case "$2" in
    *write_probation*) printf "{\"version\": \"%s\", \"previous_slot\": \"%s\", \"started_at\": \"x\", \"expires_at\": \"%s\"}\n" \
        "$BM_VERSION" "$BM_PREV_SLOT" "$(date -u -d "+6 hours" +%Y-%m-%dT%H:%M:%S+00:00)" > /opt/boxmunge/upgrade-state/probation.json ;;
    *add_to_blocklist*|*remove_from_blocklist*) exec '"$REALPY"' -I /stub/blocklist.py ;;
    *get_build_version*|*__version__*) [[ "$rel" != '"$NEW"' ]] || exec /relvenv/bin/python -c "$2"
        echo "$rel" ;;
esac
exit 0'

# release <version> <shim> <install.sh>: the built bundle as that release,
# with its upgrade notes, in /rel/v<version>/.
release() {
    local d="/rel/v$1"
    mkdir -p "$d/src"
    cp -R /bundle/boxmunge "$d/src/boxmunge"
    sed -i "s/^version = \".*\"$/version = \"$1\"/" "$d/src/boxmunge/pyproject.toml"
    cp "$2" "$d/src/boxmunge/scripts/boxmunge-upgrade"
    cp "$3" "$d/src/boxmunge/install.sh"
    tar czf "$d/boxmunge-$1.tar.gz" -C "$d/src" boxmunge
    printf '{"format": 1, "release": "%s", "releases": {"%s": {"class": "feature", "breaking": false}}}\n' \
        "$1" "$1" > "$d/upgrade-notes.json"
    (cd "$d" && sha256sum "boxmunge-$1.tar.gz" upgrade-notes.json > SHA256SUMS)
    touch "$d/SHA256SUMS.sig" "$d/SHA256SUMS.cert"
}
I=/bundle/boxmunge/install.sh
case "$MODE" in
    floor) printf '#!/usr/bin/env bash\ntouch /tmp/install-sh-ran\n' > /tmp/install.sh
           printf '#!/usr/bin/env bash\nexit 0\n' > /tmp/install-bridge.sh
           release "$BRIDGE" "/t/old_shims/boxmunge-upgrade-v$BRIDGE" /tmp/install-bridge.sh ;;
    fail) printf '#!/usr/bin/env bash\necho "apt-get update failed (simulated)"; exit 100\n' > /tmp/install.sh ;;
    ok|rollback) { printf '#!/usr/bin/env bash\nset -e\nSCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"\nBOXMUNGE_ROOT=/opt/boxmunge\n'
          sed -n '/^FROM_UPGRADE_SHIM=0$/,/^fi$/p' "$I"
          grep -F 'bootstrap/upgrade-floor.sh"' "$I"
          sed -n '/^if \[\[ "${FROM_UPGRADE_SHIM}" -eq 0 \]\]; then$/,/^fi$/p' "$I"
          grep -F 'bootstrap/install-shim.sh"' "$I"
          echo 'cp "$BOXMUNGE_SUDOERS_FILE" /tmp/sudoers-before-install-sh'
          grep -Fx '"${BOXMUNGE_ROOT}/bin/boxmunge-upgrade" install-sudoers' "$I"
          sed -n '/^INSTALLED_VERSION=/,/^fi$/p' "$I"
          # The jobs directory and gate the installer makes. The new shim makes
          # them deploy's when missing, and this box has no deploy user.
          echo 'install -d -m 0750 "$BOXMUNGE_ROOT/state/jobs"; install -m 0660 /dev/null "$BOXMUNGE_ROOT/state/jobs/gate.lock"'
          # The release's units, as bootstrap/systemd-units.sh installs them.
          echo 'rm -f "$BOXMUNGE_SYSTEMD_DIR"/boxmunge-*; cp "$SCRIPT_DIR"/systemd/boxmunge-* "$BOXMUNGE_SYSTEMD_DIR/"'
          echo 'ls "$BOXMUNGE_SYSTEMD_DIR" | sort | paste -sd, - > /tmp/units-after-install-sh'
        } > /tmp/install.sh ;;
    *) echo "usage: shim_hop.sh <floor|ok|fail|rollback> <old-shim> <installed>" >&2; exit 2 ;;
esac
release "$NEW" /bundle/boxmunge/scripts/boxmunge-upgrade /tmp/install.sh

# The box: <installed> live in slot a, with the old shim. Releases before
# 0.10.1 kept docs/ as a plain directory.
mkdir -p "$R"/{upgrade-state,bin,state/deploy,config,projects,caddy/sites,env-a/boxmunge-docs}
install -d -m 0770 "$R/stashes"
printf 'hostname: box.example.com\nadmin_email: ops@example.com\n' > "$R/config/boxmunge.yml"
cp -R /mockvenv/bin "$R/env-a/"
echo "$WAS" > "$R/env-a/release"
echo "$WAS+abc1234" > "$R/config/version"
echo a > "$R/upgrade-state/active-slot"
ln -s "$R/env-a" "$R/env-active"
echo docs > "$R/env-a/boxmunge-docs/OPERATIONS.md"
case "$WAS" in
    0.[0-9].*|0.10.0) cp -R "$R/env-a/boxmunge-docs" "$R/docs" ;;
    *) cp -R "$R/env-a/boxmunge-docs" "$R/.docs.seed"; ln -s .docs.seed "$R/docs" ;;
esac
install -m 0755 "$OLD" "$R/bin/boxmunge-upgrade"
export PATH="/stub/bin:$PATH" BOXMUNGE_SUDOERS_FILE=/tmp/sudoers-boxmunge BOXMUNGE_SYSTEMD_DIR=/tmp/units
mkdir -p "$BOXMUNGE_SYSTEMD_DIR"
cp /bundle/boxmunge/systemd/boxmunge-* "$BOXMUNGE_SYSTEMD_DIR/"
rm "$BOXMUNGE_SYSTEMD_DIR"/boxmunge-{maintenance,kev-watch,audit-rotate}.{timer,service} "$BOXMUNGE_SYSTEMD_DIR/boxmunge-autofix.service"
for t in cve-scan container-update; do
    printf '[Timer]\nOnCalendar=daily\nUnit=boxmunge-%s.service\n' "$t" > "$BOXMUNGE_SYSTEMD_DIR/boxmunge-$t.timer"
done
units() { ls "$BOXMUNGE_SYSTEMD_DIR" | sort | paste -sd, -; }
echo "UNITS_BEFORE=$(units)"

shim() {  # shim <log> <args...>: run the installed shim, print its exit code
    local log="$1" rc=0; shift
    bash "$R/bin/boxmunge-upgrade" "$@" > "$log" 2>&1 || rc=$?
    echo "$rc"
}
box_facts() {  # box_facts <prefix>
    echo "${1}LIVE=$(readlink "$R/env-active")"
    echo "${1}PROBATION=$([[ -f "$R/upgrade-state/probation.json" ]] && echo yes || echo no)"
    echo "${1}BLOCKLIST=$($REALPY -c 'import json, sys; print(",".join(sorted(json.load(open(sys.argv[1])))) or "none")' \
        "$R/upgrade-state/blocklist.json" 2>/dev/null || echo none)"
    echo "${1}VERSION_RECORD=$(cat "$R/config/version")"
}
[[ "$MODE" != ok ]] || touch /tmp/watch-apply
[[ "$MODE" != rollback ]] || touch /tmp/fail-apply
echo "HOP rc=$(shim /tmp/hop.log target "$NEW")"
rm -f /tmp/watch-apply /tmp/fail-apply
[[ ! -e "$BOXMUNGE_SUDOERS_FILE" ]] || cp "$BOXMUNGE_SUDOERS_FILE" /tmp/sudoers-after-hop
box_facts ""
echo "UNITS=$(units)"
echo "UNITS_AFTER_INSTALL_SH=$(cat /tmp/units-after-install-sh 2>/dev/null || echo none)"
echo "DISABLED=$(sed -n 's/^disable --now //p' /tmp/systemctl.log 2>/dev/null | sort | paste -sd, -)"
echo "ENABLED=$(sed -n 's/^enable --now //p' /tmp/systemctl.log 2>/dev/null | tr ' ' '\n' | sort | paste -sd, -)"
for shim in "$OLD" /bundle/boxmunge/scripts/boxmunge-upgrade "/t/old_shims/boxmunge-upgrade-v$BRIDGE"; do
    ! cmp -s "$R/bin/boxmunge-upgrade" "$shim" || echo "SHIM_IS=$(basename "$shim")"
done
echo "INSTALL_SH_RAN=$([[ -e /tmp/install-sh-ran ]] && echo yes || echo no)"
echo "ENV_A_PIP_CALLS=$(grep -cE '^/opt/boxmunge/env-(a|active)/bin/pip install' /tmp/pip.log 2>/dev/null || true)"
echo "VERSION_BEFORE_APPLY=$(cat /tmp/version-before-apply 2>/dev/null || echo none)"
if [[ "$MODE" == floor ]]; then
    echo "BRIDGE rc=$(shim /tmp/bridge.log target "$BRIDGE")"
    box_facts BRIDGE_
    echo "BRIDGE_SHIM_IS_THE_BRIDGE_RELEASES=$(cmp -s "$R/bin/boxmunge-upgrade" "/t/old_shims/boxmunge-upgrade-v$BRIDGE" && echo yes || echo no)"
    echo "CLEAR rc=$(shim /tmp/clear.log clear-blocklist "$NEW")"
    box_facts CLEARED_
else
    for c in "check-probation" "run $NEXT https://example.com/x feature" "target $NEXT"; do
        # shellcheck disable=SC2086  # word-split the subcommand on purpose
        rc="$(shim /tmp/cmd.log $c)"
        echo "CMD ${c%% *} rc=$rc :: $(tr '\n' ' ' < /tmp/cmd.log | cut -c1-2000)"
    done
    for f in /tmp/during-*.log; do
        [[ -e "$f" ]] || continue
        name="${f#/tmp/during-}"
        echo "DURING ${name%.log} $(tail -n 1 "$f") :: $(head -n -1 "$f" | tr '\n' ' ' | cut -c1-2000)"
    done
fi
for log in hop bridge clear; do
    [[ -e "/tmp/$log.log" ]] || continue
    echo "--- $log log"
    cat "/tmp/$log.log"
done
for rule in before-install-sh after-hop; do
    [[ -e "/tmp/sudoers-$rule" ]] || continue
    echo "--- sudoers $rule"
    cat "/tmp/sudoers-$rule"
done
echo "--- end"
