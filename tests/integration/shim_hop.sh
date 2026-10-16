#!/usr/bin/env bash
# tests/integration/shim_hop.sh <fail|ok> <old-shim> — run as root in a
# throwaway container by test_shim_hop.py.
#
# A box on release 1.4.0, running an older release's upgrade shim, upgrades
# to a 1.5.0 bundle built from this tree (mounted at /bundle). The old shim
# does what it always did: installs the bundle's scripts/boxmunge-upgrade
# over itself, then, if it is new enough, re-runs the bundle's install.sh.
# install.sh here is a stand-in: `fail` exits like an apt outage, `ok` runs
# the real install.sh's shim-install section. Then the installed shim must
# work. Network, signing, pip and the venv are stubbed.
# shellcheck disable=SC2016  # stub bodies are literal bash
set -uo pipefail
MODE="$1" OLD="$2"
R=/opt/boxmunge
mkdir -p /stub/bin /rel /mockvenv/bin
REALPY="$(command -v python3)" REALSHA="$(command -v sha256sum)"
st() { printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"; chmod +x "$1"; }
st /stub/bin/python3 "if [[ \"\$1 \$2\" == '-m venv' ]]; then mkdir -p \"\$3\"; cp -R /mockvenv/bin \"\$3/\"; exit 0; fi; exec $REALPY \"\$@\""
st /stub/bin/curl 'cp "/rel/$(basename "${@: -1}")" "$3"'
st /stub/bin/cosign 'exit 0'
st /stub/bin/visudo 'exit 0'
st /stub/bin/sha256sum "if [[ \"\$1\" == -c ]]; then cat >/dev/null; exit 0; fi; exec $REALSHA \"\$@\""
st /mockvenv/bin/pip 'exit 0'
st /mockvenv/bin/boxmunge-server 'case "$1" in --version) echo "boxmunge 1.5.0";; esac; exit 0'
st /mockvenv/bin/python 'if [[ "$1" == "-" ]]; then cat >/dev/null; exit 0; fi
case "$2" in
    *write_probation*) printf "{\"version\": \"%s\", \"previous_slot\": \"%s\", \"started_at\": \"x\", \"expires_at\": \"%s\"}\n" \
        "$BM_VERSION" "$BM_PREV_SLOT" "$(date -u -d "+6 hours" +%Y-%m-%dT%H:%M:%S+00:00)" > /opt/boxmunge/upgrade-state/probation.json ;;
    *get_build_version*) echo 1.5.0 ;;
esac
exit 0'

# The release: the built bundle, with install.sh replaced by the stand-in.
cp -R /bundle/boxmunge /rel/boxmunge
case "$MODE" in
    fail) printf '#!/usr/bin/env bash\necho "apt-get update failed (simulated)"; exit 100\n' > /rel/boxmunge/install.sh ;;
    ok) { printf '#!/usr/bin/env bash\nset -e\nSCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"\nBOXMUNGE_ROOT=/opt/boxmunge\n'
          sed -n '/^# Install the boxmunge-upgrade shim/,/bin\/boxmunge-upgrade.d"$/p' /bundle/boxmunge/install.sh
        } > /rel/boxmunge/install.sh ;;
    *) echo "usage: shim_hop.sh <fail|ok> <old-shim>" >&2; exit 2 ;;
esac
tar czf /rel/boxmunge-1.5.0.tar.gz -C /rel boxmunge
echo "0  boxmunge-1.5.0.tar.gz" > /rel/SHA256SUMS
touch /rel/SHA256SUMS.sig /rel/SHA256SUMS.cert

# The box: 1.4.0 live in slot a, the old shim installed, and a library
# directory left by a pre-release build of the split.
mkdir -p "$R"/{upgrade-state,bin/boxmunge-upgrade.d,state,config,docs,env-a}
cp -R /mockvenv/bin "$R/env-a/"
st "$R/env-a/bin/boxmunge-server" 'case "$1" in --version) echo "boxmunge 1.4.0";; esac; exit 0'
echo 1.4.0 > "$R/config/version"
echo a > "$R/upgrade-state/active-slot"
ln -s "$R/env-a" "$R/env-active"
echo docs > "$R/docs/OPERATIONS.md"
install -m 0755 "$OLD" "$R/bin/boxmunge-upgrade"
export PATH="/stub/bin:$PATH" BOXMUNGE_SUDOERS_FILE=/tmp/sudoers-boxmunge

rc=0
bash "$R/bin/boxmunge-upgrade" target 1.5.0 > /tmp/hop.log 2>&1 || rc=$?
echo "HOP rc=$rc"
echo "SHIM_IS_BUNDLED=$(cmp -s "$R/bin/boxmunge-upgrade" /bundle/boxmunge/scripts/boxmunge-upgrade && echo yes || echo no)"
echo "LIVE=$(readlink "$R/env-active")"
echo "PROBATION=$([[ -f "$R/upgrade-state/probation.json" ]] && echo yes || echo no)"
echo "LEFTOVER_LIBS=$([[ -e "$R/bin/boxmunge-upgrade.d" ]] && echo yes || echo no)"
for c in "check-probation" "run 1.5.1 https://example.com/x" "target 1.5.1"; do
    rc=0
    # shellcheck disable=SC2086  # word-split the subcommand on purpose
    out="$(bash "$R/bin/boxmunge-upgrade" $c 2>&1)" || rc=$?
    echo "CMD ${c%% *} rc=$rc :: $(echo "$out" | tr '\n' ' ' | cut -c1-2000)"
done
echo "--- hop log"
cat /tmp/hop.log
