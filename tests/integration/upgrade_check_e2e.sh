#!/usr/bin/env bash
# tests/integration/upgrade_check_e2e.sh <case> <installed> <image> — run as
# root in a throwaway container by test_upgrade_check_e2e.py, whose image
# holds this tree's package, numbered $NEXT, in /relvenv, Docker's CLI and
# Compose (the host's daemon is at /var/run/docker.sock) and sudo.
#
# A box on release <installed> runs the upgrade shim that release ships (the
# built shim of the bundle mounted at /bundle) and deploy's sudo rule as that
# shim writes it. Release $NEXT is the bundle, compiled upgrade notes that
# mark $NEXT breaking, and a SHA256SUMS listing both. deploy asks, as an
# agent does: `upgrade-check --version $NEXT --json`, which sudoes the
# shim's `check`; in case `blocked` also `upgrade --target $NEXT`'s sudo.
#
#   floor99  $NEXT's bootstrap/python-floor.sh asks for Python 99.0.
#   blocked  two deployed projects: shop, whose compose.yml has a pull_policy
#            deploy refuses, and blog, whose image is not on this box (<image>
#            is, and shop uses it).
#   noready  $NEXT's CLI has no upgrade-readiness command.
#
# Stubbed: the network (curl serves /rel), cosign, and systemd: the
# stand-in systemd-run runs the unit's command here, as <user> with its
# groups (so deploy reaches Docker as a box's deploy does), its output where
# the unit sends it, its environment and limit, with the stand-ins first on
# PATH, but without the sandbox. A venv is the stand-ins below: pip records
# its calls and copies an installed bundle's src/ into the venv, whose
# boxmunge-server and python then run that code (on /relvenv's packages).
# The stand-ins are in /usr/local/sbin, first on sudo's secure_path.
set -euo pipefail
CASE="$1" INSTALLED="$2" IMAGE="$3"
NEXT="$(/relvenv/bin/pip show boxmunge-server | sed -n 's/^Version: //p')"
R=/opt/boxmunge
S=/usr/local/sbin
REALPY=/usr/local/bin/python3
mkdir -p /e2e /rel /mockvenv/bin

cat > "$S/curl" <<'EOF'
#!/usr/bin/env bash
exec cp "/rel/$(basename "${@: -1}")" "$3"
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$S/cosign"
cat > "$S/python3" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-} \${2:-}" == "-m venv" ]]; then mkdir -p "\$3"; cp -R /mockvenv/bin "\$3/"; exit 0; fi
exec $REALPY "\$@"
EOF
cat > "$S/systemd-run" <<'EOF'
#!/usr/bin/env bash
unit="" secs="" user=root out=inherit err=inherit dir="" envs=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --) shift; break ;;
        --unit=*) unit="${1#--unit=}" ;;
        --setenv=PATH=*) envs+=("PATH=/usr/local/sbin:${1#--setenv=PATH=}") ;;
        --setenv=*) envs+=("${1#--setenv=}") ;;
        --working-directory=*) dir="${1#*=}" ;;
        --quiet|--wait) ;;
        -p) shift
            case "$1" in
                RuntimeMaxSec=*) secs="${1#*=}" ;;
                User=*) user="${1#*=}" ;;
                StandardOutput=*) out="${1#*=}" ;;
                StandardError=*) err="${1#*=}" ;;
            esac ;;
        *) echo "systemd-run stand-in: unexpected argument $1" >&2; exit 64 ;;
    esac
    shift
done
[[ -n "$unit" && -n "$secs" && -n "$dir" && $# -gt 0 ]] \
    || { echo "systemd-run stand-in: no unit, limit, directory or command" >&2; exit 64; }
echo "${unit%-*} $user" >> /e2e/units.log
as=()
if [[ "$user" != root ]]; then
    as=(setpriv "--reuid=$user" "--regid=$user" --init-groups)
    envs+=("USER=$user" "HOME=/home/$user" "LOGNAME=$user" "SHELL=/bin/sh")
fi
case "$out" in truncate:*) exec >"${out#truncate:}" ;; null) exec >/dev/null ;; esac
case "$err" in truncate:*) exec 2>"${err#truncate:}" ;; null) exec 2>/dev/null ;; inherit) exec 2>&1 ;; esac
cd "$dir"
rc=0
timeout --kill-after=5 "$secs" "${as[@]}" env -i "${envs[@]}" "$@" </dev/null || rc=$?
mkdir -p /e2e/units
case "$rc" in
    0) exit 0 ;;
    124) echo timeout > "/e2e/units/$unit"; exit 1 ;;
    *) echo exit-code > "/e2e/units/$unit"; exit "$rc" ;;
esac
EOF
cat > "$S/systemctl" <<'EOF'
#!/usr/bin/env bash
state="/e2e/units/${*: -1}"
state="${state%.service}"
case "$1" in
    show) if [[ -f "$state" ]]; then printf 'LoadState=loaded\nResult=%s\n' "$(cat "$state")"
          else printf 'LoadState=not-found\nResult=success\n'; fi ;;
    reset-failed) [[ -f "$state" ]] || { echo "Unit ${*: -1} not loaded." >&2; exit 1; }; rm -f "$state" ;;
    *) echo "systemctl stand-in: unexpected $*" >&2; exit 64 ;;
esac
EOF

cat > /mockvenv/bin/pip <<'EOF'
#!/usr/bin/env bash
echo "$0 $*" >> /e2e/pip.log
venv="$(cd "$(dirname "$0")/.." && pwd)" src="${*: -1}"
[[ "$1" == install && -f "$src/pyproject.toml" ]] || exit 0
sed -n 's/^version = "\(.*\)"$/\1/p' "$src/pyproject.toml" > "$venv/release"
cp -R "$src/src" "$venv/pkg"
EOF
# The live release (no pkg/) answers only what the shim asks of it.
cat > /mockvenv/bin/boxmunge-server <<'EOF'
#!/usr/bin/env bash
venv="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -d "$venv/pkg" ]]; then
    PYTHONPATH="$venv/pkg" exec /relvenv/bin/python -c \
        'import sys; from boxmunge.cli import main; sys.argv[0] = "boxmunge-server"; main()' "$@"
fi
case "$*" in
    --version) echo "boxmunge $(cat "$venv/release")+abc1234" ;;
    "health --json") echo '{"healthy": true, "exit_code": 0, "checks": [{"name": "docker", "status": "ok", "detail": ""}]}' ;;
    *) echo "live venv stand-in: unexpected boxmunge-server $*" >&2; exit 64 ;;
esac
EOF
cat > /mockvenv/bin/python <<'EOF'
#!/usr/bin/env bash
venv="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "${1:-}" == - ]]; then cat >/dev/null; echo "$BM_LEVEL $BM_MSG $BM_DETAIL" >> /e2e/oplog.log; exit 0; fi
[[ ! -d "$venv/pkg" ]] || PYTHONPATH="$venv/pkg" exec /relvenv/bin/python "$@"
case "${2:-}" in
    *send_notification*) echo "$BM_PRIORITY $BM_TITLE" >> /e2e/alerts.log ;;
    *) echo "live venv stand-in: unexpected python $*" >&2; exit 64 ;;
esac
EOF
chmod 0755 "$S"/* /mockvenv/bin/*

# Release $NEXT: the bundle (as this case has it), its compiled notes, and
# the SHA256SUMS that lists both.
B=/rel/src/boxmunge
mkdir -p /rel/src
cp -R /bundle/boxmunge "$B"
case "$CASE" in
    floor99) sed -i 's/^MIN_PYTHON="3\.[0-9]*"$/MIN_PYTHON="99.0"/' "$B/bootstrap/python-floor.sh"
             grep -qx 'MIN_PYTHON="99.0"' "$B/bootstrap/python-floor.sh" ;;
    noready) sed -i '/^    "upgrade-readiness": cmd_upgrade_readiness,$/d' "$B/src/boxmunge/cli.py"
             if grep -q '"upgrade-readiness"' "$B/src/boxmunge/cli.py"; then
                 echo "cli.py still names upgrade-readiness; the sed above no longer matches" >&2
                 exit 1
             fi ;;
    blocked) ;;
    *) echo "usage: upgrade_check_e2e.sh <floor99|blocked|noready> <installed> <image>" >&2; exit 2 ;;
esac
tar czf "/rel/boxmunge-$NEXT.tar.gz" -C /rel/src boxmunge
/relvenv/bin/python - "$INSTALLED" "$NEXT" /rel/upgrade-notes.json <<'EOF'
import json, sys, tempfile
from pathlib import Path
from boxmunge.upgrade_floor import BRIDGE_RELEASE, UPGRADE_FLOOR
from boxmunge.upgrade_notes import compile_notes, dump_notes
installed, nxt, out = sys.argv[1:4]
releases = {"releases": [{"version": installed, "class": "breakfix", "breaking": False},
                         {"version": nxt, "class": "feature", "breaking": True}]}
with tempfile.TemporaryDirectory() as d:
    for v in (installed, nxt):
        Path(d, f"{v}.json").write_text(json.dumps({"version": v, "no_project_action": True, "entries": []}))
    Path(out).write_bytes(dump_notes(compile_notes(Path(d), nxt, releases, UPGRADE_FLOOR, BRIDGE_RELEASE)))
EOF
(cd /rel && sha256sum "boxmunge-$NEXT.tar.gz" upgrade-notes.json > SHA256SUMS)
touch /rel/SHA256SUMS.sig /rel/SHA256SUMS.cert

# The box: <installed> live in slot a, its shim, deploy's sudo rule, deploy
# in the group that owns the Docker socket, one blocklisted release.
useradd -m -s /bin/bash deploy
gid="$(stat -c %g /var/run/docker.sock)"
if ! group="$(getent group "$gid")"; then groupadd -g "$gid" docker-host; group=docker-host; fi
usermod -aG "${group%%:*}" deploy
mkdir -p "$R"/{upgrade-state,bin,config,logs,state/deploy,projects,caddy/sites,env-a/boxmunge-docs}
install -d -m 0770 -g deploy "$R/stashes"
printf 'hostname: box.example.com\nadmin_email: ops@example.com\n' > "$R/config/boxmunge.yml"
echo "$INSTALLED+abc1234" > "$R/config/version"
cp -R /mockvenv/bin "$R/env-a/"
echo "$INSTALLED" > "$R/env-a/release"
echo a > "$R/upgrade-state/active-slot"
ln -s "$R/env-a" "$R/env-active"
echo docs > "$R/env-a/boxmunge-docs/OPERATIONS.md"
cp -R "$R/env-a/boxmunge-docs" "$R/.docs.seed"
ln -s .docs.seed "$R/docs"
printf '{"0.11.9": {"reason": "preflight_failed: dry_run", "failed_at": "2026-01-01T00:00:00+00:00"}}' \
    > "$R/upgrade-state/blocklist.json"
install -m 0755 /bundle/boxmunge/scripts/boxmunge-upgrade "$R/bin/boxmunge-upgrade"
"$R/bin/boxmunge-upgrade" install-sudoers
if [[ "$CASE" == blocked ]]; then
    absent="bmtest-absent-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
    PYTHONPATH=/src /relvenv/bin/python - "$IMAGE" "$absent" <<'EOF'
import sys
from boxmunge.paths import BoxPaths
from tests.readiness_helpers import add_project
image, absent = sys.argv[1:3]
add_project(BoxPaths(), "shop", compose=f"services:\n  web:\n    image: {image}\n    pull_policy: always\n")
add_project(BoxPaths(), "blog", compose=f"services:\n  web:\n    image: {absent}:v1\n")
EOF
fi
chown -R deploy:deploy "$R/projects" "$R/state" "$R/logs" "$R/caddy/sites"
blocklist="$(sha256sum < "$R/upgrade-state/blocklist.json")"
shim="$(sha256sum < "$R/bin/boxmunge-upgrade")"

as_deploy() { runuser -u deploy -- "$@"; }
keep() {  # keep <step>: what the stand-ins recorded during it, as <step>-<file>
    local f
    for f in units.log pip.log; do [[ ! -e "/e2e/$f" ]] || mv "/e2e/$f" "/e2e/$1-$f"; done
}
rc=0
as_deploy /relvenv/bin/boxmunge-server upgrade-check --version "$NEXT" --json \
    > /e2e/check.json 2> /e2e/check.err || rc=$?
echo "CHECK rc=$rc"
keep check
if [[ "$CASE" == blocked ]]; then
    rc=0
    as_deploy sudo -n "$R/bin/boxmunge-upgrade" target "$NEXT" > /e2e/target.log 2>&1 || rc=$?
    echo "TARGET rc=$rc"
    keep target
fi
echo "BLOCKLIST_UNCHANGED=$([[ "$(sha256sum < "$R/upgrade-state/blocklist.json")" == "$blocklist" ]] && echo yes || echo no)"
echo "SHIM_UNCHANGED=$([[ "$(sha256sum < "$R/bin/boxmunge-upgrade")" == "$shim" ]] && echo yes || echo no)"
echo "LIVE=$(readlink "$R/env-active")"
echo "VERSION_RECORD=$(cat "$R/config/version")"
echo "STANDBY=$([[ -e "$R/env-b" ]] && echo yes || echo no)"
echo "CHECK_DIR=$([[ -e "$R/upgrade-check" ]] && echo yes || echo no)"
for f in check.json check.err check-units.log check-pip.log target.log target-units.log \
        target-pip.log alerts.log oplog.log; do
    [[ -e "/e2e/$f" ]] || continue
    echo "--- $f"
    cat "/e2e/$f"
done
echo "--- end"
