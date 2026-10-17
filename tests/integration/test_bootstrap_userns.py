"""bootstrap/userns.sh on a real Debian 13 userland (no Docker needed)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from boxmunge.userns.offset import allocate_offset
from tests.integration.conftest import skip_no_docker
from tests.integration.test_bootstrap_trixie import _run_on_trixie

pytestmark = [pytest.mark.integration, skip_no_docker]

SUBUID = "dockremap:165536:65536\nalice:1048576:65536\n"
SUBGID = "bob:1114112:100\n"
SCRIPT = f"""
set -e
printf '{SUBUID}' > /etc/subuid
printf '{SUBGID}' > /etc/subgid
. /bootstrap/userns.sh
umask 077  # root's umask must not decide what deploy can read
userns_preflight
userns_before_docker
S="$USERNS_OFFSET"; echo "S=$S"
userns_identity "$S"
userns_daemon_json
export BOXMUNGE_ROOT=/tmp/bm
install -d -m 750 /tmp/bm/config /tmp/bm/caddy
printf 'hostname: h\\nadmin_email: a@b.c\\n' > /tmp/bm/config/boxmunge.yml
userns_caddy_logs "$S"; userns_caddy_logs "$S"
userns_record "$S"; userns_journal_committed "$S"
echo "again=$(userns_allocate)"
echo "subuid=$(grep '^boxmunge-remap:' /etc/subuid | tr '\\n' ' ')"
echo "subgid=$(grep '^boxmunge-remap:' /etc/subgid | tr '\\n' ' ')"
echo "group=$(getent group boxmunge-remap | cut -d: -f1)"
echo "daemon=$(tr -d '\\n' < /etc/docker/daemon.json)"
echo "daemon_mode=$(stat -c '%a' /etc/docker/daemon.json)"
echo "logs=$(stat -c '%a %u:%g' /tmp/bm/caddy/logs)"
echo "dir=$(stat -c '%a %u' /tmp/bm/upgrade-root)"
echo "journal=$(cat /tmp/bm/upgrade-root/userns-migration.json)"
echo "mode=$(stat -c '%a' /tmp/bm/upgrade-root/userns-migration.json)"
echo "tmp=$(ls /tmp/bm/upgrade-root | tr '\\n' ' ')"
tail -3 /tmp/bm/config/boxmunge.yml
userns_record "$S" && echo "record-twice=accepted" || echo "record-twice=refused"
"""


def _outputs(stdout: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in stdout.splitlines()
                if "=" in line and not line.startswith(" "))


def test_userns_bootstrap_on_trixie(tmp_path: Path) -> None:
    result = _run_on_trixie(SCRIPT)
    assert result.returncode == 0, result.stdout + result.stderr
    out = _outputs(result.stdout)
    (tmp_path / "subuid").write_text(SUBUID)
    (tmp_path / "subgid").write_text(SUBGID)
    s = allocate_offset(tmp_path, host_ids=set())  # parity with the Python allocation
    assert out["S"] == out["again"] == str(s) == "1179648"
    assert out["subuid"] == out["subgid"] == f"boxmunge-remap:{s}:65536 "
    assert out["group"] == "boxmunge-remap"
    assert json.loads(out["daemon"]) == {
        "log-driver": "json-file", "log-opts": {"max-size": "50m", "max-file": "5"},
        "userns-remap": "boxmunge-remap:boxmunge-remap", "storage-driver": "overlay2",
        "features": {"containerd-snapshotter": False}}
    assert out["daemon_mode"] == "644"
    assert out["logs"] == f"750 {s}:{s}"
    assert out["dir"] == "700 0" and out["mode"] == "600"
    assert out["tmp"] == "userns-migration.json "
    assert json.loads(out["journal"]) == {"version": 1, "direction": "forward",
                                          "phase": "committed", "offset": s,
                                          "fresh_install": True}
    assert f"userns:\n  name: boxmunge-remap\n  offset: {s}" in result.stdout
    assert out["record-twice"] == "refused"


# Each case runs in a subshell from a clean subid state and prints
# <case>=ok:<stdout> or <case>=refused:<stderr>.
REFUSALS = r"""
. /bootstrap/userns.sh
export BOXMUNGE_ROOT=/tmp/bm
try() {
    local name="$1"; shift
    : > /etc/subuid; : > /etc/subgid
    if ( "$@" ) >/tmp/out 2>/tmp/err; then echo "$name=ok:$(tr '\n' ' ' </tmp/out)"
    else echo "$name=refused:$(tr '\n' ' ' </tmp/err)"; fi
}
no_group() {  # identity refused: daemon.json must not name it
    useradd --system -N -g nogroup --no-create-home boxmunge-remap
    userns_preflight && userns_before_docker; local rc=$?
    echo "daemon_json=$(test -e /etc/docker/daemon.json && echo written || echo absent)" >&2
    userdel boxmunge-remap; return $rc
}
link_logs() { mkdir -p /tmp/bm/caddy /victim; ln -sfn /victim /tmp/bm/caddy/logs; userns_caddy_logs 1048576; }
file_logs() { mkdir -p /tmp/bm2/caddy; : > /tmp/bm2/caddy/logs; BOXMUNGE_ROOT=/tmp/bm2 userns_caddy_logs 1048576; }
malformed() { printf 'alice:x:65536\n' > /etc/subuid; userns_allocate; }
misaligned() { printf 'boxmunge-remap:1048577:65536\n' | tee /etc/subuid > /etc/subgid; userns_allocate; }
by_uid() {
    id boxmunge-remap >/dev/null 2>&1 || useradd --system --user-group --no-create-home boxmunge-remap
    printf '%s:1245184:65536\n' "$(id -u boxmunge-remap)" > /etc/subuid
    printf 'boxmunge-remap:1245184:65536\n' > /etc/subgid
    S="$(userns_allocate)"; userns_identity "$S"; echo "$S $(wc -l < /etc/subuid)"
}
host_gid() { groupadd -g 1048600 big; userns_allocate; }
no_files() {  # trixie's passwd package creates neither file; usermod needs both
    rm -f /etc/subuid /etc/subgid
    S="$(userns_allocate)"; userns_identity "$S"
    echo "$S $(stat -c '%a %U' /etc/subuid) $(stat -c '%a %U' /etc/subgid)"
}
zeros() {
    printf 'boxmunge-remap:01048576:065536\n' | tee /etc/subuid > /etc/subgid
    S="$(userns_allocate)"; userns_identity "$S"; echo "$S"
}
foreign_first() {
    mkdir -p /etc/docker; echo '{"debug": true}' > /etc/docker/daemon.json
    userns_preflight; local rc=$?
    echo "ranges=$(grep -c . /etc/subuid)" >&2; return $rc
}
fake_docker() { printf '#!/bin/sh\n%s\n' "$1" > /usr/local/bin/docker; chmod +x /usr/local/bin/docker; }
docker_used() { fake_docker 'case "$1" in ps) echo c0ffee;; esac'; userns_refuse_existing_docker; }
docker_volume() { fake_docker 'case "$1" in volume) echo data;; esac'; userns_refuse_existing_docker; }
docker_down() { fake_docker 'exit 1'; userns_refuse_existing_docker; }
docker_empty() { fake_docker 'exit 0'; userns_refuse_existing_docker; }
info() { fake_docker "echo '$1'"; userns_verify 1048576; }
foreign_json() { mkdir -p /etc/docker; echo '{"data-root": "/srv/docker"}' > /etc/docker/daemon.json; userns_daemon_json; }
try no_group no_group
try link_logs link_logs; echo "victim=$(stat -c '%u:%g' /victim)"
try file_logs file_logs
try malformed malformed
try misaligned misaligned
try by_uid by_uid
try host_gid host_gid
try no_files no_files
try zeros zeros
try foreign_first foreign_first
rm -f /etc/docker/daemon.json
try docker_used docker_used
try docker_volume docker_volume
try docker_down docker_down
try docker_empty docker_empty
try verify_ok info '["name=seccomp,profile=builtin","name=userns"]|overlay2|/var/lib/docker/1048576.1048576'
try verify_store info '["name=seccomp,profile=builtin","name=userns"]|overlayfs|/var/lib/docker/1048576.1048576'
try verify_plain info '["name=seccomp,profile=builtin"]|overlay2|/var/lib/docker'
rm -f /usr/local/bin/docker
try foreign_json foreign_json; echo "kept=$(cat /etc/docker/daemon.json)"
"""


def test_userns_bootstrap_refusals_on_trixie(tmp_path: Path) -> None:
    # The Python side of the host_gid and zeros cases.
    assert allocate_offset(tmp_path, host_ids={1048600}) == 1114112
    (tmp_path / "subuid").write_text("boxmunge-remap:01048576:065536\n")
    (tmp_path / "subgid").write_text("boxmunge-remap:01048576:065536\n")
    assert allocate_offset(tmp_path, host_ids=set()) == 1048576
    result = _run_on_trixie(REFUSALS)
    assert result.returncode == 0, result.stdout + result.stderr
    out = _outputs(result.stdout)
    assert out["no_group"].startswith("refused:") and "without a group" in out["no_group"]
    assert "daemon_json=absent" in out["no_group"]
    assert out["link_logs"].startswith("refused:") and "link" in out["link_logs"]
    assert out["victim"] == "0:0"
    assert out["file_logs"].startswith("refused:") and "not a directory" in out["file_logs"]
    assert out["malformed"].startswith("refused:") and "/etc/subuid:1" in out["malformed"]
    assert out["misaligned"].startswith("refused:") and "by hand" in out["misaligned"]
    assert out["by_uid"] == "ok:1245184 1 "
    assert out["host_gid"] == "ok:1114112 "
    assert out["no_files"] == "ok:1114112 644 root 644 root "
    assert out["zeros"] == "ok:1048576 "
    # Refused before the identity is touched: no range was added.
    assert out["foreign_first"].startswith("refused:") and "ranges=0" in out["foreign_first"]
    for case in ("docker_used", "docker_volume"):
        assert out[case].startswith("refused:") and "userns-migrate" in out[case], out[case]
    assert out["docker_down"].startswith("refused:") and "not answering" in out["docker_down"]
    assert out["docker_empty"] == "ok:"
    assert out["verify_ok"] == "ok:"
    for case in ("verify_store", "verify_plain"):
        assert out[case].startswith("refused:") and "remapped" in out[case], out[case]
    assert out["foreign_json"].startswith("refused:") and "/srv/docker" in out["foreign_json"]
    assert out["kept"] == '{"data-root": "/srv/docker"}'


# init-host's own useradd lines, run as written; a plain useradd is the control.
USERS = r"""
: > /etc/subuid; : > /etc/subgid
DEPLOY_USER=deploy
grep -E '^\s*useradd -m ' /bootstrap/init-host.sh > /tmp/users.sh
echo "lines=$(wc -l < /tmp/users.sh)"
. /tmp/users.sh
useradd -m control
echo "owners=$(cut -d: -f1 /etc/subuid /etc/subgid | sort -u | tr '\n' ' ')"
"""


def test_init_host_users_get_no_subordinate_ids_on_trixie() -> None:
    """Debian's useradd gives every new login user a 65536-id range; deploy
    and supervisor have no use for one, and boxmunge-remap's must stay alone."""
    result = _run_on_trixie(USERS)
    assert result.returncode == 0, result.stdout + result.stderr
    out = _outputs(result.stdout)
    assert out["lines"] == "2"
    assert out["owners"] == "control "
