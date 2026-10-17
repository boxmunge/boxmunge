"""Caddy's access log reaches CrowdSec through Docker, on Debian 13's CrowdSec.

A real caddy:2-alpine runs a site block from generate_caddy_config; a
debian:trixie container installs CrowdSec with bootstrap/crowdsec.sh, talks to
the same Docker daemon through its socket, and runs bootstrap/crowdsec-acquis.sh
exactly as install.sh does. The only change to the script is the container
name (a shared daemon cannot host a second boxmunge-caddy) and, for the
failure test, the wait. Also covers bootstrap/caddy-access-log.sh, which moves
an existing box's site configs off the old log file. Needs Docker and network
access to the Debian mirror and CrowdSec's hub.
"""
from __future__ import annotations

import json
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from boxmunge.caddy import generate_caddy_config
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

REPO = Path(__file__).resolve().parents[2]
TRIXIE = "debian:trixie"
CADDY = "caddy:2-alpine"
HOST = "bmtest.example.com"
MANIFEST = {
    "project": "myapp",
    "hosts": [f"http://{HOST}"],
    "services": {"frontend": {"type": "frontend", "port": 3000, "routes": [{"path": "/"}]}},
}
# What crowdsec.sh appended to acquis.yaml before this release.
LEGACY_ACQUIS = (
    "\n---\nsource: file\nfilenames:\n  - /opt/boxmunge/caddy/logs/access.log\n"
    "labels:\n  type: caddy\n"
)
# What crowdsec.sh appended where acquis.yaml had no journal source.
LEGACY_SSH = (
    '\n---\nsource: journalctl\njournalctl_filter:\n  - "_SYSTEMD_UNIT=sshd.service"\n'
    "labels:\n  type: syslog\n"
)
# Each site block's access log as caddy.py generated it before this release.
OLD_LOG = (
    "    log {\n"
    "        output file /var/log/caddy/access.log {\n"
    "            roll_size 50MiB\n"
    "            roll_keep 5\n"
    "        }\n"
    "        format json\n"
    "    }\n"
)
NEW_LOG = "    log {\n        output stdout\n        format json\n    }\n"

# No systemd in a container. restart runs the daemon in the background the way
# the unit does; real systemctl returns once CrowdSec is ready (Type=notify).
_SYSTEMCTL = """#!/bin/sh
if [ "$1 $2" = "restart crowdsec" ]; then
    [ -f /run/cs.pid ] && kill "$(cat /run/cs.pid)" && sleep 2
    setsid crowdsec -c /etc/crowdsec/config.yaml >/tmp/cs.out 2>&1 &
    echo $! > /run/cs.pid
    sleep 5
fi
exit 0
"""


def _run(args: list[str], timeout: int = 900, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise AssertionError(f"{args[:4]} exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result


def _sh(container: str, script: str, **kw) -> subprocess.CompletedProcess:
    return _run(["docker", "exec", container, "bash", "-c", script], **kw)


@pytest.fixture
def caddy(tmp_path: Path):
    """Real Caddy serving a generated site block on :80, no network."""
    name = f"bmtest-cs-caddy-{uuid.uuid4().hex[:10]}"
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("{\n    admin off\n}\n" + generate_caddy_config(MANIFEST))
    caddyfile.chmod(0o644)
    _run(["docker", "run", "-d", "--name", name, "--network", "none",
          "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro", CADDY])
    try:
        yield name
    finally:
        _run(["docker", "rm", "-f", name], check=False)


@pytest.fixture
def crowdsec(tmp_path: Path):
    """debian:trixie with CrowdSec from bootstrap/crowdsec.sh and the Docker socket."""
    name = f"bmtest-cs-agent-{uuid.uuid4().hex[:10]}"
    _run(["docker", "run", "-d", "--name", name,
          "-v", "/var/run/docker.sock:/var/run/docker.sock",
          "-v", f"{REPO / 'bootstrap'}:/bootstrap:ro", TRIXIE, "sleep", "infinity"])
    try:
        (tmp_path / "systemctl").write_text(_SYSTEMCTL)
        _run(["docker", "cp", str(tmp_path / "systemctl"), f"{name}:/usr/local/bin/systemctl"])
        _sh(name, "set -eu; export DEBIAN_FRONTEND=noninteractive\n"
                  "chmod +x /usr/local/bin/systemctl\n"
                  "echo 'APT::Install-Recommends \"false\";' > /etc/apt/apt.conf.d/99norecommends\n"
                  "apt-get update -qq >/dev/null\n"
                  "apt-get install -y -qq ca-certificates curl >/dev/null\n"
                  "bash /bootstrap/crowdsec.sh > /tmp/cs.log 2>&1 || { tail -20 /tmp/cs.log; exit 1; }\n"
                  f"printf '%s' '{LEGACY_ACQUIS}{LEGACY_SSH}' >> /etc/crowdsec/acquis.yaml\n"
                  # A box whose collection step failed: crowdsec-acquis.sh installs it.
                  "cscli collections remove crowdsecurity/caddy >/dev/null\n")
        yield name
    finally:
        _run(["docker", "rm", "-f", name], check=False)


def _script_for(container: str, caddy_name: str, tmp_path: Path, wait: int = 60) -> None:
    text = (REPO / "bootstrap" / "crowdsec-acquis.sh").read_text()
    assert "CADDY_CONTAINER=boxmunge-caddy\n" in text and "VERIFY_SECONDS=60\n" in text
    text = text.replace("CADDY_CONTAINER=boxmunge-caddy\n", f"CADDY_CONTAINER={caddy_name}\n")
    text = text.replace("VERIFY_SECONDS=60\n", f"VERIFY_SECONDS={wait}\n")
    (tmp_path / "crowdsec-acquis.sh").write_text(text)
    _run(["docker", "cp", str(tmp_path / "crowdsec-acquis.sh"), f"{container}:/crowdsec-acquis.sh"])


def _acquisition(container: str) -> dict:
    """The first table of `cscli metrics -o json` (1.4.6 prints one JSON object per table)."""
    out = _sh(container, "cscli metrics -o json 2>/dev/null").stdout
    return json.JSONDecoder().raw_decode(out)[0]


def test_caddy_access_lines_reach_crowdsec_through_docker(caddy, crowdsec, tmp_path) -> None:
    _script_for(crowdsec, caddy, tmp_path)
    result = _sh(crowdsec, "bash /crowdsec-acquis.sh", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"CrowdSec tails {caddy}" in result.stdout

    state = _sh(crowdsec, "cat /etc/crowdsec/acquis.yaml; echo ===; "
                          "cat /etc/systemd/system/crowdsec.service.d/boxmunge-limits.conf").stdout
    assert "caddy/logs" not in state
    assert "sshd.service" not in state and "_SYSTEMD_UNIT=ssh.service" in state
    assert "MemoryMax=512M" in state

    for _ in range(3):
        _run(["docker", "exec", caddy, "wget", "-q", "-O", "/dev/null",
              "--header", f"Host: {HOST}", "http://127.0.0.1/wp-login.php"], check=False)
    source, deadline = f"docker:{caddy}", time.monotonic() + 60
    while _acquisition(crowdsec).get(source, {}).get("reads", 0) < 3:
        assert time.monotonic() < deadline, _acquisition(crowdsec)
        time.sleep(2)
    time.sleep(3)
    # Exactly the three access lines: Caddy's runtime log on stderr is not read.
    assert _acquisition(crowdsec)[source] == {"reads": 3, "parsed": 3}


def test_crowdsec_caddy_fails_loudly_when_caddy_is_not_tailed(crowdsec, tmp_path) -> None:
    _script_for(crowdsec, "bmtest-cs-no-such-caddy", tmp_path, wait=10)
    result = _sh(crowdsec, "bash /crowdsec-acquis.sh", check=False)
    assert result.returncode != 0
    assert "CrowdSec is not reading bmtest-cs-no-such-caddy's access log" in result.stderr


_BOX = """set -eu
useradd -M deploy
mkdir -p /opt/boxmunge/caddy/sites /opt/boxmunge/projects/app /victim
chown root:deploy /opt/boxmunge/caddy/sites; chmod 775 /opt/boxmunge/caddy/sites
chown deploy:deploy /opt/boxmunge/projects/app
echo secret > /victim/keep
"""


def _trixie(script: str) -> subprocess.CompletedProcess:
    return _run(["docker", "run", "--rm", "--network", "none",
                 "--name", f"bmtest-cs-sites-{uuid.uuid4().hex[:10]}",
                 "-v", f"{REPO / 'bootstrap'}:/bootstrap:ro", TRIXIE,
                 "bash", "-c", _BOX + script], timeout=300, check=False)


def test_sites_moves_generated_configs_and_pending_journal_to_stdout(tmp_path) -> None:
    new = generate_caddy_config(MANIFEST)
    old = new.replace(NEW_LOG, OLD_LOG)
    assert OLD_LOG in old
    site = "/opt/boxmunge/caddy/sites/myapp.conf"
    entry = json.dumps({"path": site, "previous": old, "written": old})
    result = _trixie(
        f"printf '%s' '{old}' > {site}\n"
        "ln -s /victim/keep /opt/boxmunge/caddy/sites/planted.conf\n"
        "install -d -m 700 -o deploy -g deploy /opt/boxmunge/caddy/.site-journal\n"
        f"printf '%s' '{entry}' > /opt/boxmunge/caddy/.site-journal/myapp.conf.json\n"
        "chown deploy /opt/boxmunge/caddy/.site-journal/myapp.conf.json\n"
        # install.sh runs from the installer's root-only extraction directory.
        "cd /root\n"
        "bash /bootstrap/caddy-access-log.sh sites\n"
        "bash /bootstrap/caddy-access-log.sh sites\n"  # idempotent
        f"cat {site}; echo ===\n"
        "cat /opt/boxmunge/caddy/.site-journal/myapp.conf.json; echo ===\n"
        "test -L /opt/boxmunge/caddy/sites/planted.conf && cat /victim/keep\n")
    assert result.returncode == 0, result.stdout + result.stderr
    conf, journal, rest = result.stdout.split("===\n")
    assert conf == new
    assert json.loads(journal) == {"path": site, "previous": new, "written": new}
    assert rest == "secret\n"


def test_sites_refuses_an_override_that_still_names_the_file() -> None:
    result = _trixie(
        f"printf '%s' 'app.example.com {{\n{OLD_LOG}}}\n'"
        " > /opt/boxmunge/projects/app/caddy.override.conf\n"
        "bash /bootstrap/caddy-access-log.sh sites\n")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "/opt/boxmunge/projects/app/caddy.override.conf" in result.stderr
    assert "output stdout" in result.stderr


def test_retire_removes_caddy_logs_without_following_links() -> None:
    result = _trixie(
        "mkdir /opt/boxmunge/caddy/logs\n"
        "ln -s /victim /opt/boxmunge/caddy/logs/access.log\n"
        "bash /bootstrap/caddy-access-log.sh retire\n"
        "bash /bootstrap/caddy-access-log.sh retire\n"
        "test ! -e /opt/boxmunge/caddy/logs && cat /victim/keep\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.endswith("secret\n")


def _compose_tmpfs() -> list[str]:
    import yaml
    service = yaml.safe_load((REPO / "caddy" / "compose.yml").read_text())["services"]["caddy"]
    assert service["read_only"] is True
    return service["tmpfs"]


@pytest.mark.parametrize("with_tmpfs", [True, False])
def test_rolled_back_site_configs_still_load_on_the_new_compose(tmp_path, with_tmpfs) -> None:
    """A rollback's `upgrade --apply` regenerates every site with the old file
    block; on a read-only rootfs only the compose tmpfs lets Caddy load it."""
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("{\n    admin off\n}\n"
                         + generate_caddy_config(MANIFEST).replace(NEW_LOG, OLD_LOG))
    caddyfile.chmod(0o644)
    name = f"bmtest-cs-rollback-{uuid.uuid4().hex[:10]}"
    tmpfs = [arg for t in _compose_tmpfs() for arg in ("--tmpfs", t)] if with_tmpfs else []
    try:
        _run(["docker", "run", "-d", "--name", name, "--network", "none", "--read-only",
              "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", *tmpfs,
              "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro", CADDY])
        time.sleep(2)
        validate = _run(["docker", "exec", name, "caddy", "validate",
                         "--config", "/etc/caddy/Caddyfile"], check=False)
        assert (validate.returncode == 0) is with_tmpfs, validate.stdout + validate.stderr
    finally:
        _run(["docker", "rm", "-f", name], check=False)
