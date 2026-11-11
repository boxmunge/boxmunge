"""Caddy's access log reaches CrowdSec through Docker, on Debian 13's CrowdSec.

A real caddy:2-alpine runs a site block from generate_caddy_config; a
debian:trixie container installs CrowdSec with bootstrap/crowdsec.sh, talks to
the same Docker daemon through its socket, and runs bootstrap/crowdsec-acquis.sh
exactly as install.sh does. The only change to the script is the container
name (a shared daemon cannot host a second boxmunge-caddy) and, for the
failure test, the wait. Needs Docker and network access to the Debian mirror
and CrowdSec's hub.
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
# What compose sets on the container caddy/compose.yml makes (crowdsec-acquis.sh checks it).
SYSTEM_CADDY = ["--label", "com.docker.compose.project=caddy"]
# An upstream answering with a header far longer than CrowdSec's 64 KiB line limit.
HUGE_RESPONSE = 'header X-Huge "{}"\n        respond "ok"'.format("a" * 70000)

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
    """Real Caddy serving a generated site block on :80, no network, as
    caddy/compose.yml labels it; its route answers with a huge header."""
    name = f"bmtest-cs-caddy-{uuid.uuid4().hex[:10]}"
    caddyfile = tmp_path / "Caddyfile"
    site = generate_caddy_config(MANIFEST).replace("reverse_proxy myapp-frontend:3000", HUGE_RESPONSE)
    assert HUGE_RESPONSE in site
    caddyfile.write_text("{\n    admin off\n}\n" + site)
    caddyfile.chmod(0o644)
    _run(["docker", "run", "-d", "--name", name, "--network", "none", *SYSTEM_CADDY,
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
                  # The box's docker CLI: crowdsec-acquis.sh inspects Caddy with it.
                  "apt-get install -y -qq ca-certificates curl docker-cli >/dev/null\n"
                  "bash /bootstrap/crowdsec.sh > /tmp/cs.log 2>&1 || { tail -20 /tmp/cs.log; exit 1; }\n"
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


def _get(caddy: str, extra: str = "", path: str = "/wp-login.php") -> None:
    """One request through Caddy; extra is shell that adds wget arguments."""
    _run(["docker", "exec", caddy, "sh", "-c",
          f'wget -q -O /dev/null --header "Host: {HOST}" {extra} "http://127.0.0.1{path}"'],
         check=False)


def _wait_reads(crowdsec: str, source: str, reads: int) -> dict:
    deadline = time.monotonic() + 60
    while _acquisition(crowdsec).get(source, {}).get("reads", 0) < reads:
        assert time.monotonic() < deadline, _acquisition(crowdsec)
        time.sleep(2)
    time.sleep(3)
    return _acquisition(crowdsec)[source]


def _tail_starts(crowdsec: str, caddy: str) -> int:
    log = _sh(crowdsec, "cat /var/log/crowdsec.log").stdout
    return log.count(f'start tail for container {caddy}"')


# 0xFF is valid in a header and escaped by Caddy into six bytes (\\ufffd):
# a request near the server's header limit, everything in it as long as it goes.
_FF = "$(head -c 3000 /dev/zero | tr '\\0' '\\377')"
_HOSTILE = f'--header "User-Agent: Nikto {_FF}{_FF}" --header "X-A: {_FF}{_FF}"'


def test_caddy_access_lines_reach_crowdsec_through_docker(caddy, crowdsec, tmp_path) -> None:
    _script_for(crowdsec, caddy, tmp_path)
    result = _sh(crowdsec, "bash /crowdsec-acquis.sh", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"CrowdSec tails {caddy}" in result.stdout

    limits = _sh(crowdsec,
                 "cat /etc/systemd/system/crowdsec.service.d/boxmunge-limits.conf").stdout
    assert "MemoryMax=512M" in limits

    starts = _tail_starts(crowdsec, caddy)
    _get(caddy, _HOSTILE, path=f"/{_FF}?q={_FF}")
    for _ in range(5):
        _get(caddy)
    # Every line read and parsed, the hostile one included, and the tail never
    # restarted (a line over 64 KiB would have killed it and lost those after).
    # Caddy's runtime log on stderr is not read.
    assert _wait_reads(crowdsec, f"docker:{caddy}", 6) == {"reads": 6, "parsed": 6}
    assert _tail_starts(crowdsec, caddy) == starts
    stdout = _run(["docker", "logs", caddy]).stdout.splitlines()
    assert len(stdout) == 6 and max(map(len, stdout)) < 32 * 1024
    assert "Nikto" in stdout[0] and "X-Huge" not in "".join(stdout)


def test_crowdsec_acquis_refuses_a_boxmunge_caddy_compose_did_not_make(crowdsec, tmp_path) -> None:
    name = f"bmtest-cs-squat-{uuid.uuid4().hex[:10]}"
    # What a project's compose would make: its own project label, set by Compose.
    _run(["docker", "create", "--name", name, "--network", "none",
          "--label", "com.docker.compose.project=myapp", CADDY])
    try:
        _script_for(crowdsec, name, tmp_path)
        result = _sh(crowdsec, "bash /crowdsec-acquis.sh", check=False)
    finally:
        _run(["docker", "rm", "-f", name], check=False)
    assert result.returncode != 0
    assert f"{name} belongs to compose project 'myapp', not the" in result.stderr


def test_crowdsec_acquis_fails_loudly_when_caddy_is_not_tailed(crowdsec, tmp_path) -> None:
    name = f"bmtest-cs-stopped-{uuid.uuid4().hex[:10]}"
    _run(["docker", "create", "--name", name, "--network", "none", *SYSTEM_CADDY, CADDY])
    try:
        _script_for(crowdsec, name, tmp_path, wait=10)
        result = _sh(crowdsec, "bash /crowdsec-acquis.sh", check=False)
    finally:
        _run(["docker", "rm", "-f", name], check=False)
    assert result.returncode != 0
    assert f"CrowdSec is not reading {name}'s access log" in result.stderr
