# SPDX-License-Identifier: Apache-2.0
"""A fresh install on a real daemon: bootstrap/userns.sh remaps Docker before
its first start, and Caddy, laid out as init-host.sh lays it out, serves and
logs its access lines to stdout under the remap. docker-userns is ok on the first run."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from boxmunge.docker_run import docker_env
from boxmunge.health_checks.userns import check_docker_userns
from boxmunge.paths import BoxPaths
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import (
    BUSYBOX, DAEMON_JSON, ProcessDaemon, prior_daemon_json, write_daemon_json,
)

pytestmark = USERNS_DIND

REPO = Path(__file__).resolve().parents[3]
DEPLOY_GID = 4242  # init-host's deploy group; Caddy is not in it
CADDY = "caddy:2-alpine"  # caddy/compose.yml's image


def userns(script: str, root: Path | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "BOXMUNGE_ROOT": str(root or "/nonexistent")}
    return subprocess.run(["bash", "-c", f". {REPO / 'bootstrap' / 'userns.sh'}\n{script}"],
                          env=env, capture_output=True, text=True, check=False)


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], env=docker_env(), capture_output=True,
                          text=True, check=check)


@pytest.fixture
def daemon():
    """The prior daemon, given back with its daemon.json however the test ends."""
    d = ProcessDaemon()
    yield d
    d.stop()
    write_daemon_json(prior_daemon_json())
    d.start()


def _init_host_caddy(root: Path) -> None:
    """caddy/ with init-host.sh's owners and modes (Steps 9 and 13)."""
    caddy = root / "caddy"
    caddy.mkdir(parents=True, mode=0o750)
    os.chown(caddy, 0, DEPLOY_GID)
    (caddy / "sites").mkdir(mode=0o775)
    os.chown(caddy / "sites", 0, DEPLOY_GID)
    (caddy / "maintenance").mkdir(mode=0o755)
    os.chown(caddy / "maintenance", 0, DEPLOY_GID)
    caddyfile = caddy / "Caddyfile"
    caddyfile.write_text("{\n    email ops@example.com\n}\n\nimport /etc/caddy/sites/*.conf\n")
    os.chown(caddyfile, 0, DEPLOY_GID)
    os.chmod(caddyfile, 0o644)
    site = caddy / "sites" / "fresh.conf"
    site.write_text(":80 {\n    log {\n        output stdout\n        format json\n"
                    "    }\n    respond \"fresh\"\n}\n")
    os.chmod(site, 0o644)
    shutil.copy(REPO / "caddy" / "compose.yml", caddy / "compose.yml")


def _caddy_reads(caddyfile: Path) -> bool:
    """Can Caddy's remapped root (caddy/compose.yml's capabilities) read it?"""
    return docker("run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add",
                  "NET_BIND_SERVICE", "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro", CADDY,
                  "cat", "/etc/caddy/Caddyfile", check=False).returncode == 0


def test_fresh_install_is_remapped_and_caddy_works(daemon, tmp_path: Path) -> None:
    # A host that already ran a container is not fresh.
    docker("pull", "-q", BUSYBOX)
    docker("create", "--name", "bm-fresh-probe", BUSYBOX)
    try:
        used = userns("userns_refuse_existing_docker")
    finally:
        docker("rm", "bm-fresh-probe")
    assert used.returncode != 0 and "userns-migrate" in used.stderr
    # The prior daemon.json is not init-host's: refused, not overwritten.
    prior = DAEMON_JSON.read_text()
    foreign = userns("userns_preflight")
    assert foreign.returncode != 0 and "Move it aside" in foreign.stderr
    assert DAEMON_JSON.read_text() == prior
    DAEMON_JSON.unlink()

    before = userns('userns_preflight && userns_before_docker && echo "$USERNS_OFFSET"')
    assert before.returncode == 0, before.stderr
    s = int(before.stdout)
    daemon.stop()  # init-host Step 10: systemctl restart docker
    daemon.start()
    verify = userns(f"userns_verify {s}")
    assert verify.returncode == 0, verify.stderr

    root = tmp_path / "boxmunge"
    (root / "config").mkdir(parents=True)
    (root / "config" / "boxmunge.yml").write_text(
        "hostname: dind.localhost\nadmin_email: ops@example.com\n")
    _init_host_caddy(root)
    done = userns(f"userns_record {s} && userns_journal_committed {s}", root)
    assert done.returncode == 0, done.stderr

    docker("pull", "-q", CADDY)
    caddyfile = root / "caddy" / "Caddyfile"
    os.chmod(caddyfile, 0o640)  # init-host's mode before the remap
    assert not _caddy_reads(caddyfile)
    os.chmod(caddyfile, 0o644)
    assert _caddy_reads(caddyfile)

    compose = ["compose", "-f", str(root / "caddy" / "compose.yml")]
    docker("network", "create", "boxmunge-proxy", check=False)
    try:
        up = docker(*compose, "up", "-d", "--wait", "--wait-timeout", "120", check=False)
        assert up.returncode == 0, up.stderr + docker("logs", "boxmunge-caddy", check=False).stderr
        served = docker("exec", "boxmunge-caddy", "wget", "-qO-", "http://127.0.0.1/")
        assert served.stdout == "fresh"
        # stdout only: what CrowdSec's docker source reads (follow_stderr: false).
        access = subprocess.run(["docker", "logs", "boxmunge-caddy"], env=docker_env(),
                                capture_output=True, text=True, check=True).stdout
        assert '"msg":"handled request"' in access
        check = check_docker_userns(BoxPaths(root=root))
        assert check.status == "ok", check.detail
    finally:
        docker(*compose, "down", "-v", check=False)
        docker("network", "rm", "boxmunge-proxy", check=False)
