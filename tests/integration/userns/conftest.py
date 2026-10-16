"""Fixtures for the remapped-daemon tests (privileged dind job only)."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.userns import offset
from tests.integration.userns.dockerd import (
    ProcessDaemon, prior_daemon_json, write_daemon_json,
)

IN_DIND = os.environ.get("BOXMUNGE_USERNS_DIND") == "1"
DIND = pytest.mark.skipif(not IN_DIND, reason="needs the privileged dind job "
                          "(tests/integration/userns/run-in-dind.sh)")
USERNS_DIND = [pytest.mark.integration, pytest.mark.userns_dind, DIND]


@pytest.fixture
def dind_paths(tmp_path: Path) -> BoxPaths:
    root = tmp_path / "boxmunge"
    for sub in ("config", "projects", "state/deploy", "state/health", "logs",
                "caddy/sites", "caddy/logs", "system", "upgrade-state"):
        (root / sub).mkdir(parents=True)
    (root / "config" / "boxmunge.yml").write_text(
        "hostname: dind.localhost\nadmin_email: ops@example.com\n")
    return BoxPaths(root=root)


def ensure_identity() -> int:
    """boxmunge-remap and its ranges, as the migration's phase 1 makes them."""
    s = offset.allocate_offset(Path("/etc"), host_ids=set())
    if subprocess.run(["id", offset.REMAP_NAME], capture_output=True).returncode != 0:
        subprocess.run(["useradd", "--system", "--user-group", "--no-create-home",
                        "--shell", "/sbin/nologin", offset.REMAP_NAME], check=True)
    uids, _ = offset.remap_ranges(Path("/etc"))
    if not uids:
        span = f"{s}-{s + offset.RANGE - 1}"
        subprocess.run(["usermod", "--add-subuids", span, "--add-subgids", span,
                        offset.REMAP_NAME], check=True)
    return s


@pytest.fixture(scope="module")
def remapped_daemon(tmp_path_factory):
    """Switch dockerd to the boxmunge remap for one module, then back."""
    s = ensure_identity()
    daemon = ProcessDaemon()
    daemon.stop()
    write_daemon_json({**prior_daemon_json(), "userns-remap": offset.DAEMON_REMAP_VALUE,
                       "storage-driver": "overlay2",
                       "features": {"containerd-snapshotter": False}})
    daemon.start()
    subprocess.run(["docker", "pull", "-q", "busybox:1.36"], check=True, capture_output=True)
    yield s
    daemon.stop()
    write_daemon_json(prior_daemon_json())
    daemon.start()


@pytest.fixture
def dind_record(dind_paths, remapped_daemon):
    """dind_paths with the userns record for the remapped daemon."""
    offset.write_offset_record(dind_paths, remapped_daemon)
    return dind_paths
