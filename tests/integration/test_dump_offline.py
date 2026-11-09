"""The offline dump, on Docker: a one-off of the stopped service, no network.

data chown dumps a stopped backup service's data this way (backup_offline).
The one-off runs as the service's user over its mounts, sees no network but
loopback, publishes nothing, and is gone afterwards, also when it overruns.
The start checks are stood in for: they are the unit tier's.
"""
import subprocess
import uuid
from unittest.mock import patch

import pytest

from boxmunge import backup_offline
from boxmunge.backup import BackupError

pytestmark = pytest.mark.integration

PROJECT = f"dumpoff{uuid.uuid4().hex[:8]}"
COMPOSE = """\
services:
  app:
    image: alpine:3.20
    command: ["sleep", "infinity"]
    user: "10002:10002"
    read_only: true
    cap_drop: [ALL]
    networks: [inner]
    ports: ["127.0.0.1::8080"]
    volumes: ["./data:/data:ro"]
networks:
  inner: {}
"""


@pytest.fixture
def project(tmp_path):
    from boxmunge.paths import BoxPaths
    paths = BoxPaths(tmp_path)
    project_dir = paths.project_dir(PROJECT)
    (project_dir / "data").mkdir(parents=True)
    (project_dir / "data" / "rows").write_text("ROW-1\n")
    (project_dir / "compose.yml").write_text(COMPOSE)
    (project_dir / "compose.boxmunge.yml").write_text("services:\n  app: {}\n")
    with patch.object(backup_offline, "check_start"):
        yield paths
    subprocess.run(["docker", "compose", "-p", PROJECT, "-f", "compose.yml", "down",
                    "--remove-orphans"], cwd=project_dir, capture_output=True, timeout=120)


def _left() -> str:
    return subprocess.run(["docker", "ps", "-a", "-q", "--filter",
                           f"label=com.docker.compose.project={PROJECT}"],
                          capture_output=True, text=True, timeout=30).stdout.strip()


def test_the_dump_reads_the_data_as_the_service_with_no_network(project) -> None:
    script = "cat /data/rows; id -u; ls /sys/class/net"
    result = backup_offline.run_offline(project, PROJECT, "app", script, timeout=120,
                                        component="test", capture_output=True)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.decode().split()
    assert lines[:2] == ["ROW-1", "10002"]
    assert "eth0" not in lines
    assert _left() == ""


def test_an_overrun_leaves_no_one_off_behind(project) -> None:
    with pytest.raises(BackupError, match="timed out after 3s; its one-off container"):
        backup_offline.run_offline(project, PROJECT, "app", "sleep 600", timeout=3,
                                   component="test", capture_output=True)
    assert _left() == ""
