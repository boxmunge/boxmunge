"""A dump or restore that overruns is killed inside the container.

Killing the `docker compose exec` client leaves the command running in the
container (a hung pg_dump keeps its locks). Here the service is hardened the
way boxmunge runs services (read-only root, every capability dropped) and the
command forks a child, so the whole process tree must be found and killed.
"""
import shutil
import subprocess
import uuid
from unittest.mock import patch

import pytest

from boxmunge import backup_dump
from boxmunge.backup import BackupError
from boxmunge.service_exec import ServiceCommandTimeout, run_in_service

pytestmark = pytest.mark.integration

PROJECT = f"dumpto{uuid.uuid4().hex[:8]}"
COMPOSE = """\
services:
  db:
    image: alpine:3.20
    command: ["sleep", "infinity"]
    read_only: true
    cap_drop: [ALL]
"""
# A parent shell with a forked child, both outliving the timeout.
HANGS = "printf SECRET-ROW; sleep 3001 & sleep 3002; wait"


def _processes(project_dir) -> str:
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, "-f", "compose.yml",
         "exec", "-T", "db", "ps", "-o", "args"],
        cwd=project_dir, capture_output=True, text=True, timeout=60, check=True,
    ).stdout


@pytest.fixture
def project(int_paths):
    project_dir = int_paths.project_dir(PROJECT)
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir()
    (project_dir / "compose.yml").write_text(COMPOSE)
    try:
        subprocess.run(["docker", "compose", "-p", PROJECT, "-f", "compose.yml", "up", "-d"],
                       cwd=project_dir, capture_output=True, timeout=120, check=True)
        yield int_paths, project_dir
    finally:
        subprocess.run(["docker", "compose", "-p", PROJECT, "-f", "compose.yml",
                        "down", "-t", "1", "--remove-orphans"],
                       cwd=project_dir, capture_output=True, timeout=60, check=False)
        shutil.rmtree(project_dir, ignore_errors=True)


def test_timed_out_dump_leaves_nothing_running_or_on_disk(project) -> None:
    paths, project_dir = project
    with patch.object(backup_dump, "BACKUP_CMD_TIMEOUT", 3), \
         patch.object(backup_dump._backup, "chown_for_system_container"):
        with pytest.raises(BackupError, match="timed out after 3s; it was stopped inside"):
            backup_dump.execute_dump(paths, PROJECT, HANGS, "db")
    assert "sleep 300" not in _processes(project_dir)
    assert list(paths.project_backups(PROJECT).glob(".dump-*")) == []


def test_timed_out_restore_command_leaves_nothing_running(project) -> None:
    _, project_dir = project
    with pytest.raises(ServiceCommandTimeout) as exc:
        run_in_service(project_dir, PROJECT, "db", "cat >/dev/null; " + HANGS,
                       timeout=3, stdin=subprocess.DEVNULL, capture_output=True)
    assert exc.value.stop_error is None
    assert "sleep 300" not in _processes(project_dir)
