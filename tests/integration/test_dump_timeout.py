"""A dump or restore that overruns is killed inside the container.

Killing the `docker compose exec` client leaves the command running in the
container (a hung pg_dump keeps its locks). Here services are hardened the
way boxmunge runs them (read-only root, every capability dropped) and the
command forks a child, so its whole process group must be killed and
verified gone. Variants cover an image without grep and a command that
clears its environment.
"""
import shutil
import subprocess
import time
import uuid
from unittest.mock import patch

import pytest

from boxmunge import backup_dump, service_exec
from boxmunge.backup import BackupError
from boxmunge.service_exec import ServiceCommandTimeout, run_in_service

pytestmark = pytest.mark.integration

PROJECT = f"dumpto{uuid.uuid4().hex[:8]}"
NOGREP_IMAGE = f"boxmunge-test-nogrep:{PROJECT}"
COMPOSE = f"""\
x-hardened: &hardened
  command: ["sleep", "infinity"]
  read_only: true
  cap_drop: [ALL]
services:
  db:
    image: alpine:3.20
    <<: *hardened
  nogrep:
    image: {NOGREP_IMAGE}
    <<: *hardened
"""
# A parent shell with a forked child, both outliving the timeout.
HANGS = "printf SECRET-ROW; sleep 3001 & sleep 3002; wait"
COMMANDS = {
    "forks": HANGS,
    "clears-env": f"env -i sh -c '{HANGS}'",
}


def _compose(project_dir, *args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", "-p", PROJECT, "-f", "compose.yml", *args],
                          cwd=project_dir, capture_output=True, text=True, timeout=120, **kwargs)


def _left_running(project_dir, service: str) -> list[str]:
    ps = _compose(project_dir, "exec", "-T", service, "ps", "-o", "args")
    assert ps.returncode == 0, ps.stderr
    return [line for line in ps.stdout.splitlines() if "sleep 300" in line]


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    from boxmunge.paths import BoxPaths
    paths = BoxPaths(tmp_path_factory.mktemp("dumpto"))
    project_dir = paths.project_dir(PROJECT)
    project_dir.mkdir(parents=True)
    (project_dir / "compose.yml").write_text(COMPOSE)
    build = subprocess.run(["docker", "build", "-q", "-t", NOGREP_IMAGE, "-"],
                           input="FROM alpine:3.20\nRUN rm /bin/grep\n",
                           capture_output=True, text=True, timeout=300)
    assert build.returncode == 0, build.stderr
    try:
        up = _compose(project_dir, "up", "-d")
        assert up.returncode == 0, up.stderr
        nogrep = _compose(project_dir, "exec", "-T", "nogrep", "sh", "-c", "command -v grep")
        assert nogrep.returncode != 0, "the no-grep image still has grep"
        yield paths, project_dir
    finally:
        _compose(project_dir, "down", "-t", "1", "--remove-orphans")
        subprocess.run(["docker", "image", "rm", "-f", NOGREP_IMAGE],
                       capture_output=True, timeout=60)
        shutil.rmtree(project_dir, ignore_errors=True)


@pytest.mark.parametrize("service", ["db", "nogrep"])
@pytest.mark.parametrize("command", COMMANDS.values(), ids=COMMANDS.keys())
def test_timed_out_dump_leaves_nothing_running_or_on_disk(project, service, command) -> None:
    paths, project_dir = project
    with patch.object(backup_dump, "BACKUP_CMD_TIMEOUT", 3), \
         patch.object(backup_dump._backup, "chown_for_system_container"):
        with pytest.raises(BackupError, match="timed out after 3s; it was stopped inside"):
            backup_dump.execute_dump(paths, PROJECT, command, service)
    assert _left_running(project_dir, service) == []
    assert list(paths.project_backups(PROJECT).glob(".dump-*")) == []


def test_timed_out_restore_command_leaves_nothing_running(project) -> None:
    _, project_dir = project
    with pytest.raises(ServiceCommandTimeout) as exc:
        run_in_service(project_dir, PROJECT, "db", "cat >/dev/null; " + HANGS,
                       timeout=3, stdin=subprocess.DEVNULL, capture_output=True)
    assert exc.value.stop_error is None
    assert _left_running(project_dir, "db") == []


def test_a_command_that_does_not_lead_its_group_is_moved_into_its_own(project) -> None:
    """Outside `docker exec` the wrapper may start as a group member; it then
    re-executes under setsid so the group it records is its own."""
    _, project_dir = project
    pid_name = f"boxmunge-exec-{uuid.uuid4().hex}.pid"
    nested = 'sh -c "$1" "$1" "$2" "$3" & wait'
    outer = subprocess.Popen(
        ["docker", "compose", "-p", PROJECT, "-f", "compose.yml", "exec", "-T", "db",
         "sh", "-c", nested, "outer", service_exec._WRAPPER, pid_name, HANGS],
        cwd=project_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 30
        while len(_left_running(project_dir, "db")) < 2:
            assert time.monotonic() < deadline, "the nested command never started"
            time.sleep(0.5)
        assert service_exec._stop(project_dir, PROJECT, "db", pid_name) is None
        assert _left_running(project_dir, "db") == []
    finally:
        outer.kill()
        outer.wait(timeout=30)


def test_a_stop_it_cannot_verify_is_reported_as_failed(project) -> None:
    _, project_dir = project
    error = service_exec._stop(project_dir, PROJECT, "db", "boxmunge-exec-unknown.pid")
    assert error is not None and "no record" in error
    assert "may still be running" in str(ServiceCommandTimeout(3, error))
