"""The plaintext dump is bounded in time and never outlives a failed backup.

The dump runs as a real local process: only the `docker compose exec` it
would be is swapped for a shell command, the in-container stop is recorded
(tests/integration/test_dump_timeout.py runs both against a real
container), and the ownership handoff to the system container's uid is
stubbed.
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import boxmunge
from boxmunge import backup_dump, service_exec
from boxmunge.backup import BackupError, BackupKind
from boxmunge.commands import backup_cmd
from boxmunge.paths import BoxPaths

_real_run = subprocess.run


class _Docker:
    """Stands in for subprocess.run in service_exec."""

    def __init__(self, dump_argv: list[str]) -> None:
        self.dump_argv = dump_argv
        self.stops: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        if "boxmunge-stop" in cmd:
            self.stops.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        assert any(a.startswith("BOXMUNGE_EXEC_ID=") for a in cmd), cmd
        return _real_run(self.dump_argv, **{k: v for k, v in kwargs.items() if k != "cwd"})


def _dumps_left(paths: BoxPaths) -> list[Path]:
    return list(paths.project_backups("myapp").glob(".dump-*"))


@pytest.fixture
def project(paths: BoxPaths) -> BoxPaths:
    paths.project_dir("myapp").mkdir(parents=True)
    with patch.object(backup_dump._backup, "chown_for_system_container"):
        yield paths


def _run_dump(paths: BoxPaths, docker) -> Path:
    with patch.object(service_exec.subprocess, "run", side_effect=docker):
        return backup_dump.execute_dump(paths, "myapp", "dump", "db")


def test_a_hung_dump_times_out_is_stopped_and_leaves_no_plaintext(project: BoxPaths) -> None:
    docker = _Docker(["sh", "-c", "printf 'SECRET-ROW'; exec sleep 60"])
    with patch.object(backup_dump, "BACKUP_CMD_TIMEOUT", 1):
        started = time.monotonic()
        with pytest.raises(BackupError, match="timed out after 1s; it was stopped inside"):
            _run_dump(project, docker)
    assert time.monotonic() - started < 30
    assert len(docker.stops) == 1
    assert _dumps_left(project) == []


def test_a_timeout_that_cannot_be_stopped_says_so(project: BoxPaths) -> None:
    docker = _Docker(["sh", "-c", "exec sleep 60"])

    def unstoppable(cmd, **kwargs):
        if "boxmunge-stop" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "processes still running after SIGKILL")
        return docker(cmd, **kwargs)
    with patch.object(backup_dump, "BACKUP_CMD_TIMEOUT", 1):
        with pytest.raises(BackupError, match="FAILED .*may still be running"):
            _run_dump(project, unstoppable)
    assert _dumps_left(project) == []


def test_an_interrupted_dump_is_stopped_and_leaves_no_plaintext(project: BoxPaths) -> None:
    docker = _Docker(["sh", "-c", "printf 'SECRET-ROW'"])

    def interrupted(cmd, **kwargs):
        result = docker(cmd, **kwargs)
        if "boxmunge-stop" in cmd:
            return result
        assert _dumps_left(project)[0].read_bytes() == b"SECRET-ROW"
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        _run_dump(project, interrupted)
    assert len(docker.stops) == 1
    assert _dumps_left(project) == []


def test_a_dump_that_cannot_start_is_a_backup_error(project: BoxPaths) -> None:
    with pytest.raises(BackupError, match="could not run"):
        _run_dump(project, _Docker([str(project.root / "no-such-docker")]))
    assert _dumps_left(project) == []


def test_a_successful_dump_hands_its_plaintext_to_the_caller(project: BoxPaths) -> None:
    raw = _run_dump(project, _Docker(["sh", "-c", "printf 'ROWS'"]))
    assert raw.read_bytes() == b"ROWS"
    assert raw.stat().st_mode & 0o077 == 0


def test_backup_sweeps_dumps_a_killed_backup_left(project: BoxPaths) -> None:
    backups = project.project_backups("myapp")
    backups.mkdir()
    (backups / ".dump-killed.tar.gz").write_bytes(b"SECRET-ROW")
    seen: list[list[str]] = []

    def dump(paths, name, command, service):
        seen.append(sorted(p.name for p in _dumps_left(paths)))
        raise BackupError("stop here")
    with patch.object(backup_cmd, "execute_dump", side_effect=dump):
        assert backup_cmd._run_backup_inner(
            "myapp", project, "dump", "db", BackupKind.MANUAL, 5) == 1
    assert seen == [[]], "the stale dump was still there when the new one started"
    assert "Removed stale plaintext dump .dump-killed.tar.gz" in project.log_file.read_text()


_SIGTERMED_BACKUP = """
import sys
from pathlib import Path
from unittest.mock import patch
import boxmunge.cli
from boxmunge import backup_dump, service_exec
from boxmunge.paths import BoxPaths

paths, marker = BoxPaths(Path(sys.argv[1])), Path(sys.argv[2])
real_run = service_exec.subprocess.run
def docker(cmd, **kw):
    if "boxmunge-stop" in cmd:
        marker.write_text("stopped")
        return real_run(["true"])
    return real_run(["sh", "-c", "printf SECRET-ROW; exec sleep 60"],
                    **{k: v for k, v in kw.items() if k != "cwd"})
def backup(args):
    backup_dump.execute_dump(paths, "myapp", "dump", "db")
with patch.object(service_exec.subprocess, "run", side_effect=docker), \\
     patch.object(backup_dump._backup, "chown_for_system_container"), \\
     patch.dict(boxmunge.cli.COMMANDS, {"backup": backup}), \\
     patch.object(sys, "argv", ["boxmunge-server", "backup", "myapp"]):
    boxmunge.cli.main()
"""


def test_sigterm_during_a_backup_unwinds_and_removes_the_plaintext(project: BoxPaths) -> None:
    """systemd stops units with SIGTERM; the CLI must unwind, not just die."""
    marker = project.root / "stopped-in-container"
    proc = subprocess.Popen(
        [sys.executable, "-c", _SIGTERMED_BACKUP, str(project.root), str(marker)],
        env={**os.environ, "PYTHONPATH": str(Path(boxmunge.__file__).parents[1])},
        stderr=subprocess.PIPE, text=True,
    )
    deadline = time.monotonic() + 20
    while not any(p.stat().st_size for p in _dumps_left(project)):
        assert time.monotonic() < deadline, "the dump never started writing"
        time.sleep(0.05)
    proc.send_signal(signal.SIGTERM)
    _, err = proc.communicate(timeout=30)
    assert proc.returncode == 128 + signal.SIGTERM, err
    assert "stopped by signal 15" in err
    assert _dumps_left(project) == []
    assert marker.read_text() == "stopped"
