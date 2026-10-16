"""The plaintext dump is bounded in time and never outlives a failed backup.

The dump runs as a real process; only the `docker compose exec` command it
would be is swapped for a local shell command, and only the ownership
handoff to the system container's uid is stubbed.
"""

import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.backup import BackupError
from boxmunge.commands import backup_cmd
from boxmunge.paths import BoxPaths

_real_run = subprocess.run


def _dump_runs(argv: list[str]):
    """Run ``argv`` in place of the docker exec, keeping every other kwarg."""
    def run(cmd, **kwargs):
        return _real_run(argv, **{k: v for k, v in kwargs.items() if k != "cwd"})
    return run


def _dumps_left(paths: BoxPaths) -> list[Path]:
    return list(paths.project_backups("myapp").glob(".dump-*"))


@pytest.fixture
def project(paths: BoxPaths) -> BoxPaths:
    paths.project_dir("myapp").mkdir(parents=True)
    with patch.object(backup_cmd._backup, "chown_for_system_container"):
        yield paths


def test_a_hung_dump_times_out_and_leaves_no_plaintext(project: BoxPaths) -> None:
    hung = _dump_runs(["sh", "-c", "printf 'SECRET-ROW'; exec sleep 60"])
    with patch.object(backup_cmd, "BACKUP_CMD_TIMEOUT", 1), \
         patch("boxmunge.commands.backup_cmd.subprocess.run", side_effect=hung):
        started = time.monotonic()
        with pytest.raises(BackupError, match="timed out after 1s"):
            backup_cmd._execute_dump(project, "myapp", "dump", "db")
    assert time.monotonic() - started < 30
    assert _dumps_left(project) == []


def test_an_interrupted_dump_leaves_no_plaintext(project: BoxPaths) -> None:
    def interrupted(cmd, **kwargs):
        _dump_runs(["sh", "-c", "printf 'SECRET-ROW'"])(cmd, **kwargs)
        assert _dumps_left(project)[0].read_bytes() == b"SECRET-ROW"
        raise KeyboardInterrupt
    with patch("boxmunge.commands.backup_cmd.subprocess.run", side_effect=interrupted):
        with pytest.raises(KeyboardInterrupt):
            backup_cmd._execute_dump(project, "myapp", "dump", "db")
    assert _dumps_left(project) == []


def test_a_dump_that_cannot_start_is_a_backup_error(project: BoxPaths) -> None:
    missing = _dump_runs([str(project.root / "no-such-docker")])
    with patch("boxmunge.commands.backup_cmd.subprocess.run", side_effect=missing):
        with pytest.raises(BackupError, match="could not run"):
            backup_cmd._execute_dump(project, "myapp", "dump", "db")
    assert _dumps_left(project) == []


def test_a_successful_dump_hands_its_plaintext_to_the_caller(project: BoxPaths) -> None:
    ok = _dump_runs(["sh", "-c", "printf 'ROWS'"])
    with patch("boxmunge.commands.backup_cmd.subprocess.run", side_effect=ok):
        raw = backup_cmd._execute_dump(project, "myapp", "dump", "db")
    assert raw.read_bytes() == b"ROWS"
    assert raw.stat().st_mode & 0o077 == 0
