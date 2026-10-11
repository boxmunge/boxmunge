"""Restore and test-restore must decrypt somewhere the system container can see.

When age runs in the system container, every path handed to it must
translate through ``_container_path``. A decrypt target under /tmp does
not, which crashed restore and test-restore on container-age hosts.
"""

import stat
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import backup
from boxmunge.backup import BackupError
from boxmunge.commands.restore import run_restore
from boxmunge.commands.test_restore_cmd import run_test_restore
from boxmunge.paths import BoxPaths

PROJECT = "myapp"
SNAPSHOT = f"{PROJECT}-2026-10-11T181604.tar.gz.age"


class FakeAge:
    """Stand-in for ``_run_age_cmd``: checks paths translate, writes output."""

    def __init__(self, paths: BoxPaths) -> None:
        self.paths = paths
        self.calls: list[list[str]] = []
        self.output_dir_mode: int | None = None

    def __call__(self, cmd: list[str], **_: object) -> subprocess.CompletedProcess:
        self.calls.append(cmd)
        out = cmd[cmd.index("-o") + 1]
        # The container path must map back onto the real host path.
        assert out.startswith("/projects/")
        host_out = self.paths.projects / out.removeprefix("/projects/")
        self.output_dir_mode = stat.S_IMODE(host_out.parent.stat().st_mode)
        host_out.write_bytes(b"plaintext snapshot")
        return subprocess.CompletedProcess(cmd, 0)


@pytest.fixture
def project(paths: BoxPaths) -> BoxPaths:
    paths.backup_key.write_text("AGE-SECRET-KEY-1TEST\n")
    bdir = paths.project_backups(PROJECT)
    bdir.mkdir(parents=True)
    (bdir / SNAPSHOT).write_bytes(b"encrypted")
    return paths


@pytest.fixture
def fake_age(project: BoxPaths):
    fake = FakeAge(project)
    with patch("boxmunge.backup._use_container", return_value=True), \
         patch("boxmunge.backup._run_age_cmd", side_effect=fake):
        yield fake


def _leftovers(paths: BoxPaths) -> list[str]:
    return sorted(p.name for p in paths.project_backups(PROJECT).iterdir()
                  if p.name != SNAPSHOT)


class TestContainerPath:
    def test_untranslatable_path_raises_backup_error(self) -> None:
        with pytest.raises(BackupError):
            backup._container_path(Path("/tmp/x/out.tar.gz"))


class TestTestRestore:
    def test_decrypts_into_mounted_private_dir(self, project, fake_age, capsys) -> None:
        assert run_test_restore(PROJECT, project) == 0
        assert "PASS" in capsys.readouterr().out
        assert len(fake_age.calls) == 1
        assert fake_age.output_dir_mode == 0o700
        assert _leftovers(project) == []

    def test_untranslatable_path_fails_cleanly(self, project, capsys) -> None:
        with patch("boxmunge.backup._use_container", return_value=True), \
             patch("boxmunge.backup._container_path",
                   side_effect=BackupError("cannot translate")):
            assert run_test_restore(PROJECT, project) == 1
        assert "FAIL" in capsys.readouterr().out
        assert _leftovers(project) == []


class TestRestore:
    @pytest.fixture
    def env(self, project: BoxPaths):
        project_dir = project.project_dir(PROJECT)
        manifest = {"backup": {"service": "web", "restore_command": "restore.sh"}}
        with patch("boxmunge.commands.restore.is_blocked", return_value=None), \
             patch("boxmunge.commands.restore.clear_probation_if_active"), \
             patch("boxmunge.commands.restore.load_manifest", return_value=manifest), \
             patch("boxmunge.commands.restore.resolve_backup_service", return_value="web"), \
             patch("boxmunge.commands.restore.compose_down"), \
             patch("boxmunge.commands.restore.compose_up") as up, \
             patch("boxmunge.commands.restore.time.sleep"), \
             patch("boxmunge.commands.restore.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="healthy", stderr="")
            assert project_dir.exists()
            yield up, run

    def test_restore_decrypts_into_mounted_private_dir(self, project, fake_age, env) -> None:
        up, run = env
        assert run_restore(PROJECT, project, snapshot=SNAPSHOT, yes=True) == 0
        assert fake_age.output_dir_mode == 0o700
        restore_calls = [c for c in run.call_args_list if "exec" in c.args[0]]
        assert len(restore_calls) == 1
        assert _leftovers(project) == []
        up.assert_called_once()

    def test_failed_decrypt_brings_project_back_up(self, project, env) -> None:
        up, _ = env
        with patch("boxmunge.backup._use_container", return_value=True), \
             patch("boxmunge.backup._run_age_cmd",
                   side_effect=BackupError("age failed")):
            assert run_restore(PROJECT, project, snapshot=SNAPSHOT, yes=True) == 1
        up.assert_called_once()
        assert _leftovers(project) == []
