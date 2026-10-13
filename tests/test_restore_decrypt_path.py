"""Restore and test-restore must decrypt somewhere the system container can see.

When age runs in the system container, every path handed to it must
translate through ``container_path``. A decrypt target under /tmp does
not, which crashed restore and test-restore on container-age hosts.
"""

import stat
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import backup
from boxmunge.backup import BackupError
from boxmunge.system_container import SystemContainerError
from boxmunge.commands.restore import run_restore
from boxmunge.commands.test_restore_cmd import run_test_restore
from boxmunge.paths import BoxPaths
from tests.fake_system_container import FakeSystemContainer, host_path

PROJECT = "myapp"
SNAPSHOT = f"{PROJECT}-2026-10-11T181604.tar.gz.age"
# Any valid project name works, including `config` (C-11: the old substring
# translation sent it to the read-only key mount).
PROJECTS = ["myapp", "config"]


class FakeAge:
    """Stand-in for age in the container: checks paths translate, writes output."""

    def __init__(self, paths: BoxPaths) -> None:
        self.paths = paths
        self.calls: list[list[str]] = []
        self.output_dir_mode: int | None = None

    def __call__(self, cmd: list[str]) -> subprocess.CompletedProcess:
        self.calls.append(cmd)
        out = cmd[cmd.index("-o") + 1]
        # The container path must map back onto the real host path.
        assert out.startswith("/projects/")
        host_out = host_path(self.paths, out)
        self.output_dir_mode = stat.S_IMODE(host_out.parent.stat().st_mode)
        host_out.write_bytes(b"plaintext snapshot")
        return subprocess.CompletedProcess(cmd, 0)


@pytest.fixture
def project(paths: BoxPaths) -> BoxPaths:
    paths.backup_key.write_text("AGE-SECRET-KEY-1TEST\n")
    paths.rclone_config_dir.mkdir()
    bdir = paths.project_backups(PROJECT)
    bdir.mkdir(parents=True)
    (bdir / SNAPSHOT).write_bytes(b"encrypted")
    return paths


@pytest.fixture
def fake_age(project: BoxPaths, monkeypatch):
    fake = FakeAge(project)
    FakeSystemContainer(project, handler=fake).install(monkeypatch)
    return fake


def _leftovers(paths: BoxPaths) -> list[str]:
    return sorted(p.name for p in paths.project_backups(PROJECT).iterdir()
                  if p.name != SNAPSHOT)


class TestContainerPath:
    def test_untranslatable_path_raises_backup_error(self, project, fake_age) -> None:
        with pytest.raises(BackupError, match="outside the system container"):
            backup.decrypt_file(project.project_backups(PROJECT) / SNAPSHOT,
                                Path("/tmp/x/out.tar.gz"), project)
        assert fake_age.calls == []


class TestProjectNamedConfig:
    def test_test_restore_of_project_named_config(self, project, fake_age) -> None:
        bdir = project.project_backups("config")
        bdir.mkdir(parents=True)
        (bdir / "config-2026-10-11T181604.tar.gz.age").write_bytes(b"encrypted")
        fake = fake_age
        assert run_test_restore("config", project) == 0
        cmd = fake.calls[0]
        assert cmd[cmd.index("-o") + 1].startswith("/projects/config/backups/.restore-")
        assert cmd[-1] == "/projects/config/backups/config-2026-10-11T181604.tar.gz.age"
        assert cmd[cmd.index("-i") + 1] == "/config/backup.key"


class TestTestRestore:
    def test_decrypts_into_mounted_private_dir(self, project, fake_age, capsys) -> None:
        assert run_test_restore(PROJECT, project) == 0
        assert "PASS" in capsys.readouterr().out
        assert len(fake_age.calls) == 1
        assert fake_age.output_dir_mode == 0o700
        assert _leftovers(project) == []

    def test_untranslatable_path_fails_cleanly(self, project, fake_age, capsys) -> None:
        with patch("boxmunge.system_container.container_path",
                   side_effect=SystemContainerError("cannot translate")):
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
            run.return_value = subprocess.CompletedProcess([], 0, stdout="running healthy", stderr="")
            assert project_dir.exists()
            yield up, run

    def test_restore_decrypts_into_mounted_private_dir(self, project, fake_age, env) -> None:
        up, run = env
        assert run_restore(PROJECT, project, snapshot=SNAPSHOT, yes=True,
                           safety_snapshot=False) == 0
        assert fake_age.output_dir_mode == 0o700
        restore_calls = [c for c in run.call_args_list if "exec" in c.args[0]]
        assert len(restore_calls) == 1
        assert _leftovers(project) == []
        up.assert_called_once()

    def test_failed_decrypt_never_stops_the_project(self, project, env, monkeypatch) -> None:
        up, _ = env

        def age_fails(cmd):
            raise SystemContainerError("age failed")
        FakeSystemContainer(project, handler=age_fails).install(monkeypatch)
        with patch("boxmunge.commands.restore.compose_down") as down:
            assert run_restore(PROJECT, project, snapshot=SNAPSHOT, yes=True) == 1
        down.assert_not_called()
        up.assert_not_called()
        assert _leftovers(project) == []
