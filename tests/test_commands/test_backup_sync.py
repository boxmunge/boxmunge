"""backup-sync runs rclone only inside the system container (D-08/C-20)."""

import subprocess
from unittest.mock import patch

import pytest

import boxmunge.system_container as sc
from boxmunge.commands.backup_cmd import run_backup_sync
from boxmunge.paths import BoxPaths


def _ok(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


@pytest.fixture
def configured(paths: BoxPaths) -> BoxPaths:
    paths.config_file.write_text(
        "hostname: box.example.com\nadmin_email: a@example.com\n"
        "backup_remote: offsite:bucket\n"
    )
    paths.project_backups("myapp").mkdir(parents=True)
    return paths


class TestDumpOwnership:
    """C-12: a root-invoked backup (container-update, self-test) must not
    leave a root-owned backups/ dir that the deploy user and the system
    container can no longer create temp files in."""

    def test_new_backups_dir_and_dump_go_to_the_platform_user(self, paths) -> None:
        from boxmunge.commands import backup_cmd
        paths.project_dir("myapp").mkdir()
        chowned = []
        with patch.object(backup_cmd._backup, "chown_for_system_container",
                          side_effect=lambda p, _paths: chowned.append(p)), \
             patch("boxmunge.commands.backup_cmd.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, stderr=b"")):
            raw = backup_cmd._execute_dump(paths, "myapp", "dump", "db")
        assert chowned == [paths.project_backups("myapp"), raw]

    def test_existing_backups_dir_is_left_alone(self, paths) -> None:
        from boxmunge.commands import backup_cmd
        paths.project_backups("myapp").mkdir(parents=True)
        chowned = []
        with patch.object(backup_cmd._backup, "chown_for_system_container",
                          side_effect=lambda p, _paths: chowned.append(p)), \
             patch("boxmunge.commands.backup_cmd.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, stderr=b"")):
            raw = backup_cmd._execute_dump(paths, "myapp", "dump", "db")
        assert chowned == [raw]


class TestBackupSync:
    def test_rclone_uses_the_mounted_operator_config(self, configured, system_container) -> None:
        system_container.handler = _ok
        assert run_backup_sync(configured) == 0
        [cmd] = system_container.calls
        assert cmd[0] == "rclone"
        assert cmd[cmd.index("--config") + 1] == "/config/rclone/rclone.conf"
        assert "/projects" in cmd

    def test_copies_and_never_mirrors_deletions(self, configured, system_container) -> None:
        """C-10: `rclone sync` deleted every off-site copy that a local prune
        or project-delete had removed. The remote is an archive."""
        system_container.handler = _ok
        assert run_backup_sync(configured) == 0
        [cmd] = system_container.calls
        assert cmd[:4] == ["rclone", "copy", "/projects", "offsite:bucket"]
        assert "sync" not in cmd
        assert cmd[cmd.index("--include") + 1] == "/*/backups/*.tar.gz.age"

    def test_single_project_uses_the_same_remote_layout(self, configured, system_container) -> None:
        system_container.handler = _ok
        assert run_backup_sync(configured, "myapp") == 0
        [cmd] = system_container.calls
        assert cmd[:4] == ["rclone", "copy", "/projects/myapp/backups",
                           "offsite:bucket/myapp/backups"]
        assert cmd[cmd.index("--include") + 1] == "/*.tar.gz.age"

    def test_missing_container_fails_without_host_rclone(
        self, configured, monkeypatch, capsys,
    ) -> None:
        monkeypatch.setattr(sc, "_inspect", lambda name: None)
        with patch("subprocess.run") as host_run:
            assert run_backup_sync(configured) == 1
        host_run.assert_not_called()
        err = capsys.readouterr().err
        assert "does not exist" in err
        assert "up -d --build" in err

    def test_rclone_failure_is_reported(self, configured, system_container, capsys) -> None:
        def fail(cmd):
            raise sc.SystemContainerError("Command failed in system container: rclone")
        system_container.handler = fail
        assert run_backup_sync(configured) == 1
        assert "rclone" in capsys.readouterr().err
