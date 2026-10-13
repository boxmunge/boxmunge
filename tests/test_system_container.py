"""Tests for system container abstraction (unit tests with mocked Docker)."""

from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

import pytest

from boxmunge.system_container import (
    system_exec, ensure_system_container, SystemContainerError,
    CONTAINER_NAME,
)


class TestSystemExec:
    @patch("boxmunge.system_container.subprocess.run")
    def test_exec_returns_stdout(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="output\n", stderr=""
        )
        result = system_exec(["age", "--version"])
        assert result.stdout == "output\n"
        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["docker", "exec", CONTAINER_NAME]
        assert "age" in cmd
        assert "--version" in cmd

    @patch("boxmunge.system_container.subprocess.run")
    def test_exec_raises_on_failure(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "docker", stderr="error"
        )
        with pytest.raises(SystemContainerError, match="Command failed"):
            system_exec(["age", "--encrypt"])

    @patch("boxmunge.system_container.subprocess.run")
    def test_exec_raises_on_timeout(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 600)
        with pytest.raises(SystemContainerError, match="timed out"):
            system_exec(["rclone", "sync"])

    @patch("boxmunge.system_container.subprocess.run")
    def test_exec_with_stdin(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        system_exec(["age", "--decrypt"], stdin=b"encrypted-data")
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("input") == b"encrypted-data"


class TestEnsureSystemContainer:
    @patch("boxmunge.system_container.subprocess.run")
    def test_returns_true_when_running(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="running\n")
        assert ensure_system_container() is True

    @patch("boxmunge.system_container.subprocess.run")
    def test_returns_false_when_not_running(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert ensure_system_container() is False


class TestContainerPath:
    """Host-to-container translation is a prefix match on the real mounts.

    The old translation matched the substrings "/config/" and "/projects/",
    so a project named `config` mapped onto the read-only key mount, and any
    root other than /opt/boxmunge silently mapped to the default tree.
    """

    def test_project_path_translates_under_projects(self, paths) -> None:
        from boxmunge.system_container import container_path
        p = paths.project_backups("web") / "web-2026.tar.gz.age"
        assert container_path(p, paths) == "/projects/web/backups/web-2026.tar.gz.age"

    def test_project_named_config_translates_under_projects(self, paths) -> None:
        from boxmunge.system_container import container_path
        p = paths.project_backups("config") / ".encrypt-x.tmp"
        assert container_path(p, paths) == "/projects/config/backups/.encrypt-x.tmp"

    def test_backup_key_translates_to_key_mount(self, paths) -> None:
        from boxmunge.system_container import container_path
        assert container_path(paths.backup_key, paths) == "/config/backup.key"

    def test_non_default_root_translates_relative_to_that_root(self, tmp_path) -> None:
        from boxmunge.paths import BoxPaths
        from boxmunge.system_container import container_path
        other = BoxPaths(root=tmp_path / "srv" / "other-root")
        p = other.project_backups("web") / "web-1.tar.gz.age"
        assert container_path(p, other) == "/projects/web/backups/web-1.tar.gz.age"

    def test_path_under_a_different_root_raises(self, paths, tmp_path) -> None:
        from boxmunge.paths import BoxPaths
        from boxmunge.system_container import container_path
        other = BoxPaths(root=tmp_path / "elsewhere")
        p = other.project_backups("web") / "web-1.tar.gz.age"
        with pytest.raises(SystemContainerError) as exc:
            container_path(p, paths)
        msg = str(exc.value)
        assert str(p) in msg
        assert str(paths.projects.resolve()) in msg
        assert "/projects" in msg

    def test_tmp_path_raises_naming_path_and_mounts(self, paths) -> None:
        from boxmunge.system_container import container_path
        with pytest.raises(SystemContainerError, match="/tmp/x/out.tar.gz"):
            container_path(Path("/tmp/x/out.tar.gz"), paths)

    def test_sibling_directory_with_shared_prefix_raises(self, paths) -> None:
        from boxmunge.system_container import container_path
        sibling = paths.root / "projects-evil" / "web" / "x"
        with pytest.raises(SystemContainerError):
            container_path(sibling, paths)

    def test_other_config_files_are_not_mounted(self, paths) -> None:
        from boxmunge.system_container import container_path
        with pytest.raises(SystemContainerError):
            container_path(paths.host_secrets, paths)

    def test_symlink_escaping_the_mount_raises(self, paths, tmp_path) -> None:
        from boxmunge.system_container import container_path
        outside = tmp_path / "outside"
        outside.mkdir()
        link = paths.projects / "web"
        link.symlink_to(outside)
        with pytest.raises(SystemContainerError):
            container_path(link / "backups" / "x", paths)
