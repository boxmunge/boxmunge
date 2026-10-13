"""Tests for the system container abstraction (unit tests, docker mocked)."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import boxmunge.system_container as sc
from boxmunge.system_container import (
    CONTAINER_NAME, SystemContainerError, connect, system_exec,
)
from tests.fake_system_container import healthy_inspect


class TestSystemExec:
    @patch("boxmunge.system_container.subprocess.run")
    def test_exec_returns_stdout(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="output\n", stderr="")
        result = system_exec(["age", "--version"])
        assert result.stdout == "output\n"
        assert mock_run.call_args[0][0] == ["docker", "exec", CONTAINER_NAME, "age", "--version"]

    @patch("boxmunge.system_container.subprocess.run")
    def test_exec_raises_on_failure(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker", stderr="error")
        with pytest.raises(SystemContainerError, match="Command failed"):
            system_exec(["age", "--encrypt"])

    @patch("boxmunge.system_container.subprocess.run")
    def test_exec_raises_on_timeout(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 600)
        with pytest.raises(SystemContainerError, match="timed out"):
            system_exec(["rclone", "copy"])


def _inspect_result(stdout: str = "", stderr: str = "", rc: int = 0) -> MagicMock:
    return MagicMock(returncode=rc, stdout=stdout, stderr=stderr)


class TestConnect:
    """No host fallback (D-08/C-20): connect() succeeds only for a running
    container mounted for this root, and otherwise says how to fix it."""

    def test_running_and_correctly_mounted(self, paths, monkeypatch) -> None:
        monkeypatch.setattr(sc, "_inspect", lambda name: healthy_inspect(paths))
        tools = connect(paths)
        assert tools.name == CONTAINER_NAME
        assert tools.path(paths.backup_key) == "/config/backup.key"

    def test_missing_container_fails_with_start_command(self, paths) -> None:
        with patch("boxmunge.system_container.subprocess.run",
                   return_value=_inspect_result(rc=1, stderr="Error: No such container: x")):
            with pytest.raises(SystemContainerError) as exc:
                connect(paths)
        msg = str(exc.value)
        assert "does not exist" in msg
        assert f"docker compose -f {paths.system_compose} up -d --build" in msg
        assert "never fall back to host tools" in msg

    def test_stopped_container_fails(self, paths, monkeypatch) -> None:
        info = healthy_inspect(paths)
        info["State"]["Status"] = "exited"
        monkeypatch.setattr(sc, "_inspect", lambda name: info)
        with pytest.raises(SystemContainerError, match="is exited, not running"):
            connect(paths)

    def test_container_mounted_for_another_root_fails(self, paths, tmp_path, monkeypatch) -> None:
        from boxmunge.paths import BoxPaths
        other = BoxPaths(root=tmp_path / "other")
        monkeypatch.setattr(sc, "_inspect", lambda name: {
            "State": {"Status": "running"},
            "Mounts": [{"Source": str(m.host), "Destination": m.container}
                       for m in sc.system_mounts(other)],
        })
        with pytest.raises(SystemContainerError) as exc:
            connect(paths)
        assert "not mounted for the boxmunge root" in str(exc.value)
        assert "--force-recreate" in str(exc.value)

    def test_rclone_config_mount_is_required(self, paths, monkeypatch) -> None:
        """The old compose file mounted /dev/null as the rclone config."""
        info = healthy_inspect(paths)
        info["Mounts"] = [m for m in info["Mounts"] if m["Destination"] != "/config/rclone"]
        monkeypatch.setattr(sc, "_inspect", lambda name: info)
        with pytest.raises(SystemContainerError, match="/config/rclone: expected"):
            connect(paths)

    def test_docker_cli_missing_fails(self, paths) -> None:
        with patch("boxmunge.system_container.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(SystemContainerError, match="docker CLI not found"):
                connect(paths)

    def test_inspect_error_other_than_missing_is_surfaced(self, paths) -> None:
        with patch("boxmunge.system_container.subprocess.run",
                   return_value=_inspect_result(rc=1, stderr="permission denied on socket")):
            with pytest.raises(SystemContainerError, match="permission denied on socket"):
                connect(paths)

    def test_tools_run_execs_in_the_container(self, paths, monkeypatch) -> None:
        monkeypatch.setattr(sc, "_inspect", lambda name: healthy_inspect(paths))
        with patch("boxmunge.system_container.subprocess.run",
                   return_value=_inspect_result(stdout="ok")) as run:
            connect(paths).run(["age", "--version"])
        assert run.call_args[0][0][:3] == ["docker", "exec", CONTAINER_NAME]


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
