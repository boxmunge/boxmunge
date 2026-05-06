"""Tests for boxmunge.docker — compose stop/start commands."""

import fcntl
import os
import threading
import time
from pathlib import Path
from unittest.mock import patch, call, MagicMock

import pytest

from boxmunge.docker import (
    compose_stop,
    compose_start,
    compose_pull,
    image_digest,
    container_image_digest,
    tag_image,
    container_running,
    caddy_reload,
    DockerError,
)


class TestComposeStop:
    @patch("boxmunge.docker._run")
    def test_stop_default(self, mock_run: any, tmp_path: Path) -> None:
        compose_stop(tmp_path)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "compose", "-f", "compose.yml", "stop", "-t", "15"]

    @patch("boxmunge.docker._run")
    def test_stop_custom_timeout(self, mock_run: any, tmp_path: Path) -> None:
        compose_stop(tmp_path, timeout=30)
        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd
        assert cmd[cmd.index("-t") + 1] == "30"

    @patch("boxmunge.docker._run")
    def test_stop_with_project_name(self, mock_run: any, tmp_path: Path) -> None:
        compose_stop(tmp_path, project_name="myapp")
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        assert cmd[cmd.index("-p") + 1] == "myapp"


class TestComposeStart:
    @patch("boxmunge.docker._run")
    def test_start_default(self, mock_run: any, tmp_path: Path) -> None:
        compose_start(tmp_path)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "compose", "-f", "compose.yml", "start"]

    @patch("boxmunge.docker._run")
    def test_start_with_project_name(self, mock_run: any, tmp_path: Path) -> None:
        compose_start(tmp_path, project_name="myapp")
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        assert cmd[cmd.index("-p") + 1] == "myapp"


class TestComposePull:
    @patch("boxmunge.docker._run")
    def test_runs_compose_pull(self, mock_run):
        compose_pull(Path("/projects/myapp"))
        cmd = mock_run.call_args[0][0]
        assert cmd[:2] == ["docker", "compose"]
        assert "pull" in cmd

    @patch("boxmunge.docker._run")
    def test_includes_compose_files(self, mock_run):
        compose_pull(Path("/projects/myapp"), compose_files=["compose.yml", "compose.boxmunge.yml"])
        cmd = mock_run.call_args[0][0]
        assert "compose.yml" in cmd
        assert "compose.boxmunge.yml" in cmd


class TestImageDigest:
    @patch("boxmunge.docker._run")
    def test_returns_digest(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "caddy@sha256:abc123\n"
        mock_run.return_value = mock_result
        assert image_digest("caddy:2-alpine") == "sha256:abc123"

    @patch("boxmunge.docker._run")
    def test_returns_none_on_no_digest(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "<no value>\n"
        mock_run.return_value = mock_result
        assert image_digest("caddy:2-alpine") is None

    @patch("boxmunge.docker._run", side_effect=DockerError("not found"))
    def test_returns_none_on_error(self, mock_run):
        assert image_digest("nonexistent:tag") is None


class TestContainerImageDigest:
    @patch("boxmunge.docker.image_digest")
    @patch("boxmunge.docker._run")
    def test_returns_digest_via_image_id(self, mock_run, mock_image_digest):
        mock_result = MagicMock()
        mock_result.stdout = "sha256:imgid\n"
        mock_run.return_value = mock_result
        mock_image_digest.return_value = "sha256:abc123"
        assert container_image_digest("mycontainer") == "sha256:abc123"


class TestTagImage:
    @patch("boxmunge.docker._run")
    def test_tags_image(self, mock_run):
        tag_image("sha256:abc123", "caddy:2-alpine")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "tag", "sha256:abc123", "caddy:2-alpine"]


class TestContainerRunning:
    @patch("boxmunge.docker._run")
    def test_returns_true_when_running(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "true\n"
        mock_run.return_value = mock_result
        assert container_running("mycontainer") is True
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "inspect", "--format", "{{.State.Running}}", "mycontainer"]

    @patch("boxmunge.docker._run")
    def test_returns_false_when_not_running(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "false\n"
        mock_run.return_value = mock_result
        assert container_running("mycontainer") is False

    @patch("boxmunge.docker._run", side_effect=DockerError("no such container"))
    def test_returns_false_on_docker_error(self, mock_run):
        assert container_running("nonexistent") is False


class TestCaddyReloadLock:
    """caddy_reload must serialise validate+reload under a flock at lock_dir/.caddy.lock.

    Without the lock, two parallel deploys race: deploy-A passes validate,
    deploy-B writes a malformed site config, deploy-A's reload then fails
    on a config that was valid when checked. The lock turns that into a
    serialised sequence.
    """

    @patch("boxmunge.docker._run")
    def test_creates_lock_file_in_lock_dir(self, mock_run, tmp_path: Path) -> None:
        caddy_dir = tmp_path / "caddy"
        caddy_dir.mkdir()
        lock_dir = tmp_path / "state"

        caddy_reload(caddy_dir, lock_dir)

        assert (lock_dir / ".caddy.lock").exists()

    @patch("boxmunge.docker._run")
    def test_validate_and_reload_both_called(
        self, mock_run, tmp_path: Path
    ) -> None:
        caddy_dir = tmp_path / "caddy"
        caddy_dir.mkdir()
        lock_dir = tmp_path / "state"

        caddy_reload(caddy_dir, lock_dir)

        # First call is validate, second is reload.
        assert mock_run.call_count == 2
        validate_cmd = mock_run.call_args_list[0][0][0]
        reload_cmd = mock_run.call_args_list[1][0][0]
        assert "validate" in validate_cmd
        assert "reload" in reload_cmd

    def test_concurrent_reloads_serialize(self, tmp_path: Path) -> None:
        """When the lock is held externally, caddy_reload blocks until released.

        Holds the lock from a separate thread; starts caddy_reload (with
        _run mocked); confirms it hasn't completed while the lock is held;
        releases the lock; confirms it then completes promptly.
        """
        caddy_dir = tmp_path / "caddy"
        caddy_dir.mkdir()
        lock_dir = tmp_path / "state"
        lock_dir.mkdir()
        lock_path = lock_dir / ".caddy.lock"

        # Externally acquire the lock.
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)

        completed = threading.Event()

        def _do_reload() -> None:
            with patch("boxmunge.docker._run"):
                caddy_reload(caddy_dir, lock_dir)
            completed.set()

        t = threading.Thread(target=_do_reload, daemon=True)
        t.start()

        # While we hold the lock, the reload thread must be blocked.
        assert not completed.wait(timeout=0.3)

        # Release the external lock; reload should now complete.
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

        assert completed.wait(timeout=2.0), "caddy_reload did not unblock after lock release"
        t.join(timeout=1.0)
