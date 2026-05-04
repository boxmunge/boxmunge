"""Tests for boxmunge.docker — compose stop/start commands."""

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
