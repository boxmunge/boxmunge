"""Tests for boxmunge.docker — compose stop/start commands."""

from pathlib import Path
from unittest.mock import patch, call

import pytest

from boxmunge.docker import compose_stop, compose_start, DockerError


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
