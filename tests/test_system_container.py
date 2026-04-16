"""Tests for system container abstraction (unit tests with mocked Docker)."""

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
