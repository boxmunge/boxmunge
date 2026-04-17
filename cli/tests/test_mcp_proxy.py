"""Tests for the MCP stdio proxy."""

import pytest
from unittest.mock import patch, MagicMock

from boxmunge_cli.mcp_proxy import run_mcp_proxy


class TestRunMcpProxy:
    @patch("boxmunge_cli.mcp_proxy.subprocess.Popen")
    def test_spawns_ssh_with_mcp_serve(self, mock_popen: MagicMock) -> None:
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        run_mcp_proxy(config)

        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert cmd == ["ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new",
                       "deploy@box.example.com", "mcp-serve"]

    @patch("boxmunge_cli.mcp_proxy.subprocess.Popen")
    def test_uses_stdin_stdout_passthrough(self, mock_popen: MagicMock) -> None:
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        run_mcp_proxy(config)

        _, kwargs = mock_popen.call_args
        assert "stdin" not in kwargs or kwargs["stdin"] is None
        assert "stdout" not in kwargs or kwargs["stdout"] is None

    @patch("boxmunge_cli.mcp_proxy.subprocess.Popen")
    def test_returns_exit_code(self, mock_popen: MagicMock) -> None:
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 42
        mock_popen.return_value = mock_proc

        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        result = run_mcp_proxy(config)
        assert result == 42
