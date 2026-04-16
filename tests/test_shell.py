"""Tests for the restricted boxmunge shell."""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge.shell import parse_shell_command, run_command, dispatch_command, ALLOWED_COMMANDS


class TestParseShellCommand:
    def test_simple_command(self) -> None:
        cmd, args = parse_shell_command("status")
        assert cmd == "status"
        assert args == []

    def test_command_with_args(self) -> None:
        cmd, args = parse_shell_command("prod-deploy myapp")
        assert cmd == "prod-deploy"
        assert args == ["myapp"]

    def test_command_with_flags(self) -> None:
        cmd, args = parse_shell_command("prod-deploy myapp --dry-run")
        assert cmd == "prod-deploy"
        assert args == ["myapp", "--dry-run"]

    def test_help_command(self) -> None:
        cmd, args = parse_shell_command("help")
        assert cmd == "help"
        assert args == []

    def test_empty_command(self) -> None:
        cmd, args = parse_shell_command("")
        assert cmd == ""
        assert args == []

    def test_whitespace_only(self) -> None:
        cmd, args = parse_shell_command("   ")
        assert cmd == ""
        assert args == []

    def test_secrets_with_value(self) -> None:
        cmd, args = parse_shell_command('secrets set myapp DB_URL="postgres://x"')
        assert cmd == "secrets"
        assert "set" in args

    def test_detects_scp_sink(self) -> None:
        cmd, args = parse_shell_command("scp -t /some/path")
        assert cmd == "scp"
        assert args == ["-t", "/some/path"]

    def test_detects_scp_source(self) -> None:
        cmd, args = parse_shell_command("scp -f /some/path")
        assert cmd == "scp"
        assert args == ["-f", "/some/path"]


class TestAllowedCommands:
    def test_known_commands_are_allowed(self) -> None:
        for cmd in ["help", "status", "prod-deploy", "stage", "promote",
                     "unstage", "inbox", "secrets", "check", "logs",
                     "agent-help", "doctor", "list-projects"]:
            assert cmd in ALLOWED_COMMANDS, f"{cmd} not in ALLOWED_COMMANDS"

    def test_shell_commands_not_allowed(self) -> None:
        for cmd in ["bash", "sh", "ls", "cat", "cd", "vi", "rm",
                     "python", "python3", "curl", "wget", "docker"]:
            assert cmd not in ALLOWED_COMMANDS, f"{cmd} should not be allowed"


class TestDispatchCommand:
    @patch("boxmunge.shell.subprocess.run")
    def test_dispatches_allowed_command(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        run_command("status", [])
        mock_run.assert_called_once_with(["boxmunge", "status"])

    @patch("boxmunge.shell.subprocess.run")
    def test_dispatches_with_args(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        run_command("prod-deploy", ["myapp", "--dry-run"])
        mock_run.assert_called_once_with(["boxmunge", "prod-deploy", "myapp", "--dry-run"])

    def test_rejects_unknown_command(self) -> None:
        assert run_command("bash", []) == 1

    def test_rejects_ls(self) -> None:
        assert run_command("ls", ["/opt/boxmunge"]) == 1

    @patch("boxmunge.shell.handle_scp_upload")
    def test_dispatches_scp_sink(self, mock_scp: MagicMock) -> None:
        run_command("scp", ["-t", "/some/path"])
        mock_scp.assert_called_once_with(["-t", "/some/path"])

    def test_rejects_scp_source(self) -> None:
        assert run_command("scp", ["-f", "/some/path"]) == 1

    def test_empty_command_exits_silently(self) -> None:
        """Empty -c '' from SSH session setup must not print anything."""
        with pytest.raises(SystemExit) as exc_info:
            dispatch_command("", [])
        assert exc_info.value.code == 0

    @patch("boxmunge.shell.subprocess.run")
    def test_handles_sftp(self, mock_run: MagicMock) -> None:
        """SFTP subsystem is routed through the shell by sshd."""
        mock_run.return_value = MagicMock(returncode=0)
        with patch("boxmunge.shell.Path.home", return_value=Path("/tmp/fakehome")):
            result = run_command("/usr/lib/openssh/sftp-server", [])
        assert result == 0
        mock_run.assert_called_once_with(["/usr/lib/openssh/sftp-server"], check=False)
