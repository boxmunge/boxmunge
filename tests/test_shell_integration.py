"""Integration tests for the restricted shell."""

import os
import pytest
from unittest.mock import patch, MagicMock

from boxmunge.shell import main, parse_shell_command, dispatch_command, run_command, ALLOWED_COMMANDS


class TestShellMain:
    @patch("boxmunge.shell.dispatch_command")
    def test_main_reads_dash_c(self, mock_dispatch: MagicMock) -> None:
        """Login shell is called with -c 'command string'."""
        with patch("sys.argv", ["boxmunge-shell", "-c", "status"]):
            main()
        mock_dispatch.assert_called_once_with("status", [])

    @patch("boxmunge.shell.dispatch_command")
    def test_main_reads_ssh_original_command(self, mock_dispatch: MagicMock) -> None:
        """ForceCommand mode uses SSH_ORIGINAL_COMMAND."""
        with patch("sys.argv", ["boxmunge-shell"]):
            with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "prod-deploy myapp"}):
                main()
        mock_dispatch.assert_called_once_with("prod-deploy", ["myapp"])

    @patch("boxmunge.shell.interactive_loop")
    def test_main_no_command_starts_interactive(self, mock_loop: MagicMock) -> None:
        with patch("sys.argv", ["boxmunge-shell"]):
            with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": ""}):
                main()
        mock_loop.assert_called_once()


class TestAllCommandsDispatch:
    """Verify every allowed command dispatches to boxmunge."""

    @patch("boxmunge.shell.subprocess.run")
    @pytest.mark.parametrize("command", sorted(ALLOWED_COMMANDS))
    def test_allowed_command_dispatches(self, mock_run: MagicMock,
                                        command: str) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        result = run_command(command, [])
        mock_run.assert_called_once_with(
            ["boxmunge", command]
        )
        assert result == 0

    @pytest.mark.parametrize("command", [
        "bash", "sh", "zsh", "fish",
        "ls", "cat", "rm", "mv", "cp", "mkdir",
        "vi", "vim", "nano", "emacs",
        "python", "python3", "node", "ruby",
        "docker", "docker-compose",
        "curl", "wget", "nc", "ssh",
        "apt", "apt-get", "pip",
        "sudo", "su",
        "chmod", "chown", "chgrp",
    ])
    def test_dangerous_command_rejected(self, command: str) -> None:
        assert run_command(command, []) == 1
