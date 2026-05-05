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
        for cmd in ["help", "status", "version", "prod-deploy", "stage", "promote",
                     "unstage", "inbox", "secrets", "security", "check", "log", "logs",
                     "agent-help", "doctor", "project-add", "project-list",
                     "project-delete"]:
            assert cmd in ALLOWED_COMMANDS, f"{cmd} not in ALLOWED_COMMANDS"

    def test_dropped_commands_not_allowed(self) -> None:
        for cmd in ["list-projects", "remove-project", "project-remove",
                     "add-project"]:
            assert cmd not in ALLOWED_COMMANDS, f"{cmd} should not be allowed"

    def test_shell_commands_not_allowed(self) -> None:
        for cmd in ["bash", "sh", "ls", "cat", "cd", "vi", "rm",
                     "python", "python3", "curl", "wget", "docker"]:
            assert cmd not in ALLOWED_COMMANDS, f"{cmd} should not be allowed"

    def test_every_cli_command_has_an_allowlist_decision(self) -> None:
        """Every command registered in cli.COMMANDS must either be in
        ALLOWED_COMMANDS or in INTENTIONALLY_RESTRICTED below.

        Catches the v0.5.0 bug where `security` was added to cli.COMMANDS
        but forgotten in shell.ALLOWED_COMMANDS — making it invisible to
        the deploy user.
        """
        from boxmunge.cli import COMMANDS

        # Commands deliberately not exposed to the deploy shell (root-only,
        # or wrappers shell.py routes through sudo to the upgrade shim).
        INTENTIONALLY_RESTRICTED = {
            "init-host",         # Bootstrap-only, runs as root before deploy user exists.
            "_discover-update",  # Internal JSON dispatcher used by the upgrade shim.
            "handshake",         # Used by the local CLI to fingerprint the box; not for ops.
            "stash",             # Root-context only; reached via the upgrade shim.
            "container-update",  # Triggered by systemd timer, not by operators.
            "bundle",            # Local-dev only — packages a project on the developer's machine.
        }

        for cmd in COMMANDS:
            assert cmd in ALLOWED_COMMANDS or cmd in INTENTIONALLY_RESTRICTED, (
                f"CLI command '{cmd}' is registered in cli.COMMANDS but not "
                f"in shell.ALLOWED_COMMANDS or INTENTIONALLY_RESTRICTED. "
                f"If it's an operator command, add it to ALLOWED_COMMANDS. "
                f"If it's intentionally root-only, add it to "
                f"INTENTIONALLY_RESTRICTED in this test."
            )


class TestDispatchCommand:
    @patch("boxmunge.shell.subprocess.run")
    def test_dispatches_allowed_command(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        run_command("status", [])
        mock_run.assert_called_once_with(["boxmunge-server", "status"])

    @patch("boxmunge.shell.subprocess.run")
    def test_upgrade_no_args_routes_to_shim(self, mock_run: MagicMock) -> None:
        """Bare `upgrade` from deploy goes through the root-context shim
        (which handles stash + venv swap that need root perms)."""
        mock_run.return_value = MagicMock(returncode=0)
        run_command("upgrade", [])
        mock_run.assert_called_once_with(
            ["sudo", "-n", "/opt/boxmunge/bin/boxmunge-upgrade", "auto"]
        )

    @patch("boxmunge.shell.subprocess.run")
    def test_upgrade_with_flags_uses_boxmunge_server(self, mock_run: MagicMock) -> None:
        """Flags like --dry-run are pre-flight checks that don't need root."""
        mock_run.return_value = MagicMock(returncode=0)
        run_command("upgrade", ["--dry-run"])
        mock_run.assert_called_once_with(["boxmunge-server", "upgrade", "--dry-run"])

    @patch("boxmunge.shell.subprocess.run")
    def test_upgrade_target_version_routes_to_shim(self, mock_run: MagicMock) -> None:
        """`upgrade --target VERSION` goes through the root-context shim
        (downloading a specific bundle requires the same privileged path
        as `upgrade auto`)."""
        mock_run.return_value = MagicMock(returncode=0)
        run_command("upgrade", ["--target", "0.3.5"])
        mock_run.assert_called_once_with(
            ["sudo", "-n", "/opt/boxmunge/bin/boxmunge-upgrade", "target", "0.3.5"]
        )

    @patch("boxmunge.shell.subprocess.run")
    def test_upgrade_target_without_version_errors(self, mock_run: MagicMock) -> None:
        """`upgrade --target` without a version must fail noisily and must NOT
        be routed onward (neither to the shim nor to boxmunge-server)."""
        rc = run_command("upgrade", ["--target"])
        assert rc != 0
        mock_run.assert_not_called()

    @patch("boxmunge.shell.subprocess.run")
    def test_dispatches_with_args(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        run_command("prod-deploy", ["myapp", "--dry-run"])
        mock_run.assert_called_once_with(["boxmunge-server", "prod-deploy", "myapp", "--dry-run"])

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
    def test_handles_sftp_direct(self, mock_run: MagicMock) -> None:
        """SFTP subsystem via direct sftp-server path."""
        mock_run.return_value = MagicMock(returncode=0)
        with patch("boxmunge.shell.Path.home", return_value=Path("/tmp/fakehome")):
            result = run_command("/usr/lib/openssh/sftp-server", [])
        assert result == 0
        mock_run.assert_called_once_with(["/usr/lib/openssh/sftp-server"], check=False)

    @patch("boxmunge.shell.subprocess.run")
    def test_handles_boxmunge_sftp(self, mock_run: MagicMock) -> None:
        """SFTP subsystem via boxmunge-sftp wrapper (the normal case)."""
        mock_run.return_value = MagicMock(returncode=0)
        with patch("boxmunge.shell.Path.home", return_value=Path("/tmp/fakehome")):
            result = run_command("/opt/boxmunge/bin/boxmunge-sftp", [])
        assert result == 0
        # Should delegate to the real sftp-server, not boxmunge-sftp
        mock_run.assert_called_once_with(["/usr/lib/openssh/sftp-server"], check=False)


class TestPauseResumeAllowed:
    def test_pause_in_allowlist(self) -> None:
        from boxmunge.shell import ALLOWED_COMMANDS
        assert "pause" in ALLOWED_COMMANDS

    def test_resume_in_allowlist(self) -> None:
        from boxmunge.shell import ALLOWED_COMMANDS
        assert "resume" in ALLOWED_COMMANDS
