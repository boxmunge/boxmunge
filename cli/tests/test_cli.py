# SPDX-License-Identifier: Apache-2.0
"""Tests for the boxmunge local CLI entry point."""

import pytest
from unittest.mock import patch, MagicMock
from io import StringIO


class TestCLI:
    def test_no_args_shows_help(self, capsys) -> None:
        from boxmunge_cli.cli import main
        with patch("sys.argv", ["boxmunge"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0
        output = capsys.readouterr().out
        assert "boxmunge" in output
        assert "init" in output

    def test_version_flag(self, capsys) -> None:
        from boxmunge_cli.cli import main
        with patch("sys.argv", ["boxmunge", "--version"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0
        output = capsys.readouterr().out
        assert "0.1.0" in output

    def test_unknown_command_exits_2(self) -> None:
        from boxmunge_cli.cli import main
        with patch("sys.argv", ["boxmunge", "nonexistent"]):
            with patch("sys.stderr", new_callable=StringIO):
                with pytest.raises(SystemExit) as exc:
                    main()
                assert exc.value.code == 2

    def test_all_commands_registered(self) -> None:
        from boxmunge_cli.cli import COMMANDS
        expected = {"init", "bundle", "stage", "promote", "prod-deploy",
                    "status", "logs", "mcp-serve", "server-setup"}
        assert expected == set(COMMANDS.keys())

    def test_help_shows_only_local_commands(self, capsys) -> None:
        from boxmunge_cli.cli import main
        with patch("sys.argv", ["boxmunge"]):
            with pytest.raises(SystemExit):
                main()
        output = capsys.readouterr().out
        assert "restore" not in output
        assert "backup" not in output
        assert "health" not in output
