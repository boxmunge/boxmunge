# SPDX-License-Identifier: Apache-2.0
"""Tests for the boxmunge local CLI entry point."""

import pytest
from unittest.mock import patch
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
        # Assert against the package version rather than a literal, so a
        # version bump does not require editing this test.
        import boxmunge_cli
        assert boxmunge_cli.__version__ in output

    def test_unknown_command_exits_2(self) -> None:
        from boxmunge_cli.cli import main
        with patch("sys.argv", ["boxmunge", "nonexistent"]):
            with patch("sys.stderr", new_callable=StringIO):
                with pytest.raises(SystemExit) as exc:
                    main()
                assert exc.value.code == 2

    def test_all_commands_registered(self) -> None:
        import argparse
        from boxmunge_cli.cli import build_parser
        sub = next(a for a in build_parser()._actions
                   if isinstance(a, argparse._SubParsersAction))
        expected = {"init", "bundle", "stage", "promote", "prod-deploy",
                    "status", "logs", "mcp-serve", "server-setup",
                    "secrets", "rollback", "validate", "remote"}
        assert expected == set(sub.choices)

    def test_help_shows_only_local_commands(self, capsys) -> None:
        from boxmunge_cli.cli import main
        with patch("sys.argv", ["boxmunge"]):
            with pytest.raises(SystemExit):
                main()
        output = capsys.readouterr().out
        assert "restore" not in output
        assert "backup" not in output
        assert "health" not in output
