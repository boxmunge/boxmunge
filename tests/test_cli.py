"""Tests for boxmunge CLI entry point."""

import pytest
from unittest.mock import patch
from io import StringIO

from boxmunge.cli import main


class TestCLI:
    def test_help_exits_zero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["boxmunge", "help"]):
                main()
        assert exc_info.value.code == 0

    def test_agent_help_exits_zero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["boxmunge", "agent-help"]):
                main()
        assert exc_info.value.code == 0

    def test_no_args_shows_help(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["boxmunge"]):
                main()
        assert exc_info.value.code == 0

    def test_unknown_command_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["boxmunge", "nonexistent"]):
                with patch("sys.stderr", new_callable=StringIO):
                    main()
        assert exc_info.value.code == 2

    def test_prod_deploy_registered(self) -> None:
        from boxmunge.cli import COMMANDS
        assert "prod-deploy" in COMMANDS
        assert "deploy" not in COMMANDS
