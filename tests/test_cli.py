"""Tests for boxmunge CLI entry point."""

import os
import signal
import subprocess
import sys
from pathlib import Path

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


def test_security_command_is_registered() -> None:
    from boxmunge.cli import COMMANDS
    assert "security" in COMMANDS
    from boxmunge.commands.security_cmd import cmd_security
    assert COMMANDS["security"] is cmd_security


_SERVER_STAND_IN = """
import sys, threading
from unittest.mock import patch
import boxmunge.cli

def serve(args):
    # Like mcp-serve's anyio stdin reader: a non-daemon thread blocked on I/O.
    reader = threading.Thread(target=sys.stdin.read)
    reader.start()
    print("serving", flush=True)
    reader.join()

with patch.dict(boxmunge.cli.COMMANDS, {"mcp-serve": serve}), \\
     patch.object(sys, "argv", ["boxmunge-server", "mcp-serve"]):
    boxmunge.cli.main()
"""


def test_sigterm_stops_a_long_running_server_promptly() -> None:
    import boxmunge
    proc = subprocess.Popen(
        [sys.executable, "-c", _SERVER_STAND_IN],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONPATH": str(Path(boxmunge.__file__).parents[1])},
    )
    try:
        assert proc.stdout.readline().strip() == "serving"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == -signal.SIGTERM
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_servers_keep_the_default_sigterm_action() -> None:
    from boxmunge.cli import COMMANDS, UNWIND_ON_SIGTERM
    assert UNWIND_ON_SIGTERM <= COMMANDS.keys()
    assert not {"mcp-serve", "console"} & UNWIND_ON_SIGTERM
