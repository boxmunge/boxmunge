# SPDX-License-Identifier: Apache-2.0
"""MCP tools take the same privileged paths as the deploy shell (A-07), and
nothing a tool runs can read or write the protocol stream (A-08)."""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from boxmunge.mcp_server import _TOOL_DEFS
from boxmunge.mcp_tools import capture_tool_call
from boxmunge.shell import ALLOWED_COMMANDS

SRC = Path(__file__).resolve().parents[1] / "src"
SHIM = "/opt/boxmunge/bin/boxmunge-upgrade"


def _defn(name: str) -> dict:
    return next(d for d in _TOOL_DEFS if d["name"] == name)


class TestUpgradeTool:
    @patch("boxmunge.mcp_tools.subprocess.run")
    def test_upgrade_goes_through_the_sudo_shim(self, mock_run: MagicMock) -> None:
        from boxmunge.mcp_tools import _tool_upgrade
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="ok\n")
        result = _tool_upgrade()
        argv = mock_run.call_args[0][0]
        assert argv == ["sudo", "-n", SHIM, "auto"]
        assert mock_run.call_args[1]["stdin"] is subprocess.DEVNULL
        assert result["success"] is True
        assert result["messages"] == ["ok"]

    @patch("boxmunge.mcp_tools.subprocess.run")
    def test_upgrade_target_version(self, mock_run: MagicMock) -> None:
        from boxmunge.mcp_tools import _tool_upgrade
        mock_run.return_value = subprocess.CompletedProcess([], 1, stdout="FATAL: Refusing\n")
        result = _tool_upgrade(version="0.3.5")
        assert mock_run.call_args[0][0] == ["sudo", "-n", SHIM, "target", "0.3.5"]
        assert result["success"] is False
        assert result["exit_code"] == 1
        assert "FATAL: Refusing" in result["messages"]

    @patch("boxmunge.mcp_tools.subprocess.run")
    def test_upgrade_merges_stderr_into_messages(self, mock_run: MagicMock) -> None:
        from boxmunge.mcp_tools import _tool_upgrade
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="a\nb\n")
        _tool_upgrade()
        assert mock_run.call_args[1]["stderr"] is subprocess.STDOUT

    def test_upgrade_never_runs_in_process(self) -> None:
        from boxmunge.mcp_tools import _tool_upgrade
        with patch("boxmunge.commands.upgrade_cmd.run_upgrade") as in_process, \
             patch("boxmunge.mcp_tools.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="")
            _tool_upgrade()
        in_process.assert_not_called()

    def test_upgrade_schema_offers_version_not_skip_self_test(self) -> None:
        props = _defn("upgrade")["inputSchema"]["properties"]
        assert set(props) == {"version"}


@pytest.mark.parametrize("tool,module,func", [
    ("restore", "boxmunge.commands.restore", "run_restore"),
    ("rollback", "boxmunge.commands.rollback", "run_rollback"),
])
class TestDestructiveToolsNeedConfirm:
    def test_schema_requires_confirm(self, tool: str, module: str, func: str) -> None:
        schema = _defn(tool)["inputSchema"]
        assert "confirm" in schema["required"]
        assert schema["properties"]["confirm"]["type"] == "boolean"

    @pytest.mark.parametrize("confirm", [False, None, "true", 1])
    def test_without_confirm_true_nothing_runs(
        self, tool: str, module: str, func: str, confirm: object,
    ) -> None:
        handler = _defn(tool)["handler"]
        with patch(f"{module}.{func}") as run:
            result = handler("myapp", confirm=confirm)
        run.assert_not_called()
        assert result["success"] is False
        assert any("confirm" in m for m in result["messages"])

    def test_confirm_true_runs_with_yes(self, tool: str, module: str, func: str) -> None:
        handler = _defn(tool)["handler"]
        with patch(f"{module}.{func}") as run:
            run.return_value = 0
            result = handler("myapp", confirm=True)
        assert run.call_args[1]["yes"] is True
        assert result["success"] is True


class TestCapture:
    def test_stderr_is_captured(self) -> None:
        def noisy() -> int:
            print("progress")
            print("ERROR: it broke", file=sys.stderr)
            return 1
        result = capture_tool_call(noisy)
        assert result["messages"] == ["progress", "ERROR: it broke"]

    def test_input_cannot_read_the_protocol(self) -> None:
        def prompts() -> int:
            input("Type yes: ")
            return 0
        result = capture_tool_call(prompts)
        assert result["success"] is False
        assert any("ERROR" in m for m in result["messages"])


class TestProtocolIsolation:
    def test_children_cannot_touch_the_protocol_fds(self) -> None:
        """After isolation, fd 0 is /dev/null and fd 1 is stderr, so child
        processes and stray prints never reach the MCP stream; the protocol
        keeps private duplicates of the original fds."""
        script = textwrap.dedent("""
            import os, subprocess, sys
            from boxmunge.mcp_server import isolate_protocol_streams
            proto_in, proto_out = isolate_protocol_streams()
            print("stray print")
            sys.stdout.flush()
            subprocess.run(["sh", "-c", "echo child-out; cat"])
            proto_out.write(b"PROTO:" + proto_in.readline())
            proto_out.flush()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script], input=b"request-line\n",
            capture_output=True, env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == b"PROTO:request-line\n"
        assert b"child-out" in result.stderr
        assert b"stray print" in result.stderr


def test_every_mcp_tool_is_an_allowlisted_shell_command() -> None:
    for defn in _TOOL_DEFS:
        command = defn["name"].replace("_", "-")
        assert command in ALLOWED_COMMANDS, f"MCP tool {defn['name']} has no shell command"
