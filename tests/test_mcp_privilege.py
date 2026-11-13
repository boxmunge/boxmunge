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


class TestUpgradeGuideAndCheckTools:
    @pytest.mark.parametrize("tool,command", [("upgrade_howto", "upgrade-howto"),
                                              ("upgrade_check", "upgrade-check")])
    @patch("boxmunge.mcp_tools.subprocess.run")
    def test_run_the_deploy_shells_command_as_a_subprocess(
            self, mock_run: MagicMock, tool: str, command: str) -> None:
        """As deploy: the command itself reaches the shim's check or guide verb."""
        from boxmunge import mcp_tools
        mock_run.return_value = subprocess.CompletedProcess([], 1, stdout="Result: BLOCKED\n")
        result = getattr(mcp_tools, f"_tool_{tool}")()
        assert mock_run.call_args[0][0] == ["boxmunge-server", command]
        assert mock_run.call_args[1]["stdin"] is subprocess.DEVNULL
        assert result["exit_code"] == 1 and result["messages"] == ["Result: BLOCKED"]
        getattr(mcp_tools, f"_tool_{tool}")(version="0.12.0", as_json=True)
        assert mock_run.call_args[0][0] == ["boxmunge-server", command, "--version",
                                            "0.12.0", "--json"]


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
