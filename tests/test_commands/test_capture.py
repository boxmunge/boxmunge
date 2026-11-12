# SPDX-License-Identifier: Apache-2.0
"""capture_tool_call: a command's output, stderr and exit code as a result
dict, for the MCP tools and the TUI's project actions."""
from __future__ import annotations

import sys
from pathlib import Path

from boxmunge.commands.capture import capture_tool_call

SRC = Path(__file__).resolve().parents[2] / "src" / "boxmunge"


class TestCaptureToolCall:
    def test_captures_stdout(self) -> None:
        def my_func() -> int:
            print("hello")
            print("world")
            return 0

        result = capture_tool_call(my_func)
        assert result["success"] is True
        assert result["exit_code"] == 0
        assert result["messages"] == ["hello", "world"]
        assert result["data"] == {}

    def test_failure_exit_code(self) -> None:
        def my_func() -> int:
            print("something failed")
            return 1

        result = capture_tool_call(my_func)
        assert result["success"] is False
        assert result["exit_code"] == 1
        assert result["messages"] == ["something failed"]

    def test_exception_returns_failure(self) -> None:
        def my_func() -> int:
            raise RuntimeError("boom")

        result = capture_tool_call(my_func)
        assert result["success"] is False
        assert result["exit_code"] == 1
        assert any("boom" in m for m in result["messages"])

    def test_with_data(self) -> None:
        def my_func() -> int:
            print("done")
            return 0

        result = capture_tool_call(my_func, data={"count": 42})
        assert result["data"] == {"count": 42}
        assert result["success"] is True

    def test_empty_stdout(self) -> None:
        def my_func() -> int:
            return 0

        result = capture_tool_call(my_func)
        assert result["messages"] == []
        assert result["success"] is True

    def test_stderr_is_captured(self) -> None:
        def noisy() -> int:
            print("progress")
            print("ERROR: it broke", file=sys.stderr)
            return 1
        result = capture_tool_call(noisy)
        assert result["messages"] == ["progress", "ERROR: it broke"]

    def test_input_cannot_read_the_protocol(self) -> None:
        """A-08: nothing a tool runs can read the MCP protocol stream."""
        def prompts() -> int:
            input("Type yes: ")
            return 0
        result = capture_tool_call(prompts)
        assert result["success"] is False
        assert any("ERROR" in m for m in result["messages"])


def test_the_console_does_not_import_the_mcp_layer() -> None:
    """The TUI and the MCP server are both front ends over commands/."""
    modules = sorted((SRC / "tui").rglob("*.py"))
    assert len(modules) > 5
    assert [m.name for m in modules if "boxmunge.mcp_" in m.read_text()] == []
