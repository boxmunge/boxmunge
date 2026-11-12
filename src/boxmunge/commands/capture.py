# SPDX-License-Identifier: Apache-2.0
"""Run a command's `run_*` function with its output captured.

For the front ends that show a command's result instead of letting it
print: the MCP tools and the TUI's project actions. It lives beside the
commands it wraps so that neither front end imports the other.
"""

import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Callable


def capture_tool_call(
    func: Callable[[], int],
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a function, capturing its stdout, stderr and exit code.

    stdout and stderr share one buffer so messages keep their order, and
    errors (printed to stderr as `ERROR: ...`) reach the caller. stdin is
    empty for the duration, so a stray input() fails instead of waiting.

    Returns a standardised result dict:
    {
        "success": bool,
        "exit_code": int,
        "data": dict,
        "messages": list[str],
    }
    """
    captured = io.StringIO()
    try:
        with redirect_stdout(captured), redirect_stderr(captured), _empty_stdin():
            exit_code = func()
    except Exception as e:
        return {
            "success": False,
            "exit_code": 1,
            "data": data or {},
            "messages": captured.getvalue().splitlines() + [f"ERROR: {e}"],
        }

    return {
        "success": exit_code == 0,
        "exit_code": exit_code,
        "data": data or {},
        "messages": captured.getvalue().splitlines(),
    }


class _empty_stdin:
    """Swap sys.stdin for an empty stream; input() then raises EOFError."""

    def __enter__(self) -> None:
        self._saved = sys.stdin
        sys.stdin = io.StringIO("")

    def __exit__(self, *exc: object) -> None:
        sys.stdin = self._saved
