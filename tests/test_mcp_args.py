# SPDX-License-Identifier: Apache-2.0
"""MCP tool arguments are checked at the boundary, against the tool's schema.

`inbox(project="--json")` used to reach argv as a flag, `log(tail="5")`
raised TypeError and a bad `since` a ValueError: a Python traceback string
instead of a refusal naming the argument. Each call is now checked before
its handler runs.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.mcp_server import call_tool


def _refused(result: dict) -> str:
    assert result["success"] is False and result["exit_code"] == 2
    return "\n".join(result["messages"])


@pytest.mark.parametrize("tool,arguments,needle", [
    ("inbox", {"project": "--json"}, "project"),
    ("check", {"project": "../etc"}, "Invalid project name"),
    ("project_add", {"name": "Bad_Name"}, "Invalid project name"),
    ("log", {"tail": "5"}, "tail must be integer"),
    ("log", {"tail": True}, "tail must be integer"),
    ("check", {"project": "myapp", "verbose": "yes"}, "verbose must be boolean"),
    ("rollback", {"project": "myapp", "confirm": "true"}, "confirm must be boolean"),
    ("secrets", {"args": ["list", 3]}, "args must be an array of strings"),
    ("check", {"project": "myapp", "force": True}, "unknown argument"),
    ("check", {}, "missing required argument"),
    ("agent_help", {"topic": "-h"}, "may not start with '-'"),
    ("prod_deploy", {"project": "myapp", "ref": "--upload-pack=x"}, "may not start with '-'"),
])
def test_bad_arguments_are_refused_before_the_handler(tool, arguments, needle) -> None:
    with patch("boxmunge.mcp_server._handler", side_effect=AssertionError("ran")):
        text = _refused(call_tool(tool, arguments))
    assert needle in text


def test_a_bad_since_is_refused_with_the_expected_form() -> None:
    text = _refused(call_tool("log", {"since": "yesterday"}))
    assert "since" in text and "1h" in text


def test_good_arguments_reach_the_handler() -> None:
    with patch("boxmunge.mcp_server._handler") as handler:
        handler.return_value = lambda **kw: {"success": True, "kw": kw}
        result = call_tool("check", {"project": "myapp", "verbose": False})
    assert result == {"success": True, "kw": {"project": "myapp", "verbose": False}}


def test_no_arguments_is_an_empty_object() -> None:
    with patch("boxmunge.mcp_server._handler") as handler:
        handler.return_value = lambda **kw: {"success": True, "kw": kw}
        assert call_tool("status", None) == {"success": True, "kw": {}}


def test_an_unknown_tool_is_refused() -> None:
    result = call_tool("nope", {})
    assert result["success"] is False and "Unknown tool: nope" in result["messages"][0]
