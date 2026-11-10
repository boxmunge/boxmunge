# SPDX-License-Identifier: Apache-2.0
"""Integration test — the MCP server against a real `mcp` client.

The `mcp` package is not installed for the unit job, so everything that
needs it lives here: the stdio flow a box's agents use, the server's tool
contract in-process, and the older protocol versions agents still speak.
"""

import json
import subprocess
import sys
import threading

import pytest

from boxmunge.version import get_build_version, parse_version_string
from tests.integration.conftest import REQUIRE_INTEGRATION

pytestmark = [pytest.mark.integration]


def _mcp_available() -> bool:
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


# Every server install includes mcp (requirements-mcp.txt), so CI installs it
# too, and a missing package there is a failure, not a skip.
if REQUIRE_INTEGRATION and not _mcp_available():
    raise RuntimeError(
        "BOXMUNGE_REQUIRE_INTEGRATION=1 but the mcp package is not installed "
        "(pip install --require-hashes -r requirements-mcp.txt)"
    )

skip_no_mcp = pytest.mark.skipif(not _mcp_available(), reason="mcp package not installed")

SERVE = [sys.executable, "-m", "boxmunge.commands.mcp_serve_cmd"]


def _stdio_client():
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    return Client(StdioServerParameters(command=SERVE[0], args=SERVE[1:]))


@skip_no_mcp
class TestMCPIntegration:
    def test_tools_list(self) -> None:
        """Spawn mcp-serve, request tools/list, verify tools are registered."""
        import asyncio

        async def run():
            async with _stdio_client() as client:
                tools = await client.list_tools()
                tool_names = {t.name for t in tools.tools}
                assert "prod_deploy" in tool_names
                assert "health" in tool_names
                assert "backup" in tool_names
                assert "log" in tool_names
                assert len(tool_names) >= 21
                assert "project_delete" in tool_names
                assert "list_projects" not in tool_names
                assert "project_remove" not in tool_names

        asyncio.run(run())

    def test_project_list_returns_structured(self) -> None:
        """Call project_list tool and verify response format."""
        import asyncio

        async def run():
            async with _stdio_client() as client:
                result = await client.call_tool("project_list", {})
                text = result.content[0].text
                data = json.loads(text)
                assert "success" in data
                assert "exit_code" in data
                assert "messages" in data

        asyncio.run(run())


def _in_process(coro_fn):
    """Run coro_fn(client) against create_mcp_server(), in-process."""
    import asyncio

    from mcp import Client

    from boxmunge.mcp_server import create_mcp_server

    async def run():
        async with Client(create_mcp_server()) as client:
            return await coro_fn(client)

    return asyncio.run(run())


@skip_no_mcp
class TestServerContract:
    """What an agent sees: the tool list and the shape of every result."""

    def test_lists_every_tool_def_unchanged(self) -> None:
        from boxmunge.mcp_server import _TOOL_DEFS

        async def tools(client):
            return (await client.list_tools()).tools

        listed = {t.name: t for t in _in_process(tools)}
        assert list(listed) == [d["name"] for d in _TOOL_DEFS]
        for defn in _TOOL_DEFS:
            tool = listed[defn["name"]]
            assert tool.description == defn["description"]
            assert tool.input_schema == defn["inputSchema"]

    def test_a_tool_result_is_the_json_envelope(self) -> None:
        async def call(client):
            return await client.call_tool("project_list", {})

        result = _in_process(call)
        assert result.is_error is False
        assert len(result.content) == 1
        data = json.loads(result.content[0].text)
        assert set(data) == {"success", "exit_code", "data", "messages"}

    def test_an_unknown_tool_is_an_envelope(self) -> None:
        async def call(client):
            return await client.call_tool("no_such_tool", {})

        result = _in_process(call)
        assert result.is_error is False
        assert json.loads(result.content[0].text) == {
            "success": False, "exit_code": 1, "data": {},
            "messages": ["Unknown tool: no_such_tool"]}

    def test_a_raising_tool_is_a_tool_error_the_agent_can_read(self) -> None:
        """Not a JSON-RPC error: the agent gets the message as an isError result."""
        from unittest.mock import patch

        async def call(client):
            return await client.call_tool("health", {})

        with patch("boxmunge.mcp_tools._run_health_checks",
                   side_effect=RuntimeError("compose exploded")):
            result = _in_process(call)
        assert result.is_error is True
        assert [c.text for c in result.content] == ["compose exploded"]

    @pytest.mark.parametrize("arguments,needle", [
        ({}, "missing required argument(s): project"),
        ({"project": "myapp", "verbose": "yes"}, "verbose must be boolean"),
    ])
    def test_a_bad_argument_is_an_envelope_naming_it(self, arguments, needle) -> None:
        """mcp 1 ran jsonschema over the arguments; now mcp_args does, before
        the handler, and the agent gets a refusal it can act on."""
        async def call(client):
            return await client.call_tool("check", arguments)

        result = _in_process(call)
        assert result.is_error is False
        data = json.loads(result.content[0].text)
        assert data["success"] is False and data["exit_code"] == 2
        assert needle in data["messages"][0]

    def test_the_server_records_no_traces(self) -> None:
        from boxmunge.mcp_server import create_mcp_server
        assert create_mcp_server().middleware == []


def _raw_session(protocol_version: str, requests: list[dict],
                 argv: list[str] = SERVE) -> tuple[list[dict], bytes]:
    """Speak raw JSON-RPC to mcp-serve, as a client of that protocol version would.

    Returns the responses and the server's stderr. Every stdout line must be
    a JSON-RPC message: anything else there would corrupt the client's stream.
    """
    lines = [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": protocol_version, "capabilities": {},
            "clientInfo": {"name": "older-client", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ] + [{"jsonrpc": "2.0", "id": i + 1, **r} for i, r in enumerate(requests)]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    watchdog = threading.Timer(60, proc.kill)  # a hung server ends at EOF, not never
    watchdog.start()
    try:
        proc.stdin.write("".join(json.dumps(m) + "\n" for m in lines).encode())
        proc.stdin.flush()
        # Read every response before closing stdin (communicate closes it):
        # EOF ends the session.
        responses = [json.loads(proc.stdout.readline()) for _ in range(len(requests) + 1)]
        trailing, stderr = proc.communicate(timeout=30)
        assert proc.returncode == 0, stderr
        assert trailing == b""
    finally:
        watchdog.cancel()
        proc.kill()
    return sorted(responses, key=lambda r: r["id"]), stderr


@skip_no_mcp
@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
def test_clients_of_older_protocol_versions_are_served(version: str) -> None:
    """Agents on an mcp 1.x client speak these handshake-era versions."""
    (init, listed, called), _ = _raw_session(version, [
        {"method": "tools/list", "params": {}},
        {"method": "tools/call", "params": {"name": "project_list", "arguments": {}}},
    ])
    assert init["result"]["protocolVersion"] == version
    # mcp 1 reported its own version here, mcp 2 an empty one: ours is the
    # answer, from the same source as the handshake tool's server_version.
    assert init["result"]["serverInfo"] == {
        "name": "boxmunge", "version": parse_version_string(get_build_version())[0]}
    assert len(listed["result"]["tools"]) == 21
    assert called["result"]["isError"] is False
    assert json.loads(called["result"]["content"][0]["text"])["success"] is True


NOISY_SERVER = """
import asyncio, os, subprocess, sys
from boxmunge import mcp_server

def noisy():
    print("stray print")
    sys.stdout.flush()
    subprocess.run(["sh", "-c", "echo child-out; cat"])
    os.write(1, b"raw fd 1\\n")
    return {"success": True, "exit_code": 0, "data": {}, "messages": []}

noisy_def = {"name": "noisy", "description": "writes everywhere",
    "inputSchema": {"type": "object", "properties": {}}, "handler": noisy}
mcp_server._TOOL_DEFS[:] = [noisy_def]
mcp_server._DEFS_BY_NAME["noisy"] = noisy_def
asyncio.run(mcp_server.serve_stdio(mcp_server.create_mcp_server()))
"""


@skip_no_mcp
def test_nothing_a_tool_writes_or_reads_reaches_the_protocol() -> None:
    """Prints, a child's stdout and stdin, raw fd 1: none of it touches the wire."""
    (_, called), stderr = _raw_session("2025-06-18", [
        {"method": "tools/call", "params": {"name": "noisy", "arguments": {}}},
    ], argv=[sys.executable, "-c", NOISY_SERVER])
    assert json.loads(called["result"]["content"][0]["text"])["success"] is True
    for line in (b"stray print", b"child-out", b"raw fd 1"):
        assert line in stderr
