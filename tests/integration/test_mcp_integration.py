# SPDX-License-Identifier: Apache-2.0
"""Integration test — spawn mcp-serve, connect via MCP client, call tools."""

import json
import sys

import pytest

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


@skip_no_mcp
class TestMCPIntegration:
    def test_tools_list(self) -> None:
        """Spawn mcp-serve, request tools/list, verify tools are registered."""
        import asyncio
        from mcp.client.session import ClientSession
        from mcp.client.stdio import stdio_client, StdioServerParameters

        async def run():
            server_params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "boxmunge.commands.mcp_serve_cmd"],
            )
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
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
        from mcp.client.session import ClientSession
        from mcp.client.stdio import stdio_client, StdioServerParameters

        async def run():
            server_params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "boxmunge.commands.mcp_serve_cmd"],
            )
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool("project_list", {})
                    text = result.content[0].text
                    data = json.loads(text)
                    assert "success" in data
                    assert "exit_code" in data
                    assert "messages" in data

        asyncio.run(run())
