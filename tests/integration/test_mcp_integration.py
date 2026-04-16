# SPDX-License-Identifier: Apache-2.0
"""Integration test — spawn mcp-serve, connect via MCP client, call tools."""

import json
import sys

import pytest

pytestmark = [pytest.mark.integration]


def _mcp_available() -> bool:
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


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
                    assert "deploy" in tool_names
                    assert "health" in tool_names
                    assert "backup" in tool_names
                    assert "log" in tool_names
                    assert "secrets_set" in tool_names
                    assert len(tool_names) >= 18

        asyncio.run(run())

    def test_list_projects_returns_structured(self) -> None:
        """Call list_projects tool and verify response format."""
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
                    result = await session.call_tool("list_projects", {})
                    text = result.content[0].text
                    data = json.loads(text)
                    assert "success" in data
                    assert "exit_code" in data
                    assert "messages" in data

        asyncio.run(run())
