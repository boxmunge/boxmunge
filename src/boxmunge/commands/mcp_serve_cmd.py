# SPDX-License-Identifier: Apache-2.0
"""boxmunge mcp-serve — start MCP server over stdio.

Designed to be invoked via SSH:
  ssh -p 922 deploy@box mcp-serve

The MCP protocol runs over stdin/stdout. All boxmunge logging
goes to stderr.
"""

import sys


def cmd_mcp_serve(args: list[str]) -> None:
    """CLI entry point for mcp-serve command."""
    try:
        from boxmunge.mcp_server import create_mcp_server
    except ImportError:
        print(
            "ERROR: MCP support requires the 'mcp' package.\n"
            "Install with: pip install boxmunge[mcp]",
            file=sys.stderr,
        )
        sys.exit(1)

    server = create_mcp_server()

    import asyncio
    from mcp.server.stdio import stdio_server

    async def run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(run())


if __name__ == "__main__":
    cmd_mcp_serve([])
