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
    from boxmunge.commands.argv import parse_args
    parse_args("mcp-serve", args)
    try:
        # boxmunge.mcp_server imports the third-party package lazily, inside
        # create_mcp_server and serve_stdio, so probe the optional extra itself.
        import mcp.server  # noqa: F401
        import mcp.server.stdio  # noqa: F401
    except ImportError as e:
        print(
            f"ERROR: MCP support requires the 'mcp' package ({e}).\n"
            "It is not installed by default. As root, install it into the "
            "server's active environment with:\n"
            "  /opt/boxmunge/env-active/bin/pip install 'mcp>=1.0'\n"
            "A platform upgrade builds a fresh environment without it, so "
            "repeat this after each upgrade.",
            file=sys.stderr,
        )
        sys.exit(1)

    import asyncio
    from boxmunge.mcp_server import create_mcp_server, serve_stdio

    asyncio.run(serve_stdio(create_mcp_server()))


if __name__ == "__main__":
    cmd_mcp_serve([])
