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
        from boxmunge.mcp_server import create_mcp_server
    except ImportError:
        print(
            "ERROR: MCP support requires the 'mcp' package.\n"
            "Install it into the server's environment with:\n"
            "  /opt/boxmunge/env-active/bin/pip install 'mcp>=1.0'",
            file=sys.stderr,
        )
        sys.exit(1)

    import asyncio
    from boxmunge.mcp_server import serve_stdio

    asyncio.run(serve_stdio(create_mcp_server()))


if __name__ == "__main__":
    cmd_mcp_serve([])
