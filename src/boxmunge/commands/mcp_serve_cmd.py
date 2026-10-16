# SPDX-License-Identifier: Apache-2.0
"""boxmunge mcp-serve — start MCP server over stdio.

Designed to be invoked via SSH:
  ssh -p 922 deploy@box mcp-serve

The MCP protocol runs over stdin/stdout. All boxmunge logging
goes to stderr.
"""

import sys

MCP_REPAIR = (
    "install.sh and every platform upgrade install it from the release's "
    "hash-pinned requirements-mcp.txt, so this environment is incomplete. "
    "Repair it by re-running the installed release's installer as root: "
    "`sudo bash boxmunge-install.sh`, from that version's GitHub release "
    "(`boxmunge-server --version` shows the version)."
)


def mcp_import_error() -> str | None:
    """Why the third-party `mcp` package cannot be imported, or None if it can."""
    try:
        # boxmunge.mcp_server imports the package lazily, inside
        # create_mcp_server and serve_stdio, so probe the package itself.
        import mcp.server  # noqa: F401
        import mcp.server.stdio  # noqa: F401
    except ImportError as e:
        return str(e)
    return None


def cmd_mcp_serve(args: list[str]) -> None:
    """CLI entry point for mcp-serve command."""
    from boxmunge.commands.argv import parse_args
    parse_args("mcp-serve", args)
    error = mcp_import_error()
    if error is not None:
        print(f"ERROR: MCP support requires the 'mcp' package ({error}).\n{MCP_REPAIR}",
              file=sys.stderr)
        sys.exit(1)

    import asyncio
    from boxmunge.mcp_server import create_mcp_server, serve_stdio

    asyncio.run(serve_stdio(create_mcp_server()))


if __name__ == "__main__":
    cmd_mcp_serve([])
