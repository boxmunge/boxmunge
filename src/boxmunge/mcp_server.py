# SPDX-License-Identifier: Apache-2.0
"""MCP server for boxmunge — exposes CLI commands as MCP tools.

Runs over stdio transport (stdin/stdout = MCP protocol).
All boxmunge operational output goes to stderr.
"""

import json
import os
import sys
from typing import Any, BinaryIO, Callable

from boxmunge.mcp_tools import (
    _tool_agent_help,
    _tool_backup,
    _tool_check,
    _tool_prod_deploy,
    _tool_handshake,
    _tool_health,
    _tool_inbox,
    _tool_log,
    _tool_promote,
    _tool_project_add,
    _tool_project_delete,
    _tool_project_list_mcp,
    _tool_restore,
    _tool_rollback,
    _tool_secrets,
    _tool_self_test,
    _tool_stage,
    _tool_status,
    _tool_unstage,
    _tool_upgrade,
    _tool_validate,
)

# ---------------------------------------------------------------------------
# MCP tool definitions (name, description, inputSchema, handler)
# ---------------------------------------------------------------------------

_TOOL_DEFS: list[dict[str, Any]] = [
    {
        "name": "prod_deploy",
        "description": "Deploy a project directly to production (skip staging).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "ref": {"type": "string", "description": "Git ref or bundle to deploy"},
                "no_snapshot": {"type": "boolean", "description": "Skip pre-deploy snapshot"},
                "dry_run": {"type": "boolean", "description": "Preview without applying"},
            },
            "required": ["project"],
        },
        "handler": _tool_prod_deploy,
    },
    {
        "name": "stage",
        "description": "Stage a project alongside production for testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "ref": {"type": "string", "description": "Bundle to stage"},
                "dry_run": {"type": "boolean", "description": "Preview without applying"},
            },
            "required": ["project"],
        },
        "handler": _tool_stage,
    },
    {
        "name": "promote",
        "description": "Promote staging to production.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "dry_run": {"type": "boolean", "description": "Preview without applying"},
            },
            "required": ["project"],
        },
        "handler": _tool_promote,
    },
    {
        "name": "unstage",
        "description": "Tear down staging, leave production untouched.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "dry_run": {"type": "boolean", "description": "Preview without applying"},
            },
            "required": ["project"],
        },
        "handler": _tool_unstage,
    },
    {
        "name": "rollback",
        "description": "Rollback a project to the previous deployment. Destructive: requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "confirm": {"type": "boolean", "description": "Must be true; rollback replaces the running deployment"},
            },
            "required": ["project", "confirm"],
        },
        "handler": _tool_rollback,
    },
    {
        "name": "check",
        "description": "Run health checks for a specific project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "verbose": {"type": "boolean", "description": "Show detailed output"},
            },
            "required": ["project"],
        },
        "handler": _tool_check,
    },
    {
        "name": "backup",
        "description": "Create a backup snapshot for a project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
            },
            "required": ["project"],
        },
        "handler": _tool_backup,
    },
    {
        "name": "restore",
        "description": "Restore a project from a backup snapshot. Destructive: requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "snapshot": {"type": "string", "description": "Snapshot filename to restore"},
                "confirm": {"type": "boolean", "description": "Must be true; restore overwrites the project's data"},
            },
            "required": ["project", "confirm"],
        },
        "handler": _tool_restore,
    },
    {
        "name": "validate",
        "description": "Validate a project's manifest and configuration.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
            },
            "required": ["project"],
        },
        "handler": _tool_validate,
    },
    {
        "name": "secrets",
        "description": "Manage project or host secrets (get, set, list, unset).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Arguments: e.g. ['set', 'myapp', 'KEY', 'VALUE']",
                },
            },
            "required": ["args"],
        },
        "handler": _tool_secrets,
    },
    {
        "name": "upgrade",
        "description": (
            "Upgrade the boxmunge platform through the root upgrade shim (signature check, "
            "venv swap, probation with automatic rollback). Without a version, installs the "
            "latest release; with one, that release, which must not be older than the installed "
            "version or blocklisted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "version": {"type": "string", "description": "Release to install, e.g. 0.11.2"},
            },
        },
        "handler": _tool_upgrade,
    },
    {
        "name": "self_test",
        "description": "Run the canary self-test to verify platform integrity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "as_json": {"type": "boolean", "description": "Return JSON output"},
            },
        },
        "handler": _tool_self_test,
    },
    {
        "name": "health",
        "description": "Run platform-wide health checks and return structured results.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "handler": _tool_health,
    },
    {
        "name": "log",
        "description": "Query structured operational logs with filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Filter by project name"},
                "component": {"type": "string", "description": "Filter by component"},
                "level": {"type": "string", "description": "Filter by log level (info, warn, error)"},
                "since": {"type": "string", "description": "Duration filter, e.g. '1h', '7d', '30m'"},
                "tail": {"type": "integer", "description": "Number of recent entries to return"},
            },
        },
        "handler": _tool_log,
    },
    {
        "name": "status",
        "description": "Show dashboard status of all projects.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "handler": _tool_status,
    },
    {
        "name": "inbox",
        "description": "List uploaded bundles in the inbox.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Filter by project name"},
            },
        },
        "handler": _tool_inbox,
    },
    {
        "name": "agent_help",
        "description": "Show agent-specific orientation and help topics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "topic": {"type": "string", "description": "Help topic to show"},
            },
        },
        "handler": _tool_agent_help,
    },
    {
        "name": "project_add",
        "description": "Register a project name on this server.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Project name to register"},
            },
            "required": ["name"],
        },
        "handler": _tool_project_add,
    },
    {
        "name": "project_delete",
        "description": "Destructively delete a project: stop containers, remove files, deregister. Requires yes=true to skip confirmation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Project name to delete"},
                "yes": {"type": "boolean", "description": "Skip interactive confirmation"},
            },
            "required": ["name"],
        },
        "handler": _tool_project_delete,
    },
    {
        "name": "project_list",
        "description": "List all registered project names.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "handler": _tool_project_list_mcp,
    },
    {
        "name": "handshake",
        "description": "Return server version and compatibility info.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "handler": _tool_handshake,
    },
]

# ---------------------------------------------------------------------------
# Protocol stream isolation
# ---------------------------------------------------------------------------

def isolate_protocol_streams() -> tuple[BinaryIO, BinaryIO]:
    """Move the MCP protocol off fds 0 and 1 and return private handles to it.

    Tools run in-process and start subprocesses (docker compose, git). Any of
    them could read fd 0 or write fd 1, which are the JSON-RPC stream. After
    this call fd 0 is /dev/null and fd 1 is a copy of stderr, for this process
    and every child it starts; only the returned handles reach the client.
    """
    sys.stdout.flush()
    proto_in = os.fdopen(os.dup(0), "rb")
    proto_out = os.fdopen(os.dup(1), "wb")
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    os.dup2(2, 1)
    return proto_in, proto_out


async def serve_stdio(server: Any) -> None:
    """Run the MCP server over the original stdin/stdout, isolated from tools."""
    from io import TextIOWrapper

    import anyio
    from mcp.server.stdio import stdio_server

    proto_in, proto_out = isolate_protocol_streams()
    stdin = anyio.wrap_file(TextIOWrapper(proto_in, encoding="utf-8", errors="replace"))
    stdout = anyio.wrap_file(TextIOWrapper(proto_out, encoding="utf-8"))
    async with stdio_server(stdin=stdin, stdout=stdout) as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


# ---------------------------------------------------------------------------
# MCP server factory (requires `mcp` package)
# ---------------------------------------------------------------------------

def create_mcp_server() -> Any:
    """Create and configure the MCP server with all boxmunge tools.

    Requires the `mcp` package to be installed.
    """
    from mcp.server import Server
    from mcp.types import TextContent, Tool

    server = Server("boxmunge")

    # Build handler lookup (strip 'handler' from defs sent to client)
    _handlers: dict[str, Callable[..., dict]] = {}
    tool_objects: list[Tool] = []
    for defn in _TOOL_DEFS:
        _handlers[defn["name"]] = defn["handler"]
        tool_objects.append(Tool(
            name=defn["name"],
            description=defn["description"],
            inputSchema=defn["inputSchema"],
        ))

    @server.list_tools()
    async def handle_list_tools() -> list[Tool]:
        return tool_objects

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict | None) -> list[TextContent]:
        handler = _handlers.get(name)
        if handler is None:
            error = {"success": False, "exit_code": 1,
                     "data": {}, "messages": [f"Unknown tool: {name}"]}
            return [TextContent(type="text", text=json.dumps(error))]
        result = handler(**(arguments or {}))
        return [TextContent(type="text", text=json.dumps(result, default=str))]

    return server
