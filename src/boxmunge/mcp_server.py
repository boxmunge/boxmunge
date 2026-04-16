# SPDX-License-Identifier: Apache-2.0
"""MCP server for boxmunge — exposes CLI commands as MCP tools.

Runs over stdio transport (stdin/stdout = MCP protocol).
All boxmunge operational output goes to stderr.
"""

import json
from typing import Any, Callable

from boxmunge.mcp_tools import (
    _tool_agent_help,
    _tool_backup,
    _tool_check,
    _tool_deploy,
    _tool_health,
    _tool_inbox,
    _tool_list_projects,
    _tool_log,
    _tool_promote,
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
        "name": "deploy",
        "description": "Deploy a project to production.",
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
        "handler": _tool_deploy,
    },
    {
        "name": "stage",
        "description": "Stage a project alongside production for testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "ref": {"type": "string", "description": "Git ref or bundle to stage"},
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
        "description": "Rollback a project to the previous deployment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
            },
            "required": ["project"],
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
        "description": "Restore a project from a backup snapshot.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name"},
                "snapshot": {"type": "string", "description": "Snapshot filename to restore"},
            },
            "required": ["project"],
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
        "name": "list_projects",
        "description": "List all registered projects.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "handler": _tool_list_projects,
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
        "description": "Upgrade the boxmunge platform.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skip_self_test": {"type": "boolean", "description": "Skip post-upgrade self-test"},
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
]

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
