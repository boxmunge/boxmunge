# SPDX-License-Identifier: Apache-2.0
"""MCP server for boxmunge — exposes CLI commands as MCP tools.

Runs over stdio transport (stdin/stdout = MCP protocol).
All boxmunge operational output goes to stderr.
"""

import json
import os
import sys
from typing import Any, BinaryIO, Callable

from boxmunge.mcp_args import argument_problem
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
    _tool_upgrade_check,
    _tool_upgrade_howto,
    _tool_validate,
)
from boxmunge.version_check_notice import MCP_INSTRUCTIONS
from boxmunge.version import get_build_version, parse_version_string

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
                "no_pull": {"type": "boolean", "description": "Build from the base images in "
                            "this box's local image store instead of checking their "
                            "registries for newer digests (when a registry is unreachable)"},
                "redeploy": {"type": "boolean", "description": "Deploy the installed "
                             "release again when the inbox has no new bundle"},
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
                "no_pull": {"type": "boolean", "description": "Build from the base images in "
                            "this box's local image store instead of checking their "
                            "registries for newer digests (when a registry is unreachable)"},
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
                "no_pull": {"type": "boolean", "description": "Build from the base images in "
                            "this box's local image store instead of checking their "
                            "registries for newer digests (when a registry is unreachable)"},
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
                    "description": "Arguments: e.g. ['set', 'myapp', 'KEY=VALUE']",
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
        "name": "upgrade_howto",
        "description": (
            "What to change before and after a platform upgrade, on the box and in each "
            "project, from the target release's signed upgrade notes. Run it before "
            "upgrade_check and before any upgrade (agent-help upgrade)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "version": {"type": "string", "description": "Release to prepare for, "
                            "X.Y.Z (default: the newest; required when the box has "
                            "version checks off)"},
                "as_json": {"type": "boolean", "description": "Return JSON output"},
            },
        },
        "handler": _tool_upgrade_howto,
    },
    {
        "name": "upgrade_check",
        "description": (
            "Run the target release's own readiness check against this box and every "
            "project: PASS, BLOCKED or CAN'T VERIFY, per project. It can take several "
            "minutes (if the call times out, run upgrade-check in the deploy shell). "
            "Upgrade only on PASS; never force."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "version": {"type": "string", "description": "Release to check, X.Y.Z "
                            "(default: the newest; required when the box has version "
                            "checks off)"},
                "as_json": {"type": "boolean", "description": "Return JSON output"},
            },
        },
        "handler": _tool_upgrade_check,
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

_DEFS_BY_NAME: dict[str, dict[str, Any]] = {d["name"]: d for d in _TOOL_DEFS}


def _handler(name: str) -> Callable[..., dict]:
    return _DEFS_BY_NAME[name]["handler"]


def call_tool(name: str, arguments: dict | None) -> dict:
    """Run tool `name`, after checking `arguments` against its schema."""
    defn = _DEFS_BY_NAME.get(name)
    if defn is None:
        return {"success": False, "exit_code": 1,
                "data": {}, "messages": [f"Unknown tool: {name}"]}
    arguments = {} if arguments is None else arguments
    problem = argument_problem(defn["inputSchema"], arguments)
    if problem:
        return {"success": False, "exit_code": 2, "data": {},
                "messages": [f"ERROR: {name}: {problem}. Call it again with "
                             f"arguments that match its input schema."]}
    return _handler(name)(**arguments)


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
    """Run the MCP server over the original stdin/stdout, isolated from tools.

    mcp's stdio_server() diverts fds 0 and 1 itself, but best-effort: when it
    cannot, it serves the wire in place without saying so. Ours raises
    instead, and passing the streams explicitly skips mcp's claim, so the
    descriptors are moved once.
    """
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
    from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

    tools = ListToolsResult(tools=[
        Tool(name=d["name"], description=d["description"], input_schema=d["inputSchema"])
        for d in _TOOL_DEFS
    ])

    async def on_list_tools(ctx: Any, params: Any) -> ListToolsResult:
        return tools

    async def on_call_tool(ctx: Any, params: Any) -> CallToolResult:
        # A tool that raises is a tool error: the agent reads it as an
        # isError result. mcp 2 would make it a JSON-RPC error, which MCP
        # keeps for protocol failures and clients need not show the model.
        try:
            result = call_tool(params.name, params.arguments)
        except Exception as e:
            return CallToolResult(
                content=[TextContent(type="text", text=str(e) or type(e).__name__)],
                is_error=True)
        return CallToolResult(content=[TextContent(type="text",
                                                   text=json.dumps(result, default=str))])

    server = Server("boxmunge", version=parse_version_string(get_build_version())[0],
                    instructions=MCP_INSTRUCTIONS, on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    _drop_tracing(server)
    return server


def _drop_tracing(server: Any) -> None:
    """Remove the OpenTelemetry middleware mcp 2 installs on every server.

    The box runs no collector and sends nothing anywhere: without it no span
    is recorded at all, whatever is later installed into the venv or set in
    OTEL_* variables, and no client trace context is read from `_meta`.
    """
    names = [type(m).__name__ for m in server.middleware]
    if names != ["OpenTelemetryMiddleware"]:
        raise RuntimeError(
            f"mcp's default server middleware is now {names}, not the tracing "
            "middleware alone: review what it does before dropping it in "
            "boxmunge.mcp_server._drop_tracing")
    server.middleware.clear()
