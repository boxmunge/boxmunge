# SPDX-License-Identifier: Apache-2.0
"""project-add, project-list — manage the project allowlist.

For destructive removal (containers + files + registry), use project-delete.
"""

import json
import sys

from boxmunge.commands.argv import parse_args
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project, load_registered_projects


def cmd_project_add(args: list[str]) -> None:
    """Register a project name on this server."""
    parsed = parse_args("project-add", args, min_positional=1, max_positional=1)
    name = parsed.positional[0]
    paths = BoxPaths()
    try:
        add_project(name, paths)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    log_operation("project-add", "Project registered", paths, project=name)
    print(f"Project '{name}' registered.")


def cmd_project_list(args: list[str]) -> None:
    """List all registered project names."""
    as_json = parse_args("project-list", args, flags={"--json"}).has("--json")
    paths = BoxPaths()
    projects = sorted(load_registered_projects(paths))
    if as_json:
        print(json.dumps({"projects": projects}))
        return
    if not projects:
        print("No projects registered. Use 'project-add <name>' to register one.")
        return
    for name in projects:
        print(name)
