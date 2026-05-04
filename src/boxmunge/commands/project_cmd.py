# SPDX-License-Identifier: Apache-2.0
"""project-add, project-list — manage the project allowlist.

For destructive removal (containers + files + registry), use project-delete.
"""

import sys

from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project, load_registered_projects


def cmd_project_add(args: list[str]) -> None:
    """Register a project name on this server."""
    if not args:
        print("Usage: project-add <name>", file=sys.stderr)
        sys.exit(2)
    name = args[0]
    paths = BoxPaths()
    try:
        add_project(name, paths)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"Project '{name}' registered.")


def cmd_project_list(args: list[str]) -> None:
    """List all registered project names."""
    paths = BoxPaths()
    projects = load_registered_projects(paths)
    if not projects:
        print("No projects registered. Use 'project-add <name>' to register one.")
        return
    for name in sorted(projects):
        print(name)
