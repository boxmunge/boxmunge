# SPDX-License-Identifier: Apache-2.0
"""boxmunge project-delete <project> — destructive removal: containers, files, registry."""

import shutil
import sys

from boxmunge.docker import compose_down, caddy_reload, DockerError
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import is_registered, remove_project as registry_remove


def run_project_delete(project_name: str, paths: BoxPaths, yes: bool = False) -> int:
    """Delete a project: stop containers, remove Caddy config, delete files, deregister."""
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists() and not is_registered(project_name, paths):
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    if not yes:
        print(f"This will permanently delete project '{project_name}':")
        print(f"  - Stop and remove all containers")
        print(f"  - Delete {project_dir}")
        print(f"  - Remove Caddy site config")
        print(f"  - Remove health and deploy state")
        print(f"  - Deregister from project allowlist")
        response = input("\nProceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    if project_dir.exists():
        compose_files = ["compose.yml"]
        override = paths.project_compose_override(project_name)
        if override.exists():
            compose_files.append("compose.boxmunge.yml")
        try:
            compose_down(project_dir, compose_files=compose_files)
        except DockerError:
            pass

    caddy_conf = paths.project_caddy_site(project_name)
    if caddy_conf.exists():
        caddy_conf.unlink()
        try:
            caddy_reload(paths.caddy, paths.state)
        except DockerError as e:
            print(f"  WARN: Caddy reload failed: {e}")

    for state_file in [
        paths.project_health_state(project_name),
        paths.project_deploy_state(project_name),
    ]:
        if state_file.exists():
            state_file.unlink()

    if project_dir.exists():
        shutil.rmtree(project_dir)

    if is_registered(project_name, paths):
        try:
            registry_remove(project_name, paths)
        except ValueError:
            pass

    log_operation("project-delete", "Project deleted", paths, project=project_name)
    print(f"Project '{project_name}' deleted.")
    return 0


def cmd_project_delete(args: list[str]) -> None:
    if not args:
        print("Usage: boxmunge project-delete <project> [--yes]", file=sys.stderr)
        sys.exit(2)
    project = args[0]

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    yes = "--yes" in args
    paths = BoxPaths()
    sys.exit(run_project_delete(project, paths, yes=yes))
