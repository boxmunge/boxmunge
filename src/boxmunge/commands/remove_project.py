"""boxmunge remove-project <project> — deregister and clean up."""

import shutil
import sys
from pathlib import Path

from boxmunge.docker import compose_down, DockerError
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths


def run_remove_project(project_name: str, paths: BoxPaths, yes: bool = False) -> int:
    """Remove a project: stop containers, remove Caddy config, delete directory."""
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_name}")
        return 1

    if not yes:
        print(f"This will permanently remove project '{project_name}':")
        print(f"  - Stop and remove all containers")
        print(f"  - Delete {project_dir}")
        print(f"  - Remove Caddy site config")
        print(f"  - Remove health and deploy state")
        response = input("\nProceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

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

    for state_file in [
        paths.project_health_state(project_name),
        paths.project_deploy_state(project_name),
    ]:
        if state_file.exists():
            state_file.unlink()

    shutil.rmtree(project_dir)

    log_operation("remove", "Project removed", paths, project=project_name)
    print(f"Project '{project_name}' removed.")
    return 0


def cmd_remove_project(args: list[str]) -> None:
    if not args:
        print("Usage: boxmunge remove-project <project> [--yes]", file=sys.stderr)
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
    sys.exit(run_remove_project(project, paths, yes=yes))
