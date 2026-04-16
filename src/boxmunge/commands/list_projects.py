"""boxmunge list-projects — list registered projects."""

import sys

from boxmunge.paths import BoxPaths


def run_list_projects(paths: BoxPaths) -> int:
    """List all projects under the projects directory.

    Returns 0 always.
    """
    projects_dir = paths.projects
    if not projects_dir.exists():
        print("No projects directory found.")
        return 0

    projects = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and (p / "manifest.yml").exists()
    )

    if not projects:
        print("No projects registered.")
        return 0

    print(f"{'PROJECT':<30} {'MANIFEST':<10}")
    print(f"{'-'*30} {'-'*10}")
    for name in projects:
        print(f"{name:<30} {'yes':<10}")

    return 0


def cmd_list_projects(args: list[str]) -> None:
    """CLI entry point."""
    paths = BoxPaths()
    sys.exit(run_list_projects(paths))
