"""boxmunge unstage <project> — tear down staging, leave production untouched."""
from __future__ import annotations
import sys
from typing import TYPE_CHECKING
from boxmunge.docker import compose_down, caddy_reload, DockerError
from boxmunge.log import log_operation
from boxmunge.state import read_state, write_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def run_unstage(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    staging_state = read_state(paths.project_staging_state(project_name))
    if not staging_state.get("active"):
        print(f"ERROR: No active staging for '{project_name}'.")
        return 1

    if dry_run:
        print(f"[DRY RUN] Would tear down staging for '{project_name}'")
        return 0

    project_dir = paths.project_dir(project_name)
    print(f"Unstaging {project_name}...")

    staging_override = paths.project_staging_compose_override(project_name)
    staging_project_name = f"{project_name}-staging"
    if staging_override.exists():
        compose_files = ["compose.yml", "compose.boxmunge-staging.yml"]
        try:
            compose_down(project_dir, compose_files=compose_files,
                         project_name=staging_project_name)
        except DockerError as e:
            print(f"  WARN: Staging container teardown failed: {e}")

    staging_conf = paths.project_staging_caddy_site(project_name)
    if staging_conf.exists():
        staging_conf.unlink()

    if staging_override.exists():
        staging_override.unlink()

    try:
        caddy_reload(paths.caddy)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    write_state(paths.project_staging_state(project_name), {"active": False})

    log_operation("unstage", "Unstaged", paths, project=project_name)
    print(f"{project_name}: staging torn down.")

    try:
        from boxmunge.config import load_config
        from boxmunge.webhooks import fire_webhook
        config = load_config(paths)
        fire_webhook("unstage", project_name, config)
    except Exception:
        pass

    return 0


def cmd_unstage(args: list[str]) -> None:
    from boxmunge.paths import BoxPaths
    if not args:
        print("Usage: boxmunge unstage <project> [--dry-run]", file=sys.stderr)
        sys.exit(2)
    dry_run = "--dry-run" in args
    project = [a for a in args if not a.startswith("--")][0]

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    paths = BoxPaths()
    sys.exit(run_unstage(project, paths, dry_run=dry_run))
