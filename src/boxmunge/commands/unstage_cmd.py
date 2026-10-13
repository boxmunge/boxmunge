"""boxmunge unstage <project> — tear down staging, leave production untouched.

Unstage removes whatever a stage left behind, whether or not the stage got
as far as recording itself active (audit C-13): staging containers, the
staging Caddy site and compose files, and the staged release in the project
dir, which is replaced by the production release stage kept aside.
"""
from __future__ import annotations
import sys
from typing import TYPE_CHECKING
from boxmunge.docker import compose_down, caddy_reload, DockerError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_error, log_operation
from boxmunge.release import has_prestage, restore_prestage
from boxmunge.state import read_state, write_state

if TYPE_CHECKING:
    from pathlib import Path
    from boxmunge.paths import BoxPaths


def _staging_files(project_name: str, paths: BoxPaths) -> list[Path]:
    return [
        paths.project_staging_caddy_site(project_name),
        paths.project_staging_compose_override(project_name),
        paths.project_dir(project_name) / "compose.staging-base.yml",
    ]


def staging_exists(project_name: str, paths: BoxPaths) -> bool:
    """True if any trace of a stage exists: state, files, or a kept release."""
    return (
        bool(read_state(paths.project_staging_state(project_name)).get("active"))
        or any(p.exists() for p in _staging_files(project_name, paths))
        or has_prestage(paths, project_name)
    )


def teardown_staging(project_name: str, paths: BoxPaths) -> bool:
    """Remove every staging artefact and put production's release back.

    Idempotent. Returns False if a step failed (each failure is reported);
    the remaining steps still run so as much as possible is cleaned up.
    """
    project_dir = paths.project_dir(project_name)
    ok = True

    staging_override = paths.project_staging_compose_override(project_name)
    if staging_override.exists():
        staging_base = project_dir / "compose.staging-base.yml"
        base = "compose.staging-base.yml" if staging_base.exists() else "compose.yml"
        try:
            compose_down(project_dir, compose_files=[base, "compose.boxmunge-staging.yml"],
                         project_name=f"{project_name}-staging")
        except DockerError as e:
            print(f"  WARN: Staging container teardown failed: {e}")
            ok = False

    for path in _staging_files(project_name, paths):
        path.unlink(missing_ok=True)

    if has_prestage(paths, project_name):
        try:
            restore_prestage(paths, project_name)
            print("  Production release files restored.")
        except (OSError, ValueError) as e:
            print(f"ERROR: Restoring the production release files failed: {e}",
                  file=sys.stderr)
            log_error("unstage", f"Restoring the production release failed: {e}",
                      paths, project=project_name)
            ok = False

    try:
        caddy_reload(paths.caddy, paths.state)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    write_state(paths.project_staging_state(project_name), {"active": False})
    return ok


def _run_unstage_inner(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """Inner unstage logic — caller must hold the project lock."""
    if not staging_exists(project_name, paths):
        print(f"ERROR: No staging found for '{project_name}'.", file=sys.stderr)
        return 1
    if dry_run:
        print(f"[DRY RUN] Would tear down staging for '{project_name}'")
        return 0

    print(f"Unstaging {project_name}...")
    if not teardown_staging(project_name, paths):
        print(f"ERROR: Staging for '{project_name}' was only partly torn down; "
              f"fix the errors above and run 'unstage {project_name}' again.",
              file=sys.stderr)
        return 1

    log_operation("unstage", "Unstaged", paths, project=project_name)
    print(f"{project_name}: staging torn down.")

    from boxmunge.webhooks import webhook_safe
    webhook_safe("unstage", project_name, paths)

    return 0


def run_unstage(project_name: str, paths: BoxPaths, dry_run: bool = False,
                _lock_held: bool = False) -> int:
    """Tear down staging for a project. Returns 0 on success, 1 on failure."""
    if not _lock_held:
        try:
            with project_lock(project_name, paths):
                return _run_unstage_inner(project_name, paths, dry_run)
        except LockError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    return _run_unstage_inner(project_name, paths, dry_run)


def cmd_unstage(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    from boxmunge.paths import BoxPaths
    parsed = parse_args(
        "unstage", args, flags={"--dry-run"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("unstage", parsed.positional[0])
    paths = BoxPaths()
    sys.exit(run_unstage(project, paths, dry_run=parsed.has("--dry-run")))
