"""boxmunge unstage <project> — tear down staging, leave production untouched.

Unstage removes whatever a stage left behind, whether or not the stage got
as far as recording itself active (audit C-13): staging containers, the
staging Caddy site and compose files, and the staged release in the project
dir, which is replaced by the production release stage kept aside.
"""
from __future__ import annotations
import sys
from typing import TYPE_CHECKING
from boxmunge.caddy_journal import remove_site
from boxmunge.docker import caddy_config_lock, compose_down, caddy_reload, DockerError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_error, log_operation
from boxmunge.release_staging import has_prestage, prestage_replaced, restore_prestage
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


def refuse_if_promotion_interrupted(project_name: str, paths: BoxPaths) -> bool:
    """Print why and return True if a promote switched production to the
    staged release but stopped before it finished.

    The kept production release then no longer describes what production
    runs: putting it back (unstage) or staging over it would put old files
    under the new containers. Finishing the promote resolves it.
    """
    if not (has_prestage(paths, project_name) and prestage_replaced(paths, project_name)):
        return False
    print(f"ERROR: An earlier promote of '{project_name}' was interrupted after "
          f"it started the staged release in production, so the kept production "
          f"release no longer matches what is running. Run 'promote "
          f"{project_name}' to finish it; 'rollback {project_name}' then returns "
          f"to the earlier release.", file=sys.stderr)
    return True


def _remove_staging_containers(project_name: str, paths: BoxPaths) -> str | None:
    """compose down the staging project. Returns the error, or None."""
    project_dir = paths.project_dir(project_name)
    if not paths.project_staging_compose_override(project_name).exists():
        return None
    staging_base = project_dir / "compose.staging-base.yml"
    base = "compose.staging-base.yml" if staging_base.exists() else "compose.yml"
    try:
        compose_down(project_dir, compose_files=[base, "compose.boxmunge-staging.yml"],
                     project_name=f"{project_name}-staging")
    except DockerError as e:
        return str(e)
    return None


def teardown_staging(project_name: str, paths: BoxPaths) -> bool:
    """Remove every staging artefact and put production's release back.

    Idempotent. Returns False if a step failed (each failure is reported).
    If the staging containers cannot be removed, nothing else is touched:
    the compose files that reach them stay, and the staging state records
    the incomplete cleanup, so running unstage again retries it. After
    that, the remaining steps all run so as much as possible is cleaned up.
    """
    if refuse_if_promotion_interrupted(project_name, paths):
        return False
    state_path = paths.project_staging_state(project_name)
    error = _remove_staging_containers(project_name, paths)
    if error is not None:
        print(f"ERROR: Removing the staging containers failed: {error}. Nothing "
              f"else was removed; the staging compose files are kept so "
              f"'unstage {project_name}' can retry.", file=sys.stderr)
        log_error("unstage", f"Staging container teardown failed: {error}",
                  paths, project=project_name)
        write_state(state_path, {**read_state(state_path), "cleanup_incomplete": error})
        return False

    ok = True
    with caddy_config_lock(paths.state):
        remove_site(paths.caddy, paths.project_staging_caddy_site(project_name))
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

    write_state(state_path, {"active": False})
    return ok


def unstage_locked(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """The unstage core. Caller holds the project lock; never takes it."""
    if not staging_exists(project_name, paths):
        print(f"ERROR: No staging found for '{project_name}'.", file=sys.stderr)
        return 1
    if refuse_if_promotion_interrupted(project_name, paths):
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


def run_unstage(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """unstage: take the project lock and tear down staging. Returns 0 on
    success, 1 on failure."""
    try:
        with project_lock(project_name, paths):
            return unstage_locked(project_name, paths, dry_run)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_unstage(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    from boxmunge.paths import BoxPaths
    parsed = parse_args(
        "unstage", args, flags={"--dry-run"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("unstage", parsed.positional[0])
    paths = BoxPaths()
    sys.exit(run_unstage(project, paths, dry_run=parsed.has("--dry-run")))
