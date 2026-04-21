"""boxmunge promote <project> — promote staging to production."""
from __future__ import annotations
import sys
from typing import TYPE_CHECKING
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_operation
from boxmunge.state import read_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def run_promote(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    staging_state = read_state(paths.project_staging_state(project_name))
    if not staging_state.get("active"):
        print(f"ERROR: No active staging for '{project_name}'.")
        return 1

    if dry_run:
        print(f"[DRY RUN] Would promote '{project_name}' from staging to production")
        return 0

    try:
        with project_lock(project_name, paths):
            # Re-read state inside the lock to avoid TOCTOU
            staging_state = read_state(paths.project_staging_state(project_name))
            if not staging_state.get("active"):
                print(f"ERROR: Staging was torn down before lock was acquired.")
                return 1
            return _run_promote_inner(project_name, paths, staging_state)
    except LockError as e:
        print(f"ERROR: {e}")
        return 1


def _run_promote_inner(
    project_name: str, paths: BoxPaths, staging_state: dict,
) -> int:
    print(f"Promoting {project_name} from staging to production...")

    staged_ref = staging_state.get("ref")
    ref_arg = staged_ref if staged_ref and staged_ref != "latest" else None

    # Deploy to production FIRST — staging stays live as fallback
    print("  Deploying to production...")
    deploy_result = run_deploy(project_name, paths, ref=ref_arg, _lock_held=True)
    if deploy_result != 0:
        print("ERROR: Production deploy failed. Staging is still live.")
        return 1

    # Only tear down staging after successful production deploy
    print("  Tearing down staging...")
    unstage_result = run_unstage(project_name, paths, _lock_held=True)
    if unstage_result != 0:
        print("  WARN: Unstage had issues (production is live)")

    log_operation("promote", "Promoted from staging to production", paths, project=project_name)
    print(f"{project_name}: promoted to production successfully.")

    try:
        from boxmunge.config import load_config
        from boxmunge.webhooks import fire_webhook
        config = load_config(paths)
        fire_webhook("promote", project_name, config)
    except Exception:
        pass

    return 0


def cmd_promote(args: list[str]) -> None:
    from boxmunge.paths import BoxPaths
    if not args:
        print("Usage: boxmunge promote <project> [--dry-run]", file=sys.stderr)
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
    sys.exit(run_promote(project, paths, dry_run=dry_run))
