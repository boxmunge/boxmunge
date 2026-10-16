"""boxmunge promote <project> — promote staging to production."""
from __future__ import annotations
import sys
from typing import TYPE_CHECKING
from boxmunge.commands.deploy import deploy_locked
from boxmunge.commands.promote_release import Promotion, deploy_staged_locked
from boxmunge.commands.unstage_cmd import unstage_locked
from boxmunge.fileutil import project_lock, LockError
from boxmunge.lifecycle import refuse_if_blocked
from boxmunge.log import log_operation
from boxmunge.state import read_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def run_promote(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """promote: take the project lock and promote staging to production."""
    try:
        with project_lock(project_name, paths):
            return promote_locked(project_name, paths, dry_run)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def promote_locked(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """The promote core. Caller holds the project lock; never takes it.

    Deploy and unstage run as cores under the same lock, so nothing can
    land between production going live and staging being torn down.
    """
    if refuse_if_blocked(project_name, paths):
        return 1
    staging_state = read_state(paths.project_staging_state(project_name))
    if not staging_state.get("active"):
        print(f"ERROR: No active staging for '{project_name}'.", file=sys.stderr)
        return 1
    if dry_run:
        print(f"[DRY RUN] Would promote '{project_name}' from staging to production")
        return 0
    return _run_promote_inner(project_name, paths, staging_state)


def _run_promote_inner(
    project_name: str, paths: BoxPaths, staging_state: dict,
) -> int:
    print(f"Promoting {project_name} from staging to production...")

    # Deploy to production FIRST — staging stays live as fallback
    print("  Deploying to production...")
    deployed = _deploy_to_production(project_name, paths, staging_state)
    if deployed.rc != 0:
        if deployed.switched:
            print(f"ERROR: Production deploy failed after the switch (see above). "
                  f"Staging is still up; run 'unstage {project_name}' to remove "
                  f"it.", file=sys.stderr)
        else:
            print("ERROR: Production deploy failed. Staging is still live.",
                  file=sys.stderr)
        # Preserve hardening-rejection exit code (3) so operators can
        # distinguish security policy failures from generic deploy errors.
        return deployed.rc if deployed.rc == 3 else 1

    # Only tear down staging after successful production deploy
    print("  Tearing down staging...")
    if unstage_locked(project_name, paths) != 0:
        print(f"ERROR: {project_name} is live in production, but tearing down "
              f"staging failed (see above). Run 'unstage {project_name}' to "
              f"finish.", file=sys.stderr)
        log_operation("promote", "Promoted; staging teardown incomplete", paths,
                      project=project_name)
        return 1

    log_operation("promote", "Promoted from staging to production", paths, project=project_name)
    print(f"{project_name}: promoted to production successfully.")

    from boxmunge.webhooks import webhook_safe
    webhook_safe("promote", project_name, paths)

    return 0


def _deploy_to_production(project_name: str, paths: BoxPaths,
                          staging_state: dict) -> Promotion:
    """A bundle project deploys the release `stage` installed, never a newer
    inbox bundle; a git project deploys the staged ref."""
    if (paths.project_dir(project_name) / "repo").exists():
        staged_ref = staging_state.get("ref")
        ref_arg = staged_ref if staged_ref and staged_ref != "latest" else None
        rc = deploy_locked(project_name, paths, ref=ref_arg, component="promote")
        return Promotion(rc, switched=False)
    return deploy_staged_locked(project_name, paths)


def cmd_promote(args: list[str]) -> None:
    from boxmunge.paths import BoxPaths
    if not args:
        print("Usage: boxmunge promote <project> [--dry-run]", file=sys.stderr)
        sys.exit(2)

    known_flags = {"--dry-run"}
    unknown = [a for a in args if a.startswith("--") and a not in known_flags]
    if unknown:
        print(
            f"ERROR: unknown argument(s): {' '.join(unknown)}",
            file=sys.stderr,
        )
        print("Usage: boxmunge promote <project> [--dry-run]", file=sys.stderr)
        sys.exit(2)

    dry_run = "--dry-run" in args
    positional = [a for a in args if not a.startswith("--")]
    if not positional:
        print("Usage: boxmunge promote <project> [--dry-run]", file=sys.stderr)
        sys.exit(2)
    if len(positional) > 1:
        print(
            f"ERROR: unknown argument(s): {' '.join(positional[1:])}",
            file=sys.stderr,
        )
        print("Usage: boxmunge promote <project> [--dry-run]", file=sys.stderr)
        sys.exit(2)
    project = positional[0]

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    paths = BoxPaths()
    sys.exit(run_promote(project, paths, dry_run=dry_run))
