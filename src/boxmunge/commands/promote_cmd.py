"""boxmunge promote <project> — promote staging to production."""
from __future__ import annotations
import sys
from typing import TYPE_CHECKING
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_operation
from boxmunge.pause import is_paused
from boxmunge.state import read_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def run_promote(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    if is_paused(project_name, paths):
        print(f"ERROR: Project '{project_name}' is paused. "
              f"Run 'resume {project_name}' before promoting.",
              file=sys.stderr)
        return 1
    if is_quarantined(project_name, paths):
        print(
            f"ERROR: Project '{project_name}' is CVE-quarantined. "
            f"Run `boxmunge security resume {project_name}` to restore.\n"
            f"       (Resume re-scans first; if a quarantine-level finding "
            f"remains, you must suppress or wait for upstream fix.)",
            file=sys.stderr,
        )
        return 1
    staging_state = read_state(paths.project_staging_state(project_name))
    if not staging_state.get("active"):
        print(f"ERROR: No active staging for '{project_name}'.", file=sys.stderr)
        return 1

    if dry_run:
        print(f"[DRY RUN] Would promote '{project_name}' from staging to production")
        return 0

    try:
        with project_lock(project_name, paths):
            # Re-read state inside the lock to avoid TOCTOU
            staging_state = read_state(paths.project_staging_state(project_name))
            if not staging_state.get("active"):
                print(f"ERROR: Staging was torn down before lock was acquired.", file=sys.stderr)
                return 1
            return _run_promote_inner(project_name, paths, staging_state)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def _run_promote_inner(
    project_name: str, paths: BoxPaths, staging_state: dict,
) -> int:
    print(f"Promoting {project_name} from staging to production...")

    staged_ref = staging_state.get("ref")
    ref_arg = staged_ref if staged_ref and staged_ref != "latest" else None

    # Deploy to production FIRST — staging stays live as fallback
    print("  Deploying to production...")
    deploy_result = run_deploy(
        project_name, paths, ref=ref_arg, _lock_held=True,
        component="promote",
    )
    if deploy_result != 0:
        print("ERROR: Production deploy failed. Staging is still live.", file=sys.stderr)
        # Preserve hardening-rejection exit code (3) so operators can
        # distinguish security policy failures from generic deploy errors.
        return deploy_result if deploy_result == 3 else 1

    # Only tear down staging after successful production deploy
    print("  Tearing down staging...")
    unstage_result = run_unstage(project_name, paths, _lock_held=True)
    if unstage_result != 0:
        print("  WARN: Unstage had issues (production is live)")

    log_operation("promote", "Promoted from staging to production", paths, project=project_name)
    print(f"{project_name}: promoted to production successfully.")

    from boxmunge.webhooks import webhook_safe
    webhook_safe("promote", project_name, paths)

    return 0


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
