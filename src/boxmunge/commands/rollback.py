"""boxmunge rollback <project> — restore pre-deploy snapshot + redeploy previous ref."""

import sys
from dataclasses import dataclass
from pathlib import Path

from boxmunge.commands.restore import run_restore
from boxmunge.commands.deploy import run_deploy
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.state import read_state


@dataclass
class RollbackTarget:
    previous_ref: str
    snapshot: str


def find_rollback_target(paths: BoxPaths, project_name: str) -> RollbackTarget | None:
    """Find what to rollback to: previous ref and current deploy's snapshot."""
    state = read_state(paths.project_deploy_state(project_name))
    if not state:
        return None

    history = state.get("history", [])
    if not history:
        return None

    previous = history[0]
    snapshot = state.get("pre_deploy_snapshot", "")

    if not previous.get("ref"):
        return None

    if not snapshot:
        return None

    return RollbackTarget(
        previous_ref=previous["ref"],
        snapshot=snapshot,
    )


def run_rollback(project_name: str, paths: BoxPaths, yes: bool = False) -> int:
    """Rollback: restore pre-deploy snapshot + redeploy previous ref."""
    clear_probation_if_active(paths, "rollback")
    target = find_rollback_target(paths, project_name)
    if target is None:
        print(f"ERROR: Cannot rollback {project_name} — no deploy history or snapshot")
        return 1

    print(f"Rollback {project_name}:")
    print(f"  Restore snapshot: {target.snapshot}")
    print(f"  Redeploy ref:     {target.previous_ref}")

    if not yes:
        response = input("\nProceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    try:
        with project_lock(project_name, paths):
            # Re-read target inside the lock to avoid TOCTOU
            target = find_rollback_target(paths, project_name)
            if target is None:
                print(f"ERROR: Deploy state changed before lock was acquired.")
                return 1
            return _run_rollback_inner(project_name, paths, target)
    except LockError as e:
        print(f"ERROR: {e}")
        return 1


def _run_rollback_inner(
    project_name: str, paths: BoxPaths, target: RollbackTarget,
) -> int:
    print("\n--- Restoring data ---")
    result = run_restore(project_name, paths, snapshot=target.snapshot, yes=True, _lock_held=True)
    if result != 0:
        print("ERROR: Restore failed — rollback incomplete")
        return 1

    print("\n--- Redeploying previous version ---")
    result = run_deploy(project_name, paths, ref=target.previous_ref, no_snapshot=True, _lock_held=True)
    if result != 0:
        print("ERROR: Deploy failed — rollback incomplete")
        return 1

    log_operation(
        "rollback",
        f"Rollback completed: restored {target.snapshot}, deployed {target.previous_ref}",
        paths,
        project=project_name,
    )
    print(f"\n{project_name}: rollback complete")

    try:
        from boxmunge.config import load_config
        from boxmunge.webhooks import fire_webhook
        config = load_config(paths)
        fire_webhook("rollback", project_name, config)
    except Exception:
        pass

    return 0


def cmd_rollback(args: list[str]) -> None:
    if not args:
        print("Usage: boxmunge rollback <project> [--yes]", file=sys.stderr)
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
    sys.exit(run_rollback(project, paths, yes=yes))
