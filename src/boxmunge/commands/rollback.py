"""boxmunge rollback <project> — undo the last deploy: its code and its data.

A bundle project puts back the release the last deploy replaced (kept in
``.releases/previous/``) together with the data snapshot taken just before
that deploy. A git project restores that snapshot and checks out the
previous ref. Whenever either half is missing, rollback refuses and says
why; it never reports success for a half-done rollback (audit C-02).
"""

import sys
from dataclasses import dataclass
from pathlib import Path

from boxmunge.commands.deploy import deploy_locked, redeploy_installed
from boxmunge.commands.restore import restore_locked
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_guard import ComposeRefused, check_start
from boxmunge.data_dirs import log_kept, set_aside_announcer
from boxmunge.fileutil import project_lock, LockError
from boxmunge.intake import (
    IntakeError, check_installable, report_refusal, validate_release_tree,
)
from boxmunge.lifecycle import refuse_if_blocked
from boxmunge.log import log_error, log_operation
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.release import (
    ReleaseStateError, discard_previous_release, install_release,
    load_previous_release, mark_live,
)
from boxmunge.release_staging import has_prestage
from boxmunge.state import read_state


class RollbackUnavailable(Exception):
    """Rollback cannot restore both the code and the data; says why."""


@dataclass(frozen=True)
class RollbackTarget:
    ref: str
    snapshot: str            # data snapshot to restore; "" when there is no data
    tree: Path | None        # previous release tree (bundle projects)
    note: str = ""           # when/what replaced it, for the plan


def _backup_type(manifest_path: Path) -> str:
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        raise RollbackUnavailable(f"cannot read {manifest_path}: {e}") from e
    return manifest.get("backup", {}).get("type", "none")


def _required_snapshot(snapshot: str, backup_type: str, paths: BoxPaths,
                       project_name: str) -> str:
    """The data snapshot to restore ("" for a project with no data)."""
    if backup_type == "none":
        return ""
    if not snapshot:
        raise RollbackUnavailable(
            "no pre-deploy data snapshot was taken when that release was "
            "replaced (the backup failed, or --no-snapshot was used). Rolling "
            "back the code alone would run the old release against data the "
            "newer one may have changed. Restore data with 'restore' and "
            "deploy a known-good bundle instead."
        )
    if not (paths.project_backups(project_name) / snapshot).exists():
        raise RollbackUnavailable(
            f"the pre-deploy data snapshot {snapshot} is no longer in backups/"
        )
    return snapshot


def find_rollback_target(paths: BoxPaths, project_name: str) -> RollbackTarget:
    """What rollback would restore. Raises RollbackUnavailable with the reason."""
    project_dir = paths.project_dir(project_name)
    if not (project_dir / "manifest.yml").exists():
        raise RollbackUnavailable("the project has not been deployed")

    if (project_dir / "repo").exists():
        state = read_state(paths.project_deploy_state(project_name))
        history = state.get("history", [])
        if not history or not history[0].get("ref"):
            raise RollbackUnavailable("there is no previous deploy in its history")
        snapshot = _required_snapshot(
            state.get("pre_deploy_snapshot", ""),
            _backup_type(project_dir / "manifest.yml"), paths, project_name)
        return RollbackTarget(ref=history[0]["ref"], snapshot=snapshot, tree=None)

    if has_prestage(paths, project_name):
        raise RollbackUnavailable(
            f"a staged release is installed; run 'promote {project_name}' or "
            f"'unstage {project_name}' first")
    try:
        previous = load_previous_release(paths, project_name)
    except ReleaseStateError as e:
        raise RollbackUnavailable(str(e)) from e
    if previous is None:
        raise RollbackUnavailable(
            "no previous release is kept. Rollback restores the release the "
            "last bundle deploy replaced; there is none after a first deploy, "
            "or once a rollback has used it. Deploy a known-good bundle instead."
        )
    snapshot = _required_snapshot(
        previous.data_snapshot, _backup_type(previous.tree / "manifest.yml"),
        paths, project_name)
    return RollbackTarget(
        ref=previous.ref, snapshot=snapshot, tree=previous.tree,
        note=f"replaced {previous.replaced_at} by {previous.replaced_by}",
    )


def run_rollback(project_name: str, paths: BoxPaths, yes: bool = False) -> int:
    """rollback: show the plan, confirm, take the project lock and roll back."""
    if refuse_if_blocked(project_name, paths):
        return 1
    try:
        target = find_rollback_target(paths, project_name)
    except RollbackUnavailable as e:
        print(f"ERROR: Cannot roll back {project_name}: {e}", file=sys.stderr)
        return 1

    print(f"Rollback {project_name}:")
    print(f"  Code: {target.ref}" + (f" ({target.note})" if target.note else ""))
    if target.snapshot:
        print(f"  Data: restore snapshot {target.snapshot}")
    else:
        print("  Data: nothing to restore (backup.type: none)")

    if not yes:
        response = input("\nProceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    try:
        with project_lock(project_name, paths):
            return rollback_locked(project_name, paths, expected=target)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def rollback_locked(project_name: str, paths: BoxPaths,
                    expected: RollbackTarget | None = None) -> int:
    """The rollback core. Caller holds the project lock; never takes it.

    Eligibility and the target are worked out here, under the lock.
    ``expected`` is the plan the operator confirmed: if the deploy state
    changed since, nothing is done.
    """
    if refuse_if_blocked(project_name, paths):
        return 1
    try:
        target = find_rollback_target(paths, project_name)
    except RollbackUnavailable as e:
        print(f"ERROR: Cannot roll back {project_name}: {e}", file=sys.stderr)
        return 1
    if expected is not None and target != expected:
        print("ERROR: Deploy state changed before the lock was acquired.",
              file=sys.stderr)
        return 1
    clear_probation_if_active(paths, "rollback")
    return _run_rollback_inner(project_name, paths, target)


def _restore_data(project_name: str, paths: BoxPaths, snapshot: str) -> bool:
    print("\n--- Restoring data ---")
    if restore_locked(project_name, paths, snapshot=snapshot) != 0:
        print(f"ERROR: Restoring {snapshot} failed — rollback incomplete.",
              file=sys.stderr)
        log_error("rollback", f"Data restore failed: {snapshot}", paths,
                  project=project_name)
        return False
    return True


def _run_rollback_inner(
    project_name: str, paths: BoxPaths, target: RollbackTarget,
) -> int:
    if target.tree is None:
        if target.snapshot and not _restore_data(project_name, paths, target.snapshot):
            return 1
        print("\n--- Redeploying previous version ---")
        rc = deploy_locked(project_name, paths, ref=target.ref, no_snapshot=True,
                           component="rollback")
    else:
        rc = _roll_back_release(project_name, paths, target, target.tree)
    if rc != 0:
        print("ERROR: Rollback incomplete — see the errors above.", file=sys.stderr)
        return rc

    log_operation(
        "rollback",
        f"Rollback completed: code {target.ref}, "
        f"data {target.snapshot or 'none (no backups)'}",
        paths, project=project_name,
    )
    print(f"\n{project_name}: rollback complete")

    from boxmunge.webhooks import webhook_safe
    webhook_safe("rollback", project_name, paths)
    return 0


def _roll_back_release(project_name: str, paths: BoxPaths,
                       target: RollbackTarget, tree: Path) -> int:
    """Bundle project: check, install the previous release, restore, start."""
    print("\n--- Checking the previous release ---")
    try:
        manifest = validate_release_tree(tree, project_name, paths, "rollback")
        check_installable(tree, paths.project_dir(project_name))
    except IntakeError as e:
        return report_refusal(e)

    print("--- Restoring code ---")
    try:
        kept = install_release(tree, paths.project_dir(project_name),
                               set_aside_announcer(paths, project_name, "rollback"))
        mark_live(paths, project_name, target.ref)
        log_kept(paths, project_name, kept, "rollback")
    except (OSError, ValueError) as e:
        print(f"ERROR: Restoring the previous release failed part-way: {e}",
              file=sys.stderr)
        log_error("rollback", f"Code restore failed: {e}", paths, project=project_name)
        return 1

    if target.snapshot:
        # restore runs the restored release's compose; give it a matching
        # overlay, and record its files and mounts as a deploy does (it was
        # validated above), before restore checks and starts the backup
        # service. Otherwise that check compares the old release with the
        # record of the release it just replaced, and refuses.
        prepare_compose_override(paths, manifest, component="rollback")
        try:
            check_start(paths, project_name, component="rollback",
                        compose_files=["compose.yml", "compose.boxmunge.yml"],
                        record=True, deploying=True)
        except ComposeRefused as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        if not _restore_data(project_name, paths, target.snapshot):
            return 1

    print("\n--- Starting the previous release ---")
    rc = redeploy_installed(project_name, paths, target.ref, no_snapshot=True,
                            dry_run=False, component="rollback")
    if rc == 0:
        discard_previous_release(paths, project_name)
    return rc


def cmd_rollback(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args(
        "rollback", args, flags={"--yes"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("rollback", parsed.positional[0])
    yes = parsed.has("--yes")

    paths = BoxPaths()
    sys.exit(run_rollback(project, paths, yes=yes))
