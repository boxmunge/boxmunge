# SPDX-License-Identifier: Apache-2.0
"""boxmunge promote <project> — deploy the staged release to production.

Promote is an ordinary install (deploy_tree_locked, source "staged") whose
tree is the slot's release, never a newer inbox bundle. Once
replace_release returns the slot is marked retired, so it is never
promoted twice; on success staging is torn down. A killed promote is
finished by running promote again.

promote_locked runs the spec's steps as named functions, in order:
_eligibility, _verify_slot, _deploy_tree (whose switch ends in _retire),
_teardown (in _teardown_after on success).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from boxmunge.commands.deploy import deploy_eligible
from boxmunge.commands.deploy_tree import TreeDeploy, deploy_tree_locked
from boxmunge.commands.unstage_cmd import teardown_staging_locked
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.fileutil import LockError, project_lock
from boxmunge.intake import IntakeError, check_installable, report_refusal, validate_release_tree
from boxmunge.log import log_error, log_operation
from boxmunge.probation import clear_probation_if_active
from boxmunge.release_txn import InstallTxn, close_txn, load_txn, options_text
from boxmunge.staged_release import (
    SlotError, StagedRelease, load_slot, release_dir, slot_dir, update_meta,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

COMPONENT = "promote"


@dataclass(frozen=True)
class _Promotion:
    meta: StagedRelease
    txn: InstallTxn | None
    resuming: bool  # the open install is this slot's promote


def run_promote(project: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """promote: take the project lock and promote staging to production."""
    try:
        with project_lock(project, paths):
            return promote_locked(project, paths, dry_run)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def promote_locked(project: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """The promote core. Caller holds the project lock; never takes it."""
    found = _eligibility(project, paths)
    if isinstance(found, int):
        return found
    if dry_run:
        what = ("finish tearing down staging" if found.meta.state == "retired"
                else f"promote '{project}' ({found.meta.ref}) to production")
        print(f"[DRY RUN] Would {what}")
        return 0
    if found.meta.state == "retired":
        return _finish_retired(project, paths, found)
    manifest = _verify_slot(project, paths, found)
    if isinstance(manifest, int):
        return manifest
    rc = _deploy_tree(project, paths, found.meta, manifest)
    if rc != 0:
        return _report_failed(project, paths, found.meta, rc)
    return _teardown_after(project, paths, found.meta.ref)


def _eligibility(project: str, paths: BoxPaths) -> _Promotion | int:
    """Step 1, under the lock: not blocked, registered, a readable slot
    that finished staging (or this slot's open promote, to resume)."""
    if not deploy_eligible(project, paths):
        return 1
    txn = None
    try:
        txn = load_txn(paths, project)
        meta = load_slot(paths, project)
    except (SlotError, ReleaseStateError) as e:
        print(f"ERROR: Cannot promote '{project}': {e}. {_unreadable_advice(project, txn)}",
              file=sys.stderr)
        return 1
    if meta is None:
        print(f"ERROR: No staged release for '{project}'.", file=sys.stderr)
        return 1
    if meta.kind != "bundle":
        print(f"ERROR: Cannot promote '{project}': it is a git stage, which this build of "
              f"boxmunge cannot promote. Unstage it and deploy with prod-deploy.",
              file=sys.stderr)
        return 1
    resuming = txn is not None and txn.source == "staged" and txn.staged_id == meta.id
    if meta.state == "starting" and not resuming:
        print(f"ERROR: Cannot promote '{project}': the stage did not finish; stage again "
              f"or unstage.", file=sys.stderr)
        return 1
    return _Promotion(meta, txn, resuming)


def _unreadable_advice(project: str, txn: InstallTxn | None) -> str:
    """A slot record that cannot be read under this project's open promote
    cannot be resumed, and unstage keeps the slot for it: name the
    install's own ways out instead of a stage that would be refused."""
    if txn is None or txn.source != "staged":
        return "Stage again, or unstage."
    return (f"The promote of {txn.ref} is open (phase {txn.phase}) and cannot resume "
            f"without it: {options_text(project, txn, rerun=False)}")


def _finish_retired(project: str, paths: BoxPaths, found: _Promotion) -> int:
    """A promote killed after replace_release returned: production runs the
    staged release, so only the close and the teardown are left. The slot
    records how the switch ended, so a rerun reports it truthfully."""
    if found.resuming:
        close_txn(paths, project, found.txn)
    ref = found.meta.ref
    if found.meta.switch_rc == 0:
        print(f"{ref} is already live in production; finishing the teardown of staging.")
        return _teardown_after(project, paths, ref)
    print(f"{ref} was switched to production but its promotion failed; finishing the "
          f"teardown of staging.")
    if not _teardown(project, paths):
        return 1
    print(f"ERROR: staging was torn down, but the promotion of {ref} failed after "
          f"production was switched (see 'rollback {project}' below).", file=sys.stderr)
    report_failed_after_switch(project, paths, ref)
    return 1


def _verify_slot(project: str, paths: BoxPaths, found: _Promotion) -> dict[str, Any] | int:
    """Step 2: the slot's release must pass this boxmunge's checks (upgrades
    do not migrate the slot). A resume skips check_installable: the
    release is already partly in the project dir."""
    release = release_dir(slot_dir(paths, project))
    try:
        manifest = validate_release_tree(release, project, paths, COMPONENT)
        if not found.resuming:
            check_installable(release, paths.project_dir(project))
    except IntakeError as e:
        print("  The staged release no longer passes this boxmunge's checks; stage it "
              "again.", file=sys.stderr)
        return report_refusal(e)
    return manifest


def _deploy_tree(project: str, paths: BoxPaths, meta: StagedRelease,
                 manifest: dict[str, Any]) -> int:
    """Step 3: the same install core as a bundle deploy, over the slot's tree."""
    print(f"Promoting {project} ({meta.ref}) from staging to production...")
    return deploy_tree_locked(project, paths, TreeDeploy(
        tree=release_dir(slot_dir(paths, project)), ref=meta.ref, source="staged",
        staged_id=meta.id, manifest=manifest, component=COMPONENT,
        on_installed=lambda: clear_probation_if_active(paths, "deploy"),
        on_switched=lambda rc: _retire(project, paths, rc)))


def _retire(project: str, paths: BoxPaths, rc: int) -> None:
    """Step 4, once replace_release returns (any result) and before the
    transaction closes: the slot is never promoted again, and it records
    how the switch ended for a rerun that only has the teardown left."""
    update_meta(paths, project, load_slot(paths, project), state="retired", switch_rc=rc)


def _report_failed(project: str, paths: BoxPaths, meta: StagedRelease, rc: int) -> int:
    now = load_slot(paths, project)
    if now is not None and now.state == "retired":
        report_failed_after_switch(project, paths, meta.ref)
        print(f"  Staging is still up; run 'unstage {project}' to remove it.",
              file=sys.stderr)
    else:
        print("ERROR: Production deploy failed. Staging is still live.", file=sys.stderr)
    # A hardening rejection keeps its exit code (3) so operators can tell
    # security policy failures from other deploy errors.
    return rc if rc == 3 else 1


def _teardown(project: str, paths: BoxPaths) -> bool:
    """Step 5: the unstage core, under the same lock."""
    print("  Tearing down staging...")
    if teardown_staging_locked(project, paths, component=COMPONENT):
        return True
    print(f"ERROR: {project} is live in production, but tearing down staging failed "
          f"(see above). Run 'unstage {project}' to finish.", file=sys.stderr)
    log_operation(COMPONENT, "Staging teardown after the switch incomplete", paths,
                  project=project)
    return False


def _teardown_after(project: str, paths: BoxPaths, ref: str) -> int:
    if not _teardown(project, paths):
        return 1
    log_operation(COMPONENT, f"Promoted {ref} from staging to production", paths,
                  project=project, detail={"ref": ref})
    print(f"{project}: promoted to production successfully.")
    from boxmunge.webhooks import webhook_safe
    webhook_safe("promote", project, paths)
    return 0


def report_failed_after_switch(project: str, paths: BoxPaths, staged_ref: str) -> None:
    # rollback imports deploy, which this module also builds on: imported
    # here, where it is needed, rather than at module load.
    from boxmunge.commands.rollback import RollbackUnavailable, find_rollback_target
    print(f"ERROR: The promotion failed after production was switched: production now "
          f"runs {staged_ref}.", file=sys.stderr)
    try:
        target = find_rollback_target(paths, project)
    except RollbackUnavailable as e:
        print(f"  'rollback {project}' is not available: {e}. Fix the cause and deploy "
              f"again.", file=sys.stderr)
    else:
        data = (f"restores the data snapshot {target.snapshot} taken before the promotion"
                if target.snapshot else "has no data to restore (backup.type: none)")
        print(f"  'rollback {project}' returns to {target.ref} and {data}. Or fix the "
              f"cause and deploy again.", file=sys.stderr)
    log_error("deploy", f"Promotion of {staged_ref} failed after production was switched "
              f"to it", paths, project=project)


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
