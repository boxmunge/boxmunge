"""boxmunge rollback <project> — undo the last deploy: its code and its data.

A bundle project puts back the release the last deploy replaced (kept in
``.releases/previous/``) together with the data snapshot taken just before
that deploy. A git project restores that snapshot and checks out the
previous ref. Whenever either half is missing, rollback refuses and says
why; it never reports success for a half-done rollback (audit C-02).
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from boxmunge.commands.deploy import (
    GIT_WHILE_STAGED, decide_release_users, deploy_locked, generate_release_config,
    replace_release, run_pre_deploy_hook,
)
from boxmunge.commands.restore import restore_locked
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_guard import ComposeRefused, check_start
from boxmunge.crashpoint import crash_point
from boxmunge.docker_run import DockerError
from boxmunge.data_dirs import log_kept, set_aside_announcer
from boxmunge.fileutil import project_lock, LockError
from boxmunge.intake import (
    IntakeError, check_installable, report_refusal, validate_release_tree,
)
from boxmunge.lifecycle import refuse_if_blocked
from boxmunge.legacy_stage import refuse_if_legacy_stage
from boxmunge.log import log_error, log_operation
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.release import (
    ReleaseStateError, discard_previous_release, install_release, live_ref,
    load_previous_release, mark_live, sync_release_code,
)
from boxmunge.release_keep import ensure_kept_pairing
from boxmunge.release_target import DeployRefused
from boxmunge.release_txn import (
    InstallTxn, advance, close_txn, load_txn, open_txn, stale_reason, start_refusal,
    supersede_txn,
)
from boxmunge.staged_release import has_slot, sweep_debris
from boxmunge.staging_isolation import StagingIsolationError, check_install_isolation
from boxmunge.state import read_state


class RollbackUnavailable(Exception):
    """Rollback cannot restore both the code and the data; says why."""


@dataclass(frozen=True)
class RollbackTarget:
    ref: str
    snapshot: str            # data snapshot to restore; "" when there is no data
    tree: Path | None        # previous release tree (bundle projects)
    # When/what replaced it, for the plan. Not compared: repairing an open
    # install's pairing rewrites it under the lock (ensure_kept_pairing).
    note: str = field(default="", compare=False)


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


def find_rollback_target(paths: BoxPaths, project_name: str,
                         txn: InstallTxn | None = None) -> RollbackTarget:
    """What rollback would restore. Raises RollbackUnavailable with the reason.

    With an open install ``txn`` that kept (or took over) the previous
    release, its snapshot is the one that pairs with it: previous.json may
    not say so yet after a crash (ensure_kept_pairing)."""
    project_dir = paths.project_dir(project_name)
    if not (project_dir / "manifest.yml").exists():
        raise RollbackUnavailable("the project has not been deployed")

    if (project_dir / "repo").exists():
        if has_slot(paths, project_name):
            raise RollbackUnavailable(GIT_WHILE_STAGED.format(p=project_name))
        state = read_state(paths.project_deploy_state(project_name))
        history = state.get("history", [])
        if not history or not history[0].get("ref"):
            raise RollbackUnavailable("there is no previous deploy in its history")
        snapshot = _required_snapshot(
            state.get("pre_deploy_snapshot", ""),
            _backup_type(project_dir / "manifest.yml"), paths, project_name)
        return RollbackTarget(ref=history[0]["ref"], snapshot=snapshot, tree=None)

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
    paired = previous.data_snapshot
    if (txn is not None and txn.source != "rollback" and txn.replaced_ref is not None
            and not txn.abandoning and txn.reached("previous_kept")):
        paired = txn.snapshot
    snapshot = _required_snapshot(
        paired, _backup_type(previous.tree / "manifest.yml"), paths, project_name)
    return RollbackTarget(
        ref=previous.ref, snapshot=snapshot, tree=previous.tree,
        note=f"replaced {previous.replaced_at} by {previous.replaced_by}",
    )


def run_rollback(project_name: str, paths: BoxPaths, yes: bool = False) -> int:
    """rollback: show the plan, confirm, take the project lock and roll back."""
    if refuse_if_blocked(project_name, paths) or refuse_if_legacy_stage(paths, project_name):
        return 1
    # Checked before the prompt too (and again under the lock): an open
    # install may make a rollback meaningless, or already finished.
    ok, txn = _open_install(project_name, paths)
    if not ok:
        return 1
    if _rollback_finished(paths, project_name, txn):
        return _locked(project_name, paths, None)
    try:
        target = find_rollback_target(paths, project_name, txn)
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

    return _locked(project_name, paths, target)


def _locked(project_name: str, paths: BoxPaths, expected: RollbackTarget | None) -> int:
    try:
        with project_lock(project_name, paths):
            return rollback_locked(project_name, paths, expected=expected)
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
    if refuse_if_blocked(project_name, paths) or refuse_if_legacy_stage(paths, project_name):
        return 1
    ok, txn = _open_install(project_name, paths)
    if not ok:
        return 1
    if _rollback_finished(paths, project_name, txn):
        return _finish_rollback(project_name, paths, txn)
    try:
        if txn is not None:
            ensure_kept_pairing(paths, project_name, txn)
        target = find_rollback_target(paths, project_name, txn)
    except (OSError, RollbackUnavailable) as e:
        print(f"ERROR: Cannot roll back {project_name}: {e}", file=sys.stderr)
        return 1
    if expected is not None and target != expected:
        print("ERROR: Deploy state changed before the lock was acquired.",
              file=sys.stderr)
        return 1
    clear_probation_if_active(paths, "rollback")
    return _run_rollback_inner(project_name, paths, target, txn)


def _open_install(project_name: str, paths: BoxPaths) -> tuple[bool, InstallTxn | None]:
    """(eligible, the open install). Prints why when not eligible."""
    try:
        txn = load_txn(paths, project_name)
    except ReleaseStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False, None
    if txn is None:
        return True, None
    stale = stale_reason(paths, project_name, txn)
    if stale:
        print(f"ERROR: {start_refusal(project_name, txn, stale)}.", file=sys.stderr)
        return False, None
    if txn.abandoning:
        print(f"ERROR: Cannot roll back {project_name}: {start_refusal(project_name, txn, None)}.",
              file=sys.stderr)
        return False, None
    if not txn.data_may_have_changed():
        what = (f"`prod-deploy {project_name} --abandon` puts `{txn.replaced_ref}`'s files back"
                if txn.replaced_ref else
                f"`prod-deploy {project_name} --abandon` removes this first deploy's code")
        print(f"ERROR: Cannot roll back {project_name}: nothing to roll back: production's "
              f"containers and data are untouched; {what}.", file=sys.stderr)
        return False, None
    return True, txn


def _rollback_finished(paths: BoxPaths, project_name: str, txn: InstallTxn | None) -> bool:
    """A rollback that reached switching drops its target's metadata only
    once production runs the target: a crash after that left it open."""
    return (txn is not None and txn.source == "rollback" and txn.reached("switching")
            and not os.path.lexists(paths.project_releases(project_name) / "previous.json"))


def _finish_rollback(project_name: str, paths: BoxPaths, txn: InstallTxn) -> int:
    print(f"The rollback of {project_name} to {txn.ref} had already succeeded; "
          f"finishing it.")
    try:
        discard_previous_release(paths, project_name)
    except (OSError, ReleaseStateError) as e:
        print(f"ERROR: Removing the used rollback target failed: {e}", file=sys.stderr)
        return 1
    close_txn(paths, project_name, txn)
    log_operation("rollback", f"Finished the rollback to {txn.ref} after an interruption",
                  paths, project=project_name)
    print(f"\n{project_name}: rollback complete")
    return 0


def _restore_data(project_name: str, paths: BoxPaths, snapshot: str, txn: str | None) -> bool:
    print("\n--- Restoring data ---")
    if restore_locked(project_name, paths, snapshot=snapshot, txn=txn) != 0:
        print(f"ERROR: Restoring {snapshot} failed — rollback incomplete. Rerun "
              f"'rollback {project_name}' once the cause is fixed.", file=sys.stderr)
        log_error("rollback", f"Data restore failed: {snapshot}", paths,
                  project=project_name)
        return False
    return True


def _run_rollback_inner(
    project_name: str, paths: BoxPaths, target: RollbackTarget, txn: InstallTxn | None,
) -> int:
    if target.tree is None:
        if target.snapshot and not _restore_data(project_name, paths, target.snapshot, None):
            return 1
        print("\n--- Redeploying previous version ---")
        rc = deploy_locked(project_name, paths, ref=target.ref, no_snapshot=True,
                           component="rollback")
    else:
        rc = _roll_back_release(project_name, paths, target, target.tree, txn)
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


def _roll_back_release(project_name: str, paths: BoxPaths, target: RollbackTarget,
                       tree: Path, current: InstallTxn | None) -> int:
    """Bundle project, in a `rollback` transaction: code, data, hook, start.
    The target stays in previous/ until the rollback has succeeded, so a
    rerun after any failure or crash resumes from the recorded phase."""
    print("\n--- Checking the previous release ---")
    try:
        manifest = validate_release_tree(tree, project_name, paths, "rollback")
        check_installable(tree, paths.project_dir(project_name))
    except IntakeError as e:
        return report_refusal(e)
    try:  # D8, before the transaction opens
        sweep_debris(paths, project_name)
        check_install_isolation(paths, project_name, tree, manifest)
    except (StagingIsolationError, OSError) as e:
        print(f"ERROR: {e}\n  Nothing was changed.", file=sys.stderr)
        return 1
    txn = current
    if txn is None or txn.source != "rollback":
        try:
            replaced = live_ref(paths, project_name)
        except ReleaseStateError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        fields = {"source": "rollback", "ref": target.ref, "staged_id": None,
                  "replaced_ref": replaced, "snapshot": target.snapshot}
        txn = (supersede_txn(paths, project_name, txn, phase="committed", **fields)
               if txn is not None else open_txn(paths, project_name, **fields))
    crash_point("rollback.committed")
    if not txn.reached("installed"):
        print("--- Restoring code ---")
        try:
            kept = install_release(tree, paths.project_dir(project_name),
                                   set_aside_announcer(paths, project_name, "rollback"))
            mark_live(paths, project_name, target.ref)
            log_kept(paths, project_name, kept, "rollback")
            sync_release_code(paths.project_dir(project_name))
        except (OSError, ValueError) as e:
            print(f"ERROR: Restoring the previous release failed part-way: {e}. Rerun "
                  f"'rollback {project_name}' to finish it.", file=sys.stderr)
            log_error("rollback", f"Code restore failed: {e}", paths, project=project_name)
            return 1
        txn = advance(paths, project_name, txn, "installed")
    crash_point("rollback.installed")
    if not txn.reached("data_restored"):
        if target.snapshot and not _restore_rolled_back_data(
                project_name, paths, manifest, target.snapshot, txn):
            return 1
        txn = advance(paths, project_name, txn, "data_restored")
    crash_point("rollback.data_restored")
    return _start_rolled_back(project_name, paths, manifest, target, txn)


def _restore_rolled_back_data(project_name: str, paths: BoxPaths, manifest: dict,
                              snapshot: str, txn: InstallTxn) -> bool:
    # restore runs the restored release's compose; give it a matching
    # overlay, and record its files and mounts as a deploy does (it was
    # validated above), before restore checks and starts the backup
    # service. Otherwise that check compares the old release with the
    # record of the release it just replaced, and refuses.
    try:
        # The backup service restores as the user the restored release runs as.
        decide_release_users(project_name, paths, manifest, "rollback")
        prepare_compose_override(paths, manifest, component="rollback")
        check_start(paths, project_name, component="rollback",
                    compose_files=["compose.yml", "compose.boxmunge.yml"],
                    record=True, deploying=True, txn=txn.id)
    except (ComposeRefused, DeployRefused, DockerError, OSError, ValueError) as e:
        print(f"ERROR: {e}. Rerun 'rollback {project_name}' once the cause is fixed.",
              file=sys.stderr)
        return False
    return _restore_data(project_name, paths, snapshot, txn.id)


def _start_rolled_back(project_name: str, paths: BoxPaths, manifest: dict,
                       target: RollbackTarget, txn: InstallTxn) -> int:
    print("\n--- Starting the previous release ---")
    if not txn.reached("switching"):
        if not txn.reached("hook_started"):
            txn = advance(paths, project_name, txn, "hook_started")
        crash_point("rollback.hook_started")
        rc = run_pre_deploy_hook(project_name, paths, manifest)
        if rc != 0:
            print(f"ERROR: The pre-deploy hook failed; rerun 'rollback {project_name}' "
                  f"once it is fixed.", file=sys.stderr)
            return rc
    try:
        generate_release_config(project_name, paths, manifest, "rollback")
    except (DeployRefused, DockerError, OSError, ValueError) as e:
        print(f"ERROR: Generating the previous release's configs failed: {e}. Rerun "
              f"'rollback {project_name}' once the cause is fixed.", file=sys.stderr)
        log_error("rollback", f"Config generation failed: {e}", paths, project=project_name)
        return 1
    if not txn.reached("switching"):
        txn = advance(paths, project_name, txn, "switching")
    crash_point("rollback.switching")
    rc = replace_release(project_name, paths, manifest, target.ref, None,
                         component="rollback", txn=txn.id)
    if rc == 0:
        discard_previous_release(paths, project_name)
    close_txn(paths, project_name, txn)
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
