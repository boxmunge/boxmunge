# SPDX-License-Identifier: Apache-2.0
"""Rollback of a git project, in a `rollback` install transaction.

The target is the commit an open install replaced (from hook_started on),
or the previous deploy in the history, with the snapshot that pairs with
it. Recorded refs may be 0.10.1's short SHAs (resolve_recorded_ref). The
phases are the bundle rollback's (commands/rollback): the target is
checked out detached, its data restored, its hook run and it is started;
a rerun resumes from the recorded phase. While a release is staged the
target is first proved disjoint from staging (D8).
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from boxmunge.commands.git_deploy import prove_disjoint_git
from boxmunge.commands.rollback import (
    RollbackTarget, RollbackUnavailable, required_snapshot, restore_rolled_back_data,
    start_rolled_back,
)
from boxmunge.crashpoint import crash_point
from boxmunge.git_slot import (
    GitRefError, checkout_detached, head_sha, manifest_at, resolve_recorded_ref,
)
from boxmunge.intake import IntakeError, report_refusal, validate_release_tree
from boxmunge.log import log_error
from boxmunge.manifest import ManifestError
from boxmunge.release_txn import InstallTxn, advance, open_txn, supersede_txn
from boxmunge.state import read_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def git_rollback_target(paths: BoxPaths, project_name: str,
                        txn: InstallTxn | None) -> RollbackTarget:
    """What a git rollback restores. Raises RollbackUnavailable."""
    repo = paths.project_dir(project_name) / "repo"
    if txn is not None and txn.source == "rollback":
        ref, snapshot, note = txn.ref, txn.snapshot, "finishing the interrupted rollback"
    elif txn is not None:
        ref, snapshot = txn.replaced_ref, txn.snapshot
        note = f"replaced by the unfinished install of {txn.ref}"
    else:
        state = read_state(paths.project_deploy_state(project_name))
        history = state.get("history", [])
        if not history or not history[0].get("ref"):
            raise RollbackUnavailable("there is no previous deploy in its history")
        ref, snapshot, note = history[0]["ref"], state.get("pre_deploy_snapshot", ""), ""
    try:
        sha = resolve_recorded_ref(repo, ref or "")
        backup = manifest_at(repo, sha).get("backup", {}).get("type", "none")
    except (GitRefError, ManifestError) as e:
        raise RollbackUnavailable(f"cannot read the release to roll back to ({ref}): {e}") from e
    return RollbackTarget(ref=sha, snapshot=required_snapshot(snapshot, backup, paths,
                                                              project_name),
                          tree=None, note=note)


def roll_back_git(project_name: str, paths: BoxPaths, target: RollbackTarget,
                  current: InstallTxn | None) -> int:
    repo = paths.project_dir(project_name) / "repo"
    if not prove_disjoint_git(project_name, paths, target.ref,
                              advice="Unstage first, or deploy a fix."):
        return 1
    txn = current
    if txn is None or txn.source != "rollback":
        try:
            replaced = head_sha(repo)
        except GitRefError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        fields = {"source": "rollback", "ref": target.ref, "staged_id": None,
                  "replaced_ref": replaced, "snapshot": target.snapshot}
        txn = (supersede_txn(paths, project_name, txn, phase="committed", **fields)
               if txn is not None else open_txn(paths, project_name, **fields))
    crash_point("rollback.committed")
    print(f"--- Checking out {target.ref} ---")
    try:  # idempotent: a resume makes sure the tree is the target
        checkout_detached(repo, target.ref)
    except GitRefError as e:
        print(f"ERROR: {e}. Rerun 'rollback {project_name}' once the cause is fixed.",
              file=sys.stderr)
        log_error("rollback", f"Checkout of {target.ref} failed: {e}", paths,
                  project=project_name)
        return 1
    if not txn.reached("installed"):
        txn = advance(paths, project_name, txn, "installed")
    crash_point("rollback.installed")
    try:
        manifest = validate_release_tree(paths.project_dir(project_name), project_name,
                                         paths, "rollback")
    except IntakeError as e:
        return report_refusal(e)
    if not txn.reached("data_restored"):
        if target.snapshot and not restore_rolled_back_data(
                project_name, paths, manifest, target.snapshot, txn):
            return 1
        txn = advance(paths, project_name, txn, "data_restored")
    crash_point("rollback.data_restored")
    return start_rolled_back(project_name, paths, manifest, target, txn)
