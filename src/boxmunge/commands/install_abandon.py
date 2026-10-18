# SPDX-License-Identifier: Apache-2.0
"""prod-deploy <project> --abandon: undo an install before its hook ran.

Allowed before hook_started: the replaced release's code goes back into the
project dir (a git project's replaced commit is checked out again), the superseded previous release goes back to previous/, and
the transaction closes. Containers and data are untouched, and a staged
slot stays as it was. From hook_started on the hook may have changed data,
so rollback is the way back.
"""
from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from boxmunge.commands import release_config
from boxmunge.data_dirs import ReleaseStateError, log_kept, set_aside_announcer
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import LockError, discard_dir, fsync_dir, project_lock, sweep_discarded
from boxmunge.git_slot import checkout_detached
from boxmunge.log import log_error, log_operation
from boxmunge.release import (
    _remove, install_release, live_code_entries, mark_live, previous_dir, sync_release_code,
)
from boxmunge.release_keep import restore_superseded
from boxmunge.release_txn import (
    ABANDONING, CODE_RESTORED, InstallTxn, close_txn, load_txn, mark_abandon, stale_reason,
    start_refusal,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _put_code_back(project_name: str, paths: BoxPaths, txn: InstallTxn) -> None:
    """Install the replaced release from previous/ (the keep's copy of it),
    or remove a first deploy's code; a git project checks the replaced
    commit out again. Safe to run again: previous/ is not touched until
    CODE_RESTORED is recorded."""
    project_dir = paths.project_dir(project_name)
    if (project_dir / "repo").is_dir():
        # A first deploy replaced nothing that ran: its checkout stays.
        if txn.replaced_ref is not None:
            checkout_detached(project_dir / "repo", txn.replaced_ref)
        return
    if txn.replaced_ref is None:
        for entry in live_code_entries(project_dir):
            _remove(entry)
        live = paths.project_releases(project_name) / "live.json"
        if os.path.lexists(live):
            live.unlink()
        fsync_dir(live.parent)
        fsync_dir(project_dir)
        return
    kept = install_release(previous_dir(paths, project_name), project_dir,
                           set_aside_announcer(paths, project_name, "abandon"))
    log_kept(paths, project_name, kept, "abandon")
    mark_live(paths, project_name, txn.replaced_ref)
    sync_release_code(project_dir)


def _refusal(project_name: str, txn: InstallTxn) -> str | None:
    if txn.source == "rollback":
        return (f"A rollback cannot be abandoned: rerun 'rollback {project_name}' to "
                f"finish it, or deploy a fix.")
    if not txn.data_may_have_changed():
        return None
    why = ("the pre-deploy hook may have changed data" if txn.touched == "" else
           "an earlier attempt this install replaced may have run its pre-deploy hook "
           "or its containers, or a rollback restored data")
    if txn.replaced_ref is None:
        return (f"Cannot abandon the install of {txn.ref}: {why}, and this is a first "
                f"deploy, with no release to go back to; deploy a fix.")
    return (f"Cannot abandon the install of {txn.ref}: {why}; `rollback {project_name}` "
            f"restores `{txn.snapshot or 'no data snapshot'}` with `{txn.replaced_ref}`, "
            f"or deploy a fix.")


def abandon_locked(project_name: str, paths: BoxPaths) -> int:
    """The abandon core. Caller holds the project lock; never takes it.

    Checkpointed (release_txn.ABANDON_PHASES), so a rerun after a crash at
    any step finishes it without installing from a changed previous/."""
    try:
        txn = load_txn(paths, project_name)
    except ReleaseStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if txn is None:
        print(f"ERROR: No install is open for '{project_name}'; nothing to abandon.",
              file=sys.stderr)
        return 1
    stale = stale_reason(paths, project_name, txn)
    if stale:
        print(f"ERROR: {start_refusal(paths, project_name, txn, stale)}.", file=sys.stderr)
        return 1
    refusal = _refusal(project_name, txn)
    if refusal:
        print(f"ERROR: {refusal}", file=sys.stderr)
        return 1
    try:
        if txn.phase in ("previous_kept", "installed"):
            txn = mark_abandon(paths, project_name, txn, ABANDONING)
        if txn.phase == ABANDONING:
            _put_code_back(project_name, paths, txn)
        if txn.phase != CODE_RESTORED:
            txn = mark_abandon(paths, project_name, txn, CODE_RESTORED)
        restore_superseded(paths, project_name, txn)
        # A killed deploy leaves its unpacked bundle behind (intake removes it
        # on its next run); everything is put back, so that goes too.
        releases = paths.project_releases(project_name)
        discard_dir(releases / "incoming")
        sweep_discarded(releases)
        release_config.remove_candidates(project_name)  # the images its users were decided from
    except (OSError, ValueError, DockerError) as e:
        print(f"ERROR: Abandoning the install of {txn.ref} failed: {e}. The install stays "
              f"open; run 'prod-deploy {project_name} --abandon' again once the cause is "
              f"fixed.", file=sys.stderr)
        log_error("deploy", f"Abandon of {txn.ref} failed: {e}", paths, project=project_name)
        return 1
    close_txn(paths, project_name, txn)
    git = (paths.project_dir(project_name) / "repo").is_dir()
    back = (f"{txn.replaced_ref}'s files are back" if txn.replaced_ref else
            f"repo/ stays checked out at {txn.ref}, which nothing runs" if git else
            "the first deploy's code was removed")
    print(f"{project_name}: abandoned the install of {txn.ref}; {back}. Containers and "
          f"data were not touched.")
    log_operation("deploy", f"Abandoned the install of {txn.ref}", paths,
                  project=project_name, detail={"ref": txn.ref, "replaced_ref": txn.replaced_ref})
    return 0


def run_abandon(project_name: str, paths: BoxPaths) -> int:
    try:
        with project_lock(project_name, paths):
            return abandon_locked(project_name, paths)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
