# SPDX-License-Identifier: Apache-2.0
"""prod-deploy <project> --abandon: undo an install before its hook ran.

Allowed before hook_started: the replaced release's code goes back into the
project dir, the superseded previous release goes back to previous/, and
the transaction closes. Containers and data are untouched, and a staged
slot stays as it was. From hook_started on the hook may have changed data,
so rollback is the way back.
"""
from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from boxmunge.data_dirs import ReleaseStateError, log_kept, set_aside_announcer
from boxmunge.fileutil import LockError, discard_dir, fsync_dir, project_lock
from boxmunge.log import log_error, log_operation
from boxmunge.release import _remove, install_release, live_code_entries, mark_live, previous_dir
from boxmunge.release_keep import restore_superseded
from boxmunge.release_txn import InstallTxn, close_txn, load_txn, stale_reason, start_refusal

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _put_code_back(project_name: str, paths: BoxPaths, txn: InstallTxn) -> None:
    project_dir = paths.project_dir(project_name)
    if txn.replaced_ref is None:
        for entry in live_code_entries(project_dir):
            _remove(entry)
        live = paths.project_releases(project_name) / "live.json"
        if os.path.lexists(live):
            live.unlink()
            fsync_dir(live.parent)
        return
    kept = install_release(previous_dir(paths, project_name), project_dir,
                           set_aside_announcer(paths, project_name, "abandon"))
    log_kept(paths, project_name, kept, "abandon")
    mark_live(paths, project_name, txn.replaced_ref)


def abandon_locked(project_name: str, paths: BoxPaths) -> int:
    """The abandon core. Caller holds the project lock; never takes it."""
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
        print(f"ERROR: {start_refusal(project_name, txn, stale)}.", file=sys.stderr)
        return 1
    if txn.source == "rollback":
        print(f"ERROR: A rollback cannot be abandoned: rerun 'rollback {project_name}' "
              f"to finish it, or deploy a fix.", file=sys.stderr)
        return 1
    if txn.reached("hook_started"):
        print(f"ERROR: Cannot abandon the install of {txn.ref}: the pre-deploy hook may "
              f"have changed data; `rollback {project_name}` restores "
              f"`{txn.snapshot or 'no snapshot'}` with `{txn.replaced_ref}`, or deploy a fix.",
              file=sys.stderr)
        return 1
    try:
        if txn.reached("previous_kept"):
            _put_code_back(project_name, paths, txn)
        restore_superseded(paths, project_name, txn)
        # A killed deploy leaves its unpacked bundle behind (intake removes it
        # on its next run); everything is put back, so that goes too.
        discard_dir(paths.project_releases(project_name) / "incoming")
    except (OSError, ValueError) as e:
        print(f"ERROR: Abandoning the install of {txn.ref} failed: {e}. The install stays "
              f"open; run 'prod-deploy {project_name} --abandon' again once the cause is "
              f"fixed.", file=sys.stderr)
        log_error("deploy", f"Abandon of {txn.ref} failed: {e}", paths, project=project_name)
        return 1
    close_txn(paths, project_name, txn)
    back = txn.replaced_ref or "the empty project"
    print(f"{project_name}: abandoned the install of {txn.ref}; {back}'s files are back. "
          f"Containers and data were not touched.")
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
