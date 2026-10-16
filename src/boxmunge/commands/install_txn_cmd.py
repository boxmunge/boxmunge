# SPDX-License-Identifier: Apache-2.0
"""boxmunge-server install-txn <project> --drop: remove a stale install record.

A record is stale when the files no longer match it (an older boxmunge ran
after a platform rollback, or a hand edit): nothing resumes, abandons or
drops it automatically. After checking that production is what
.releases/live.json says, the operator drops it; an unreadable record is
dropped the same way. A record that still matches the files is refused:
it has a supported way out (rerun, --abandon, rollback or a fix).
"""
from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from boxmunge.data_dirs import ReleaseStateError
from boxmunge.fileutil import LockError, fsync_dir, project_lock
from boxmunge.log import log_operation
from boxmunge.release_keep import discard_superseded
from boxmunge.release_txn import close_txn, load_txn, options_text, stale_reason, txn_path

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def drop_locked(project_name: str, paths: BoxPaths) -> int:
    """The drop core. Caller holds the project lock; never takes it."""
    path = txn_path(paths, project_name)
    if not os.path.lexists(path):
        print(f"ERROR: No install record for '{project_name}' ({path}).", file=sys.stderr)
        return 1
    try:
        txn = load_txn(paths, project_name)
    except ReleaseStateError as e:
        discard_superseded(paths, project_name)
        path.unlink()
        fsync_dir(path.parent)
        print(f"{project_name}: dropped the unreadable install record ({e}).")
        log_operation("deploy", f"Dropped an unreadable install record: {e}", paths,
                      project=project_name)
        return 0
    assert txn is not None
    stale = stale_reason(paths, project_name, txn)
    if not stale:
        print(f"ERROR: The install of {txn.ref} (phase {txn.phase}) is not stale: the "
              f"files are as it left them. {options_text(project_name, txn)}.",
              file=sys.stderr)
        return 1
    close_txn(paths, project_name, txn)
    print(f"{project_name}: dropped the stale record of the install of {txn.ref} "
          f"({stale}).")
    log_operation("deploy", f"Dropped the stale install record of {txn.ref}: {stale}",
                  paths, project=project_name, detail={"ref": txn.ref, "phase": txn.phase})
    return 0


def run_drop(project_name: str, paths: BoxPaths) -> int:
    try:
        with project_lock(project_name, paths):
            return drop_locked(project_name, paths)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_install_txn(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name, usage_error
    from boxmunge.paths import BoxPaths
    parsed = parse_args("install-txn", args, flags={"--drop"},
                        min_positional=1, max_positional=1)
    project = require_project_name("install-txn", parsed.positional[0])
    if not parsed.has("--drop"):
        usage_error("install-txn", "--drop is required")
    from boxmunge.commands import install_txn_cmd
    sys.exit(install_txn_cmd.run_drop(project, BoxPaths()))
