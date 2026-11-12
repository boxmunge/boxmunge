# SPDX-License-Identifier: Apache-2.0
"""The snapshots something is paired with, which retention never prunes.

A rollback restores the exact snapshot its target pairs with, and refuses
when it is gone from backups/. Per-kind retention counts only snapshots of
one kind, so a run of deploy attempts that each take a pre-deploy snapshot
but fail before the switch would otherwise evict the one the rollback
needs. The pairings: the kept previous release's data_snapshot
(previous.json), the deploy state's pre_deploy_snapshot (a git project's
rollback pairs with it), an open install's snapshot, and the snapshot
pause or data chown recorded for the next deploy (pending_snapshot).
"""
from __future__ import annotations

import sys
from pathlib import Path

from boxmunge.backup import BackupKind, prune_backups
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths
from boxmunge.pending_snapshot import pending
from boxmunge.release import ReleaseStateError, load_previous_release
from boxmunge.release_txn import load_txn
from boxmunge.state import StateError, read_state


def paired_snapshots(paths: BoxPaths, project: str) -> set[str]:
    """Names of the snapshots in the project's backups/ that a rollback or
    the next deploy is paired with. Raises ReleaseStateError or StateError
    when a record cannot be read: the caller must not prune then."""
    names: set[str] = set()
    previous = load_previous_release(paths, project)
    if previous is not None:
        names.add(previous.data_snapshot)
    names.add(str(read_state(paths.project_deploy_state(project)).get(
        "pre_deploy_snapshot") or ""))
    txn = load_txn(paths, project)
    if txn is not None:
        names.add(txn.snapshot)
    kept = pending(paths, project)
    if kept is not None:
        names.add(kept["name"])
    names.discard("")
    return names


def prune_unpaired(paths: BoxPaths, project: str, kind: BackupKind,
                   retention: int, *, published: str | None) -> list[Path]:
    """prune_backups, sparing every paired snapshot and ``published``, the
    snapshot the caller has just written (None: it wrote none). Retention
    orders by the timestamp in the name, so after the clock steps back the
    newest snapshot can sort as the oldest; it is never the one removed.
    When a pairing record cannot be read nothing is pruned (a paired
    snapshot cannot be told apart), and that is said: the record's own
    readers report it too."""
    try:
        keep = paired_snapshots(paths, project) | ({published} if published else set())
    except (ReleaseStateError, StateError) as e:
        message = (f"Not pruning old {kind.value} backups of {project}: which snapshot a "
                   f"rollback is paired with cannot be read ({e}). Fix or remove that "
                   f"record; the next backup prunes them")
        print(f"  WARN: {message}.", file=sys.stderr)
        log_warning("backup", message, paths, project=project)
        return []
    return prune_backups(paths.project_backups(project), project, kind, retention,
                         keep=keep)
