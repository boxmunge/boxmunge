# SPDX-License-Identifier: Apache-2.0
"""The previous release kept by an install transaction (release_txn).

The keep moves today's rollback target aside to ``previous.superseded``
instead of deleting it, so an abandoned install can put everything back;
closing the transaction discards it. previous.json written by the keep is
deterministic (its replaced_at is the transaction's started_at), so a
reader can tell the transaction's own writes from anyone else's.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.data_dirs import naming_set_aside, set_aside_announcer
from boxmunge.fileutil import (
    atomic_write_text, discard_dir, durable_rename, durable_rename_dir, fsync_dir, sync_tree,
)
from boxmunge.release import _copy_entry, _ensure_record, live_code_entries, previous_meta_text

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths
    from boxmunge.release_txn import InstallTxn

SUPERSEDED = "previous.superseded"


def superseded_paths(paths: BoxPaths, project: str) -> tuple[Path, Path]:
    releases = paths.project_releases(project)
    return releases / SUPERSEDED, releases / f"{SUPERSEDED}.json"


def kept_previous_text(txn: InstallTxn) -> str:
    return previous_meta_text(txn.replaced_ref or "", txn.snapshot, txn.started_at, txn.ref)


def _names(paths: BoxPaths, project: str) -> tuple[Path, Path, Path, Path, Path]:
    releases = paths.project_releases(project)
    sup_dir, sup_meta = superseded_paths(paths, project)
    return (releases / "previous.building", releases / "previous",
            releases / "previous.json", sup_dir, sup_meta)


def keep_previous_release_txn(paths: BoxPaths, project: str, txn: InstallTxn,
                              release_tree: Path | None) -> None:
    """Copy the live release code to ``previous/``, moving today's previous
    release aside to ``previous.superseded`` (see the module docstring).

    The copy is synced before it is renamed into place. Raises OSError or
    ReleaseStateError; ``restore_superseded`` then puts everything back.
    """
    building, prev, prev_meta, sup_dir, sup_meta = _names(paths, project)
    project_dir = paths.project_dir(project)
    discard_dir(building)
    building.mkdir(parents=True)
    for entry in live_code_entries(project_dir, release_tree):
        _copy_entry(entry, building / entry.name)
    copies = _ensure_record(project_dir, release_tree,
                            set_aside_announcer(paths, project, "deploy"))
    with naming_set_aside(copies):
        sync_tree(building)
        if os.path.lexists(prev):
            durable_rename_dir(prev, sup_dir)
        if os.path.lexists(prev_meta):
            durable_rename(prev_meta, sup_meta)
        durable_rename_dir(building, prev)
        atomic_write_text(prev_meta, kept_previous_text(txn), mode=0o644)


def restore_superseded(paths: BoxPaths, project: str, txn: InstallTxn) -> None:
    """Undo a keep, whole or partial: the superseded previous release goes
    back to ``previous/``. Safe to run again."""
    building, prev, prev_meta, sup_dir, sup_meta = _names(paths, project)
    discard_dir(building)
    if os.path.lexists(sup_dir):
        discard_dir(prev)
        durable_rename_dir(sup_dir, prev)
    elif txn.previous_before is None:
        discard_dir(prev)  # there was no previous release: only the keep made this one
    if os.path.lexists(sup_meta):
        if os.path.lexists(prev_meta):
            prev_meta.unlink()
        durable_rename(sup_meta, prev_meta)
    elif txn.previous_before is None and os.path.lexists(prev_meta):
        prev_meta.unlink()
        fsync_dir(prev_meta.parent)


def discard_superseded(paths: BoxPaths, project: str) -> None:
    sup_dir, sup_meta = superseded_paths(paths, project)
    discard_dir(sup_dir)
    if os.path.lexists(sup_meta):
        sup_meta.unlink()
        fsync_dir(sup_meta.parent)
