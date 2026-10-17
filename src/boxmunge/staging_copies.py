# SPDX-License-Identifier: Apache-2.0
"""Which top-level ``<entry>-staging`` entries are staging's own.

Staging keeps its copy of a project entry as ``<entry>-staging`` beside it
(staging_compose rewrites ``./foo`` to it). A name alone proves nothing: a
release installed before bundles were refused the suffix (bundle.
check_bundle_contents) may ship ``foo-staging/`` as code, and an operator
may make one. An entry is staging's only when

- its entry is production's data: production's own compose.yml mounts it,
  it is recorded as data, or it is box-owned state (``data/``); or
- the slot records that staging created it (StagedRelease.made): before
  staging first mounts a copy that does not exist yet, the name is claimed
  in the slot, durably, so a crash never leaves a copy staging made but
  does not know (a claimed name that was never made is harmless). A
  re-stage carries its slot's claims over.

Production's own entry is never staging's, whatever its name (a recorded
``cache-staging`` data dir, a ``cache-staging`` compose.yml mounts). The
classification is production's own, without the slot's staged view, which
treats the copy of every staged mount as box state. Anything else is not
staging's: staging never mounts it (staging_isolation.separation_problems
refuses the stage) and unstage never removes it (staging_cleanup).
"""
from __future__ import annotations

import os
from collections.abc import Collection
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.bundle import BOX_OWNED_ENTRIES, STAGING_SUFFIX
from boxmunge.data_dirs import DataDirs
from boxmunge.release import project_data_dirs
from boxmunge.staged_release import SlotError, load_slot, slot_dir, update_meta

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def production_view(project_dir: Path) -> DataDirs:
    """Production's classification, without the slot's staged view.
    Raises ReleaseStateError for an unreadable compose.yml or record."""
    return project_data_dirs(project_dir, with_staged=False)


def is_staging_copy(name: str, dirs: DataDirs, made: Collection[str]) -> bool:
    """Whether ``name`` is staging's (see the module docstring)."""
    if not name.endswith(STAGING_SUFFIX) or name in dirs.recorded | dirs.mounted:
        return False
    base = name[:-len(STAGING_SUFFIX)]
    return (name in made or base in dirs.mounted or base in dirs.recorded
            or base in BOX_OWNED_ENTRIES)


def foreign_copies(project_dir: Path, made: Collection[str]) -> set[str]:
    """The ``-staging`` names in the project dir, and those production
    itself mounts or records, that are not staging's."""
    dirs = production_view(project_dir)
    names = {n for n in dirs.recorded | dirs.mounted if n.endswith(STAGING_SUFFIX)}
    if project_dir.is_dir():
        names |= {e.name for e in project_dir.iterdir() if e.name.endswith(STAGING_SUFFIX)}
    return {n for n in names if not is_staging_copy(n, dirs, made)}


def slot_made(paths: BoxPaths, project: str) -> tuple[str, ...]:
    """The copies the current slot records that staging created; none
    without a slot, or with one whose record cannot be read (its copies
    are then not staging's: refused and kept, never mounted or removed)."""
    try:
        meta = load_slot(paths, project)
    except SlotError:
        return ()
    return meta.made if meta is not None else ()


def claim_new_copies(paths: BoxPaths, project: str, tops: set[str]) -> None:
    """Record in the slot, before staging mounts them, the copies among
    ``tops`` (staging's top-level ``-staging`` sources) that do not exist
    yet: staging, or Docker on its behalf, creates them."""
    project_dir = paths.project_dir(project)
    meta = load_slot(paths, project)
    if meta is None:
        raise SlotError(f"{slot_dir(paths, project)} is gone; stage again")
    new = {t for t in tops if not os.path.lexists(project_dir / t)} - set(meta.made)
    if new:
        update_meta(paths, project, meta, made=tuple(sorted({*meta.made, *new})))
