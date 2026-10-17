# SPDX-License-Identifier: Apache-2.0
"""Build the slot for a stage and retire the previous one (spec Flows,
Stage steps 3-4).

The candidate is moved (bundle) into ``staged.building/release``; staging's
files are generated beside it, the read-only bind sources it lacks are
created as the deploy user (so dockerd never makes root-owned directories
inside the slot), the meta is written as ``starting``, and the whole tree
is synced before the swap.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from boxmunge import bind_sources
from boxmunge.docker import compose_down
from boxmunge.fileutil import sync_tree
from boxmunge.production_stopped import start_again
from boxmunge.staged_release import (
    SlotError, StagedRelease, building_dir, has_slot, load_slot, refuse_planted, release_dir,
    staging_target, update_meta, write_meta,
)
from boxmunge.staging_isolation import resolving, staging_model
from boxmunge.staging_prepare import write_staging_files

if TYPE_CHECKING:
    from pathlib import Path

    from boxmunge.paths import BoxPaths


def create_missing_sources(paths: BoxPaths, project: str, slot: Path) -> None:
    """Create the bind sources staging's model names inside the slot's
    release that the release lacks (I2). Separation already refused any
    read-write bind into it, so these are all read-only mounts."""
    with resolving():
        model = staging_model(staging_target(paths, project, slot))
    project_dir = paths.project_dir(project)
    prefix = os.path.relpath(release_dir(slot), project_dir) + os.sep
    for rel in sorted(bind_sources.model_sources(model, project_dir)):
        if rel.startswith(prefix):
            bind_sources.source_kind(release_dir(slot), rel[len(prefix):], create=True)


def build_slot(paths: BoxPaths, project: str, manifest: dict[str, Any],
               meta: StagedRelease) -> None:
    """Complete ``staged.building`` around the release already moved into it."""
    building = building_dir(paths, project)
    write_staging_files(paths, project, manifest, release_dir(building), building)
    create_missing_sources(paths, project, building)
    write_meta(building, meta)
    sync_tree(building)


def retire_previous_staging(paths: BoxPaths, project: str) -> None:
    """A re-stage: production first runs again if a copy stopped it, the old
    slot is marked `starting` (so nothing can promote it) and its staging
    containers are taken down. Raises DockerError or OSError (a planted
    link in place of the slot is refused before any compose call)."""
    if not has_slot(paths, project):
        return
    refuse_planted(paths, project)
    try:
        old = load_slot(paths, project)
    except SlotError as e:
        print(f"  WARN: the previous stage's record is unreadable ({e}); taking its "
              f"staging down with the slot's compose files. If a data copy had "
              f"stopped production, start it with `boxmunge recover {project}`.")
        old = None
    if old is not None:
        start_again(paths, project, component="stage", alert=True)
        update_meta(paths, project, load_slot(paths, project), state="starting")
    print("  Stopping the previous staging...")
    target = staging_target(paths, project)
    compose_down(target.cwd, **target.kwargs())
