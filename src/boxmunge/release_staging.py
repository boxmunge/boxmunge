# SPDX-License-Identifier: Apache-2.0
"""The production release kept aside while another release is staged.

`stage` installs the staged release into the shared project dir (staging
containers run from it). The production release it displaced is kept in
``.releases/prestage/`` (``release/`` plus ``meta.json``) until `promote`
(it becomes the previous release) or `unstage` (it is put back). The
directory is assembled beside its final name and renamed into place
complete, so a kept release always has its metadata.

Built on boxmunge.release, whose tree-copy and record helpers it shares.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.data_dirs import (
    ReleaseStateError, log_kept, naming_set_aside, set_aside_announcer,
)
from boxmunge.fileutil import atomic_write_text
from boxmunge.release import (
    _PRESTAGE, _copy_entry, _ensure_record, _live_meta, _previous_meta, _read_meta,
    _remove, install_release, live_code_entries, live_ref, mark_live, previous_dir,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _prestage(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / _PRESTAGE


def prestage_tree(paths: BoxPaths, project_name: str) -> Path:
    """The kept production release's code."""
    return _prestage(paths, project_name) / "release"


def has_prestage(paths: BoxPaths, project_name: str) -> bool:
    return _prestage(paths, project_name).is_dir()


def keep_prestage_release(paths: BoxPaths, project_name: str,
                          release_tree: Path) -> None:
    """Keep the production release before `stage` replaces it.

    A no-op when one is already kept (a re-stage keeps the original
    production release). For a project that was never deployed the kept
    release is empty, so `unstage` returns it to its pre-stage state.
    """
    if has_prestage(paths, project_name):
        return
    project_dir = paths.project_dir(project_name)
    deployed = (project_dir / "manifest.yml").exists()
    building = paths.project_releases(project_name) / "prestage.building"
    _remove(building)
    (building / "release").mkdir(parents=True)
    if deployed:
        for entry in live_code_entries(project_dir, release_tree):
            _copy_entry(entry, building / "release" / entry.name)
    copies = _ensure_record(project_dir, release_tree,
                            set_aside_announcer(paths, project_name, "stage"))
    with naming_set_aside(copies):
        meta = {"ref": live_ref(paths, project_name) if deployed else None}
        atomic_write_text(building / "meta.json", json.dumps(meta) + "\n", mode=0o644)
        building.rename(_prestage(paths, project_name))


def prestage_ref(paths: BoxPaths, project_name: str) -> str | None:
    """Ref of the kept production release; None if it was never deployed."""
    meta_path = _prestage(paths, project_name) / "meta.json"
    ref = _read_meta(meta_path).get("ref")
    if ref is not None and not isinstance(ref, str):
        raise ReleaseStateError(f"{meta_path} has an invalid ref")
    return ref


def mark_prestage_replaced(paths: BoxPaths, project_name: str,
                           data_snapshot: str | None) -> None:
    """Promote is starting the staged release in production: from now on the
    kept release is no longer what production runs, and must never be put
    back under the new containers.

    ``data_snapshot`` is the snapshot taken before the promotion. It is
    recorded here because it is the one that pairs with the kept release:
    a rerun of an interrupted promote must not take another one, of data
    the staged release may already have changed.
    """
    meta_path = _prestage(paths, project_name) / "meta.json"
    meta = {**_read_meta(meta_path), "production_replaced": True,
            "data_snapshot": data_snapshot or ""}
    atomic_write_text(meta_path, json.dumps(meta) + "\n", mode=0o644)


def prestage_replaced(paths: BoxPaths, project_name: str) -> bool:
    """True if a promote started the staged release over the kept one."""
    meta = _read_meta(_prestage(paths, project_name) / "meta.json")
    return meta.get("production_replaced") is True


def prestage_snapshot(paths: BoxPaths, project_name: str) -> str | None:
    """The pre-promotion snapshot mark_prestage_replaced recorded (None for
    none). Only meaningful once prestage_replaced is True."""
    meta_path = _prestage(paths, project_name) / "meta.json"
    snapshot = _read_meta(meta_path).get("data_snapshot")
    if not isinstance(snapshot, str):
        raise ReleaseStateError(f"{meta_path} has no pre-promotion data_snapshot")
    return snapshot or None


def discard_prestage(paths: BoxPaths, project_name: str) -> None:
    _ensure_record(paths.project_dir(project_name))
    _remove(_prestage(paths, project_name))


def prestage_to_previous(paths: BoxPaths, project_name: str,
                         data_snapshot: str | None, replaced_by: str) -> None:
    """On promote: the kept production release becomes the previous release."""
    _ensure_record(paths.project_dir(project_name))
    ref = prestage_ref(paths, project_name)
    if ref is None:
        # First promote of a never-deployed project: nothing to roll back to.
        discard_prestage(paths, project_name)
        return
    _remove(_previous_meta(paths, project_name))
    target = previous_dir(paths, project_name)
    _remove(target)
    prestage_tree(paths, project_name).rename(target)
    meta = {
        "ref": ref,
        "data_snapshot": data_snapshot or "",
        "replaced_at": datetime.now(timezone.utc).isoformat(),
        "replaced_by": replaced_by,
    }
    atomic_write_text(_previous_meta(paths, project_name),
                      json.dumps(meta, indent=2) + "\n", mode=0o644)
    discard_prestage(paths, project_name)


def production_release_root(paths: BoxPaths, project_name: str) -> Path:
    """Where production's release code is: the kept release during a stage."""
    if has_prestage(paths, project_name):
        return prestage_tree(paths, project_name)
    return paths.project_dir(project_name)


def restore_prestage(paths: BoxPaths, project_name: str) -> None:
    """Put the kept production release back (unstage, or a failed stage)."""
    ref = prestage_ref(paths, project_name)
    kept = install_release(prestage_tree(paths, project_name),
                           paths.project_dir(project_name),
                           set_aside_announcer(paths, project_name, "unstage"))
    log_kept(paths, project_name, kept, "unstage")
    if ref is None:
        _remove(_live_meta(paths, project_name))
    else:
        mark_live(paths, project_name, ref)
    discard_prestage(paths, project_name)
