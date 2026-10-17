# SPDX-License-Identifier: Apache-2.0
"""Remove staging's copies of data the live production release does not mount.

Staging keeps its own data between stages: an entry's ``<entry>-staging``
copy stays while production mounts the entry, so the next stage starts from
it. A copy of anything production no longer mounts (an entry a release
retired, or one only the unstaged release used) is disposable staging data
that would otherwise keep the entry in the data-dir record for good (see
data_dirs). `unstage`, and `promote` through it, removes those copies once
staging's containers are down, before the slot is dropped,
and logs each removal. An entry production itself mounts or records as data
is never a copy, whatever its name (``./cache-staging:/c``).

Staging once put a nested mount's copy beside the mounted path, inside
production's data directory (``data/db`` -> ``data/db-staging``), and kept
``<entry>-staging`` copies of mounted release code. The first cannot be told
from the app's own files and the second may hold what an operator put
there, so both are only reported, with the command to delete them.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from boxmunge.bind_mounts import project_relative
from boxmunge.bundle import BOX_OWNED_ENTRIES
from boxmunge.compose_mounts import is_bind_entry, volume_source
from boxmunge.data_dirs import holds_data
from boxmunge.data_helper import empty_dir
from boxmunge.docker import staging_compose_project
from boxmunge.log import log_operation, log_warning
from boxmunge.release import project_data_dirs

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

_SUFFIX = "-staging"


def _production_sources(project_dir: Path) -> list[str]:
    """Project-relative paths production's compose.yml mounts as files or
    directories: bind mounts and config/secret files."""
    path = project_dir / "compose.yml"
    doc: Any = yaml.safe_load(path.read_text()) if path.exists() else None
    if not isinstance(doc, dict):
        return []
    sources: list[str | None] = []
    for svc in (doc.get("services") or {}).values():
        for entry in (svc.get("volumes") or []) if isinstance(svc, dict) else []:
            if is_bind_entry(entry):
                sources.append(volume_source(entry))
    for section in ("configs", "secrets"):
        for decl in (doc.get(section) or {}).values():
            sources.append(decl.get("file") if isinstance(decl, dict) else None)
    rels = (project_relative(s, project_dir) for s in sources if isinstance(s, str))
    return sorted({r for r in rels if r and r != "."})


def retired_staging_copies(project_dir: Path) -> list[Path]:
    """``-staging`` copies of data entries the live release does not mount.

    While a release is staged, the entries it mounts read-write
    (DataDirs.staged_rw) are data only staging used, never recorded in
    production's tree, so their copies are staging's too. A copy of an entry
    it mounts read-only is not: staging reads that from the staged release,
    so such a copy is 0.10.1's code copy or the operator's
    (old_layout_copies reports it)."""
    if not project_dir.is_dir():
        return []
    dirs = project_data_dirs(project_dir)
    data = set(dirs.recorded) | set(BOX_OWNED_ENTRIES) | set(dirs.staged_rw)
    mounted = {rel.split(os.sep, 1)[0] for rel in _production_sources(project_dir)}
    return sorted(
        e for e in project_dir.iterdir()
        if e.name.endswith(_SUFFIX) and e.name[:-len(_SUFFIX)] in data
        and e.name[:-len(_SUFFIX)] not in mounted
        and e.name not in mounted and e.name not in dirs.recorded
    )


def old_layout_copies(project_dir: Path) -> list[Path]:
    """Copies the earlier staging layout made: beside a nested data mount
    (``data/db-staging``), and of release code (``appconfig-staging``),
    which staging now reads from the staged release itself. Code is what
    production mounts, or what the staged release mounts only read-only."""
    if not project_dir.is_dir():
        return []
    dirs = project_data_dirs(project_dir)
    data = set(dirs.recorded) | set(BOX_OWNED_ENTRIES)
    sources = _production_sources(project_dir)
    mounted = {rel.split(os.sep, 1)[0] for rel in sources}
    found = set()
    code_tops = set(dirs.staged - dirs.staged_rw)
    for rel in sources:
        top = rel.split(os.sep, 1)[0]
        nested = project_dir / f"{rel}{_SUFFIX}"
        if os.sep in rel and top in data and os.path.lexists(nested):
            found.add(nested)
        code_tops.add(top)
    for top in code_tops - data:
        code = project_dir / f"{top}{_SUFFIX}"
        if code.name not in mounted and code.name not in dirs.recorded \
                and os.path.lexists(code):
            found.add(code)
    return sorted(found)


def _remove(project_name: str, path: Path) -> None:
    """Remove a staging copy. Its contents were written by containers, often
    as other users, so the data helper empties a directory first."""
    if path.is_dir() and not path.is_symlink():
        try:
            occupied = holds_data(path)
        except PermissionError:
            occupied = True  # a copy of production data, owned by a container user
        if occupied:
            empty_dir(f"{staging_compose_project(project_name)}-cleanup", path)
        path.rmdir()
    elif os.path.lexists(path):
        path.unlink()


def remove_retired_staging_data(paths: BoxPaths, project_name: str) -> list[Path]:
    """Remove (and log) every retired staging copy; returns those removed.

    Raises OSError or DockerError for the copy that could not be removed;
    the ones before it are gone and logged. Old-layout copies are reported.
    """
    project_dir = paths.project_dir(project_name)
    removed: list[Path] = []
    for path in retired_staging_copies(project_dir):
        _remove(project_name, path)
        print(f"  Removed staging's {path.name} (production does not mount "
              f"{path.name[:-len(_SUFFIX)]}).")
        log_operation("unstage", f"Removed staging data {path.name}: production's "
                      f"release does not mount {path.name[:-len(_SUFFIX)]}",
                      paths, project=project_name, detail={"removed": str(path)})
        removed.append(path)
    for path in old_layout_copies(project_dir):
        print(f"  NOTE: {path} looks like a staging copy from an earlier boxmunge, "
              f"which staging no longer uses. It is left alone; if nothing needs "
              f"it, delete it with: rm -rf {path}")
        log_warning("unstage", f"Possible old staging copy left in production's data: "
                    f"{path}", paths, project=project_name, detail={"path": str(path)})
    return removed
