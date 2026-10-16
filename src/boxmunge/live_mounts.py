# SPDX-License-Identifier: Apache-2.0
"""Production's own copies of the release code its containers bind-mount.

`stage` installs the staged release into the project directory while
production keeps running from it. A bind mount of release code such as
``./appconfig:/etc/app:ro`` names a project-dir path, so production would
read the staged release's configuration at once (for a directory, which
installs refresh in place) or at its next restart (for a file). Production's
overlay therefore points each such mount at a copy of the entry in
``.releases/live-mounts/``, made from production's own release whenever its
overlay is generated. Compose merges a service's volumes by container
path, so the overlay's entry replaces the compose file's.

Box state (data directories, secrets.env, ...) is not copied: no install
changes it, and production must keep writing the real thing.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from boxmunge.bind_mounts import project_relative
from boxmunge.compose_mounts import is_bind_entry, volume_source
from boxmunge.fileutil import chown_tree_deploy, mkdir_p_deploy
from boxmunge.live_mirror import mirror_entries

LIVE_MOUNTS = ".releases/live-mounts"


class LiveMountError(ValueError):
    """Production's mounts of release code cannot be given their own copies."""


@dataclass(frozen=True)
class LiveMounts:
    """What production's overlay re-points, and the entries to copy for it."""
    entries: frozenset[str] = frozenset()
    # service -> volume entries replacing the compose file's (same target)
    volumes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # "configs" / "secrets" -> key -> {"file": copy}
    files: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)
    # paths (relative to the copies) that are mount sources themselves
    pinned: frozenset[str] = frozenset()


def _long_bind(entry: Any) -> dict[str, Any]:
    """A bind entry in long syntax (the resolved model is already long)."""
    if isinstance(entry, dict):
        return dict(entry)
    parts = entry.split(":")
    long: dict[str, Any] = {"type": "bind", "source": parts[0], "target": parts[1]}
    if len(parts) > 2 and "ro" in parts[2].split(","):
        long["read_only"] = True
    return long


def _code_path(source: str, release_root: Path, box_state: set[str]) -> str | None:
    """The source's path inside the release when it is release code.

    A mount of the whole project directory cannot be given a copy; it stays
    as it is, and `stage` refuses to run beside it (staging_isolation).
    """
    rel = project_relative(source, release_root)
    if rel is None or rel == ".":
        return None  # outside the project, or all of it
    top = rel.split(os.sep, 1)[0]
    return None if top in box_state else rel


def plan_live_mounts(user_compose: dict[str, Any], release_root: Path,
                     box_state: set[str]) -> LiveMounts:
    """Re-point production's mounts of release code at their live copies.

    ``user_compose`` is production's resolved compose model, resolved from
    ``release_root`` (its sources lie there); ``box_state`` names the
    project entries no install replaces.
    """
    entries: set[str] = set()
    pinned: set[str] = set()
    volumes: dict[str, list[dict[str, Any]]] = {}
    for svc_name, svc in (user_compose.get("services") or {}).items():
        for entry in (svc.get("volumes") or []) if isinstance(svc, dict) else []:
            if not is_bind_entry(entry):
                continue
            rel = _code_path(volume_source(entry), release_root, box_state)
            if rel is None:
                continue
            long = _long_bind(entry)
            if long.get("read_only") is not True:
                continue  # written to, so data: never copied (stage refuses to share it)
            volumes.setdefault(svc_name, []).append(
                {**long, "source": f"./{LIVE_MOUNTS}/{rel}"})
            entries.add(rel.split(os.sep, 1)[0])
            pinned.add(rel)
    files: dict[str, dict[str, dict[str, str]]] = {}
    for section in ("configs", "secrets"):
        for key, decl in (user_compose.get(section) or {}).items():
            path = decl.get("file") if isinstance(decl, dict) else None
            rel = _code_path(path, release_root, box_state) if isinstance(path, str) else None
            if rel is not None:
                files.setdefault(section, {})[key] = {"file": f"./{LIVE_MOUNTS}/{rel}"}
                entries.add(rel.split(os.sep, 1)[0])
                pinned.add(rel)
    return LiveMounts(frozenset(entries), volumes, files, frozenset(pinned))


def sync_live_mounts(project_dir: Path, release_root: Path, mounts: LiveMounts) -> None:
    """Make ``.releases/live-mounts/`` hold exactly the release's mounted
    entries, refreshed without a moment a reader misses them (live_mirror)."""
    root = project_dir / LIVE_MOUNTS
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise LiveMountError(f"{root} is not a directory")
    mkdir_p_deploy(root)
    mirror_entries(root, release_root, mounts.entries, mounts.pinned)
    chown_tree_deploy(root)
