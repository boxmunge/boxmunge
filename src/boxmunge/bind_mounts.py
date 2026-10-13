# SPDX-License-Identifier: Apache-2.0
"""Which top-level project directories a compose file bind-mounts.

Installing a release must know which project directories hold data the
containers write, so it never deletes or overwrites them. Both compose
volume syntaxes count, and so do absolute sources that point inside the
project directory.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from boxmunge.compose_validate import _bind_source


class BindMountError(ValueError):
    """A compose file cannot be read well enough to classify its bind mounts."""


def _is_read_only(entry: Any) -> bool:
    if isinstance(entry, dict):
        return entry.get("read_only") is True
    parts = entry.split(":")
    return len(parts) >= 3 and "ro" in parts[2].split(",")


def _top_dir(source: str, project_dir: Path) -> str | None:
    """The project's top-level entry a bind source points into, if any."""
    if source.startswith("~"):
        return None
    # Compare both spelled and resolved paths: /opt may be a symlink.
    for base in {os.path.normpath(project_dir), os.path.realpath(project_dir)}:
        candidates = {os.path.normpath(os.path.join(base, source))}
        if os.path.isabs(source):
            candidates.add(os.path.realpath(source))
        for path in candidates:
            rel = os.path.relpath(path, base)
            if rel not in (".", "..") and not rel.startswith(".." + os.sep):
                return rel.split(os.sep, 1)[0]
    return None


def _entries(compose_path: Path) -> list[Any]:
    try:
        doc = yaml.safe_load(compose_path.read_text())
    except (OSError, yaml.YAMLError) as e:
        raise BindMountError(f"cannot read {compose_path}: {e}") from e
    if not isinstance(doc, dict):
        raise BindMountError(f"{compose_path} is not a YAML mapping")
    services = doc.get("services") or {}
    if not isinstance(services, dict):
        raise BindMountError(f"{compose_path}: 'services' is not a mapping")
    entries: list[Any] = []
    for name, svc in services.items():
        if not isinstance(svc, dict):
            raise BindMountError(f"{compose_path}: service '{name}' is not a mapping")
        volumes = svc.get("volumes") or []
        if not isinstance(volumes, list):
            raise BindMountError(f"{compose_path}: '{name}.volumes' is not a list")
        for entry in volumes:
            if not isinstance(entry, (str, dict)):
                raise BindMountError(
                    f"{compose_path}: '{name}.volumes' has an unexpected entry {entry!r}")
            entries.append(entry)
    return entries


def bind_mounted_dirs(compose_path: Path, project_dir: Path) -> dict[str, bool]:
    """Map each bind-mounted top-level project dir to True if any mount of it
    is read-write. A missing compose file mounts nothing.

    Raises BindMountError if the file exists but cannot be classified: a
    guess here decides whether live data is deleted.
    """
    if not compose_path.exists():
        return {}
    dirs: dict[str, bool] = {}
    for entry in _entries(compose_path):
        source = _bind_source(entry)
        if source is None:
            continue
        if isinstance(entry, str) and not source.startswith((".", "/", "~")):
            continue  # short syntax "name:/dst" is a named volume
        top = _top_dir(source, project_dir)
        if top is None:
            continue
        dirs[top] = dirs.get(top, False) or not _is_read_only(entry)
    return dirs
