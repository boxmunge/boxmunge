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

from boxmunge.compose_mounts import project_rel, service_bind_entries
from boxmunge.fs_nofollow import read_text_nofollow


class BindMountError(ValueError):
    """A compose file cannot be read well enough to classify its bind mounts."""


def _top_dir(source: str, project_dir: Path) -> str | None:
    """The project's top-level entry a bind source points into, if any."""
    rel = project_rel(source, project_dir)
    if rel is None or rel == ".":
        return None
    return rel.split(os.sep, 1)[0]


def _services(compose_path: Path, nofollow: bool = False) -> dict[str, Any]:
    """The file's services, each one's volumes a list of strings and mappings."""
    try:
        text = read_text_nofollow(compose_path) if nofollow else compose_path.read_text()
        doc = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise BindMountError(f"cannot read {compose_path}: {e}") from e
    if not isinstance(doc, dict):
        raise BindMountError(f"{compose_path} is not a YAML mapping")
    services = doc.get("services") or {}
    if not isinstance(services, dict):
        raise BindMountError(f"{compose_path}: 'services' is not a mapping")
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
    return services


def bind_mounted_dirs(compose_path: Path, project_dir: Path, *,
                      nofollow: bool = False) -> dict[str, bool]:
    """Map each bind-mounted top-level project dir to True if any mount of it
    is read-write. A missing compose file mounts nothing. ``nofollow``
    reads the file without following a link or blocking on a FIFO
    (fs_nofollow.read_text_nofollow), refusing anything but a regular file.

    Raises BindMountError if the file exists but cannot be classified: a
    guess here decides whether live data is deleted.
    """
    if not (os.path.lexists(compose_path) if nofollow else compose_path.exists()):
        return {}
    dirs: dict[str, bool] = {}
    for name, svc in _services(compose_path, nofollow).items():
        for bind in service_bind_entries(name, svc, project_dir):
            top = _top_dir(bind.source, project_dir)
            if top is not None:
                dirs[top] = dirs.get(top, False) or bind.read_write
    return dirs
