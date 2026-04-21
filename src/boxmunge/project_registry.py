# SPDX-License-Identifier: Apache-2.0
"""Project registry — allowlist of known project names on this server.

Storage: /opt/boxmunge/config/projects.txt (one name per line).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.paths import validate_project_name

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _registry_path(paths: BoxPaths) -> Path:
    return paths.config / "projects.txt"


def _auto_migrate(paths: BoxPaths, registry: Path) -> set[str]:
    """One-time migration: populate registry from existing project dirs."""
    names: set[str] = set()
    if paths.projects.exists():
        for d in sorted(paths.projects.iterdir()):
            if d.is_dir() and (d / "manifest.yml").exists():
                names.add(d.name)
    if names:
        _save(registry, names)
    return names


def _save(registry: Path, names: set[str]) -> None:
    from boxmunge.fileutil import atomic_write_text
    content = "".join(f"{n}\n" for n in sorted(names))
    atomic_write_text(registry, content)


def load_registered_projects(paths: BoxPaths) -> set[str]:
    """Load the set of registered project names."""
    registry = _registry_path(paths)
    if not registry.exists():
        return _auto_migrate(paths, registry)
    return {
        line.strip()
        for line in registry.read_text().splitlines()
        if line.strip()
    }


def add_project(name: str, paths: BoxPaths) -> None:
    """Register a project name. Raises ValueError for invalid names."""
    validate_project_name(name)
    registry = _registry_path(paths)
    projects = load_registered_projects(paths)
    projects.add(name)
    _save(registry, projects)


def remove_project(name: str, paths: BoxPaths) -> None:
    """Unregister a project name. Raises ValueError if not registered."""
    projects = load_registered_projects(paths)
    if name not in projects:
        raise ValueError(f"Project '{name}' is not registered on this server.")
    projects.discard(name)
    _save(_registry_path(paths), projects)


def is_registered(name: str, paths: BoxPaths) -> bool:
    """Check if a project name is registered."""
    return name in load_registered_projects(paths)
