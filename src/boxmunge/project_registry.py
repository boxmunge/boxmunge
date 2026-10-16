# SPDX-License-Identifier: Apache-2.0
"""Project registry — allowlist of known project names on this server.

Storage: /opt/boxmunge/state/projects.txt (one name per line, deploy-writable).
Being deploy-writable, a line can hold anything; every line is validated as
a project name on read, never trusted.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.fileutil import registry_lock
from boxmunge.paths import InvalidProjectName, validate_project_name
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _registry_path(paths: BoxPaths) -> Path:
    return paths.state / "projects.txt"


def _auto_migrate(paths: BoxPaths, registry: Path) -> set[str]:
    """One-time migration: populate registry from existing project dirs."""
    names: set[str] = set()
    if paths.projects.exists():
        for d in sorted(paths.projects.iterdir()):
            if d.is_dir() and (d / "manifest.yml").exists():
                names.add(d.name)
    if names:
        _save(registry, names)
        # Already on disk, so registered anyway; add_project refuses new ones.
        pairs = overlapping_pairs(names)
        if pairs:
            from boxmunge.log import log_warning
            log_warning(
                "project-registry",
                "overlapping project names can share container names: "
                + ", ".join(f"{a} / {b}" for a, b in pairs),
                paths,
            )
    return names


def _save(registry: Path, names: set[str]) -> None:
    from boxmunge.fileutil import atomic_write_text
    content = "".join(f"{n}\n" for n in sorted(names))
    atomic_write_text(registry, content)


class RegistryError(StateError, ValueError):
    """projects.txt has lines that are not valid project names. A ValueError
    too, like the other refusals add_project and remove_project raise."""


@dataclass(frozen=True)
class RegistryRead:
    """The registry's valid names, and one `<file>:<line>: <reason>` per
    line that is not one."""

    names: frozenset[str]
    problems: tuple[str, ...]


def read_registry(paths: BoxPaths) -> RegistryRead:
    """Every valid registered name, with a problem for each invalid line.

    For fleet loops, which must report a damaged line and still reach every
    valid project. Everything else calls load_registered_projects, which
    refuses a damaged registry.
    """
    registry = _registry_path(paths)
    if not registry.exists():
        return RegistryRead(frozenset(_auto_migrate(paths, registry)), ())
    names: set[str] = set()
    problems: list[str] = []
    for lineno, line in enumerate(registry.read_text().splitlines(), 1):
        name = line.strip()
        if not name:
            continue
        try:
            validate_project_name(name)
        except InvalidProjectName as e:
            problems.append(f"{registry}:{lineno}: {e}")
            continue
        names.add(name)
    return RegistryRead(frozenset(names), tuple(problems))


def registry_problem_message(problems: tuple[str, ...]) -> str:
    """What is wrong with the registry, and what to do about it."""
    return (
        "the project registry has lines that are not project names:\n  "
        + "\n  ".join(problems)
        + "\nIt holds one project name per line. Correct or delete each line "
          "listed (as root), then re-run."
    )


def load_registered_projects(paths: BoxPaths) -> set[str]:
    """The set of registered project names. Raises RegistryError, naming
    each bad line, if the registry holds anything that is not one."""
    read = read_registry(paths)
    if read.problems:
        raise RegistryError(registry_problem_message(read.problems))
    return set(read.names)


def deployed_among(names: frozenset[str] | set[str], paths: BoxPaths) -> list[str]:
    """Those of `names` that have been deployed (have a manifest), sorted.

    A project registered but never deployed has no images to scan or watch,
    so fleet-wide checks skip it rather than report it failing every run.
    """
    return sorted(name for name in names
                  if (paths.project_dir(name) / "manifest.yml").exists())


def load_deployed_projects(paths: BoxPaths) -> list[str]:
    """Registered projects that have been deployed (deployed_among), sorted.
    Raises RegistryError as load_registered_projects does."""
    return deployed_among(load_registered_projects(paths), paths)


def name_collisions(name: str, others: set[str]) -> list[str]:
    """Other project names that `name` extends with `-<anything>`, or that
    extend it. Compose names containers `<project>-<service>-1`, so project
    `foo` with service `bar-web` and project `foo-bar` with service `web`
    would both own `foo-bar-web-1`."""
    return sorted(
        other for other in others
        if other != name and (other.startswith(name + "-") or name.startswith(other + "-"))
    )


def overlapping_pairs(names: set[str]) -> list[tuple[str, str]]:
    """Every registered pair whose names collide (name_collisions)."""
    return sorted({tuple(sorted((n, c))) for n in names for c in name_collisions(n, names)})


def check_new_name(name: str, paths: BoxPaths) -> None:
    """Raise ValueError if a new project `name` collides with a registered
    one (name_collisions)."""
    clashes = name_collisions(name, load_registered_projects(paths))
    if clashes:
        raise ValueError(
            f"Project name '{name}' overlaps registered project "
            f"{', '.join(repr(c) for c in clashes)}: one name is the other "
            f"plus '-<something>'. Compose names containers "
            f"'<project>-<service>-1', so a service in one project could "
            f"take the other's container names. Choose a name that neither "
            f"starts with '<existing>-' nor is the start of one."
        )


def add_project(name: str, paths: BoxPaths) -> None:
    """Register a project name. Raises ValueError for invalid names, and
    for a new name that collides with a registered one (check_new_name).
    Pairs registered before that rule keep working; doctor warns about them.

    The load -> mutate -> save sequence is wrapped in a registry-wide flock
    so concurrent add/remove calls cannot lose each other's writes.
    """
    validate_project_name(name)
    with registry_lock(paths):
        registry = _registry_path(paths)
        projects = load_registered_projects(paths)
        if name in projects:
            return
        check_new_name(name, paths)
        projects.add(name)
        _save(registry, projects)


def remove_project(name: str, paths: BoxPaths) -> None:
    """Unregister a project name. Raises ValueError if not registered.

    The load -> mutate -> save sequence is wrapped in a registry-wide flock
    so concurrent add/remove calls cannot lose each other's writes.
    """
    with registry_lock(paths):
        projects = load_registered_projects(paths)
        if name not in projects:
            raise ValueError(f"Project '{name}' is not registered on this server.")
        projects.discard(name)
        _save(_registry_path(paths), projects)


def is_registered(name: str, paths: BoxPaths) -> bool:
    """Check if a project name is registered."""
    return name in load_registered_projects(paths)
