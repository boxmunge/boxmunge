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
        _save(registry, names, ())
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


def _save(registry: Path, names: set[str], unparsed: tuple[str, ...]) -> None:
    """Write the valid names, then every line that is not one, verbatim:
    rewriting the registry must never silently drop a line."""
    from boxmunge.fileutil import atomic_write_text
    content = "".join(f"{n}\n" for n in [*sorted(names), *unparsed])
    atomic_write_text(registry, content)


class ProjectRegistryError(StateError):
    """projects.txt has lines that are not valid project names, and the
    caller lists the registry, so they would otherwise go unseen."""


@dataclass(frozen=True)
class RegistryRead:
    """The registry's valid names; each line that is not one, verbatim; and
    one `<file>:<line>: <reason>` per such line."""

    names: frozenset[str]
    unparsed: tuple[str, ...]
    problems: tuple[str, ...]


def read_registry(paths: BoxPaths) -> RegistryRead:
    """Every valid registered name, with each invalid line and its problem.

    A bad line can never equal a valid name, so membership checks use
    `names` and carry on: one bad line must not stop every project. Fleet
    loops report `problems`; listings call load_registered_projects.
    """
    registry = _registry_path(paths)
    if not registry.exists():
        return RegistryRead(frozenset(_auto_migrate(paths, registry)), (), ())
    names: set[str] = set()
    unparsed: list[str] = []
    problems: list[str] = []
    for lineno, line in enumerate(registry.read_text().splitlines(), 1):
        name = line.strip()
        if not name:
            continue
        try:
            validate_project_name(name)
        except InvalidProjectName as e:
            unparsed.append(line)
            problems.append(f"{registry}:{lineno}: {e}")
            continue
        names.add(name)
    return RegistryRead(frozenset(names), tuple(unparsed), tuple(problems))


def registry_problem_message(problems: tuple[str, ...]) -> str:
    """What is wrong with the registry, and what to do about it."""
    return (
        "the project registry has lines that are not project names:\n  "
        + "\n  ".join(problems)
        + "\nIt holds one project name per line. Correct or delete each line "
          "listed (as root); every valid project keeps working meanwhile."
    )


def load_registered_projects(paths: BoxPaths) -> set[str]:
    """The registered project names, for a listing. Raises
    ProjectRegistryError, naming each bad line, rather than list a registry
    with entries left out. Membership checks use is_registered."""
    read = read_registry(paths)
    if read.problems:
        raise ProjectRegistryError(registry_problem_message(read.problems))
    return set(read.names)


def deployed_among(names: frozenset[str] | set[str], paths: BoxPaths) -> list[str]:
    """Those of `names` that have been deployed (have a manifest), sorted.

    A project registered but never deployed has no images to scan or watch,
    so fleet-wide checks skip it rather than report it failing every run.
    """
    return sorted(name for name in names
                  if (paths.project_dir(name) / "manifest.yml").exists())


def missing_among(names: frozenset[str] | set[str], paths: BoxPaths) -> list[str]:
    """Those of `names` with no project directory, sorted: registered by
    project-add and not yet deployed, or left behind by a removal that did
    not finish. Neither has anything to scan; `project-forget` drops the
    entry (forget_advice)."""
    return sorted(name for name in names if not paths.project_dir(name).exists())


def forget_advice(name: str) -> str:
    return (f"{name} is registered but has no project directory: deploy it, or drop "
            f"the entry as the supervisor with `sudo boxmunge-server project-forget {name}`")


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
    clashes = name_collisions(name, set(read_registry(paths).names))
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
        read = read_registry(paths)
        if name in read.names:
            return
        check_new_name(name, paths)
        _save(_registry_path(paths), {*read.names, name}, read.unparsed)


def remove_project(name: str, paths: BoxPaths) -> None:
    """Unregister a project name. Raises ValueError if not registered.

    The load -> mutate -> save sequence is wrapped in a registry-wide flock
    so concurrent add/remove calls cannot lose each other's writes.
    """
    with registry_lock(paths):
        read = read_registry(paths)
        if name not in read.names:
            raise ValueError(f"Project '{name}' is not registered on this server.")
        _save(_registry_path(paths), set(read.names - {name}), read.unparsed)


def is_registered(name: str, paths: BoxPaths) -> bool:
    """Check if a project name is registered."""
    return name in read_registry(paths).names
