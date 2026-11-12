# SPDX-License-Identifier: Apache-2.0
"""What a start check hands to the start it allows.

compose_guard.check_start validates a project's files, resolves the model
`docker compose up` will run and checks every bind source of it. A
CheckedStart is that result: the model, and what the check read to reach
it. The start takes one, so it works from the model the check resolved
instead of resolving the same files again, and a caller has no way to say
"already checked": only a check makes one (`issue` is compose_guard's
alone; tests/test_checked_start.py holds every other module to that).

resume and restore check before they touch a container and start later,
restore twice. Each start is given the operation's first CheckedStart. It
stands while nothing the check read has changed (`unchanged`): the same
bytes, read from the same places, validate and resolve to the same model,
so neither runs again. Any difference, and the start runs the whole check
as if it had none.
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from boxmunge import bind_sources
from boxmunge.compose_mounts import path_within

_BY_A_CHECK = object()


@dataclass(frozen=True)
class CheckedStart:
    project_name: str
    staging: bool
    compose_files: tuple[str, ...]
    # The merged model of every profile, as `docker compose config` gave it.
    model: dict[str, Any] = field(repr=False)
    sources: frozenset[str]                  # project-relative bind sources
    kinds: Mapping[str, str] = field(repr=False)          # ... and their kinds
    read_files: tuple[Path, ...] = field(repr=False)
    # Those of them the reference walk found: what the mounts the project's
    # containers already hold are held to (none for staging, which asks none).
    walked: tuple[Path, ...] = field(repr=False)
    control: Mapping[str, str | None] = field(repr=False)  # sha256 of each file read
    # Where each file read lies once every link on its path is resolved.
    places: Mapping[str, str] = field(repr=False)
    control_root: Path | None                # staging: the slot's release
    # Not kept: dataclasses.replace cannot carry it over to a changed copy.
    by: InitVar[object]

    def __post_init__(self, by: object) -> None:
        if by is not _BY_A_CHECK:
            raise TypeError("a CheckedStart is the result of compose_guard.check_start; "
                            "call that, do not build one")


def issue(project_name: str, compose_files: list[str], model: dict[str, Any],
          sources: set[str], kinds: dict[str, str], read_files: list[Path],
          control: dict[str, str | None], *, walked: Iterable[Path],
          control_root: Path | None = None) -> CheckedStart:
    """For compose_guard's checks alone, once every check has passed."""
    return CheckedStart(
        project_name=project_name, staging=control_root is not None,
        compose_files=tuple(compose_files), model=model, sources=frozenset(sources),
        kinds=MappingProxyType(dict(kinds)), read_files=tuple(read_files),
        walked=tuple(walked),
        control=MappingProxyType(dict(control)),
        places=MappingProxyType(_places(read_files)),
        control_root=control_root, by=_BY_A_CHECK)


def _places(read_files: Iterable[Path]) -> dict[str, str]:
    """Each file by the path it is read as, and where that leads with every
    link resolved. A hash opens a file through whatever its parent
    directories have become, and secrets.env is not hashed at all
    (`secrets set` rewrites it): a link put anywhere on a path since the
    check moves its place, whatever bytes lie behind it."""
    return {str(path): os.path.realpath(path) for path in read_files}


def of_start(checked: object, project_name: str, compose_files: list[str]) -> CheckedStart:
    """`checked`, as the check of this production start of `compose_files`.
    Raises TypeError or ValueError for a value that is not: a caller's
    mistake, never a reason to check again quietly."""
    if not isinstance(checked, CheckedStart):
        raise TypeError(f"an earlier check is the CheckedStart check_start returned, "
                        f"not {type(checked).__name__}")
    if (checked.staging or checked.project_name != project_name
            or checked.compose_files != tuple(compose_files)):
        raise ValueError(
            f"the earlier check is of {checked.project_name}'s "
            f"{'staging ' if checked.staging else ''}start with "
            f"{', '.join(checked.compose_files)}; it cannot stand in for {project_name}'s "
            f"production start with {', '.join(compose_files)}")
    return checked


def unchanged(checked: object, project_name: str, project_dir: Path,
              compose_files: list[str]) -> bool:
    """Whether a production start of `compose_files` may run on `checked`:
    every bind source is still of the kind the check saw, reached without a
    symlink, and every file the check read still hashes to what the check
    itself took (not to the record, which the deploy user can write) and
    still lies where the check found it, inside the project. False sends
    the caller to the full check, which says what is wrong. Raises as
    of_start does."""
    checked = of_start(checked, project_name, compose_files)
    try:
        bind_sources.check_sources(project_dir, set(checked.sources), checked.kinds)
        now = bind_sources.control_hashes(project_dir, checked.read_files)
    except (bind_sources.BindSourceError, OSError):
        return False
    root = os.path.realpath(project_dir)
    places = _places(checked.read_files)
    return (now == checked.control and places == checked.places
            and all(place != root and path_within(place, root) for place in places.values()))
