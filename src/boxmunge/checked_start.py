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
bytes validate and resolve to the same model, so neither runs again. Any
difference, and the start runs the whole check as if it had none.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from boxmunge import bind_sources

_BY_A_CHECK = object()


@dataclass(frozen=True)
class CheckedStart:
    project_name: str
    staging: bool
    compose_files: tuple[str, ...]
    # The merged model of every profile, as `docker compose config` gave it.
    model: dict[str, Any] = field(repr=False)
    sources: frozenset[str]                  # project-relative bind sources
    kinds: dict[str, str] = field(repr=False)             # ... and their kinds
    read_files: tuple[Path, ...] = field(repr=False)
    control: dict[str, str | None] = field(repr=False)    # sha256 of each file read
    control_root: Path | None                # staging: the slot's release
    by: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.by is not _BY_A_CHECK:
            raise TypeError("a CheckedStart is the result of compose_guard.check_start; "
                            "call that, do not build one")


def issue(project_name: str, compose_files: list[str], model: dict[str, Any],
          sources: set[str], kinds: dict[str, str], read_files: list[Path],
          control: dict[str, str | None], *, control_root: Path | None = None) -> CheckedStart:
    """For compose_guard's checks alone, once every check has passed."""
    return CheckedStart(
        project_name=project_name, staging=control_root is not None,
        compose_files=tuple(compose_files), model=model, sources=frozenset(sources),
        kinds=dict(kinds), read_files=tuple(read_files), control=dict(control),
        control_root=control_root, by=_BY_A_CHECK)


def unchanged(checked: object, project_name: str, project_dir: Path,
              compose_files: list[str]) -> bool:
    """Whether a production start of `compose_files` may run on `checked`:
    every bind source is still of the kind the check saw, reached without a
    symlink, and every file the check read still hashes to what the check
    itself took (not to the record, which the deploy user can write). False
    sends the caller to the full check, which says what is wrong.

    Raises TypeError or ValueError for a value that is not the check of
    this start: a caller's mistake, never a reason to check again quietly."""
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
    try:
        bind_sources.check_sources(project_dir, set(checked.sources), checked.kinds)
        now = bind_sources.control_hashes(project_dir, checked.read_files)
    except (bind_sources.BindSourceError, OSError):
        return False
    return now == checked.control
