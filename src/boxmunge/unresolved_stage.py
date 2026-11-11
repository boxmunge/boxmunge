# SPDX-License-Identifier: Apache-2.0
"""The upgrade's refusal while a project holds a stage boxmunge 0.10.1 or
earlier made in the old layout: the staged release in the project directory,
over or beside production's files. Read-only.

Releases 0.11.0 to 0.11.6 resolve such a stage with their `legacy-stage`
command. This release has none, and its upgrade restarts every project, so
the upgrade names what the release the box still runs accepts. Delete this
module, and the names reserved for it in BOXMUNGE_ENTRIES and
CONTROL_ENTRIES, once the upgrade floor is 0.11.7.
"""
from __future__ import annotations

import json
import os
import stat
from typing import TYPE_CHECKING

from boxmunge.fs_nofollow import read_text_nofollow
from boxmunge.release_selection import version_tuple
from boxmunge.version import parse_version_string

if TYPE_CHECKING:
    from pathlib import Path

    from boxmunge.paths import BoxPaths

STAGING_FILES = ("compose.staging-base.yml", "compose.boxmunge-staging.yml")
CHOICES = ("discard", "keep-staged")
# Only 0.11.6 tells a stage made before 0.10.1 (kind "pre0101") from a
# 0.10.1 leftover; an earlier --discard starts production from its files.
RESOLVES = (0, 11, 6)
FIRST_WITHOUT = (0, 11, 7)  # no legacy-stage command, and no such stage either


def _mode(path: Path) -> int | None:
    """The mode of whatever is at `path`, or None when nothing is. Any other
    error (EACCES) is raised: it must not read as "no stage"."""
    try:
        return os.lstat(path).st_mode
    except (FileNotFoundError, NotADirectoryError):
        return None


def _state_active(paths: BoxPaths, project: str) -> bool:
    path = paths.state / "staging" / f"{project}.json"
    if _mode(path) is None:
        return False
    try:
        doc = json.loads(read_text_nofollow(path))
    except (OSError, ValueError):  # a link, a FIFO or garbage: still a stage
        return True
    return bool(doc.get("active")) if isinstance(doc, dict) else True


def _deployed(paths: BoxPaths, project: str) -> bool:
    """Whether 0.10.1 or later deployed it: live.json, a regular file."""
    mode = _mode(paths.project_releases(project) / "live.json")
    return mode is not None and stat.S_ISREG(mode)


def _kind(paths: BoxPaths, project: str) -> str | None:
    """The stage on disk, as 0.11.6's legacy-stage names it, or None."""
    project_dir = paths.project_dir(project)
    if _mode(project_dir / ".releases" / "prestage") is not None:
        return "bundle"
    if not (_state_active(paths, project)
            or any(_mode(project_dir / name) is not None for name in STAGING_FILES)):
        return None
    if _mode(project_dir / "repo") is not None:
        return "git"
    return "leftover" if _deployed(paths, project) else "pre0101"


def _records(paths: BoxPaths) -> dict[str, dict]:
    """What legacy-stage recorded, {project: {kind, choice, ...}}."""
    path = paths.state / "legacy-stages.json"
    doc = json.loads(read_text_nofollow(path)) if os.path.lexists(path) else {}
    if not isinstance(doc, dict) or not all(isinstance(r, dict) for r in doc.values()):
        raise ValueError("not a JSON object of per-project objects")
    return doc


def _problem(paths: BoxPaths, project: str, record: dict) -> str | None:
    """What `project` must have done before the upgrade, or None."""
    choice = record.get("choice") if record.get("choice") in CHOICES else None
    kind = _kind(paths, project)
    if kind is None:  # no longer detected: finished, unless the record says otherwise
        kind = record.get("kind")
        discarded = choice == "discard" and kind in ("pre0101", "leftover")
        if discarded and not _deployed(paths, project):
            return ("its directory holds the files of a stage that legacy-stage discarded, "
                    "and no deploy has replaced them; upload the bundle of the release "
                    f"production should run, then run `prod-deploy {project}`")
        if choice is None or discarded and kind == "pre0101":
            return None  # nothing was started, or a deploy replaced the files
    by = "a boxmunge release before 0.10.1" if kind == "pre0101" else "boxmunge 0.10.1"
    if choice is None:
        return (f"a release staged by {by} is unresolved ({kind}); run `boxmunge-server "
                f"legacy-stage {project}` and take one of the choices it shows")
    return (f"the resolution of a release staged by {by} was started with --{choice} and is "
            f"not finished; run `boxmunge-server legacy-stage {project} --{choice}`")


def refusal(paths: BoxPaths, projects: list[str], installed: str) -> str | None:
    """Why a box running the release `installed` must not be upgraded, or
    None: each project whose stage is unresolved, or discarded and awaiting
    a deploy, with the command that release accepts for it."""
    semver = parse_version_string(installed)[0]
    running = version_tuple(semver) or (0,)
    if running >= FIRST_WITHOUT:
        return None
    try:
        records = _records(paths)
        found = [(p, _problem(paths, p, records.get(p, {}))) for p in projects]
    except (OSError, ValueError) as e:
        return (f"Cannot tell which projects hold a release that boxmunge 0.10.1 or earlier "
                f"staged over production's files ({type(e).__name__}: {e}). Repair what that "
                f"names (legacy-stage's record of them is {paths.state / 'legacy-stages.json'}, "
                f"a JSON object holding one object per project), then retry the upgrade.")
    lines = [f"  - {project}: {problem}" for project, problem in found if problem]
    if not lines:
        return None
    if running >= RESOLVES:
        where = f"On this box, on the release it runs now (boxmunge {semver}):"
    else:
        runs = f"boxmunge {semver}" if any(running) else "a release it has no record of"
        where = (f"This box runs {runs}, which does not resolve every such stage safely "
                 f"(before 0.11.6, legacy-stage --discard starts production from the files of "
                 f"a stage made before 0.10.1). Upgrade it to 0.11.6 first, with `sudo "
                 f"/opt/boxmunge/bin/boxmunge-upgrade target 0.11.6`. Then, on 0.11.6:")
    hold = "1 project holds" if len(lines) == 1 else f"{len(lines)} projects hold"
    return "\n".join([
        f"{hold} a release that boxmunge 0.10.1 or earlier staged over production's files, "
        f"and it is not resolved. An upgrade restarts every project, and this release neither "
        f"starts a project from staged files nor has the legacy-stage command that resolves "
        f"them. {where}", *lines, "Then retry the upgrade."])
