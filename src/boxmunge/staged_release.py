# SPDX-License-Identifier: Apache-2.0
"""The staged release's own tree, the slot: ``<project>/.releases/staged/``.

``release/`` is the pristine staged release, exactly what promote installs
(plus the missing read-only bind sources stage created); the generated
staging compose files sit beside it, and ``meta.json`` is the single
record of the stage (state/staging is retired). Staging's compose project
runs from ``release/`` with ``--project-directory``, so its relative paths
resolve inside the staged release as production's resolve inside the
project dir. A slot is built as ``staged.building`` and renamed into place
complete; ``*.discarded`` and ``staged.building`` are crash debris, swept
under the project lock by every core that touches the slot.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge.crashpoint import crash_point
from boxmunge.docker import staging_compose_project
from boxmunge.fileutil import (
    DISCARDED, atomic_write_text, discard_dir, durable_rename_dir, read_text_nofollow,
    sweep_discarded,
)
from boxmunge.ulid import generate_ulid

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

SLOT = "staged"
BUILDING = "staged.building"
# A promoted slot is dropped under this name: its debris says the promotion
# was announced and only the slot's removal was left (promote's rerun).
PROMOTED = "staged.promoted"
STAGING_BASE = "compose.staging-base.yml"
STAGING_OVERLAY = "compose.boxmunge-staging.yml"
META_VERSION = 1
KINDS = ("bundle", "git")
STATES = ("starting", "ready", "retired")
_REQUIRED = ("id", "kind", "ref", "bundle_sha256", "staged_at", "state")


class SlotError(ValueError):
    """The slot cannot be read as a stage this release made."""


@dataclass(frozen=True)
class StagedRelease:
    id: str
    kind: str
    ref: str
    bundle_sha256: str | None
    staged_at: str
    state: str
    production_stopped: dict[str, Any] | None = None
    cleanup_incomplete: str | None = None
    switch_rc: int | None = None  # replace_release's result, recorded when retired
    # The top-level ``-staging`` entries staging created for this stage or
    # the one it replaced (staging_copies): only these, and copies of
    # production's data, are staging's to mount and remove.
    made: tuple[str, ...] = ()
    # promote's "Promoted" log line and webhook went out (recorded just
    # before they are sent), so a rerun after a kill never repeats them.
    announced: bool = False


def new_meta(kind: str, ref: str, bundle_sha256: str | None,
             made: tuple[str, ...] = ()) -> StagedRelease:
    if kind not in KINDS:
        raise ValueError(f"unknown slot kind {kind!r}")
    return StagedRelease(id=generate_ulid(), kind=kind, ref=ref, bundle_sha256=bundle_sha256,
                         staged_at=datetime.now(timezone.utc).isoformat(), state="starting",
                         made=tuple(made))


def slot_dir(paths: BoxPaths, project: str) -> Path:
    return paths.project_releases(project) / SLOT


def building_dir(paths: BoxPaths, project: str) -> Path:
    return paths.project_releases(project) / BUILDING


def release_dir(slot: Path) -> Path:
    return slot / "release"


def has_slot(paths: BoxPaths, project: str) -> bool:
    return os.path.lexists(slot_dir(paths, project))


def write_meta(slot: Path, meta: StagedRelease) -> None:
    doc = {"version": META_VERSION, **asdict(meta)}
    atomic_write_text(slot / "meta.json", json.dumps(doc, indent=2) + "\n", mode=0o644)


def load_slot(paths: BoxPaths, project: str) -> StagedRelease | None:
    slot = slot_dir(paths, project)
    if not os.path.lexists(slot):
        return None
    if slot.is_symlink() or not slot.is_dir():
        raise SlotError(f"{slot} is not a directory")
    path = slot / "meta.json"
    try:
        doc = json.loads(read_text_nofollow(path))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise SlotError(f"cannot read {path}: {e}") from e
    if not isinstance(doc, dict) or doc.get("version") != META_VERSION:
        raise SlotError(f"{path} is not a version-{META_VERSION} slot record")
    try:
        meta = StagedRelease(**{k: doc[k] for k in _REQUIRED},
                             production_stopped=doc.get("production_stopped"),
                             cleanup_incomplete=doc.get("cleanup_incomplete"),
                             switch_rc=doc.get("switch_rc"),
                             made=_made(doc.get("made", []), path),
                             announced=doc.get("announced", False))
    except KeyError as e:
        raise SlotError(f"{path} is missing {e}") from e
    if meta.kind not in KINDS or meta.state not in STATES:
        raise SlotError(f"{path} has kind {meta.kind!r} and state {meta.state!r}")
    if not (type(meta.switch_rc) is int if meta.state == "retired" else meta.switch_rc is None):
        raise SlotError(f"{path} has state {meta.state!r} with switch_rc "
                        f"{meta.switch_rc!r}: a retired slot records replace_release's "
                        f"exit code (an integer), and no other slot has one")
    if type(meta.announced) is not bool or (meta.announced and meta.state != "retired"):
        raise SlotError(f"{path} has announced {meta.announced!r} with state "
                        f"{meta.state!r}: only a retired slot's promotion is announced")
    if not _valid_marker(meta.production_stopped):
        raise SlotError(f"{path} has a malformed production_stopped marker "
                        f"{meta.production_stopped!r}: expected null or "
                        f"{{\"at\": <time>, \"containers\": [<name>, ...]}}")
    return meta


def _made(names: Any, path: Path) -> tuple[str, ...]:
    if not isinstance(names, list) or not all(
            isinstance(n, str) and n.endswith("-staging") and n != "-staging"
            and "/" not in n and "\0" not in n for n in names):
        raise SlotError(f"{path} has a malformed made list {names!r}: expected the "
                        f"top-level '<entry>-staging' names staging created")
    return tuple(names)


def _valid_marker(marker: Any) -> bool:
    if marker is None:
        return True
    if not isinstance(marker, dict) or set(marker) != {"at", "containers"}:
        return False
    names = marker["containers"]
    return (isinstance(marker["at"], str) and isinstance(names, list) and bool(names)
            and all(isinstance(n, str) and n for n in names))


def update_meta(paths: BoxPaths, project: str, meta: StagedRelease,
                **changes: Any) -> StagedRelease:
    """Write ``meta`` with ``changes``. Only a retired slot records the
    switch's exit code, so any other state drops one carried over from
    ``meta`` (load_slot refuses a slot that keeps one); passing one with
    another state is a caller's error, raised as ValueError."""
    new = replace(meta, **changes)
    if new.state != "retired":
        if changes.get("switch_rc") is not None:
            raise ValueError(f"switch_rc {changes['switch_rc']!r} is recorded only with "
                             f"state 'retired', not {new.state!r}")
        new = replace(new, switch_rc=None)
    write_meta(slot_dir(paths, project), new)
    return new


def clear_production_stopped(paths: BoxPaths, project: str) -> None:
    """Production was started (or deliberately stopped) by someone else:
    the copy's stop no longer stands."""
    meta = load_slot(paths, project)
    if meta is not None and meta.production_stopped is not None:
        update_meta(paths, project, meta, production_stopped=None)


def refuse_planted(paths: BoxPaths, project: str) -> None:
    """The slot, ``staged.building`` and the ``*.discarded`` and
    ``.isolation-*`` debris are boxmunge's own directories in the
    deploy-writable ``.releases/``. A link or anything but a directory there
    was put there by someone else: boxmunge neither follows nor removes it.
    Raises OSError naming it, before anything acts on the slot."""
    releases = paths.project_releases(project)
    if not releases.is_dir():
        return
    for path in [releases / SLOT, releases / BUILDING,
                 *sorted(releases.glob(f"*{DISCARDED}")), *sorted(releases.glob(".isolation-*"))]:
        if os.path.islink(path) or (os.path.lexists(path) and not path.is_dir()):
            what = "a symbolic link" if os.path.islink(path) else "not a directory"
            raise OSError(f"{path} is {what}, where boxmunge keeps its own directory; "
                          f"boxmunge neither follows nor removes it. Inspect it, remove it "
                          f"by hand (rm {path}), then run the command again")


def sweep_debris(paths: BoxPaths, project: str) -> None:
    """Remove crash debris; raises OSError for a planted link (refuse_planted)."""
    releases = paths.project_releases(project)
    if not releases.is_dir():
        return
    refuse_planted(paths, project)
    discard_dir(releases / BUILDING)
    sweep_discarded(releases)
    for entry in sorted(releases.glob(".isolation-*")):
        discard_dir(entry)


def swap_in(paths: BoxPaths, project: str) -> None:
    """``staged.building`` becomes the slot; an existing slot is discarded."""
    releases = paths.project_releases(project)
    slot, old = releases / SLOT, releases / f"{SLOT}{DISCARDED}"
    discard_dir(old)
    if os.path.lexists(slot):
        durable_rename_dir(slot, old)
    durable_rename_dir(releases / BUILDING, slot)
    discard_dir(old)


def drop_slot(paths: BoxPaths, project: str, *, promoted: bool = False) -> None:
    """Remove the slot through ``staged.discarded`` (``staged.promoted.discarded``
    once promote has announced it), which sweep_debris removes after a kill."""
    slot = slot_dir(paths, project)
    if not os.path.lexists(slot):
        return
    debris = slot.with_name(f"{PROMOTED if promoted else SLOT}{DISCARDED}")
    discard_dir(debris)
    durable_rename_dir(slot, debris)
    crash_point("slot.discarding")
    discard_dir(debris)


def slot_debris(paths: BoxPaths, project: str) -> list[Path]:
    """What a killed stage, unstage or promote left of a slot."""
    releases = paths.project_releases(project)
    return [p for p in (releases / BUILDING, releases / f"{SLOT}{DISCARDED}",
                        releases / f"{PROMOTED}{DISCARDED}") if os.path.lexists(p)]


def promoted_debris(paths: BoxPaths, project: str) -> bool:
    """A promote was killed while removing the slot it had announced."""
    return os.path.lexists(paths.project_releases(project) / f"{PROMOTED}{DISCARDED}")


@dataclass(frozen=True)
class ComposeTarget:
    """Where and how a compose project runs (staging's is the slot)."""
    cwd: Path
    project_name: str
    files: list[str]
    project_directory: Path | None = None
    env_file: Path | None = None

    def kwargs(self) -> dict[str, Any]:
        return {"compose_files": list(self.files), "project_name": self.project_name,
                "project_directory": self.project_directory, "env_file": self.env_file}


def staging_target_for(release: Path, files_dir: Path, project: str) -> ComposeTarget:
    env = release / ".env"
    return ComposeTarget(cwd=release, project_name=staging_compose_project(project),
                         files=[str(files_dir / STAGING_BASE), str(files_dir / STAGING_OVERLAY)],
                         project_directory=release,
                         env_file=env if os.path.isfile(env) else None)


def staging_target(paths: BoxPaths, project: str, slot: Path | None = None) -> ComposeTarget:
    slot = slot or slot_dir(paths, project)
    return staging_target_for(release_dir(slot), slot, project)


def manual_teardown(paths: BoxPaths, project: str) -> str:
    slot = slot_dir(paths, project)
    return (f"docker compose -p {project}-staging --project-directory {slot}/release "
            f"-f {slot}/{STAGING_BASE} -f {slot}/{STAGING_OVERLAY} down, then "
            f"rm -rf {slot} and rm {paths.project_staging_caddy_site(project)}")
