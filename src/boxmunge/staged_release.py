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

from boxmunge.docker import staging_compose_project
from boxmunge.fileutil import (
    DISCARDED, atomic_write_text, discard_dir, durable_rename_dir, sweep_discarded,
)
from boxmunge.ulid import generate_ulid

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

SLOT = "staged"
BUILDING = "staged.building"
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


def new_meta(kind: str, ref: str, bundle_sha256: str | None) -> StagedRelease:
    if kind not in KINDS:
        raise ValueError(f"unknown slot kind {kind!r}")
    return StagedRelease(id=generate_ulid(), kind=kind, ref=ref, bundle_sha256=bundle_sha256,
                         staged_at=datetime.now(timezone.utc).isoformat(), state="starting")


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
        doc = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise SlotError(f"cannot read {path}: {e}") from e
    if not isinstance(doc, dict) or doc.get("version") != META_VERSION:
        raise SlotError(f"{path} is not a version-{META_VERSION} slot record")
    try:
        meta = StagedRelease(**{k: doc[k] for k in _REQUIRED},
                             production_stopped=doc.get("production_stopped"),
                             cleanup_incomplete=doc.get("cleanup_incomplete"))
    except KeyError as e:
        raise SlotError(f"{path} is missing {e}") from e
    if meta.kind not in KINDS or meta.state not in STATES:
        raise SlotError(f"{path} has kind {meta.kind!r} and state {meta.state!r}")
    if not _valid_marker(meta.production_stopped):
        raise SlotError(f"{path} has a malformed production_stopped marker "
                        f"{meta.production_stopped!r}: expected null or "
                        f"{{\"at\": <time>, \"containers\": [<name>, ...]}}")
    return meta


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
    new = replace(meta, **changes)
    write_meta(slot_dir(paths, project), new)
    return new


def clear_production_stopped(paths: BoxPaths, project: str) -> None:
    """Production was started (or deliberately stopped) by someone else:
    the copy's stop no longer stands."""
    meta = load_slot(paths, project)
    if meta is not None and meta.production_stopped is not None:
        update_meta(paths, project, meta, production_stopped=None)


def sweep_debris(paths: BoxPaths, project: str) -> None:
    releases = paths.project_releases(project)
    if not releases.is_dir():
        return
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


def drop_slot(paths: BoxPaths, project: str) -> None:
    discard_dir(slot_dir(paths, project))


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
