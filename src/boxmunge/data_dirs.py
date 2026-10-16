# SPDX-License-Identifier: Apache-2.0
"""Which top-level project entries hold data the app writes.

A compose file only says what its own release bind-mounts read-write. Once a
release drops a mount, no later compose file mentions the directory, so
classifying from compose files alone turns yesterday's uploads/ into stale
release code, which the next install deletes. The project therefore keeps
``.releases/data-dirs.json``, a record of every entry that a compose file
the box has installed bind-mounted read-write. A recorded entry is box
state: installs never remove, overwrite or copy it into a kept release.

A project that has no record yet (it was deployed before the record
existed) starts one from its kept releases' compose files too, before any
kept release is replaced: a mount the live release dropped may survive only
there. An entry such a kept release mounted read-write but the live
release mounts read-only and the incoming release ships becomes code; its
old contents are first moved aside to ``.releases/retained/``, so even that
once-per-project judgement call loses nothing.

An entry leaves the record only while neither it nor its ``-staging`` copy
holds anything: when no compose file mounts it any more, or when a release
ships it as code without mounting it read-write. Deleting a retired data
directory is an operator's deliberate act, never a side effect of a deploy.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, Iterator

from boxmunge.bind_mounts import BindMountError, bind_mounted_dirs
from boxmunge.bundle import BOX_OWNED_ENTRIES, BOXMUNGE_ENTRIES, is_placeholder
from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_warning

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

RECORD_VERSION = 1


class ReleaseStateError(ValueError):
    """Release state is unreadable: a .releases/ bookkeeping file, or a
    compose.yml that says which directories hold data."""


def record_path(project_dir: Path) -> Path:
    return project_dir / ".releases" / "data-dirs.json"


def bind_dirs(compose_path: Path, project_dir: Path) -> dict[str, bool]:
    """Bind-mounted top-level dirs of a compose file -> read-write?"""
    try:
        return bind_mounted_dirs(compose_path, project_dir)
    except BindMountError as e:
        raise ReleaseStateError(
            f"Cannot tell which project directories hold data: {e}. Nothing "
            f"was changed; fix the file by hand before deploying."
        ) from e


def _read_write(compose_path: Path, project_dir: Path) -> set[str]:
    return {d for d, rw in bind_dirs(compose_path, project_dir).items() if rw}


def holds_data(path: Path) -> bool:
    """Anything but a missing entry or an empty real directory."""
    if path.is_dir() and not path.is_symlink():
        return any(path.iterdir())
    return os.path.lexists(path)


def _valid_name(name: object) -> bool:
    return (isinstance(name, str) and name not in ("", ".", "..")
            and "/" not in name and "\0" not in name)


def has_record(project_dir: Path) -> bool:
    return os.path.lexists(record_path(project_dir))


def _load_record(project_dir: Path) -> set[str] | None:
    """The recorded data entries; None for a project that has no record yet."""
    path = record_path(project_dir)
    if not has_record(project_dir):
        return None
    fix = (f"Nothing was changed. It lists the project directories that hold "
           f"data, so deploys never delete them: restore it, or rewrite it as "
           f'{{"version": {RECORD_VERSION}, "data_dirs": ["<dir>", ...]}}.')
    try:
        doc = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ReleaseStateError(f"Cannot read {path}: {e}. {fix}") from e
    if not isinstance(doc, dict):
        raise ReleaseStateError(f"{path} is not a JSON object. {fix}")
    version = doc.get("version")
    if version != RECORD_VERSION or isinstance(version, bool):
        raise ReleaseStateError(
            f"{path} has version {version!r}; this boxmunge reads only "
            f"version {RECORD_VERSION}. {fix}")
    names = doc.get("data_dirs")
    if not isinstance(names, list) or not all(_valid_name(n) for n in names):
        raise ReleaseStateError(
            f"{path}: data_dirs must be a list of top-level entry names. {fix}")
    return set(names)


def _staging_copy(name: str) -> str:
    return f"{name}-staging"


@dataclass(frozen=True)
class DataDirs:
    """How one install sees the project's entries."""
    project_dir: Path
    release: frozenset[str]   # read-write bind mounts of the incoming release
    recorded: frozenset[str]  # entries that are data, mounted or not
    mounted: frozenset[str]   # every bind-mounted entry of live + incoming
    seeded: frozenset[str] = frozenset()  # recorded only because a kept release mounts it
    adopted: frozenset[str] = frozenset()  # kept release mounted it rw; now shipped as code

    def box_state(self) -> set[str]:
        """Entries that are never release code."""
        tops = self.mounted | self.recorded
        return (set(BOX_OWNED_ENTRIES) | set(BOXMUNGE_ENTRIES) | set(self.recorded)
                | {_staging_copy(t) for t in tops})

    def occupied(self, name: str) -> list[Path]:
        """The server paths holding ``name``'s data: it and its staging copy."""
        return [path for path in (self.project_dir / name,
                                  self.project_dir / _staging_copy(name))
                if holds_data(path)]

    def after_install(self, shipped: set[str]) -> DataDirs:
        """The record once the release is installed.

        An entry the release ships that holds nothing on the server and that
        the release does not mount read-write becomes release code (e.g. an
        empty dir a release now mounts read-only and fills).
        """
        taken = {n for n in shipped & self.recorded
                 if n not in self.release and not self.occupied(n)}
        return replace(self, recorded=self.recorded - taken)

    def retained(self) -> list[str]:
        """Recorded entries holding data that the incoming release does not mount.

        Only the entry itself counts: a ``-staging`` copy alone keeps the
        entry recorded but is staging's data, not something to warn about on
        every deploy.
        """
        return sorted(n for n in self.recorded - self.release
                      if holds_data(self.project_dir / n))


def classify(project_dir: Path, release_tree: Path | None,
             kept_trees: Iterable[Path]) -> DataDirs:
    """Classify the project's entries for installing ``release_tree``.

    ``kept_trees`` (the rollback target, production's release during a
    stage) are read only while the project has no record. An entry the live
    compose.yml mounts read-only and the incoming release ships is code,
    whatever an older release once mounted; one it only reads (the release
    ships nothing for it) still holds the older release's data. Without an
    incoming release, every kept mount counts: at worst a later bundle is
    refused, never is data deleted. Raises ReleaseStateError for an
    unreadable compose file or record.
    """
    live_binds = bind_dirs(project_dir / "compose.yml", project_dir)
    release_binds: dict[str, bool] = {}
    shipped: set[str] = set()
    if release_tree is not None:
        release_binds = bind_dirs(release_tree / "compose.yml", project_dir)
        shipped = {e.name for e in release_tree.iterdir() if not is_placeholder(e)}
    release = {d for d, rw in release_binds.items() if rw}
    live_rw = {d for d, rw in live_binds.items() if rw}
    stored = _load_record(project_dir)
    kept: set[str] = set()
    adopted: set[str] = set()
    if stored is None:
        for tree in kept_trees:
            kept |= _read_write(tree / "compose.yml", project_dir)
        adopted = kept & (set(live_binds) - live_rw) & shipped
        kept -= adopted
    candidates = (stored or set()) | live_rw | kept
    dirs = DataDirs(
        project_dir=project_dir,
        release=frozenset(release),
        recorded=frozenset(),
        mounted=frozenset(live_binds) | frozenset(release_binds),
    )
    recorded = release | (set(dirs.mounted) & candidates) | {
        n for n in candidates if dirs.occupied(n)}
    recorded -= set(BOX_OWNED_ENTRIES) | set(BOXMUNGE_ENTRIES)
    seeded = recorded - release - live_rw - (stored or set())
    return replace(dirs, recorded=frozenset(recorded), seeded=frozenset(seeded),
                   adopted=frozenset(adopted - recorded))


def save_record(dirs: DataDirs) -> None:
    """Persist ``dirs.recorded``, before anything it protects can change."""
    path = record_path(dirs.project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"version": RECORD_VERSION, "data_dirs": sorted(dirs.recorded)}
    atomic_write_text(path, json.dumps(doc) + "\n", mode=0o644)


class SetAsideError(OSError):
    """A step failed after contents were moved to ``.releases/retained/``."""

    def __init__(self, cause: Exception, copies: list[Path]) -> None:
        super().__init__(f"{cause}. Before it failed, old contents were moved "
                         f"to: {', '.join(str(c) for c in copies)}")
        self.copies = copies


@contextmanager
def naming_set_aside(copies: list[Path]) -> Iterator[None]:
    """Turn a failure after contents were set aside into a SetAsideError."""
    try:
        yield
    except (OSError, ReleaseStateError) as e:
        if copies and not isinstance(e, SetAsideError):
            raise SetAsideError(e, copies) from e
        raise


# Called with each .releases/retained/ destination before anything moves into it.
Announce = Callable[[Path], None]


def set_aside_announcer(paths: BoxPaths, project_name: str, component: str) -> Announce:
    def announce(dest: Path) -> None:
        log_warning(component,
                    f"Setting aside the old contents of an entry an older release "
                    f"mounted read-write, now release code, in {dest}. An operator "
                    f"deletes it on the server once nothing needs it.",
                    paths, project=project_name, detail={"set_aside": str(dest)})
    return announce


def _move_contents(entry: Path, dest: Path) -> None:
    dest.mkdir(parents=True)
    if entry.is_dir() and not entry.is_symlink():
        # Move the contents, not the directory: a running container's
        # read-only bind mount resolves to the directory's inode.
        for child in sorted(entry.iterdir()):
            child.rename(dest / child.name)
    else:
        entry.rename(dest / entry.name)


def start_record(dirs: DataDirs, announce: Announce | None = None) -> list[Path]:
    """Start the record of a project that has none; returns the copies set aside.

    Each destination is announced (printed, and passed to ``announce``)
    before anything moves into it. The record is written after the moves: a
    crash part-way leaves no record, so the next deploy moves what is left
    instead of installing code over it. Raises SetAsideError, naming what was
    moved, if a move or the record write fails after a move began.
    """
    copies: list[Path] = []
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    with naming_set_aside(copies):
        for name in sorted(dirs.adopted):
            entry = dirs.project_dir / name
            if not holds_data(entry):
                continue
            dest = dirs.project_dir / ".releases" / "retained" / f"{name}-{stamp}"
            print(f"  WARNING: {name} was bind-mounted read-write by an older "
                  f"release (kept in .releases/), so it may hold data, and this "
                  f"release ships it as code. Its previous contents are kept in "
                  f"{dest}. When nothing needs them, an operator deletes them on "
                  f"the server with: rm -rf {dest}")
            if announce is not None:
                announce(dest)
            copies.append(dest)
            _move_contents(entry, dest)
        save_record(dirs)
    return copies


@dataclass(frozen=True)
class KeptData:
    """What an install kept that the operator must hear about."""
    retained: list[str] = field(default_factory=list)  # data the release does not mount
    copies: list[Path] = field(default_factory=list)   # contents moved to .releases/retained/


def entry_label(path: Path) -> str:
    return f"{path.name}/" if path.is_dir() and not path.is_symlink() else path.name


def warn_retained(dirs: DataDirs, names: list[str]) -> None:
    """Tell the operator which data entries the release no longer mounts."""
    for name in names:
        occupied = dirs.occupied(name)
        print(f"  WARNING: {entry_label(occupied[0])} holds data but this "
              f"release's compose.yml does not mount it read-write. It is "
              f"kept: deploys never delete data. When no release in use or "
              f"kept for rollback needs it, an operator deletes it on the "
              f"server with: rm -rf {' '.join(str(p) for p in occupied)}")


def log_kept(paths: BoxPaths, project_name: str, kept: KeptData,
             component: str) -> None:
    """Log the retired data an install kept (set-aside copies are logged as
    they are announced, before they move)."""
    if not kept.retained:
        return
    project_dir = paths.project_dir(project_name)
    labels = ", ".join(entry_label(project_dir / n) for n in kept.retained)
    log_warning(component,
                f"Kept data the installed release no longer mounts: {labels}. "
                f"An operator deletes it on the server once nothing needs it.",
                paths, project=project_name, detail={"retained": kept.retained})
