# SPDX-License-Identifier: Apache-2.0
"""Release trees: install a checked release over the live project, and keep
the release it replaced so `rollback` can restore it.

A project directory holds two kinds of entries:

- **release code**: everything a bundle ships (manifest, compose, scripts,
  build contexts, project.env, ...);
- **box state**: secrets.env, security/, data/, backups/, user bind-mount
  dirs that hold data, their ``-staging`` copies, generated compose files,
  repo/ and ``.releases/``.

Installing a release replaces all release code (entries the new release no
longer ships are removed) and never touches box state. Before an upgrade the
live code is copied to ``.releases/previous/``, with ``previous.json``
recording its ref and the data snapshot taken just before it was replaced.
That pair is exactly what `rollback` restores.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.bind_mounts import BindMountError, bind_mounted_dirs
from boxmunge.bundle import (
    BOX_OWNED_ENTRIES, BOXMUNGE_ENTRIES, BundleError, is_placeholder,
)
from boxmunge.fileutil import atomic_write_text

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class ReleaseStateError(ValueError):
    """Release state is unreadable: a .releases/ bookkeeping file, or the
    live compose.yml that says which directories hold data."""


def _read_meta(path: Path) -> dict:
    try:
        meta = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ReleaseStateError(f"Cannot read {path}: {e}") from e
    if not isinstance(meta, dict):
        raise ReleaseStateError(f"{path} is not a JSON object")
    return meta


@dataclass(frozen=True)
class PreviousRelease:
    tree: Path
    ref: str
    data_snapshot: str
    replaced_at: str
    replaced_by: str


def previous_dir(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / "previous"


def _previous_meta(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / "previous.json"


def _live_meta(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / "live.json"


def _bind_dirs(compose_path: Path, project_dir: Path) -> dict[str, bool]:
    """Bind-mounted top-level dirs of a compose file -> read-write?"""
    try:
        return bind_mounted_dirs(compose_path, project_dir)
    except BindMountError as e:
        raise ReleaseStateError(
            f"Cannot tell which project directories hold data: {e}. Nothing "
            f"was changed; fix the file by hand before deploying."
        ) from e


def _data_dirs(project_dir: Path, release_tree: Path | None) -> tuple[set[str], set[str]]:
    """(live, release) top-level dirs bind-mounted read-write: data dirs.

    Read-only bind mounts are code or config the release ships.
    """
    live = {d for d, rw in _bind_dirs(project_dir / "compose.yml", project_dir).items() if rw}
    release: set[str] = set()
    if release_tree is not None:
        release = {d for d, rw in
                   _bind_dirs(release_tree / "compose.yml", project_dir).items() if rw}
    return live, release


def _box_state_names(project_dir: Path, release_tree: Path | None) -> set[str]:
    """Names of live entries that are box state, never release code."""
    tops = set(_bind_dirs(project_dir / "compose.yml", project_dir))
    if release_tree is not None:
        tops |= set(_bind_dirs(release_tree / "compose.yml", project_dir))
    live_data, release_data = _data_dirs(project_dir, release_tree)
    staging_copies = {f"{t}-staging" for t in tops}
    return (set(BOX_OWNED_ENTRIES) | set(BOXMUNGE_ENTRIES) | live_data
            | release_data | staging_copies)


def _has_content(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink() and any(path.iterdir())


def check_install(tree: Path, project_dir: Path) -> None:
    """Refuse a release that would overwrite or seed a data directory.

    A directory bind-mounted read-write holds what the app writes. Content
    the release ships for it is ambiguous (seed data? code mounted without
    :ro?), so it is refused rather than silently skipped or installed. An
    empty placeholder is fine. Changes nothing; raises BundleError, or
    ReleaseStateError if a compose file cannot be classified.
    """
    forbidden = sorted(
        e.name for e in tree.iterdir()
        if e.name in BOX_OWNED_ENTRIES or e.name in BOXMUNGE_ENTRIES
    )
    if forbidden:
        raise BundleError(f"Release tree carries box-owned entries: {forbidden}")
    live_data, release_data = _data_dirs(project_dir, tree)
    ambiguous = sorted(
        item.name for item in tree.iterdir()
        if not is_placeholder(item) and (
            item.name in release_data
            or (item.name in live_data and _has_content(project_dir / item.name)))
    )
    if ambiguous:
        names = ", ".join(f"{n}/" for n in ambiguous)
        raise BundleError(
            f"The release ships content for {names}, which compose.yml "
            f"bind-mounts read-write, so it holds data the app writes. If it "
            f"is code or config, mount it read-only (':ro', or read_only: "
            f"true); if it is data, remove it from the bundle."
        )


def _remove(path: Path) -> None:
    """Remove a file, link or directory without following links."""
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def _copy_entry(src: Path, dest: Path) -> None:
    """Copy one entry, keeping links as links. dest must not exist."""
    if src.is_dir() and not src.is_symlink():
        shutil.copytree(src, dest, symlinks=True)
    else:
        shutil.copy2(src, dest, follow_symlinks=False)


def _refresh_dir_in_place(src_dir: Path, dest_dir: Path) -> None:
    """Mirror ``src_dir`` into an existing real ``dest_dir``, preserving its inode.

    The top-level ``dest_dir`` inode is never recreated, so a live container
    bind-mounting it keeps resolving the mount (see install_entry). Nested
    entries are not bind-mount roots, so they are replaced wholesale.
    """
    for child in dest_dir.iterdir():
        _remove(child)
    for child in src_dir.iterdir():
        _copy_entry(child, dest_dir / child.name)


def _install_entry(item: Path, dest_item: Path) -> None:
    """Install one top-level release entry over whatever is at dest_item.

    Links are never followed, on either side: a link in the old release is
    replaced, not written through, and a link in the release is installed as
    a link (the bundle check guarantees it stays inside the project).
    """
    if item.is_dir() and not item.is_symlink() \
            and dest_item.is_dir() and not dest_item.is_symlink():
        # Refresh contents in place rather than rmtree+copytree: a
        # still-running container (e.g. prod during a `stage`) may
        # bind-mount this dir, and Docker resolves a bind mount to the
        # directory inode at container start. Replacing the directory
        # gives it a new inode and severs the live mount — the classic
        # symptom being boxmunge-scripts/smoke.sh vanishing inside the
        # running prod container, failing its smoke check, and the
        # health monitor stopping prod. Preserve the inode.
        _refresh_dir_in_place(item, dest_item)
        return
    _remove(dest_item)
    _copy_entry(item, dest_item)


def _make_scripts_executable(entries: list[Path]) -> None:
    """chmod +x every real ``*.sh`` file in the given installed entries."""
    for entry in entries:
        if entry.is_symlink():
            continue
        scripts = entry.rglob("*.sh") if entry.is_dir() else [entry]
        for sh_file in scripts:
            if sh_file.suffix == ".sh" and sh_file.is_file() and not sh_file.is_symlink():
                sh_file.chmod(sh_file.stat().st_mode | 0o755)


def live_code_entries(project_dir: Path, release_tree: Path | None = None) -> list[Path]:
    """The live project entries that are release code (see module docstring)."""
    if not project_dir.exists():
        return []
    state = _box_state_names(project_dir, release_tree)
    return sorted(e for e in project_dir.iterdir() if e.name not in state)


def install_release(tree: Path, project_dir: Path) -> None:
    """Make the project's release code exactly ``tree``; keep box state.

    check_install runs first, so a refused release changes nothing. A data
    directory (read-write bind mount) that holds live data is kept when the
    release ships only an empty placeholder for it.
    """
    check_install(tree, project_dir)

    # Classify everything before changing anything.
    shipped = {e.name for e in tree.iterdir()}
    live_data, _ = _data_dirs(project_dir, tree)
    stale_entries = [e for e in live_code_entries(project_dir, tree)
                     if e.name not in shipped]

    project_dir.mkdir(parents=True, exist_ok=True)
    for stale in stale_entries:
        _remove(stale)

    installed: list[Path] = []
    for item in tree.iterdir():
        dest_item = project_dir / item.name
        if item.name in live_data and _has_content(dest_item):
            # check_install allowed this only for an empty placeholder.
            print(f"  NOTE: kept the server's {item.name}/ (it holds live "
                  f"data); the release ships only an empty placeholder")
            continue
        _install_entry(item, dest_item)
        installed.append(dest_item)

    (project_dir / "backups").mkdir(exist_ok=True)
    (project_dir / "data").mkdir(exist_ok=True)
    _make_scripts_executable(installed)


def live_ref(paths: BoxPaths, project_name: str) -> str:
    """The ref of the release code currently installed in the project dir."""
    meta = _live_meta(paths, project_name)
    if meta.exists():
        ref = _read_meta(meta).get("ref")
        if not isinstance(ref, str) or not ref:
            raise ReleaseStateError(f"{meta} has no ref")
        return ref
    # Projects deployed before .releases/ existed: the recorded deploy is
    # the release on disk.
    from boxmunge.state import read_state
    ref = read_state(paths.project_deploy_state(project_name)).get("current_ref")
    if not isinstance(ref, str) or not ref:
        raise ReleaseStateError(
            f"No record of which release is installed for '{project_name}' "
            f"(no {meta} and no recorded deploy). Deploy a bundle instead."
        )
    return ref


def mark_live(paths: BoxPaths, project_name: str, ref: str) -> None:
    """Record which release ref the project dir's code now is."""
    meta = _live_meta(paths, project_name)
    meta.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(meta, json.dumps({"ref": ref}) + "\n", mode=0o644)


def keep_previous_release(
    paths: BoxPaths, project_name: str, data_snapshot: str | None,
    replaced_by: str, release_tree: Path | None = None,
) -> None:
    """Copy the live release code to ``.releases/previous/`` before an upgrade.

    The copy is built beside the old one and swapped in only when complete,
    so a failure here leaves the live tree and the old snapshot untouched.
    """
    project_dir = paths.project_dir(project_name)
    releases = paths.project_releases(project_name)
    building = releases / "previous.building"
    _remove(building)
    building.mkdir(parents=True)
    for entry in live_code_entries(project_dir, release_tree):
        _copy_entry(entry, building / entry.name)

    meta = {
        "ref": live_ref(paths, project_name),
        "data_snapshot": data_snapshot or "",
        "replaced_at": datetime.now(timezone.utc).isoformat(),
        "replaced_by": replaced_by,
    }
    # Drop the old metadata first: a crash mid-swap then leaves no previous
    # release (rollback refuses) rather than old metadata on a new tree.
    _remove(_previous_meta(paths, project_name))
    target = previous_dir(paths, project_name)
    _remove(target)
    building.rename(target)
    atomic_write_text(_previous_meta(paths, project_name),
                      json.dumps(meta, indent=2) + "\n", mode=0o644)


def load_previous_release(paths: BoxPaths, project_name: str) -> PreviousRelease | None:
    """The kept previous release, or None if there is none."""
    tree = previous_dir(paths, project_name)
    meta_path = _previous_meta(paths, project_name)
    if not tree.is_dir() or not meta_path.exists():
        return None
    meta = _read_meta(meta_path)
    try:
        return PreviousRelease(
            tree=tree, ref=meta["ref"], data_snapshot=meta["data_snapshot"],
            replaced_at=meta["replaced_at"], replaced_by=meta["replaced_by"],
        )
    except KeyError as e:
        raise ReleaseStateError(f"{meta_path} is missing {e}") from e


def discard_previous_release(paths: BoxPaths, project_name: str) -> None:
    """Drop the kept previous release (after a rollback has used it)."""
    _remove(previous_dir(paths, project_name))
    _remove(_previous_meta(paths, project_name))


# --- staging ---------------------------------------------------------------
# `stage` installs the staged release into the shared project dir (staging
# containers run from it). The production release it displaced is kept in
# ``.releases/prestage/`` until `promote` (it becomes the previous release)
# or `unstage` (it is put back).

def prestage_dir(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / "prestage"


def _prestage_meta(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / "prestage.json"


def has_prestage(paths: BoxPaths, project_name: str) -> bool:
    return prestage_dir(paths, project_name).is_dir()


def keep_prestage_release(paths: BoxPaths, project_name: str,
                          release_tree: Path) -> None:
    """Keep the production release before `stage` replaces it.

    A no-op when one is already kept (a re-stage keeps the original
    production release). For a project that was never deployed the kept
    release is empty, so `unstage` returns it to its pre-stage state.
    """
    if has_prestage(paths, project_name):
        return
    project_dir = paths.project_dir(project_name)
    deployed = (project_dir / "manifest.yml").exists()
    building = paths.project_releases(project_name) / "prestage.building"
    _remove(building)
    building.mkdir(parents=True)
    if deployed:
        for entry in live_code_entries(project_dir, release_tree):
            _copy_entry(entry, building / entry.name)
    meta = {"ref": live_ref(paths, project_name) if deployed else None}
    building.rename(prestage_dir(paths, project_name))
    atomic_write_text(_prestage_meta(paths, project_name),
                      json.dumps(meta) + "\n", mode=0o644)


def _prestage_ref(paths: BoxPaths, project_name: str) -> str | None:
    meta_path = _prestage_meta(paths, project_name)
    ref = _read_meta(meta_path).get("ref")
    if ref is not None and not isinstance(ref, str):
        raise ReleaseStateError(f"{meta_path} has an invalid ref")
    return ref


def prestage_to_previous(paths: BoxPaths, project_name: str,
                         data_snapshot: str | None, replaced_by: str) -> None:
    """On promote: the kept production release becomes the previous release."""
    ref = _prestage_ref(paths, project_name)
    meta_path = _prestage_meta(paths, project_name)
    if ref is None:
        # First promote of a never-deployed project: nothing to roll back to.
        _remove(prestage_dir(paths, project_name))
        meta_path.unlink()
        return
    _remove(_previous_meta(paths, project_name))
    target = previous_dir(paths, project_name)
    _remove(target)
    prestage_dir(paths, project_name).rename(target)
    meta = {
        "ref": ref,
        "data_snapshot": data_snapshot or "",
        "replaced_at": datetime.now(timezone.utc).isoformat(),
        "replaced_by": replaced_by,
    }
    atomic_write_text(_previous_meta(paths, project_name),
                      json.dumps(meta, indent=2) + "\n", mode=0o644)
    meta_path.unlink()


def restore_prestage(paths: BoxPaths, project_name: str) -> None:
    """Put the kept production release back (unstage, or a failed stage)."""
    ref = _prestage_ref(paths, project_name)
    install_release(prestage_dir(paths, project_name), paths.project_dir(project_name))
    if ref is None:
        _remove(_live_meta(paths, project_name))
    else:
        mark_live(paths, project_name, ref)
    _remove(prestage_dir(paths, project_name))
    _prestage_meta(paths, project_name).unlink()
