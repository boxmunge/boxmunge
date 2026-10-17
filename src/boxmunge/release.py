# SPDX-License-Identifier: Apache-2.0
"""Release trees: install a checked release over the live project, and keep
the release it replaced so `rollback` can restore it.

A project directory holds two kinds of entries:

- **release code**: everything a bundle ships (manifest, compose, scripts,
  build contexts, project.env, ...);
- **box state**: secrets.env, security/, data/, backups/, every entry that
  a release has bind-mounted read-write and that still holds data (see
  data_dirs), ``-staging`` copies, generated compose files, repo/ and
  ``.releases/``.

Installing a release replaces all release code (entries the new release no
longer ships are removed) and never touches box state. Before an upgrade the
live code is copied to ``.releases/previous/``, with ``previous.json``
recording its ref and the data snapshot taken just before it was replaced.
That pair is exactly what `rollback` restores. The staged release lives in
its own tree (boxmunge.staged_release).
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.bundle import (
    BOX_OWNED_ENTRIES, BOXMUNGE_ENTRIES, BundleError, is_placeholder,
)
from boxmunge.data_dirs import (
    Announce, DataDirs, KeptData, ReleaseStateError, classify, entry_label,
    has_record, holds_data, record_path, save_record,
    start_record, warn_retained,
)
from boxmunge.fileutil import atomic_write_text, discard_dir, fsync_dir, sync_entries
from boxmunge.fs_nofollow import chmod_nofollow
from boxmunge.staged_release import SLOT, release_dir

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


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


_PREVIOUS = "previous"


def previous_dir(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / _PREVIOUS


def _previous_meta(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / "previous.json"


def _live_meta(paths: BoxPaths, project_name: str) -> Path:
    return paths.project_releases(project_name) / "live.json"


def _kept_trees(project_dir: Path) -> list[Path]:
    """The kept release's code: the rollback target."""
    return [project_dir / ".releases" / _PREVIOUS]


def _staged_compose(project_dir: Path) -> Path | None:
    """The staged release's compose.yml, while a release is staged. A linked
    slot is refused by its own cores; nothing is read through it. Whatever
    lies at the name is passed on: data_dirs reads it without following a
    link or blocking on a FIFO, and refuses anything but a regular file."""
    slot = project_dir / ".releases" / SLOT
    if not slot.is_dir() or slot.is_symlink():
        return None
    if os.path.islink(release_dir(slot)):
        raise ReleaseStateError(f"{release_dir(slot)} is a symbolic link, where the staged "
                                f"release's own tree belongs; nothing is read through it. "
                                f"Unstage, or remove it by hand and stage again")
    compose = release_dir(slot) / "compose.yml"
    return compose if os.path.lexists(compose) else None


def _classify(project_dir: Path, release_tree: Path | None, *,
              with_staged: bool = True) -> DataDirs:
    return classify(project_dir, release_tree, _kept_trees(project_dir),
                    _staged_compose(project_dir) if with_staged else None)


def _ensure_record(project_dir: Path, release_tree: Path | None = None,
                   announce: Announce | None = None) -> list[Path]:
    """Start the data-dir record before anything can change a kept release.

    A project deployed before the record existed may know a retired data
    directory only from a kept release's compose.yml; every function that
    replaces or drops a kept release, and install_release, calls this first,
    passing the incoming release when there is one. Returns the contents it
    set aside (see data_dirs.start_record).
    """
    if has_record(project_dir):
        return []
    return start_record(_classify(project_dir, release_tree), announce)


def check_install(tree: Path, project_dir: Path) -> None:
    """Refuse a release that would overwrite or seed a data directory.

    Changes nothing; raises BundleError, or ReleaseStateError if a compose
    file or the data-dir record cannot be read.
    """
    _check(tree, _classify(project_dir, tree))


def _check(tree: Path, dirs: DataDirs) -> None:
    """An entry the release bind-mounts read-write holds what the app writes,
    so content shipped for it is ambiguous (seed data? code mounted without
    :ro?) and is refused rather than silently skipped or installed. So is
    content for any entry that holds data on the server, mounted or not: a
    deploy never overwrites data. An empty placeholder is fine.
    """
    forbidden = sorted(
        e.name for e in tree.iterdir()
        if e.name in BOX_OWNED_ENTRIES or e.name in BOXMUNGE_ENTRIES
    )
    if forbidden:
        raise BundleError(f"Release tree carries box-owned entries: {forbidden}")
    shipped = sorted((e for e in tree.iterdir() if not is_placeholder(e)),
                     key=lambda e: e.name)
    mounted = [entry_label(e) for e in shipped if e.name in dirs.release]
    if mounted:
        raise BundleError(
            f"The release ships content for {', '.join(mounted)}, which "
            f"compose.yml bind-mounts read-write, so it holds data the app "
            f"writes. If it is code or config, mount it read-only (':ro', or "
            f"read_only: true); if it is data, remove it from the bundle."
        )
    occupied = [e for e in shipped if e.name in dirs.recorded and dirs.occupied(e.name)]
    seeded = [e for e in occupied if e.name in dirs.seeded]
    if seeded:
        labels = ", ".join(entry_label(e) for e in seeded)
        raise BundleError(
            f"The release ships content for {labels}, which the release kept "
            f"for rollback bind-mounts read-write, so boxmunge treats it as data: this project has no "
            f"record of its data directories yet ({record_path(dirs.project_dir)}). "
            f"If it is data, remove it from the bundle. If it is code, write "
            f"that file yourself listing only the directories that really hold "
            f'data, as {{"version": 1, "data_dirs": ["<dir>", ...]}} (an empty '
            f"list if none), and deploy again."
        )
    if occupied:
        server = " ".join(str(p) for e in occupied for p in dirs.occupied(e.name))
        raise BundleError(
            f"The release ships content for {', '.join(entry_label(e) for e in occupied)}, "
            f"which holds data on the server (a release bind-mounted it "
            f"read-write), and a deploy never overwrites data. Remove it from "
            f"the bundle or ship the content under another name. If the data "
            f"is no longer needed, an operator deletes it on the server first "
            f"(rm -rf {server}); the next deploy then installs the bundle's "
            f"content."
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
                # Through a no-follow descriptor: the checks above race with a
                # deploy-side swap, and Path.chmod would follow the link.
                chmod_nofollow(sh_file, add=0o755)


def live_code_entries(project_dir: Path, release_tree: Path | None = None) -> list[Path]:
    """The live project entries that are release code (see module docstring)."""
    if not project_dir.exists():
        return []
    state = _classify(project_dir, release_tree).box_state()
    return sorted(e for e in project_dir.iterdir() if e.name not in state)


def project_data_dirs(project_dir: Path, release_tree: Path | None = None, *,
                      with_staged: bool = True) -> DataDirs:
    """The project's entries as the live release, or once ``release_tree``
    is installed, classifies them (see module docstring). ``with_staged``
    False leaves the current slot's mounts out (DataDirs.staged)."""
    dirs = _classify(project_dir, release_tree, with_staged=with_staged)
    if release_tree is None:
        return dirs
    return dirs.after_install({e.name for e in release_tree.iterdir()})


def staged_box_state(project_dir: Path, staged_release: Path) -> set[str]:
    """Box state as the staged release sees it: the entries the staging base
    rewrite points at ``-staging`` copies, so also the stores the data copy
    pairs. (Production's own classification during a stage only keeps those
    copies from being pruned: DataDirs.staged.) The current slot is not
    read: ``staged_release`` is the staged view, and during a re-stage an
    old slot's unreadable compose.yml must not fail the new stage. A git
    slot's repo/ is its own clone of the staged commit (git_slot): release
    code there, never production's repo/."""
    state = project_data_dirs(project_dir, staged_release, with_staged=False).box_state()
    clone = staged_release / "repo"
    if clone.is_dir() and not clone.is_symlink():
        state.discard("repo")
    return state


def install_release(tree: Path, project_dir: Path,
                    announce: Announce | None = None) -> KeptData:
    """Make the project's release code exactly ``tree``; keep box state.

    Nothing changes if the release is refused. The data-dir record is
    written before anything else, so every entry that holds data stays box
    state from now on. A data entry the release ships only an empty
    placeholder for is kept. Returns what was kept with a warning (data the
    release no longer mounts, contents set aside), for the caller to log;
    ``announce`` hears of each set-aside destination before it is used.
    """
    dirs = _classify(project_dir, tree)
    _check(tree, dirs)
    project_dir.mkdir(parents=True, exist_ok=True)
    copies = [] if has_record(project_dir) else start_record(dirs, announce)

    # Classify everything before changing anything.
    shipped = {e.name for e in tree.iterdir()}
    dirs = dirs.after_install(shipped)
    state = dirs.box_state()
    stale_entries = sorted(e for e in project_dir.iterdir()
                           if e.name not in state and e.name not in shipped)

    save_record(dirs)
    for stale in stale_entries:
        _remove(stale)

    installed: list[Path] = []
    for item in tree.iterdir():
        dest_item = project_dir / item.name
        if item.name in dirs.recorded and holds_data(dest_item):
            # _check allowed this only for an empty placeholder.
            print(f"  NOTE: kept the server's {item.name}/ (it holds live "
                  f"data); the release ships only an empty placeholder")
            continue
        _install_entry(item, dest_item)
        installed.append(dest_item)

    (project_dir / "backups").mkdir(exist_ok=True)
    (project_dir / "data").mkdir(exist_ok=True)
    _make_scripts_executable(installed)
    retained = dirs.retained()
    warn_retained(dirs, retained)
    return KeptData(retained=retained, copies=copies)


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


def live_meta_text(ref: str) -> str:
    """live.json's exact content for ``ref`` (release_txn hashes it)."""
    return json.dumps({"ref": ref}) + "\n"


def previous_meta_text(ref: str, data_snapshot: str | None, replaced_at: str,
                       replaced_by: str) -> str:
    """previous.json's exact content (release_txn hashes it)."""
    return json.dumps({"ref": ref, "data_snapshot": data_snapshot or "",
                       "replaced_at": replaced_at, "replaced_by": replaced_by},
                      indent=2) + "\n"


def mark_live(paths: BoxPaths, project_name: str, ref: str) -> None:
    """Record which release ref the project dir's code now is."""
    meta = _live_meta(paths, project_name)
    meta.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(meta, live_meta_text(ref), mode=0o644)


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
    """Drop the kept previous release (after a rollback has used it).

    The metadata goes first and durably: from then on there is no rollback
    target, and a crash part-way through removing the tree leaves only
    debris, never a half-removed release that still looks usable."""
    _ensure_record(paths.project_dir(project_name))
    meta = _previous_meta(paths, project_name)
    if os.path.lexists(meta):
        meta.unlink()
        fsync_dir(meta.parent)
    discard_dir(previous_dir(paths, project_name))


def sync_release_code(project_dir: Path) -> None:
    """Make the release code install_release wrote durable, before an
    install records that it is in place."""
    sync_entries(live_code_entries(project_dir), project_dir)
