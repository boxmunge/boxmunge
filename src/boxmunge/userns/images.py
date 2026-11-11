# SPDX-License-Identifier: Apache-2.0
"""Images across the store switch: one tar per image, every load verified.

One image per tar matters: an unloadable image aborts the load of a whole
tar, and the images after it in that tar are never loaded (E20). docker
load restores an image's tags but never its digests, so an image a
container runs by `name@sha256:...` (as IMAGES.md advises for a base) is
pulled by that digest once loaded: its layers are already there, so only
the manifest comes from the registry, and the digest proves the content.
Nothing else is pulled during the downtime. A tar is written under a temporary name,
synced, renamed into place and its directory synced before the journal
says `saved`, so a resumed save never trusts a partial tar. Image IDs
differ between the stores, so the journal maps old to new.
"""
from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Callable

from boxmunge.docker_run import DockerError, run as _run
from boxmunge.fileutil import fsync_dir
from boxmunge.userns.inventory import ImageEntry
from boxmunge.userns.journal import Journal

IMAGES_DIR = Path("/var/lib/boxmunge-userns/images")
_TIMEOUT = 3600


class ImageError(Exception):
    """An image could not be saved or loaded as inventoried."""


def _root_only_dir(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
        fsync_dir(path.parent)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise ImageError(f"{path} must be a directory owned by uid {os.geteuid()}, mode 0700")


def ensure_dir(path: Path) -> None:
    """`path` and its parent, root-only (the parent is boxmunge's own)."""
    _root_only_dir(path.parent)
    _root_only_dir(path)


def tar_path(directory: Path, image_id: str) -> Path:
    return directory / f"{image_id.removeprefix('sha256:')}.tar"


def image_id(ref: str) -> str:
    out = _run(["docker", "image", "inspect", "--format", "{{.Id}}", ref], capture=True).stdout
    found = out.strip()
    if not found.startswith("sha256:"):
        raise ImageError(f"docker image inspect {ref} reports image ID {found!r}")
    return found


def save_all(images: list[ImageEntry], journal: Journal, directory: Path,
             save: Callable[[], None], prefix: str = "image") -> None:
    ensure_dir(directory)
    for img in images:
        key = f"{prefix}:{img.id}"
        if not img.carried or journal.items.get(key) in ("saved", "loaded"):
            continue
        tar = tar_path(directory, img.id)
        partial = tar.with_suffix(".partial")
        _run(["docker", "save", "-o", str(partial), *(img.tags or [img.id])], capture=True,
             timeout=_TIMEOUT)
        fd = os.open(partial, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(partial, tar)
        fsync_dir(directory)
        journal.items[key] = "saved"
        save()


def _loaded_id(output: str, img: ImageEntry) -> str:
    if img.tags:
        ids = {tag: image_id(tag) for tag in img.tags}
        if len(set(ids.values())) != 1:
            raise ImageError(f"after loading {img.id[:19]} its tags name different images: {ids}")
        return next(iter(ids.values()))
    found = [line.split(":", 1)[1].strip() for line in output.splitlines()
             if line.startswith("Loaded image ID:")]
    if len(found) != 1:
        raise ImageError(f"loading {img.id[:19]} did not report one image ID: {output!r}")
    return found[0]


def _resolves(ref: str) -> bool:
    try:
        image_id(ref)
    except DockerError:
        return False
    return True


def load_all(images: list[ImageEntry], journal: Journal, directory: Path,
             save: Callable[[], None], prefix: str = "image") -> None:
    for img in images:
        key = f"{prefix}:{img.id}"
        if not img.carried:
            continue
        if journal.items.get(key) != "loaded":
            if journal.items.get(key) != "saved":
                raise ImageError(f"image {', '.join(img.tags or img.refs)} was never saved; "
                                 f"nothing to load")
            out = _run(["docker", "load", "-q", "-i", str(tar_path(directory, img.id))],
                       capture=True, timeout=_TIMEOUT).stdout
            journal.image_map[img.id] = _loaded_id(out, img)
            journal.items[key] = "loaded"
            save()
        for ref in img.refs:
            if journal.items.get(f"{prefix}-ref:{ref}") == "pulled" or _resolves(ref):
                continue
            try:
                _run(["docker", "pull", "-q", ref], capture=True, timeout=_TIMEOUT)
            except DockerError as e:
                raise ImageError(f"{ref} must be pulled again by its digest (docker load keeps "
                                 f"no digests) and the pull failed: {e}. Its layers are loaded; "
                                 f"once the registry answers, run the same command again") from e
            if not _resolves(ref):
                raise ImageError(f"{ref} was pulled but does not resolve")
            journal.items[f"{prefix}-ref:{ref}"] = "pulled"
            save()


def remove_tars(directory: Path) -> None:
    if directory.is_symlink():
        raise ImageError(f"{directory} is a symlink; refusing to remove through it")
    if directory.exists():
        shutil.rmtree(directory)
