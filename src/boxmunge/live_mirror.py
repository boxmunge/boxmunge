# SPDX-License-Identifier: Apache-2.0
"""Refresh production's live copies while production reads them.

No path a reader can open ever disappears during a refresh:

- a changed file is written beside its name and renamed over it, so a
  reader opens either the old file or the new one;
- a file that is itself a bind-mount source (a single-file mount, a config
  or secret file) is rewritten in place instead. Docker pins such a mount
  to the file's inode, so a rename would leave the container reading the
  old file until it is recreated; the price is that a reader can see the
  file part-written;
- a directory is never replaced, so a directory mount keeps its inode;
- an unchanged file (same size and content, mode set if it differs) is not
  touched, and entries the release no longer has are removed last.

Only a path whose type changes (a file becoming a directory, say) is absent
for a moment. Every operation is relative to a directory descriptor opened
without following links, so a link planted anywhere in the copy is removed
or replaced, never followed: root refreshes these copies too.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CHUNK = 1 << 16


class MirrorError(OSError):
    """An entry of the release or of the copy cannot be mirrored."""


def _lstat(dfd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _rm(dfd: int, name: str) -> None:
    st = _lstat(dfd, name)
    if st is None:
        return
    if stat.S_ISDIR(st.st_mode):
        cfd = os.open(name, _DIR, dir_fd=dfd)
        try:
            for child in os.listdir(cfd):
                _rm(cfd, child)
        finally:
            os.close(cfd)
        os.rmdir(name, dir_fd=dfd)
    else:
        os.unlink(name, dir_fd=dfd)


def _same_content(src: Path, dfd: int, name: str) -> bool:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    with os.fdopen(fd, "rb") as copy, src.open("rb") as orig:
        while True:
            a, b = copy.read(_CHUNK), orig.read(_CHUNK)
            if a != b:
                return False
            if not a:
                return True


def _copy_into(fd: int, src: Path, mode: int) -> None:
    with src.open("rb") as orig:
        offset = 0
        while chunk := orig.read(_CHUNK):
            offset += os.pwrite(fd, chunk, offset)
    os.ftruncate(fd, offset)
    os.fchmod(fd, mode)


def _temp_name(name: str) -> str:
    return f".{name}.boxmunge-{os.getpid()}"


def _write_file(src: Path, st: os.stat_result, dfd: int, name: str,
                cur: os.stat_result | None, pinned: bool) -> None:
    mode = stat.S_IMODE(st.st_mode)
    regular = cur is not None and stat.S_ISREG(cur.st_mode) and cur.st_nlink == 1
    if regular and cur.st_size == st.st_size and _same_content(src, dfd, name):
        if stat.S_IMODE(cur.st_mode) != mode:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
            try:
                os.fchmod(fd, mode)
            finally:
                os.close(fd)
        return
    if cur is not None and not regular:
        _rm(dfd, name)  # a type change (or a planted link): briefly absent
    if pinned and regular:
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            _copy_into(fd, src, mode)
        finally:
            os.close(fd)
        return
    tmp = _temp_name(name)
    _rm(dfd, tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode, dir_fd=dfd)
    try:
        _copy_into(fd, src, mode)
    finally:
        os.close(fd)
    os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)


def _write_link(src: Path, dfd: int, name: str, cur: os.stat_result | None) -> None:
    target = os.readlink(src)
    if cur is not None and stat.S_ISLNK(cur.st_mode):
        if os.readlink(name, dir_fd=dfd) == target:
            return
    elif cur is not None:
        _rm(dfd, name)
    tmp = _temp_name(name)
    _rm(dfd, tmp)
    os.symlink(target, tmp, dir_fd=dfd)
    os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)


def _mirror_dir(src: Path | None, dfd: int, pinned: frozenset[str], rel: str) -> None:
    names = sorted(os.listdir(src)) if src is not None else []
    for name in names:
        _mirror_entry(src / name, os.lstat(src / name), dfd, name, pinned,
                      os.path.join(rel, name))
    for extra in sorted(set(os.listdir(dfd)) - set(names)):
        _rm(dfd, extra)


def _mirror_entry(src: Path | None, st: os.stat_result | None, dfd: int, name: str,
                  pinned: frozenset[str], rel: str) -> None:
    """Mirror ``src`` (None: missing, mirrored as an empty directory)."""
    cur = _lstat(dfd, name)
    if st is None or stat.S_ISDIR(st.st_mode):
        if cur is not None and not stat.S_ISDIR(cur.st_mode):
            _rm(dfd, name)
            cur = None
        if cur is None:
            os.mkdir(name, 0o700, dir_fd=dfd)
        cfd = os.open(name, _DIR, dir_fd=dfd)
        try:
            _mirror_dir(src if st is not None else None, cfd, pinned, rel)
            os.fchmod(cfd, stat.S_IMODE(st.st_mode) if st is not None else 0o755)
        finally:
            os.close(cfd)
    elif stat.S_ISLNK(st.st_mode):
        _write_link(src, dfd, name, cur)
    elif stat.S_ISREG(st.st_mode):
        _write_file(src, st, dfd, name, cur, rel in pinned)
    else:
        raise MirrorError(f"{src} is not a file, directory or link; cannot copy it")


def mirror_entries(root: Path, release_root: Path, entries: frozenset[str],
                   pinned: frozenset[str]) -> None:
    """Make ``root`` hold exactly ``entries`` of ``release_root``.

    A top-level entry that is a link in the release is copied as what it
    points to (Docker resolves a link given as a mount source). ``pinned``
    holds the paths, relative to ``root``, that are mount sources.
    """
    rfd = os.open(root, _DIR)
    try:
        for name in sorted(entries):
            src = release_root / name
            st = os.stat(src) if os.path.exists(src) else None
            _mirror_entry(src, st, rfd, name, pinned, name)
        for stale in sorted(set(os.listdir(rfd)) - set(entries)):
            _rm(rfd, stale)
    finally:
        os.close(rfd)
