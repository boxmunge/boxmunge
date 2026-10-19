# SPDX-License-Identifier: Apache-2.0
"""Walk a tree as root without following a link anywhere on the way.

Containers and the deploy user can write the trees the migration shifts
and the directories above them. So a tree's root is reached from / one
component at a time with O_NOFOLLOW, every entry is opened through its
directory's descriptor (O_NOFOLLOW, never a device), and the decisions are
made on the opened descriptor's own stat. A link anywhere is an error, or,
inside the tree, an entry that is never followed.
"""
from __future__ import annotations

import os
import resource
import stat
from pathlib import Path
from typing import Callable

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC


def open_parent_nofollow(path: Path) -> tuple[int, str]:
    """A descriptor for `path`'s parent, reached from / without following
    any link, and `path`'s last component. Raises OSError (ELOOP for a
    link on the way, ENOTDIR for a file)."""
    norm = os.path.normpath(path)
    if not os.path.isabs(norm) or norm == "/":
        raise ValueError(f"{path} is not an absolute path below /")
    parts = norm.split("/")[1:]
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


def _open_entry(name: str, st: os.stat_result, dir_fd: int) -> int | None:
    """A descriptor for a directory, regular file or FIFO; None otherwise."""
    if stat.S_ISDIR(st.st_mode):
        return os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    if stat.S_ISREG(st.st_mode) or stat.S_ISFIFO(st.st_mode):
        return os.open(name, _OPEN_FLAGS, dir_fd=dir_fd)
    return None  # symlink, socket or device: never opened


def raise_fd_limit() -> None:
    """The walk holds one descriptor per directory level; let it use as many
    as the hard limit allows (deep trees exceed the usual soft limit)."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != hard:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))


def _names(dir_fd: int) -> list[str]:
    with os.scandir(dir_fd) as it:
        return sorted((e.name for e in it), reverse=True)  # popped from the end


Visit = Callable[[str, os.stat_result, "int | None", int, str], None]


def _entry(dir_fd: int, name: str) -> tuple[os.stat_result, int | None]:
    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    fd = _open_entry(name, st, dir_fd)
    return (st if fd is None else os.fstat(fd)), fd


def walk(root: Path, visit: Visit) -> None:
    """Depth-first through descriptors (at most one open per level);
    visit(rel, st, fd, dir_fd, name) for the root and every entry."""
    parent, base = open_parent_nofollow(root)
    stack: list[tuple[int, str, list[str]]] = []
    try:
        st, fd = _entry(parent, base)
        try:
            visit(".", st, fd, parent, base)
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        if fd is None or not stat.S_ISDIR(st.st_mode):
            if fd is not None:
                os.close(fd)
            return
        stack.append((fd, ".", _names(fd)))
        while stack:
            dir_fd, rel_dir, names = stack[-1]
            if not names:
                stack.pop()
                os.close(dir_fd)
                continue
            name = names.pop()
            st, fd = _entry(dir_fd, name)
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            try:
                visit(rel, st, fd, dir_fd, name)
            except BaseException:
                if fd is not None:
                    os.close(fd)
                raise
            if fd is not None and stat.S_ISDIR(st.st_mode):
                stack.append((fd, rel, _names(fd)))
            elif fd is not None:
                os.close(fd)
    finally:
        for fd, _rel, _left in stack:
            os.close(fd)
        os.close(parent)


def reach_problem(root: Path) -> str | None:
    try:
        parent, base = open_parent_nofollow(root)
    except OSError as e:
        return f"{root}: cannot be reached without following a link ({e.strerror})"
    try:
        if stat.S_ISLNK(os.stat(base, dir_fd=parent, follow_symlinks=False).st_mode):
            return f"{root}: is a symlink"
    finally:
        os.close(parent)
    return None


def closed_to_other(root: Path) -> list[str]:
    """What a container reaching `root` through the "other" bits cannot
    read: files without o+r, directories without o+rx. Links are skipped."""
    closed: list[str] = []

    def visit(rel, st, _fd, _dir_fd, _name):
        if stat.S_ISLNK(st.st_mode):
            return
        need = 0o005 if stat.S_ISDIR(st.st_mode) else 0o004
        if st.st_mode & need != need:
            closed.append(str(root) if rel == "." else f"{root}/{rel}")

    walk(root, visit)
    return closed
