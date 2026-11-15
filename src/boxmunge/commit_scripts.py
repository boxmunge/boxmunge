# SPDX-License-Identifier: Apache-2.0
"""A git release's boxmunge-scripts/, installed from its checked-out commit.

The overlay mounts ``./boxmunge-scripts`` from the release's top directory
(the project dir, or a git slot's release) and a relative pre_deploy runs
from there, but a git project commits its scripts in ``repo/``. So after
every checkout of a commit that has ``boxmunge-scripts/``, the release's
copy is refreshed from it. A commit without one leaves an existing copy as
it is (scripts placed by hand before 0.12, which a rollback target may
need).

Root runs this under sudo, and both trees are the deploy user's, who can
swap any entry while it runs. So nothing is reached by name: directories are
opened one component at a time without following a link, entries are
copied through descriptors that refuse links and never keep setuid or
setgid bits, and the destination's top directory keeps its inode (a running
container's bind mount of it survives).
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from boxmunge.data_dirs import ReleaseStateError
from boxmunge.fs_nofollow import (
    chown_open_tree_deploy, clear_dir_nofollow, copy_entry_nofollow, open_dir_beneath,
)

SCRIPTS = "boxmunge-scripts"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def script_links(scripts: Path) -> list[str]:
    """Every symbolic link under ``scripts`` (and ``scripts`` itself), as
    paths relative to its parent. A link is never installed: its target is
    not in the container that mounts the copy."""
    if os.path.islink(scripts):
        return [scripts.name]
    found = []
    for root, dirs, files in os.walk(scripts, followlinks=False):
        for name in dirs + files:
            path = os.path.join(root, name)
            if os.path.islink(path):
                found.append(os.path.relpath(path, scripts.parent))
    return sorted(found)


def links_refusal(links: list[str], where: str) -> str:
    return (f"{', '.join(links)} {'is a' if len(links) == 1 else 'are'} symbolic "
            f"link{'' if len(links) == 1 else 's'} in {where}. boxmunge copies a git "
            f"project's {SCRIPTS}/ out of the repository and never follows a link: commit "
            f"the scripts as regular files, then deploy that commit")


def install_commit_scripts(tree: Path) -> None:
    """Refresh ``tree/boxmunge-scripts`` from ``tree/repo/boxmunge-scripts``
    (module docstring). Raises ReleaseStateError for a committed entry that
    is not a directory of regular files and directories; OSError if copying
    fails."""
    src_path = tree / "repo" / SCRIPTS
    try:
        st = os.lstat(src_path)
    except FileNotFoundError:
        if os.path.lexists(tree / SCRIPTS):
            print(f"  NOTE: the checked-out commit carries no {SCRIPTS}/; the existing "
                  f"{tree / SCRIPTS} was left in place")
        return
    if not stat.S_ISDIR(st.st_mode):
        what = "a symbolic link" if stat.S_ISLNK(st.st_mode) else "not a directory"
        raise ReleaseStateError(
            f"{src_path} is {what}. boxmunge copies a git project's {SCRIPTS}/ from the "
            f"checked-out commit: commit it as a directory of scripts at the top of the "
            f"repository, then deploy that commit")
    links = script_links(src_path)
    if links:
        raise ReleaseStateError(links_refusal(links, "the checked-out commit"))
    src = open_dir_beneath(tree, ["repo", SCRIPTS])
    try:
        dest = _open_dest(tree)
        try:
            clear_dir_nofollow(dest)
            _copy_tree(src, dest, SCRIPTS)
            chown_open_tree_deploy(dest, str(tree / SCRIPTS))
        finally:
            os.close(dest)
    finally:
        os.close(src)


def _open_dest(tree: Path) -> int:
    """``tree/boxmunge-scripts`` opened as a directory: the existing one
    (never replaced, so its inode stays), or a new one where nothing or a
    non-directory (a link, a file) was."""
    top = os.open(tree, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        try:
            return os.open(SCRIPTS, _DIR_FLAGS, dir_fd=top)
        except FileNotFoundError:
            pass
        except OSError:  # ELOOP or ENOTDIR: a link or a file at the name
            os.unlink(SCRIPTS, dir_fd=top)
        os.mkdir(SCRIPTS, 0o755, dir_fd=top)
        return os.open(SCRIPTS, _DIR_FLAGS, dir_fd=top)
    finally:
        os.close(top)


def _copy_tree(src: int, dest: int, label: str) -> None:
    for name in sorted(os.listdir(src)):
        where = f"{label}/{name}"
        st = os.stat(name, dir_fd=src, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            os.mkdir(name, 0o700, dir_fd=dest)
            child_src = os.open(name, _DIR_FLAGS, dir_fd=src)
            try:
                child_dest = os.open(name, _DIR_FLAGS, dir_fd=dest)
                try:
                    _copy_tree(child_src, child_dest, where)
                    os.fchmod(child_dest, stat.S_IMODE(st.st_mode) & 0o1777 | 0o700)
                finally:
                    os.close(child_dest)
            finally:
                os.close(child_src)
        elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
            copy_entry_nofollow(src, name, dest)
            _make_regular(dest, name, where, executable=name.endswith(".sh"))
        else:
            raise ReleaseStateError(
                f"{where} in the checked-out commit is not a regular file or directory "
                f"(or it changed while it was copied): commit regular files, then deploy "
                f"that commit")


def _make_regular(dest: int, name: str, where: str, *, executable: bool) -> None:
    """The copy just made must be a regular file (an entry swapped for a link
    since the check is copied as one, and is refused here); a ``*.sh`` is
    made executable, as a bundle install makes it."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=dest)
    except OSError as e:
        os.unlink(name, dir_fd=dest)
        raise ReleaseStateError(f"{where} changed while it was copied ({e}); deploy "
                                f"again") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReleaseStateError(f"{where} changed while it was copied; deploy again")
        if executable:
            os.fchmod(fd, stat.S_IMODE(st.st_mode) | 0o755)
    finally:
        os.close(fd)
