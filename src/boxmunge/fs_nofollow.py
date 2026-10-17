# SPDX-License-Identifier: Apache-2.0
"""Root's file operations in directories the deploy user can write.

Whoever can write a directory can swap any name in it for a symlink, a
hard link or a FIFO between root's check and root's use. These helpers
never reach a file through such a name: opens refuse links and anything
but a plain regular file without blocking, chmod and chown act on the
entry itself, and tree walks go through directory descriptors. They also
hand what root creates there to deploy, best-effort.
"""

import errno
import fcntl
import logging
import os
import pwd
import stat
from pathlib import Path


def running_as_root() -> bool:
    """Whether boxmunge runs as root. The real uid: boxmunge is never
    installed setuid, so it equals the effective one (root by login or
    sudo), and every root-only path here and in git_slot asks this."""
    return os.getuid() == 0


def _deploy_owner() -> tuple[int, int] | None:
    """deploy's (uid, gid) when running as root and deploy exists, else None.

    KeyError means no deploy user (bootstrap not done yet, or a dev/test
    machine), where there is nothing to hand ownership to.
    """
    if not running_as_root():
        return None
    try:
        pw = pwd.getpwnam("deploy")
    except KeyError:
        return None
    return pw.pw_uid, pw.pw_gid


def _warn_chown(what: str, e: OSError) -> None:
    # Audit I-NEW-1 / C-NEW-4: perms drift, ENOSPC, EROFS, EIO and races
    # are logged for a forensic trail but do not raise; the caller uses
    # this best-effort and a real perms problem resurfaces where the file
    # is needed.
    logging.getLogger("boxmunge").warning("chown(%s, deploy) failed: %s", what, e)


def _chown_deploy(path: str) -> None:
    """Best-effort chown to the deploy user when running as root.

    Never follows a symlink: these paths sit in directories the deploy user
    can write, so deploy could swap the entry for a link between our
    creating it and this call. On a link, only the link itself is
    re-owned, which grants nothing.
    """
    owner = _deploy_owner()
    if owner is None:
        return
    try:
        os.chown(path, *owner, follow_symlinks=False)
    except OSError as e:
        _warn_chown(path, e)


def fchown_deploy(fd: int, what: str) -> None:
    """Best-effort chown of an open descriptor to deploy (see _chown_deploy)."""
    owner = _deploy_owner()
    if owner is None:
        return
    try:
        os.fchown(fd, *owner)
    except OSError as e:
        _warn_chown(what, e)


def open_regular_nofollow(path: Path, flags: int, mode: int = 0o600) -> int:
    """os.open that refuses a symlink, a non-regular file or an extra hard link.

    For root opening a name in a directory the deploy user can write: a
    planted symlink (or a hard link to another file) would otherwise make
    root read, write, chmod or chown a file outside it. It opens O_NONBLOCK,
    so a planted FIFO is refused at once instead of blocking the open; the
    flag is cleared once the file is known to be regular, so callers get an
    ordinary blocking descriptor.
    """
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, mode)
    except OSError as e:
        # ENXIO: a write-only open of a FIFO (or socket) nobody reads.
        what = {errno.ELOOP: "a symlink", errno.ENXIO: "a FIFO or socket"}.get(e.errno)
        if what is None:
            raise
        raise OSError(e.errno, f"{path} is {what}, not a plain regular file; refusing "
                      "to use it. Remove it so it can be recreated.") from e
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise OSError(
            f"{path} is not a plain regular file (mode {oct(st.st_mode)}, "
            f"{st.st_nlink} links); refusing to use it. Remove it so it can be recreated."
        )
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
    return fd


def read_text_nofollow(path: Path) -> str:
    """A UTF-8 file's text, read without following a link (see
    open_regular_nofollow). Raises OSError (or UnicodeDecodeError)."""
    with os.fdopen(open_regular_nofollow(path, os.O_RDONLY), encoding="utf-8") as f:
        return f.read()


def chmod_nofollow(path: Path, mode: int | None = None, add: int = 0) -> None:
    """chmod that refuses a symlink rather than following it.

    Sets ``mode``, or adds ``add`` to the current bits. Linux has no lchmod,
    so the file is pinned with an O_PATH descriptor (which needs no read
    permission, so a 0000 file of the caller's own still works) and chmod'd
    through its /proc/self/fd entry. Elsewhere lchmod does the same job.
    """
    if hasattr(os, "O_PATH"):
        fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if stat.S_ISLNK(st.st_mode):
                raise OSError(f"{path} is a symlink; refusing to chmod through it")
            new = mode if mode is not None else stat.S_IMODE(st.st_mode) | add
            os.chmod(f"/proc/self/fd/{fd}", new)
        finally:
            os.close(fd)
        return
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise OSError(f"{path} is a symlink; refusing to chmod through it")
    new = mode if mode is not None else stat.S_IMODE(st.st_mode) | add
    os.chmod(path, new, follow_symlinks=False)


def mkdir_p_deploy(path: Path) -> None:
    """mkdir -p, then chown each newly-created directory to deploy.

    Plain ``Path.mkdir(parents=True, exist_ok=True)`` running as root leaves
    every new intermediate directory owned by root. A subsequent atomic-write
    from the unprivileged deploy shell then can't create a tempfile in the
    new directory and fails with EACCES — observed when `security suppress`
    tried to write the first entry into a root-owned `<project>/security/`
    that an earlier root-run code path had created.

    This helper creates the same chain but chowns each directory we
    actually create to deploy. Pre-existing directories are intentionally
    left untouched: we don't want to retroactively re-own legitimately
    root-owned parents (e.g. /opt/boxmunge itself). Best-effort like
    `_chown_deploy` — silent when not running as root or when the deploy
    user does not yet exist.
    """
    to_create: list[Path] = []
    cur = path
    while not cur.exists():
        to_create.append(cur)
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    for p in reversed(to_create):
        try:
            p.mkdir()
        except FileExistsError:
            # Race: another process created it between exists() and mkdir().
            # Don't chown — ownership belongs to whoever won the race.
            continue
        _chown_deploy(str(p))


def chown_tree_deploy(path: Path) -> None:
    """Best-effort chown of ``path`` and everything under it to deploy.

    For trees a root-run path (upgrade) copies that the deploy shell must
    later replace. Deploy can swap any entry for a link while this runs, so
    nothing is reached by name: the top is opened without following a link
    (a link or a file there is re-owned itself, which grants nothing), the
    walk goes through directory descriptors (os.fwalk refuses a directory
    swapped for a link), and each entry is re-owned relative to its
    directory without following a link. Same best-effort rules as
    ``_chown_deploy``.
    """
    if not running_as_root():
        return
    owner = _deploy_owner()
    if owner is None:
        return
    try:
        top = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            _chown_deploy(str(path))  # a link or a file: re-own just that
        else:
            _warn_chown(str(path), e)
        return
    try:
        try:
            os.fchown(top, *owner)
        except OSError as e:
            _warn_chown(str(path), e)
        for root, dirs, files, dirfd in os.fwalk(".", dir_fd=top, follow_symlinks=False):
            for name in dirs + files:
                try:
                    os.chown(name, *owner, dir_fd=dirfd, follow_symlinks=False)
                except OSError as e:
                    _warn_chown(os.path.join(str(path), root, name), e)
    finally:
        os.close(top)
