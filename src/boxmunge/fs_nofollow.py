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


def deploy_ids() -> tuple[int, int] | None:
    """deploy's (uid, gid), or None when there is no deploy user (bootstrap
    not done yet, or a dev/test machine). Whoever asks."""
    try:
        pw = pwd.getpwnam("deploy")
    except KeyError:
        return None
    return pw.pw_uid, pw.pw_gid


def _deploy_owner() -> tuple[int, int] | None:
    """deploy's (uid, gid) when running as root and deploy exists, else None:
    with no deploy user there is nothing to hand ownership to."""
    return deploy_ids() if running_as_root() else None


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
    if not running_as_root() or _deploy_owner() is None:
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
        chown_open_tree_deploy(top, str(path))
    finally:
        os.close(top)


def chown_open_tree_deploy(top: int, label: str, *, only_uid: int | None = None) -> None:
    """chown_tree_deploy for a directory the caller opened without following
    a link (``label`` names it in warnings): the descriptor itself, then
    everything under it, reached only through directory descriptors.

    A file with other links is skipped with a warning, always: its inode may
    be shared with a file outside the tree, which deploy must not gain. With
    ``only_uid``, only entries owned by that uid are re-owned, so what a
    container user or deploy made is not touched.
    """
    owner = _deploy_owner()
    if owner is None:
        return
    try:
        if only_uid is None or os.fstat(top).st_uid == only_uid:
            os.fchown(top, *owner)
    except OSError as e:
        _warn_chown(label, e)
    for root, dirs, files, dirfd in os.fwalk(".", dir_fd=top, follow_symlinks=False):
        for name in dirs + files:
            where = os.path.join(label, root, name)
            try:
                _chown_entry(name, dirfd, where, owner, only_uid)
            except OSError as e:
                _warn_chown(where, e)


def _chown_entry(name: str, dirfd: int, where: str, owner: tuple[int, int],
                 only_uid: int | None) -> None:
    """Re-own one entry through a descriptor opened on it without following a
    link, so the checks and the chown are about the same inode however the
    name is swapped meanwhile. Never blocks on a FIFO (O_NONBLOCK)."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=dirfd)
    except OSError as e:
        if e.errno != errno.ELOOP:
            raise
        # A link: re-own the link itself, which grants nothing.
        st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        if only_uid is None or st.st_uid == only_uid:
            os.chown(name, *owner, dir_fd=dirfd, follow_symlinks=False)
        return
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) and st.st_nlink > 1:
            # Its inode may be shared with a file outside the tree. Already
            # deploy's (a `git clone --local` of a stage) is nothing to report.
            if st.st_uid != owner[0]:
                logging.getLogger("boxmunge").warning(
                    "not re-owning %s: it has %d links", where, st.st_nlink)
            return
        if only_uid is None or st.st_uid == only_uid:
            os.fchown(fd, *owner)
    finally:
        os.close(fd)


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def copy_entry_nofollow(src_dir: int, name: str, dest_dir: int) -> None:
    """Copy entry ``name`` of the open directory ``src_dir`` into the open
    directory ``dest_dir``, never through a link on either side: a link is
    copied as a link; a regular file through descriptors that refuse a link
    and never block on a FIFO, its destination created exclusively (a name
    planted there is refused, not written through); a directory
    recursively, through directory descriptors. Modes are kept without the
    setuid and setgid bits. Anything else raises OSError."""
    st = os.stat(name, dir_fd=src_dir, follow_symlinks=False)
    # Never setuid or setgid: root makes these files, in a tree deploy owns.
    mode = stat.S_IMODE(st.st_mode) & 0o1777
    if stat.S_ISLNK(st.st_mode):
        os.symlink(os.readlink(name, dir_fd=src_dir), name, dir_fd=dest_dir)
    elif stat.S_ISREG(st.st_mode):
        _copy_file(src_dir, name, dest_dir, mode)
    elif stat.S_ISDIR(st.st_mode):
        os.mkdir(name, 0o700, dir_fd=dest_dir)
        src = os.open(name, _DIR_FLAGS, dir_fd=src_dir)
        try:
            dest = os.open(name, _DIR_FLAGS, dir_fd=dest_dir)
            try:
                for child in sorted(os.listdir(src)):
                    copy_entry_nofollow(src, child, dest)
                os.fchmod(dest, mode)
            finally:
                os.close(dest)
        finally:
            os.close(src)
    else:
        raise OSError(f"{name} is not a file, directory or link; refusing to copy it")


def _copy_file(src_dir: int, name: str, dest_dir: int, mode: int) -> None:
    src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                  dir_fd=src_dir)
    try:
        if not stat.S_ISREG(os.fstat(src).st_mode):
            raise OSError(f"{name} changed while it was copied; refusing to copy it")
        dest = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=dest_dir)
        try:
            while chunk := os.read(src, 1 << 20):
                os.write(dest, chunk)
            os.fchmod(dest, mode)
        finally:
            os.close(dest)
    finally:
        os.close(src)
