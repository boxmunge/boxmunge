"""File utilities — atomic writes and project locking.

Lock order
----------
Root timers and deploy-user commands coordinate through advisory flocks.
To rule out deadlock, a process only ever acquires them in this order
(outermost first) and releases them in reverse:

1. ``upgrade-state/upgrade.lock``: one platform upgrade at a time (upgrade
   shim, ``auto-update``, ``check-probation``).
2. ``state/container-updates/.lock``: one ``container-update`` run at a time.
3. ``state/<project>.lock`` (``project_lock``): every mutation of one
   project's compose, Caddy, or lifecycle state: deploy, stage, promote,
   unstage, rollback, restore, backup, pause, resume, recover,
   project-delete, container-update, CVE scan and quarantine lift, and the
   health tick. Non-blocking. A process holds **at most one** project lock
   and never acquires a second project lock while holding one.
4. Short blocking locks, always innermost: ``state/.registry.lock``
   (``registry_lock``), ``state/.caddy.lock`` (inside ``caddy_reload``),
   ``state/.cve-grace.lock``, and ``state/secrets-locks/*.lock`` (one per
   secrets file, around every write of it). None of them is held while
   acquiring any other lock, and none is held across slow work.

Gating checks (paused, quarantined, monitor-stopped) that decide whether a
project may be mutated are made *after* taking the project lock, so a
concurrent quarantine cannot land between the check and the action.

One lock owner: every operate command is split into an entry point
(``run_*``) that prompts, takes the project lock and does nothing else, and
a core (``*_locked``) that assumes the lock is held, never acquires it, and
rechecks eligibility (lifecycle blocks, staging state) itself immediately
before mutating. Cores call other cores, never another entry point, so a
composed operation (promote = deploy + unstage) holds one lock throughout.
Network calls that do not need the lock (webhooks, Pushover) run after it
is released.
"""

import errno
import fcntl
import logging
import os
import pwd
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _deploy_owner() -> tuple[int, int] | None:
    """deploy's (uid, gid) when running as root and deploy exists, else None.

    KeyError means no deploy user (bootstrap not done yet, or a dev/test
    machine), where there is nothing to hand ownership to.
    """
    if os.getuid() != 0:
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


def _fchown_deploy(fd: int, what: str) -> None:
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
    later replace. Links are re-owned, never followed. Same best-effort
    rules as ``_chown_deploy``.
    """
    if os.getuid() != 0:
        return
    _chown_deploy(str(path))
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            target = os.path.join(root, name)
            if os.path.islink(target):
                continue
            _chown_deploy(target)


def open_shared_lockfile(path: Path) -> int:
    """Open (or create) a lock file usable by both root and the deploy user.

    boxmunge runs ops under multiple uids: root for the upgrade shim and
    systemd timers, deploy for the restricted shell. Without explicit perms,
    whichever uid creates a lock file first locks the other out forever
    (lock files persist across reboots in /opt/boxmunge/state).

    This helper:
    - Creates the parent directory if needed.
    - Opens the file with mode 0o660 so both root and any uid in the deploy
      group can take the flock, and nobody else can: flock needs only a
      read-only descriptor, so a world-readable lock file would let any
      local user hold it and stall boxmunge.
    - Chmods explicitly post-open in case umask narrowed the create mode.
    - Best-effort chgrp deploy when running as root, so a deploy uid can
      open the same file later.

    Returns the fd. Caller is responsible for fcntl.flock and os.close.
    """
    mkdir_p_deploy(path.parent)
    fd = open_regular_nofollow(path, os.O_CREAT | os.O_RDWR, 0o660)
    try:
        os.fchmod(fd, 0o660)
    except OSError:
        pass  # not the owner: root, which owns it, set it up
    _fchown_deploy(fd, str(path))
    return fd


def fsync_dir(path: Path) -> None:
    """fsync a directory, making the names created or renamed in it durable.

    A rename() or link() is atomic but not durable: until the directory is
    synced, a power loss can bring back the old name or lose the new one.
    """
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RenamedNotSyncedError(OSError):
    """durable_rename renamed the file, but syncing its directory failed:
    path already holds the new content, though a crash may bring back the old."""


def durable_rename(tmp_path: Path, path: Path) -> None:
    """Rename a fully written temp file over path, durably.

    The temp file must be in path's directory. Its data is synced before
    the rename and the directory after it, so after a crash path holds
    either the old content or the complete new content, never an empty or
    partial file, and never the old content once this has returned.
    Raises RenamedNotSyncedError (an OSError) when only the directory sync
    failed, so a caller can tell a done rename from a failed one.
    """
    fd = open_regular_nofollow(tmp_path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp_path, path)
    try:
        fsync_dir(path.parent)
    except OSError as e:
        raise RenamedNotSyncedError(
            e.errno, f"{tmp_path.name} was renamed to {path}, but {path.parent} was not "
            f"synced: {e.strerror or e}") from e


class LinkedTargetError(OSError):
    """The destination of a write that refuses links is a symlink."""


def atomic_write_text(
    path: Path, content: str, mode: int | None = None, *, refuse_link: bool = False,
) -> None:
    """Write UTF-8 text to path atomically and durably (see atomic_write_bytes)."""
    atomic_write_bytes(path, content.encode("utf-8"), mode, refuse_link=refuse_link)


def atomic_write_bytes(
    path: Path, content: bytes, mode: int | None = None,
    owner: tuple[int, int] | None = None, *, refuse_link: bool = False,
) -> None:
    """Write bytes to path atomically and durably via temp file + rename.

    Creates parent directories if needed. Mode and ownership (``owner``, or
    deploy when running as root) are set on the temp file's descriptor, so
    the final file is never visible with the wrong permissions and a temp
    swapped for a symlink cannot redirect them. See durable_rename for the
    crash guarantee.

    With ``refuse_link``, a symlink at path raises LinkedTargetError instead
    of being replaced. It is checked after the temp is written, right before
    the rename; rename(2) cannot refuse a symlink itself, so a link created in
    the instant between the two is still replaced. Only a writer of path's
    directory can do that, and it could replace the file anyway.
    """
    mkdir_p_deploy(path.parent)

    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            if mode is not None:
                os.fchmod(f.fileno(), mode)
            if owner is not None:
                os.fchown(f.fileno(), *owner)
            else:
                _fchown_deploy(f.fileno(), tmp_name)
        if refuse_link and path.is_symlink():
            raise LinkedTargetError(f"{path} is a symlink; refusing to replace it")
        durable_rename(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


DISCARDED = ".discarded"


def _fsync_file(full: str) -> None:
    try:
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise OSError(e.errno, f"cannot sync {full}: {e.strerror}") from e
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_tree(path: Path) -> None:
    """fsync every regular file and directory under ``path`` (itself
    included) without following links, so a directory renamed into place
    afterwards cannot come back from a power loss holding empty files."""
    if os.path.islink(path):
        raise OSError(f"{path} is a symlink; refusing to sync through it")
    for root, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            full = os.path.join(root, name)
            if stat.S_ISREG(os.lstat(full).st_mode):
                _fsync_file(full)
        fsync_dir(Path(root))


def sync_entries(entries: list[Path], parent: Path) -> None:
    """fsync the given entries of ``parent`` (trees whole, links not
    followed) and then ``parent`` itself, which holds their names."""
    for entry in entries:
        mode = os.lstat(entry).st_mode
        if stat.S_ISDIR(mode):
            sync_tree(entry)
        elif stat.S_ISREG(mode):
            _fsync_file(str(entry))
    fsync_dir(parent)


def durable_rename_dir(src: Path, dest: Path) -> None:
    """Rename a directory to a name that must not exist, durably."""
    if os.path.lexists(dest):
        raise FileExistsError(f"{dest} already exists; refusing to replace it")
    os.rename(src, dest)
    fsync_dir(dest.parent)
    if src.parent != dest.parent:
        fsync_dir(src.parent)


def _rmtree_real_dir(path: Path) -> None:
    if os.path.islink(path) or not os.path.isdir(path):
        raise OSError(f"{path} is not a directory; refusing to discard it")
    shutil.rmtree(path)


def discard_dir(path: Path) -> None:
    """Remove a directory so that a crash never leaves it half-deleted under
    its own name: renamed to ``<name>.discarded`` first, then removed. A
    name already ending in ``.discarded`` (debris) is removed directly.
    Never follows a link."""
    if not os.path.lexists(path):
        return
    if path.name.endswith(DISCARDED):
        _rmtree_real_dir(path)
        fsync_dir(path.parent)
        return
    if os.path.islink(path) or not path.is_dir():
        raise OSError(f"{path} is not a directory; refusing to discard it")
    doomed = path.with_name(path.name + DISCARDED)
    if os.path.lexists(doomed):
        _rmtree_real_dir(doomed)
    os.rename(path, doomed)
    fsync_dir(path.parent)
    _rmtree_real_dir(doomed)
    fsync_dir(path.parent)


def sweep_discarded(directory: Path) -> None:
    """Remove the ``*.discarded`` debris a crash inside discard_dir left in
    ``directory``. Run by the cores that own it, under the project lock."""
    if not directory.is_dir():
        return
    for doomed in sorted(directory.glob(f"*{DISCARDED}")):
        discard_dir(doomed)


class LockError(Exception):
    """Raised when a project lock cannot be acquired."""


@contextmanager
def project_lock(project_name: str, paths: "BoxPaths") -> Iterator[None]:
    """Acquire an exclusive per-project lock. Non-blocking.

    Raises LockError if another operation holds the lock.
    Lock files are left on disk after release (advisory flock).
    """
    lock_path = paths.project_lock_file(project_name)
    fd = open_shared_lockfile(lock_path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise LockError(
            f"Another operation is in progress for '{project_name}'. "
            f"Try again shortly."
        )
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@contextmanager
def registry_lock(paths: "BoxPaths") -> Iterator[None]:
    """Acquire an exclusive registry-wide lock. Blocking.

    Used to serialise load -> mutate -> save sequences against the project
    registry (state/projects.txt) so concurrent add/remove calls cannot lose
    each other's writes. Scope is registry-wide rather than per-project: the
    operation we're protecting is "rewrite the whole projects.txt", which
    sees every name.

    Blocks (LOCK_EX without LOCK_NB) — the protected critical section is a
    tiny file rewrite, so contention should resolve in milliseconds. We
    deliberately do not raise LockError here: callers are
    add_project / remove_project, which the operator expects to succeed
    rather than fail with "try again".
    """
    with exclusive_lock(paths.state / ".registry.lock"):
        yield


@contextmanager
def exclusive_lock(lock_path: Path) -> Iterator[None]:
    """Hold an exclusive flock on lock_path for the block. Blocking.

    For short critical sections only (a small file's read-modify-write),
    so waiting is preferable to failing with "try again".
    """
    fd = open_shared_lockfile(lock_path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
