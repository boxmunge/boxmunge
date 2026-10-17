"""File utilities — atomic writes and project locking.

Lock order
----------
Root timers and deploy-user commands coordinate through advisory flocks.
To rule out deadlock, a process only ever acquires them in this order
(outermost first) and releases them in reverse:

1. ``upgrade-root/upgrade.lock``, then the legacy ``upgrade-state/upgrade.lock``
   older shims take: one platform upgrade at a time (upgrade shim,
   ``auto-update``, ``check-probation``, ``legacy-stage``).
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

import fcntl
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from boxmunge.fs_nofollow import fchown_deploy, mkdir_p_deploy, open_regular_nofollow

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


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
    fchown_deploy(fd, str(path))
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
                fchown_deploy(f.fileno(), tmp_name)
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
