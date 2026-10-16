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
Network calls that do not need the lock (webhooks, Pushover) run after it
is released.
"""

import fcntl
import logging
import os
import pwd
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _chown_deploy(path: str) -> None:
    """Best-effort chown to the deploy user when running as root.

    Audit I-NEW-1 / C-NEW-4: distinguish KeyError (deploy user not yet
    created during bootstrap or in dev/test machines — silent return is
    correct) from OSError (perms drift, ENOSPC, EROFS, EIO, file-vanished
    races). OSError used to be silently swallowed alongside KeyError, which
    masked the same class of bug we spent two releases fixing. Now it logs
    a warning on the boxmunge logger so a forensic trail exists, but still
    does not raise — the caller is using us in a "best-effort" mode and
    the operational path should not fail because chown couldn't fix perms.
    """
    if os.getuid() != 0:
        return
    try:
        pw = pwd.getpwnam("deploy")
    except KeyError:
        # No 'deploy' user — bootstrap hasn't created it yet, or this is a
        # dev/test box where it isn't expected. Silent return preserves
        # existing behaviour.
        return
    try:
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except OSError as e:
        # Perms-related: log but don't raise — chown is best-effort. A
        # genuine perms problem will surface again in the operational
        # path that needs the file readable, with a more specific error.
        logging.getLogger("boxmunge").warning(
            "chown(%s, deploy) failed: %s", path, e,
        )


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
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o660)
    try:
        os.chmod(str(path), 0o660)
    except OSError:
        pass
    _chown_deploy(str(path))
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


def durable_rename(tmp_path: Path, path: Path) -> None:
    """Rename a fully written temp file over path, durably.

    The temp file must be in path's directory. Its data is synced before
    the rename and the directory after it, so after a crash path holds
    either the old content or the complete new content, never an empty or
    partial file, and never the old content once this has returned.
    """
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp_path, path)
    fsync_dir(path.parent)


def atomic_write_text(path: Path, content: str, mode: int | None = None) -> None:
    """Write UTF-8 text to path atomically and durably (see atomic_write_bytes)."""
    atomic_write_bytes(path, content.encode("utf-8"), mode)


def atomic_write_bytes(path: Path, content: bytes, mode: int | None = None) -> None:
    """Write bytes to path atomically and durably via temp file + rename.

    Creates parent directories if needed. Mode and ownership are set on
    the temp file, so the final file is never visible with the wrong
    permissions. See durable_rename for the crash guarantee.
    """
    mkdir_p_deploy(path.parent)

    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        if mode is not None:
            os.chmod(tmp_path, mode)
        _chown_deploy(tmp_name)
        durable_rename(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


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
