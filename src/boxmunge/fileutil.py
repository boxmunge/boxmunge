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
   (``registry_lock``), ``state/.caddy.lock`` (inside ``caddy_reload``), and
   ``state/.cve-grace.lock``. None of them is held while acquiring any
   other lock, and none is held across slow work.

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
    - Opens the file with mode 0o664 (group-writable) so both root and any
      uid in the deploy group can take the flock.
    - Chmods explicitly post-open in case umask narrowed the create mode.
    - Best-effort chgrp deploy when running as root, so a deploy uid can
      open the same file later.

    Returns the fd. Caller is responsible for fcntl.flock and os.close.
    """
    mkdir_p_deploy(path.parent)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o664)
    try:
        os.chmod(str(path), 0o664)
    except OSError:
        pass
    _chown_deploy(str(path))
    return fd


def atomic_write_text(path: Path, content: str, mode: int | None = None) -> None:
    """Write content to path atomically via temp file + rename.

    Creates parent directories if needed. Uses fsync for durability
    and os.rename for atomicity (same-filesystem guarantee).
    If mode is provided, the temp file is chmod'd before rename so
    the final file is never visible with wrong permissions.
    """
    mkdir_p_deploy(path.parent)

    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp_path, mode)
        os.rename(tmp_path, path)
        _chown_deploy(str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_write_bytes(path: Path, content: bytes, mode: int | None = None) -> None:
    """Write bytes to path atomically via temp file + rename.

    Binary counterpart of atomic_write_text. Creates parent directories
    if needed. Uses fsync for durability and os.rename for atomicity
    (same-filesystem guarantee). If mode is provided, the temp file is
    chmod'd before rename so the final file is never visible with wrong
    permissions.
    """
    mkdir_p_deploy(path.parent)

    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp_path, mode)
        os.rename(tmp_path, path)
        _chown_deploy(str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
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
    lock_path = paths.state / ".registry.lock"
    fd = open_shared_lockfile(lock_path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
