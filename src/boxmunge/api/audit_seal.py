# SPDX-License-Identifier: Apache-2.0
"""The audit log's append-only attribute, and root's seal of the log.

logs/audit.jsonl is deploy's (apid, the CLI and MCP all write it as deploy),
mode 0640, with the filesystem's append-only attribute (`chattr +a`): every
writer can append, and none, its owner included, can truncate, rewrite,
rename or delete it. Only root can set or clear the attribute. install runs
`boxmunge-server _audit-seal` (seal) to make the log so; the monthly rotation
(api.audit_rotate) moves it aside the same way.

Some hosts cannot set the attribute at all: a filesystem without it, or a
container whose root lacks CAP_LINUX_IMMUTABLE. There the seal records why in
upgrade-root/audit-append-unsupported and leaves the log deploy's, 0640,
without it: the box installs, and `health` warns. On every other host a log
without the attribute is an error, except while a rotation, which marks
itself in upgrade-root/audit-rotating, has the log moved aside.

logs/ is deploy's, so every name there is opened without following a link
(fs_nofollow). The records are in root-only upgrade-root/, so deploy cannot
put one there, and each still counts only when root owns it.
"""
from __future__ import annotations

import errno
import fcntl
import os
import re
import stat
import struct
import time
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.api.audit import AUDIT_MODE
from boxmunge.fileutil import atomic_write_bytes
from boxmunge.fs_nofollow import deploy_ids, open_regular_nofollow, running_as_root

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_APPEND_FL = 0x20
SEAL_FIX = "sudo boxmunge-server _audit-seal"
RECORD_MODE = 0o600
RECORD_LIMIT_BYTES = 4096
# A rotation takes well under a second; a marker older than this was left by
# one that was killed, and is ignored.
ROTATION_MARKER_FRESH_SECONDS = 600

# The kernel boundary, a seam: tests replace it, as the ioctls need Linux and,
# to set +a, CAP_LINUX_IMMUTABLE.
_ioctl = fcntl.ioctl


class SealError(Exception):
    """The audit log could not be sealed, checked or rotated. *fix* is what
    the operator runs (or does) about this failure."""

    def __init__(self, message: str, fix: str = SEAL_FIX) -> None:
        super().__init__(message)
        self.fix = fix


class AppendUnsupported(SealError):
    """This host cannot set the append-only attribute at all."""

    def __init__(self, message: str, errno_name: str, filesystem: Path) -> None:
        super().__init__(message)
        self.errno_name = errno_name
        self.filesystem = filesystem


def _root_owner() -> tuple[int, int]:
    """The owner the unsupported record must have (a seam for tests)."""
    return 0, 0


def archives(logs: Path, active: str) -> list[str]:
    """The names of the audit log's archives (<active>.<YYYY-MM-DD>), newest first."""
    pattern = re.compile(rf"{re.escape(active)}\.\d{{4}}-\d{{2}}-\d{{2}}")
    return sorted((name for name in os.listdir(logs) if pattern.fullmatch(name)), reverse=True)


def is_append_only(fd: int) -> bool:
    """Whether the open file carries the append-only attribute. Raises OSError."""
    flags = struct.unpack("i", _ioctl(fd, FS_IOC_GETFLAGS, struct.pack("i", 0)))[0]
    return bool(flags & FS_APPEND_FL)


def _attribute_error(e: OSError, doing: str, where: Path) -> SealError:
    name = errno.errorcode.get(e.errno or 0, str(e.errno))
    if e.errno in (errno.EOPNOTSUPP, errno.ENOTTY):
        return AppendUnsupported(
            f"the filesystem under {where.parent} does not support the append-only "
            f"attribute ({name}: {e.strerror})", name, where.parent)
    if e.errno == errno.EPERM and running_as_root():
        return AppendUnsupported(
            f"root may not set the append-only attribute on the filesystem under "
            f"{where.parent} ({name}: {e.strerror}; a container without "
            f"CAP_LINUX_IMMUTABLE does this)", name, where.parent)
    return SealError(f"cannot {doing} the append-only attribute of {where} ({name}: {e.strerror})")


def set_append_only(fd: int, on: bool, *, where: Path) -> None:
    """Set or clear the append-only attribute of the open file *where*, then
    read it back. Raises AppendUnsupported when this host cannot set it at
    all (EOPNOTSUPP, ENOTTY, or EPERM for root), SealError otherwise."""
    doing = "set" if on else "clear"
    try:
        flags = struct.unpack("i", _ioctl(fd, FS_IOC_GETFLAGS, struct.pack("i", 0)))[0]
        wanted = flags | FS_APPEND_FL if on else flags & ~FS_APPEND_FL
        if wanted != flags:
            _ioctl(fd, FS_IOC_SETFLAGS, struct.pack("i", wanted))
        now = is_append_only(fd)
    except OSError as e:
        raise _attribute_error(e, doing, where) from e
    if now != on:
        raise SealError(f"the append-only attribute of {where} did not {doing}: "
                        f"it reads {'set' if now else 'clear'} afterwards")


def own_and_seal(fd: int, where: Path, *, attribute: bool) -> None:
    """Make the open file *where* deploy's and 0640, with the attribute when
    *attribute*. chown and chmod are refused on an append-only file, so it is
    cleared for them first. Raises SealError."""
    owner = deploy_ids()
    if owner is None:
        raise SealError(f"there is no deploy user to own {where}; run install.sh")
    if attribute:
        set_append_only(fd, False, where=where)
    try:
        os.fchown(fd, *owner)
        os.fchmod(fd, AUDIT_MODE)
    except OSError as e:
        raise SealError(f"cannot make {where} deploy's and 0640: {e}") from e
    if attribute:
        set_append_only(fd, True, where=where)


def open_log(path: Path, *, create: bool) -> int:
    """A descriptor of the audit log (or an archive), never through a link,
    a FIFO or a file with a second hard link. Raises SealError; a missing
    file raises FileNotFoundError when not *create*."""
    try:
        if create:
            return open_regular_nofollow(path, os.O_RDONLY | os.O_CREAT, AUDIT_MODE)
        return open_regular_nofollow(path, os.O_RDONLY)
    except FileNotFoundError:
        if create:
            raise SealError(f"cannot create {path}: its directory is missing") from None
        raise
    except OSError as e:
        raise SealError(str(e)) from e


def read_unsupported(paths: BoxPaths) -> str | None:
    """The record's line ("<errno name> <filesystem>"), or None when there is
    none. A record root does not own, or one that is a link or not a plain
    file, is refused with SealError: a record that is not root's own would
    keep the log unsealed. Raises PermissionError for a caller who is not
    root (upgrade-root/ is root's alone): health reports that as needing root."""
    path = paths.audit_append_unsupported
    try:
        fd = open_regular_nofollow(path, os.O_RDONLY)
    except FileNotFoundError:
        return None
    except PermissionError:
        raise
    except OSError as e:
        raise SealError(f"{e}. Then run as root: {SEAL_FIX}") from e
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if (st.st_uid, st.st_gid) != _root_owner():
            raise SealError(f"{path} is not root's (uid {st.st_uid}), so it does not show "
                            f"that this host cannot set the append-only attribute. Remove it "
                            f"and run as root: {SEAL_FIX}")
        data = f.read(RECORD_LIMIT_BYTES + 1)
    if len(data) > RECORD_LIMIT_BYTES:
        raise SealError(f"{path} is larger than {RECORD_LIMIT_BYTES} bytes; remove it and "
                        f"run as root: {SEAL_FIX}")
    return data.decode("utf-8", errors="replace").strip()


def _root_dir(paths: BoxPaths) -> None:
    """upgrade-root/, root's alone: created 0700 if missing, refused if it
    is a link or not root's."""
    try:
        os.mkdir(paths.upgrade_root, 0o700)
    except FileExistsError:
        pass
    except OSError as e:
        raise SealError(f"cannot create {paths.upgrade_root}: {e}") from e
    st = os.lstat(paths.upgrade_root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != _root_owner()[0]:
        raise SealError(f"{paths.upgrade_root} is not a directory of root's own; refusing to "
                        f"keep root's audit records there", fix="re-run install.sh as root")


def _write_root_record(paths: BoxPaths, path: Path, text: str) -> None:
    """A root-owned record in upgrade-root/, written by rename."""
    _root_dir(paths)
    try:
        atomic_write_bytes(path, text.encode(), RECORD_MODE, owner=_root_owner())
    except OSError as e:
        raise SealError(f"cannot write {path}: {e}") from e


def _remove(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        raise SealError(f"cannot remove {path}: {e}") from e


def mark_rotating(paths: BoxPaths) -> None:
    """Mark a rotation in progress: while it has the log moved aside,
    `health` warns instead of reporting the log missing."""
    _write_root_record(paths, paths.audit_rotating, f"{time.time():.0f}\n")


def unmark_rotating(paths: BoxPaths) -> None:
    _remove(paths.audit_rotating)


def rotation_in_progress(paths: BoxPaths) -> bool:
    """Whether a rotation's marker is there, root's and fresh. A stale one
    (a killed rotation) is ignored. Raises PermissionError when not root."""
    try:
        st = os.lstat(paths.audit_rotating)
    except FileNotFoundError:
        return False
    return (stat.S_ISREG(st.st_mode) and st.st_uid == _root_owner()[0]
            and time.time() - st.st_mtime < ROTATION_MARKER_FRESH_SECONDS)


def _seal_archives(paths: BoxPaths) -> list[str]:
    """Set the attribute again on every archive: a rotation that failed
    between moving the log and sealing the archive leaves one without it.
    A name of an archive's form that is not a plain regular file (a link, a
    FIFO, a second hard link: something deploy put in logs/) is no archive
    rotation made. It is skipped, not followed, and named in the list this
    returns, so it never fails install (and with it every release, security
    ones included)."""
    skipped = []
    for name in archives(paths.logs, paths.audit_log.name):
        where = paths.logs / name
        try:
            fd = open_log(where, create=False)
        except FileNotFoundError:
            continue  # removed since the listing
        except SealError as e:
            skipped.append(f"{e} Remove it if it is not an archive: sudo rm {where}")
            continue
        try:
            set_append_only(fd, True, where=where)
        finally:
            os.close(fd)
    return skipped


def seal(paths: BoxPaths) -> list[str]:
    """As root: open or create logs/audit.jsonl, make it deploy's and 0640,
    and set the append-only attribute, on it and on every archive. On a host
    that cannot set it, record why (upgrade-root/audit-append-unsupported)
    and return; a later seal that sets it removes the record. Returns what
    was wrong with each archive name it skipped (see _seal_archives). Raises
    SealError for anything else, the active log not being a plain regular
    file included."""
    where = paths.audit_log
    fd = open_log(where, create=True)
    try:
        try:
            own_and_seal(fd, where, attribute=True)
        except AppendUnsupported as e:
            own_and_seal(fd, where, attribute=False)
            _write_root_record(paths, paths.audit_append_unsupported,
                               f"{e.errno_name} {e.filesystem}\n")
            return []
    finally:
        os.close(fd)
    skipped = _seal_archives(paths)
    _remove(paths.audit_append_unsupported)
    return skipped
