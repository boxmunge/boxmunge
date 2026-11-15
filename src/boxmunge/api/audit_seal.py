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
state/audit-append-unsupported (root's) and leaves the log deploy's, 0640,
without it: the box installs, and `health` warns. On every other host a log
without the attribute is an error.

logs/ and state/ are deploy's, so every name is opened without following a
link (fs_nofollow), and the record counts only when root wrote it.
"""
from __future__ import annotations

import errno
import fcntl
import os
import struct
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
RECORD_MODE = 0o644
RECORD_LIMIT_BYTES = 4096

# The kernel boundary, a seam: tests replace it, as the ioctls need Linux and,
# to set +a, CAP_LINUX_IMMUTABLE.
_ioctl = fcntl.ioctl


class SealError(Exception):
    """The audit log could not be sealed, checked or rotated."""


class AppendUnsupported(SealError):
    """This host cannot set the append-only attribute at all."""

    def __init__(self, message: str, errno_name: str, filesystem: Path) -> None:
        super().__init__(message)
        self.errno_name = errno_name
        self.filesystem = filesystem


def _root_owner() -> tuple[int, int]:
    """The owner the unsupported record must have (a seam for tests)."""
    return 0, 0


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
    none. A record root did not write, or one that is a link or not a plain
    file, is refused with SealError: deploy can write state/, and a record it
    planted would keep the log unsealed."""
    path = paths.audit_append_unsupported
    try:
        fd = open_regular_nofollow(path, os.O_RDONLY)
    except FileNotFoundError:
        return None
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


def _record_unsupported(paths: BoxPaths, e: AppendUnsupported) -> None:
    """Root's record, written as a new file renamed over the name, so a file
    deploy planted there is replaced, not written through."""
    try:
        atomic_write_bytes(paths.audit_append_unsupported,
                           f"{e.errno_name} {e.filesystem}\n".encode(), RECORD_MODE,
                           owner=_root_owner())
    except OSError as err:
        raise SealError(f"{e}, and the record of it could not be written: {err}") from err


def seal(paths: BoxPaths) -> None:
    """As root: open or create logs/audit.jsonl, make it deploy's and 0640,
    and set the append-only attribute. On a host that cannot set it, record
    why (state/audit-append-unsupported) and return; a later seal that sets
    it removes the record. Raises SealError for anything else."""
    where = paths.audit_log
    fd = open_log(where, create=True)
    try:
        try:
            own_and_seal(fd, where, attribute=True)
        except AppendUnsupported as e:
            own_and_seal(fd, where, attribute=False)
            _record_unsupported(paths, e)
            return
    finally:
        os.close(fd)
    try:
        os.unlink(paths.audit_append_unsupported)
    except FileNotFoundError:
        pass
    except OSError as e:
        raise SealError(f"the log is sealed, but {paths.audit_append_unsupported} "
                        f"could not be removed: {e}") from e
