# SPDX-License-Identifier: Apache-2.0
"""Shift a data tree's owners into, or back out of, the remap range.

Run as root on the host while nothing uses the tree. Forward: an id below
65536 becomes id + S; an id already in [S, S+65535] is left (a resumed
walk); anything else is refused. Inverse: an id in [S, S+65535] becomes
id - S; anything else is left alone and reported.

Every entry is scanned before any is changed, so a refusal changes nothing.
Containers and the deploy user can write these trees and the directories
above them, so nothing follows a symlink (userns.walk); symlinks and
sockets are lchowned.

chown clears setuid, and setgid on a group-executable file. The scan lists
those entries with their modes; the caller journals the list before each
shift and passes it back, so a crash between an entry's chown and its chmod
is repaired by walking again. Idempotent otherwise.
"""
from __future__ import annotations

import enum
import errno
import fcntl
import os
import re
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path

from boxmunge.userns.walk import raise_fd_limit, reach_problem, walk

RANGE = 65536
MOUNTINFO = Path("/proc/self/mountinfo")
MAX_SETID = 1000  # more setuid/setgid files than this is not a data tree
_FS_IOC_GETFLAGS = 0x80086601
_FS_IMMUTABLE_FL = 0x00000010
_FS_APPEND_FL = 0x00000020
_REFUSED_XATTRS = ("system.posix_acl_access", "system.posix_acl_default",
                   "security.capability")
_OCTAL = re.compile(r"\\([0-7]{3})")  # mountinfo escapes space as \040


class Direction(enum.Enum):
    FORWARD = "forward"
    INVERSE = "inverse"


class ShiftRefused(Exception):
    """The tree holds something the shift must not touch; nothing changed."""

    def __init__(self, root: Path, problems: list[str]) -> None:
        self.problems = problems
        shown = "; ".join(problems[:20]) + (f"; and {len(problems) - 20} more"
                                           if len(problems) > 20 else "")
        super().__init__(f"{root}: {shown}")


@dataclass
class Scan:
    problems: list[str]
    entries: int
    setid: dict[str, int] = field(default_factory=dict)


@dataclass
class ShiftReport:
    entries: int = 0
    changed: int = 0
    left_alone: list[str] = field(default_factory=list)


def _check_offset(offset: int) -> None:
    if offset <= 0 or offset % RANGE:
        raise ValueError(f"remap offset {offset} is not a positive multiple of {RANGE}")


def mount_points_under(root: Path, mountinfo: Path = MOUNTINFO) -> list[str]:
    """Mount points strictly below `root` (reached without links, so its
    path is its real path)."""
    base = os.path.normpath(root).rstrip("/") + "/"
    found = []
    with open(mountinfo, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            point = _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), line.split()[4])
            if point.startswith(base):
                found.append(point)
    return sorted(found)


def _new_id(value: int, offset: int, direction: Direction) -> int | None:
    """The shifted id, the same id (already done), or None (refuse/report)."""
    in_range = offset <= value < offset + RANGE
    if direction is Direction.FORWARD:
        if value < RANGE:
            return value + offset
        return value if in_range else None
    if in_range:
        return value - offset
    return value if value < RANGE else None


def _flags(fd: int) -> int:
    try:
        buf = fcntl.ioctl(fd, _FS_IOC_GETFLAGS, struct.pack("l", 0))
    except OSError as e:
        if e.errno in (errno.ENOTTY, errno.EOPNOTSUPP, errno.EINVAL):
            return 0  # the filesystem keeps no such flags, so none is set
        raise
    return struct.unpack("l", buf)[0]


def _xattrs(fd: int) -> list[str]:
    try:
        return os.listxattr(fd)
    except OSError as e:
        if e.errno == errno.EOPNOTSUPP:
            return []  # the filesystem keeps no extended attributes
        raise


def _problems(rel: str, st: os.stat_result, fd: int | None, offset: int,
              direction: Direction, root_dev: int) -> list[str]:
    out = []
    if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
        out.append(f"{rel}: device node")
    if st.st_dev != root_dev:
        out.append(f"{rel}: on another filesystem (a mount inside the tree)")
    if direction is Direction.FORWARD:
        for kind, value in (("uid", st.st_uid), ("gid", st.st_gid)):
            if _new_id(value, offset, direction) is None:
                out.append(f"{rel}: {kind} {value} cannot be mapped (>= {RANGE})")
    if fd is not None:
        names = _xattrs(fd)
        out += [f"{rel}: has {n}" for n in _REFUSED_XATTRS if n in names]
        flags = _flags(fd)
        if flags & _FS_IMMUTABLE_FL:
            out.append(f"{rel}: immutable")
        if flags & _FS_APPEND_FL:
            out.append(f"{rel}: append-only")
    return out


def _loses_mode(st: os.stat_result) -> bool:
    """Would chown clear a bit of this entry's mode (setuid, or setgid on a
    group-executable non-directory)?"""
    if stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        return False
    return bool(st.st_mode & stat.S_ISUID) or (st.st_mode & (stat.S_ISGID | stat.S_IXGRP)
                                               == stat.S_ISGID | stat.S_IXGRP)


def scan_tree(root: Path, offset: int, direction: Direction) -> Scan:
    """Every reason the tree (or single file) cannot be shifted, its size,
    and the entries whose mode a chown would change."""
    _check_offset(offset)
    raise_fd_limit()
    problem = reach_problem(root)
    if problem:
        return Scan([problem], 0)
    problems = [f"{p}: a mount point inside the tree" for p in mount_points_under(root)]
    scan = Scan(problems, 0)
    links: dict[tuple[int, int], tuple[str, int, int]] = {}
    root_dev: list[int] = []

    def visit(rel, st, fd, _dir_fd, _name):
        if not root_dev:
            root_dev.append(st.st_dev)
        scan.entries += 1
        problems.extend(_problems(rel, st, fd, offset, direction, root_dev[0]))
        if _loses_mode(st):
            scan.setid[rel] = stat.S_IMODE(st.st_mode)
        if not stat.S_ISDIR(st.st_mode) and st.st_nlink > 1:
            first, nlink, seen = links.get((st.st_dev, st.st_ino), (rel, st.st_nlink, 0))
            links[(st.st_dev, st.st_ino)] = (first, nlink, seen + 1)

    walk(root, visit)
    problems += [f"{first}: hard link to a file outside the tree ({nlink} links, "
                 f"{seen} inside)" for first, nlink, seen in links.values() if seen < nlink]
    if len(scan.setid) > MAX_SETID:
        problems.append(f"{len(scan.setid)} setuid or setgid files (more than {MAX_SETID})")
    return scan


def shift_tree(root: Path, offset: int, direction: Direction,
               setid: dict[str, int] | None = None) -> ShiftReport:
    """Scan, then shift every entry. Raises ShiftRefused before any change.
    `setid` is the journalled list of an earlier scan (module docstring)."""
    scan = scan_tree(root, offset, direction)
    if scan.problems:
        raise ShiftRefused(root, scan.problems)
    modes = {**scan.setid, **(setid or {})}  # the journalled list knows the original modes
    report = ShiftReport()

    def visit(rel, st, fd, dir_fd, name):
        report.entries += 1
        uid = _new_id(st.st_uid, offset, direction)
        gid = _new_id(st.st_gid, offset, direction)
        if uid is None or gid is None:  # inverse only: outside both ranges
            report.left_alone.append(f"{rel} ({st.st_uid}:{st.st_gid})")
            uid = st.st_uid if uid is None else uid
            gid = st.st_gid if gid is None else gid
        if (uid, gid) != (st.st_uid, st.st_gid):
            if fd is not None:
                os.fchown(fd, uid, gid)
            else:
                os.chown(name, uid, gid, dir_fd=dir_fd, follow_symlinks=False)
            report.changed += 1
        if rel in modes and fd is not None:
            os.fchmod(fd, modes[rel])

    walk(root, visit)
    return report
