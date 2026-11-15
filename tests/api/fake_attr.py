# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the kernel's file attribute ioctls (FS_IOC_GETFLAGS and
FS_IOC_SETFLAGS), installed over api.audit_seal's seam: it keeps each inode's
flags, so a test can read which files carry the append-only attribute. The
real ioctls need Linux and, for +a, CAP_LINUX_IMMUTABLE."""
from __future__ import annotations

import os
import struct

from boxmunge.api import audit_seal


class FakeAttr:
    def __init__(self) -> None:
        self.flags: dict[int, int] = {}
        self.fail: int | None = None   # an errno every call raises
        self.fail_set: int | None = None   # an errno only setting raises

    def __call__(self, fd: int, request: int, arg: bytes) -> bytes:
        if self.fail is not None:
            raise OSError(self.fail, os.strerror(self.fail))
        ino = os.fstat(fd).st_ino
        if request == audit_seal.FS_IOC_GETFLAGS:
            return struct.pack("i", self.flags.get(ino, 0))
        if request == audit_seal.FS_IOC_SETFLAGS:
            if self.fail_set is not None:
                raise OSError(self.fail_set, os.strerror(self.fail_set))
            self.flags[ino] = struct.unpack("i", arg)[0]
            return arg
        raise AssertionError(f"unexpected ioctl request {request:#x}")

    def append_only(self, path) -> bool:
        return bool(self.flags.get(os.lstat(path).st_ino, 0) & audit_seal.FS_APPEND_FL)

    def clear(self, path) -> None:
        self.flags[os.lstat(path).st_ino] = 0


def install(monkeypatch) -> FakeAttr:
    """The fake ioctls, deploy and root played by the test's own user, and
    root running: seal and rotate run as root on a box."""
    fake = FakeAttr()
    me = (os.getuid(), os.getgid())
    monkeypatch.setattr(audit_seal, "_ioctl", fake)
    monkeypatch.setattr(audit_seal, "deploy_ids", lambda: me)
    monkeypatch.setattr(audit_seal, "_root_owner", lambda: me)
    monkeypatch.setattr(audit_seal, "running_as_root", lambda: True)
    return fake
