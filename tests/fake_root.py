# SPDX-License-Identifier: Apache-2.0
"""A simulated root run with a deploy user, for tests that cannot chown.

Tests cannot chown to another user, so the deploy uid is one nothing here
owns, "root" is whoever runs the test, and the fake chown stands in for "deploy
now owns it" by opening the directory's owner permissions (a mode-0555
directory is the stand-in for a root-owned one, which deploy cannot write).
"""
from __future__ import annotations

import os

import pytest

from boxmunge import deploy_dirs, fs_nofollow


@pytest.fixture
def fake_root(monkeypatch) -> list[str]:
    """Run as root with a deploy user nothing here owns. Returns the names
    chowned (directory fchowns record the inode)."""
    ids = (os.getuid() + 4242, os.getgid())
    for module in (deploy_dirs, fs_nofollow):
        monkeypatch.setattr(module, "running_as_root", lambda: True)
        monkeypatch.setattr(module, "deploy_ids", lambda: ids)
    monkeypatch.setattr(os, "getgrouplist", lambda user, gid: [gid])
    # "root" is whoever runs the test; a re-owned inode moves to the deploy uid.
    monkeypatch.setattr(deploy_dirs, "ROOT_UID", os.getuid())
    moved: dict[int, int] = {}
    monkeypatch.setattr(deploy_dirs, "_uid_of",
                        lambda fd: moved.get(os.fstat(fd).st_ino, os.fstat(fd).st_uid))
    chowned: list[str] = []

    def fchown(fd, uid, gid):
        chowned.append(str(os.fstat(fd).st_ino))
        moved[os.fstat(fd).st_ino] = uid
        os.fchmod(fd, 0o775)  # stand-in for "deploy owns it now"

    def chown(path, uid, gid, *, dir_fd=None, follow_symlinks=True):
        chowned.append(str(path))

    monkeypatch.setattr(os, "fchown", fchown)
    monkeypatch.setattr(os, "chown", chown)
    return chowned
