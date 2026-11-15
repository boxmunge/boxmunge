# SPDX-License-Identifier: Apache-2.0
"""deploy_dirs: the directories deploy writes and root code paths may create.

Tests cannot chown to another user, so a root run is simulated (fake_root),
and a mode-0555 directory stands in for a root-owned one, which deploy
cannot write.
"""
from __future__ import annotations

import os

import pytest

from boxmunge import deploy_dirs

from boxmunge.deploy_dirs import (
    STATE_DIRS, deploy_dirs as existing_dirs, fix_command, prepare_deploy_dirs,
    unwritable_by_deploy,
)
from boxmunge.paths import BoxPaths

pytestmark = pytest.mark.skipif(os.getuid() == 0, reason="root can write a 0555 directory")


def _box(tmp_path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path)
    paths.state.mkdir()
    paths.projects.mkdir()
    return paths


def _root_made(path) -> None:
    """A directory deploy cannot write, as a root-made one is."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o555)


def test_missing_state_dirs_are_created(tmp_path, fake_root):
    paths = _box(tmp_path)
    prepare_deploy_dirs(paths)
    assert all((paths.state / name).is_dir() for name in STATE_DIRS)


def test_a_link_in_place_of_a_directory_is_not_followed(tmp_path, fake_root):
    paths = _box(tmp_path)
    outside = tmp_path / "outside"
    _root_made(outside)
    os.symlink(outside, paths.state / "scans")
    prepare_deploy_dirs(paths)
    assert outside.stat().st_mode & 0o777 == 0o555
    assert paths.state / "scans" not in existing_dirs(paths)


def test_not_root_does_nothing(tmp_path, monkeypatch):
    paths = _box(tmp_path)
    monkeypatch.setattr(deploy_dirs, "running_as_root", lambda: False)
    prepare_deploy_dirs(paths)
    assert not (paths.state / "scans").exists()


def test_unwritable_by_deploy_names_the_fix(tmp_path, fake_root):
    paths = _box(tmp_path)
    _root_made(paths.state / "kev")
    [blocked] = unwritable_by_deploy(paths)
    assert fix_command(blocked) == f"sudo chown -R deploy:deploy {paths.state / 'kev'}"


def test_unwritable_by_deploy_is_none_without_a_deploy_user(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy_dirs, "deploy_ids", lambda: None)
    assert unwritable_by_deploy(_box(tmp_path)) is None
