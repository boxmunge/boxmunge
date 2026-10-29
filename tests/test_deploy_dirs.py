# SPDX-License-Identifier: Apache-2.0
"""deploy_dirs: the directories deploy writes and root code paths may have made.

Tests cannot chown to another user, so a root run is simulated: the deploy
uid is one nothing here owns, and the fake chown stands in for "deploy now
owns it" by opening the directory's owner permissions (a mode-0555 directory
is the stand-in for a root-owned one, which deploy cannot write).
"""
from __future__ import annotations

import os

import pytest

from boxmunge import deploy_dirs, fs_nofollow

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
    """A directory root made before v0.9.3: deploy cannot write it."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o555)


def test_root_made_scans_is_reowned_and_written_by_deploy_afterwards(tmp_path, fake_root):
    """The regression: state/scans left by v0.6-v0.9.2, then `security scan`."""
    paths = _box(tmp_path)
    _root_made(paths.state / "scans")
    target = paths.project_scan_state("demo")
    with pytest.raises(OSError):
        target.write_text("{}")  # EACCES: what the deploy shell hit
    assert unwritable_by_deploy(paths) == [paths.state / "scans"]

    reowned = prepare_deploy_dirs(paths).done

    assert paths.state / "scans" in reowned
    assert unwritable_by_deploy(paths) == []
    target.write_text("{}")


def test_scan_state_write_succeeds_after_the_migration(tmp_path, fake_root):
    from boxmunge.cve.scan_state import ScanStateWriteError, write_scan_state
    paths = _box(tmp_path)
    _root_made(paths.state / "scans")
    with pytest.raises(ScanStateWriteError, match=f"sudo chown -R deploy:deploy {paths.state / 'scans'}"):
        write_scan_state(paths.project_scan_state("demo"), decisions=())
    prepare_deploy_dirs(paths)
    write_scan_state(paths.project_scan_state("demo"), decisions=())
    assert paths.project_scan_state("demo").exists()


def test_missing_state_dirs_are_created(tmp_path, fake_root):
    paths = _box(tmp_path)
    prepare_deploy_dirs(paths)
    assert all((paths.state / name).is_dir() for name in STATE_DIRS)


def test_project_security_dirs_are_reowned_and_other_project_dirs_are_not(tmp_path, fake_root):
    paths = _box(tmp_path)
    _root_made(paths.projects / "demo" / "security")
    (paths.projects / "demo" / "data").mkdir()
    (paths.projects / "demo" / "data").chmod(0o555)

    reowned = prepare_deploy_dirs(paths).done

    assert paths.projects / "demo" / "security" in reowned
    assert (paths.projects / "demo" / "data").stat().st_mode & 0o777 == 0o555


def test_root_only_state_and_parents_are_left_alone(tmp_path, fake_root):
    """container-updates (a root timer writes it) and the parents stay root's."""
    paths = _box(tmp_path)
    _root_made(paths.container_update_state)
    paths.state.chmod(0o755)
    prepare_deploy_dirs(paths)
    assert paths.container_update_state.stat().st_mode & 0o777 == 0o555
    assert paths.container_update_state not in existing_dirs(paths)
    assert paths.state.stat().st_mode & 0o777 == 0o755
    assert tmp_path.stat().st_mode & 0o777 != 0o775


def test_a_link_in_place_of_a_directory_is_not_followed(tmp_path, fake_root):
    paths = _box(tmp_path)
    outside = tmp_path / "outside"
    _root_made(outside)
    os.symlink(outside, paths.state / "scans")
    prepare_deploy_dirs(paths)
    assert outside.stat().st_mode & 0o777 == 0o555
    assert fake_root.count(str(outside.stat().st_ino)) == 0
    assert paths.state / "scans" not in existing_dirs(paths)


def test_deploy_owned_dirs_are_not_reported_as_reowned(tmp_path, fake_root, monkeypatch):
    paths = _box(tmp_path)
    (paths.state / "scans").mkdir()
    uid = os.getuid()
    for module in (deploy_dirs, fs_nofollow):
        monkeypatch.setattr(module, "deploy_ids", lambda: (uid, os.getgid()))
    assert paths.state / "scans" not in prepare_deploy_dirs(paths).done


def test_not_root_does_nothing(tmp_path, monkeypatch):
    paths = _box(tmp_path)
    monkeypatch.setattr(deploy_dirs, "running_as_root", lambda: False)
    assert prepare_deploy_dirs(paths).done == []
    assert not (paths.state / "scans").exists()


def test_unwritable_by_deploy_names_the_fix(tmp_path, fake_root):
    paths = _box(tmp_path)
    _root_made(paths.state / "kev")
    [blocked] = unwritable_by_deploy(paths)
    assert fix_command(blocked) == f"sudo chown -R deploy:deploy {paths.state / 'kev'}"


def test_unwritable_by_deploy_is_none_without_a_deploy_user(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy_dirs, "deploy_ids", lambda: None)
    assert unwritable_by_deploy(_box(tmp_path)) is None


def test_a_chown_that_does_not_take_is_reported_as_failed(tmp_path, fake_root, monkeypatch, caplog):
    paths = _box(tmp_path)
    _root_made(paths.state / "scans")
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: None)  # EPERM swallowed, say
    result = prepare_deploy_dirs(paths)
    assert paths.state / "scans" in result.failed
    assert paths.state / "scans" not in result.done


def test_a_linked_project_dir_is_not_followed(tmp_path, fake_root):
    paths = _box(tmp_path)
    outside = tmp_path / "outside"
    _root_made(outside / "security")
    os.symlink(outside, paths.projects / "demo")
    prepare_deploy_dirs(paths)
    assert (outside / "security").stat().st_mode & 0o777 == 0o555


def test_only_root_owned_entries_without_other_links_are_reowned(tmp_path, fake_root, monkeypatch):
    paths = _box(tmp_path)
    scans = paths.state / "scans"
    scans.mkdir()
    (scans / "own.json").write_text("{}")
    (tmp_path / "shared").write_text("x")
    os.link(tmp_path / "shared", scans / "linked.json")
    prepare_deploy_dirs(paths)
    assert not [c for c in fake_root if c.endswith("linked.json")]
    assert any(c.endswith("own.json") for c in fake_root)
